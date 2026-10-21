// SPDX-License-Identifier: MIT
#include "cpkrt/cpk_assets.h"
#include "cpkrt/crilayla.h"
#include <stdlib.h>
#include <string.h>

struct archive {
    cpk_archive_source source;
    cpk index;
};

struct cpk_assets {
    struct archive *archives;
    size_t count;
    size_t leases;
    cpk_allocator allocator;
};

static void *default_alloc(void *context, size_t size)
{
    (void)context;
    return malloc(size);
}

static void default_free(void *context, void *block)
{
    (void)context;
    free(block);
}

static const cpk_allocator default_allocator = {NULL, default_alloc, default_free};

static void *assets_alloc(const cpk_assets *assets, size_t size)
{
    return assets->allocator.alloc(assets->allocator.context, size);
}

static void assets_free(const cpk_assets *assets, void *block)
{
    assets->allocator.free(assets->allocator.context, block);
}

static uint32_t cap_or_default(uint32_t cap)
{
    return cap ? cap : CPK_DEFAULT_ENTRY_CAP;
}

static cpk_asset_result error(cpk_asset_status status, const cpk_archive_source *source)
{
    return (cpk_asset_result){status,
                              source && source->last_error ? source->last_error(source->context) : 0};
}

static cpk_asset_status index_status(cpk_status status)
{
    switch (status) {
    case CPK_OK: return CPK_ASSET_OK;
    case CPK_IO: return CPK_ASSET_IO_ERROR;
    case CPK_NO_MEMORY: return CPK_ASSET_NO_MEMORY;
    default: return CPK_ASSET_INVALID;
    }
}

static bool source_valid(const cpk_archive_source *source)
{
    return source->read &&
           (source->layout == CPK_LAYOUT_ID_ORDER || source->layout == CPK_LAYOUT_TABLE_ORDER);
}

bool cpk_assets_close(cpk_assets **output)
{
    if (!output) return false;
    cpk_assets *assets = *output;
    if (!assets) return true;
    if (assets->leases) return false;
    for (size_t i = 0; i < assets->count; i++) cpk_close(&assets->archives[i].index);
    assets_free(assets, assets->archives);
    assets_free(assets, assets);
    *output = NULL;
    return true;
}

cpk_asset_result cpk_assets_open_ex(cpk_assets **output, const cpk_archive_source *sources,
                                    size_t count, const cpk_allocator *allocator)
{
    if (!output || *output || !sources || !count || count > SIZE_MAX / sizeof(struct archive) ||
        (allocator && (!allocator->alloc || !allocator->free)))
        return error(CPK_ASSET_INVALID, NULL);

    for (size_t i = 0; i < count; i++) {
        if (!source_valid(&sources[i])) return error(CPK_ASSET_INVALID, NULL);
        for (size_t j = 0; j < i; j++)
            if (sources[i].archive == sources[j].archive) return error(CPK_ASSET_INVALID, NULL);
    }

    cpk_allocator hooks = allocator ? *allocator : default_allocator;
    cpk_assets *assets = hooks.alloc(hooks.context, sizeof *assets);
    if (!assets) return error(CPK_ASSET_NO_MEMORY, NULL);
    memset(assets, 0, sizeof *assets);
    assets->allocator = hooks;
    assets->archives = assets_alloc(assets, count * sizeof *assets->archives);
    if (!assets->archives) {
        assets_free(assets, assets);
        return error(CPK_ASSET_NO_MEMORY, NULL);
    }
    memset(assets->archives, 0, count * sizeof *assets->archives);

    for (size_t i = 0; i < count; i++) {
        assets->archives[i].source = sources[i];
        cpk_open_options options = {
            .layout = sources[i].layout,
            .utf_max_version = sources[i].utf_max_version,
            .diag = sources[i].diag,
        };
        cpk_status status = cpk_open_opts(&assets->archives[i].index, sources[i].read,
                                          sources[i].context, sources[i].file_size,
                                          &options);
        if (status != CPK_OK) {
            cpk_asset_result result =
                error(index_status(status), status == CPK_IO ? &sources[i] : NULL);
            (void)cpk_assets_close(&assets);
            return result;
        }
        assets->count++;
    }

    *output = assets;
    return error(CPK_ASSET_OK, NULL);
}

cpk_asset_result cpk_assets_open(cpk_assets **output, const cpk_archive_source *sources,
                                 size_t count)
{
    return cpk_assets_open_ex(output, sources, count, NULL);
}

static const cpk_entry *locate(cpk_assets *assets, cpk_asset_key key, struct archive **found)
{
    *found = NULL;
    for (size_t i = 0; i < assets->count; i++)
        if (assets->archives[i].source.archive == key.archive) {
            *found = &assets->archives[i];
            break;
        }
    return *found ? cpk_find(&(*found)->index, key.id) : NULL;
}

static cpk_asset_result read_asset(void *context, cpk_asset_key key, cpk_asset_blob *output)
{
    cpk_assets *assets = context;
    struct archive *archive = NULL;
    if (!assets || !output || output->data || output->size || output->token)
        return error(CPK_ASSET_INVALID, NULL);

    const cpk_entry *entry = locate(assets, key, &archive);
    if (!entry) return error(CPK_ASSET_MISSING, NULL);

    const uint32_t stored_cap = cap_or_default(archive->source.max_stored_size);
    const uint32_t extract_cap = cap_or_default(archive->source.max_extract_size);
    if (entry->stored_size > stored_cap || entry->extract_size > extract_cap ||
        assets->leases == SIZE_MAX)
        return error(CPK_ASSET_TOO_LARGE, NULL);

    uint8_t *stored = assets_alloc(assets, entry->stored_size ? entry->stored_size : 1);
    if (!stored) return error(CPK_ASSET_NO_MEMORY, NULL);
    if (entry->stored_size &&
        !archive->source.read(archive->source.context, entry->offset, stored,
                              entry->stored_size)) {
        cpk_asset_result result = error(CPK_ASSET_IO_ERROR, &archive->source);
        assets_free(assets, stored);
        return result;
    }

    uint8_t *decoded = stored;
    if (cpk_entry_compressed(entry)) {
        size_t size = 0;
        crilayla_status status = crilayla_output_size(stored, entry->stored_size, &size);
        if (status != CRILAYLA_OK || size != entry->extract_size) {
            assets_free(assets, stored);
            return error(CPK_ASSET_INVALID, NULL);
        }
        decoded = assets_alloc(assets, size ? size : 1);
        if (!decoded) {
            assets_free(assets, stored);
            return error(CPK_ASSET_NO_MEMORY, NULL);
        }
        status = crilayla_decode(stored, entry->stored_size, decoded, size);
        assets_free(assets, stored);
        if (status != CRILAYLA_OK) {
            assets_free(assets, decoded);
            return error(CPK_ASSET_INVALID, NULL);
        }
    }

    *output = (cpk_asset_blob){decoded, entry->extract_size, decoded};
    assets->leases++;
    return error(CPK_ASSET_OK, NULL);
}

static cpk_asset_result read_into_asset(void *context, cpk_asset_key key, cpk_asset_buffer *buffer)
{
    cpk_assets *assets = context;
    struct archive *archive = NULL;
    if (!assets || !buffer || (!buffer->data && buffer->capacity) ||
        (!buffer->scratch && buffer->scratch_capacity))
        return error(CPK_ASSET_INVALID, NULL);

    const cpk_entry *entry = locate(assets, key, &archive);
    if (!entry) return error(CPK_ASSET_MISSING, NULL);

    const uint32_t stored_cap = cap_or_default(archive->source.max_stored_size);
    const uint32_t extract_cap = cap_or_default(archive->source.max_extract_size);
    if (entry->stored_size > stored_cap || entry->extract_size > extract_cap)
        return error(CPK_ASSET_TOO_LARGE, NULL);

    const bool packed = cpk_entry_compressed(entry);
    if (buffer->capacity < entry->extract_size ||
        (packed && buffer->scratch_capacity < entry->stored_size)) {
        buffer->size = entry->extract_size;
        buffer->scratch_size = packed ? entry->stored_size : 0;
        return error(CPK_ASSET_BUFFER_TOO_SMALL, NULL);
    }

    if (entry->stored_size &&
        !archive->source.read(archive->source.context, entry->offset,
                              packed ? buffer->scratch : buffer->data, entry->stored_size))
        return error(CPK_ASSET_IO_ERROR, &archive->source);

    if (!packed) {
        buffer->size = entry->extract_size;
        return error(CPK_ASSET_OK, NULL);
    }
    if (!entry->stored_size) return error(CPK_ASSET_INVALID, NULL);

    size_t size = 0;
    crilayla_status status = crilayla_output_size(buffer->scratch, entry->stored_size, &size);
    if (status != CRILAYLA_OK || size != entry->extract_size)
        return error(CPK_ASSET_INVALID, NULL);
    status = crilayla_decode(buffer->scratch, entry->stored_size, buffer->data, size);
    if (status != CRILAYLA_OK) return error(CPK_ASSET_INVALID, NULL);
    buffer->size = entry->extract_size;
    buffer->scratch_size = entry->stored_size;
    return error(CPK_ASSET_OK, NULL);
}

static void release_asset(void *context, const cpk_asset_blob *blob)
{
    cpk_assets *assets = context;
    if (assets)
        assets_free(assets, blob->token);
    else
        free(blob->token);
    if (assets && assets->leases) assets->leases--;
}

cpk_asset_provider cpk_assets_provider(cpk_assets *assets)
{
    return (cpk_asset_provider){assets, read_asset, release_asset, read_into_asset};
}
