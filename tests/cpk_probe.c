// SPDX-License-Identifier: MIT
/* Test adapter only: positional stdio lives outside the OS-independent core. */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#include "cpkrt/cpk.h"
#include "cpkrt/cpk_assets.h"
#include "cpkrt/crilayla.h"
#include "cpkrt/file.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <sys/types.h>
_Static_assert(sizeof(off_t) >= 8, "64-bit file offsets required");
#endif

#define LIMIT CPK_DEFAULT_ENTRY_CAP

static bool seek_file(FILE *f, uint64_t at)
{
    if (at > INT64_MAX) return false;
#ifdef _WIN32
    return _fseeki64(f, (int64_t)at, SEEK_SET) == 0;
#else
    return fseeko(f, (off_t)at, SEEK_SET) == 0;
#endif
}

static bool read_at(void *ctx, uint64_t at, void *dst, size_t n)
{
    FILE *f = ctx;
    return seek_file(f, at) && fread(dst, 1, n, f) == n;
}

static bool file_size(FILE *f, uint64_t *n)
{
#ifdef _WIN32
    int64_t end;
    if (_fseeki64(f, 0, SEEK_END) != 0) return false;
    end = _ftelli64(f);
#else
    off_t end;
    if (fseeko(f, 0, SEEK_END) != 0) return false;
    end = ftello(f);
#endif
    if (end < 0) return false;
    *n = (uint64_t)end;
    return true;
}

static bool fail_read(void *ctx, uint64_t at, void *dst, size_t n)
{
    (void)ctx;
    (void)at;
    (void)dst;
    (void)n;
    return false;
}

static bool parse_id(const char *s, uint32_t *id)
{
    uint32_t v = 0;
    if (*s == '\0') return false;
    for (; *s != '\0'; ++s) {
        uint32_t digit;
        if (*s >= '0' && *s <= '9') digit = (uint32_t)(*s - '0');
        else if (*s >= 'a' && *s <= 'f') digit = (uint32_t)(*s - 'a') + 10u;
        else if (*s >= 'A' && *s <= 'F') digit = (uint32_t)(*s - 'A') + 10u;
        else return false;
        if (v > (UINT32_MAX - digit) / 16u) return false;
        v = v * 16u + digit;
    }
    *id = v;
    return true;
}

static int emit(const uint8_t *in, size_t n, bool packed, size_t expected)
{
    uint8_t *out = NULL;
    if (packed) {
        size_t size = 0;
        crilayla_status status = crilayla_output_size(in, n, &size);
        if (status != CRILAYLA_OK || size > LIMIT || (expected != 0 && expected != size)) {
            fprintf(stderr, "header/size: %s\n", crilayla_status_name(status));
            return 1;
        }
        out = malloc(size ? size : 1);
        if (out == NULL) return 1;
        status = crilayla_decode(in, n, out, size);
        if (status != CRILAYLA_OK) {
            fprintf(stderr, "decode: %s\n", crilayla_status_name(status));
            free(out);
            return 1;
        }
        in = out;
        n = size;
    }
#ifdef _WIN32
    if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
        free(out);
        return 1;
    }
#endif
    {
        bool ok = fwrite(in, 1, n, stdout) == n && fflush(stdout) == 0;
        free(out);
        return ok ? 0 : 1;
    }
}

/* Counts hook calls so tests can assert that fills do not allocate and that
 * lease and destroy paths balance. fail_after == 0 disables failures. */
typedef struct {
    uint32_t allocs;
    uint32_t frees;
    uint32_t fail_after;
} counting_allocator;

static void *counting_alloc(void *context, size_t size)
{
    counting_allocator *counter = context;
    void *block;
    if (counter->fail_after && counter->allocs >= counter->fail_after) return NULL;
    block = malloc(size);
    if (block) counter->allocs++;
    return block;
}

static void counting_free(void *context, void *block)
{
    counting_allocator *counter = context;
    counter->frees++;
    free(block);
}

static int arguments(void)
{
    uint8_t bytes[600] = {0};
    size_t n = 99;
    cpk_asset_blob blob = {0};
    cpk_asset_provider none = {0};
    cpk_asset_buffer buffer = {0};
    cpk_archive_source dummy = {0};
    cpk_assets *assets = NULL;
    cpk_allocator pair = {NULL, counting_alloc, NULL};
    memcpy(bytes, "CRILAYLA", 8);
    if (crilayla_output_size(bytes, sizeof(bytes), NULL) != CRILAYLA_INVALID ||
        crilayla_output_size(NULL, 0, &n) == CRILAYLA_OK || n != 0 ||
        crilayla_decode(bytes, 272, bytes, 256) != CRILAYLA_INVALID ||
        crilayla_decode(bytes, 272, bytes + 16, 256) != CRILAYLA_INVALID ||
        crilayla_decode(bytes, 272, NULL, 256) == CRILAYLA_OK ||
        crilayla_decode(bytes, 272, bytes + 300, 255) != CRILAYLA_SIZE_MISMATCH)
        return 1;
    cpk_close(NULL);
    if (cpk_find(NULL, 0) != NULL) return 1;
    if (cpk_asset_read(NULL, (cpk_asset_key){1, 0}, &blob).status != CPK_ASSET_INVALID ||
        cpk_asset_release(NULL, &blob))
        return 1;
    if (cpk_asset_read_into(NULL, (cpk_asset_key){1, 0}, &buffer).status != CPK_ASSET_INVALID ||
        cpk_asset_read_into(&none, (cpk_asset_key){1, 0}, &buffer).status !=
            CPK_ASSET_UNSUPPORTED ||
        cpk_asset_read_into(&none, (cpk_asset_key){1, 0}, NULL).status != CPK_ASSET_INVALID)
        return 1;
    /* Allocation hooks must be provided together. */
    if (cpk_assets_open_ex(NULL, &dummy, 1, NULL).status != CPK_ASSET_INVALID ||
        cpk_assets_open_ex(&assets, &dummy, 1, &pair).status != CPK_ASSET_INVALID || assets)
        return 1;
    pair.alloc = NULL;
    pair.free = counting_free;
    if (cpk_assets_open_ex(&assets, &dummy, 1, &pair).status != CPK_ASSET_INVALID || assets)
        return 1;
    pair.alloc = counting_alloc;
    if (cpk_assets_open_ex(&assets, &dummy, 1, &pair).status != CPK_ASSET_INVALID || assets)
        return 1;
    if (cpk_assets_close(NULL) || cpk_assets_open(NULL, NULL, 0).status != CPK_ASSET_INVALID ||
        cpk_assets_open_ex(&assets, NULL, 0, NULL).status != CPK_ASSET_INVALID)
        return 1;
    return 0;
}

typedef struct {
    FILE *file;
    bool fail;
    uint8_t payload_mark;
} fake_source;

static bool fake_read(void *ctx, uint64_t offset, void *out, size_t size)
{
    fake_source *source = ctx;
    if (source->fail || !read_at(source->file, offset, out, size)) return false;
    if (source->payload_mark && offset >= 4096u && size)
        ((uint8_t *)out)[0] = source->payload_mark;
    return true;
}

static uint32_t fake_error(void *ctx)
{
    fake_source *source = ctx;
    return source->fail ? 123u : 0u;
}

static int provider_contracts(FILE *f, uint64_t size)
{
    fake_source source = {f, false, 0}, model = {f, false, 77};
    cpk_assets *assets = NULL;
    cpk_archive_source sources[2] = {
        {1, fake_read, &source, size, fake_error, CPK_LAYOUT_ID_ORDER, 0, 0},
        {2, fake_read, &model, size, fake_error, CPK_LAYOUT_ID_ORDER, 0, 0},
    };
    if (cpk_assets_open(&assets, sources, 2).status != CPK_ASSET_OK) return 1;
    if (cpk_assets_open(&assets, sources, 2).status != CPK_ASSET_INVALID) return 1;
    cpk_asset_provider provider = cpk_assets_provider(assets);
    cpk_asset_blob a = {0}, b = {0};
    cpk_asset_result result = cpk_asset_read(&provider, (cpk_asset_key){3, 42}, &a);
    if (result.status != CPK_ASSET_MISSING || a.data) return 1;
    if (cpk_asset_read(&provider, (cpk_asset_key){1, 42}, &a).status != CPK_ASSET_OK ||
        cpk_asset_read(&provider, (cpk_asset_key){2, 42}, &b).status != CPK_ASSET_OK ||
        a.data == b.data || a.size != b.size || a.data[0] != 65 || b.data[0] != 77)
        return 1;
    if (cpk_assets_close(&assets) || !assets) return 1;
    const uint8_t *owned = a.data;
    if (cpk_asset_read(&provider, (cpk_asset_key){1, 7}, &a).status != CPK_ASSET_INVALID ||
        a.data != owned)
        return 1;
    if (!cpk_asset_release(&provider, &a) || !cpk_asset_release(&provider, &b) ||
        !cpk_asset_release(&provider, &b))
        return 1;
    source.fail = true;
    result = cpk_asset_read(&provider, (cpk_asset_key){1, 42}, &a);
    if (result.status != CPK_ASSET_IO_ERROR || result.host_error != 123 || a.data || a.size ||
        a.token)
        return 1;
    if (!cpk_assets_close(&assets) || assets || !cpk_assets_close(&assets)) return 1;
    source.fail = false;

    /* Four archives, then more than the old fixed slot count: the provider is
     * not limited to a hard-coded number of distinct registrations. */
    cpk_archive_source all[5] = {sources[0], sources[1], sources[0], sources[0], sources[0]};
    all[2].archive = 3;
    all[3].archive = 4;
    all[4].archive = 5;
    if (cpk_assets_open(&assets, all, 4).status != CPK_ASSET_OK) return 1;
    provider = cpk_assets_provider(assets);
    cpk_asset_blob owned_all[4] = {0};
    for (uint32_t i = 0; i < 4; i++)
        if (cpk_asset_read(&provider, (cpk_asset_key){all[i].archive, 42}, &owned_all[i]).status !=
            CPK_ASSET_OK)
            return 1;
    if (cpk_assets_close(&assets)) return 1;
    for (uint32_t i = 0; i < 4; i++)
        if (!cpk_asset_release(&provider, &owned_all[i])) return 1;
    if (!cpk_assets_close(&assets)) return 1;

    if (cpk_assets_open(&assets, all, 5).status != CPK_ASSET_OK || !assets) return 1;
    provider = cpk_assets_provider(assets);
    if (cpk_asset_read(&provider, (cpk_asset_key){5, 42}, &a).status != CPK_ASSET_OK ||
        !cpk_asset_release(&provider, &a) || !cpk_assets_close(&assets))
        return 1;

    /* Per-source caps are applied before allocation, for leases and fills. */
    sources[0].max_extract_size = 3;
    if (cpk_assets_open(&assets, sources, 2).status != CPK_ASSET_OK) return 1;
    provider = cpk_assets_provider(assets);
    {
        uint8_t data[8] = {0};
        cpk_asset_buffer buffer = {data, sizeof data, NULL, 0, 0, 0};
        if (cpk_asset_read_into(&provider, (cpk_asset_key){1, 42}, &buffer).status !=
                CPK_ASSET_TOO_LARGE ||
            buffer.size || buffer.scratch_size)
            return 1;
    }
    if (cpk_asset_read(&provider, (cpk_asset_key){1, 42}, &a).status != CPK_ASSET_TOO_LARGE ||
        a.data || !cpk_assets_close(&assets))
        return 1;
    sources[0].max_extract_size = 0;

    /* Fills write into caller memory: no lease, no allocation, exact retry
     * sizes, and unaligned buffers are accepted. Hooks cover the provider's
     * own structures and lease buffers. */
    {
        counting_allocator counter = {0, 0, 0};
        cpk_allocator allocator = {&counter, counting_alloc, counting_free};
        uint8_t data[8], scratch[8];
        cpk_asset_buffer buffer;
        cpk_asset_blob lease = {0};
        uint32_t allocs, frees;

        if (cpk_assets_open_ex(&assets, sources, 2, &allocator).status != CPK_ASSET_OK) return 1;
        provider = cpk_assets_provider(assets);
        if (cpk_asset_read_into(NULL, (cpk_asset_key){1, 42}, &buffer).status !=
                CPK_ASSET_INVALID ||
            cpk_asset_read_into(&provider, (cpk_asset_key){1, 42}, NULL).status !=
                CPK_ASSET_INVALID)
            return 1;
        buffer = (cpk_asset_buffer){NULL, 0, NULL, 0, 0, 0};
        if (cpk_asset_read_into(&provider, (cpk_asset_key){3, 42}, &buffer).status !=
                CPK_ASSET_MISSING ||
            buffer.size || buffer.scratch_size)
            return 1;

        allocs = counter.allocs;
        frees = counter.frees;
        buffer = (cpk_asset_buffer){data + 1, sizeof data - 1, scratch + 1,
                                    sizeof scratch - 1, 0, 0};
        if (cpk_asset_read_into(&provider, (cpk_asset_key){1, 42}, &buffer).status !=
                CPK_ASSET_OK ||
            buffer.size != 4 || buffer.scratch_size || data[1] != 65 ||
            counter.allocs != allocs || counter.frees != frees)
            return 1;

        if (cpk_asset_read(&provider, (cpk_asset_key){1, 42}, &lease).status != CPK_ASSET_OK ||
            lease.size != 4 || lease.data[0] != 65)
            return 1;
        /* A fill is not a lease: it works while a lease is outstanding, and it
         * does not unblock close. */
        if (cpk_asset_read_into(&provider, (cpk_asset_key){1, 42}, &buffer).status !=
                CPK_ASSET_OK ||
            cpk_assets_close(&assets))
            return 1;
        if (!cpk_asset_release(&provider, &lease) || !cpk_assets_close(&assets)) return 1;
        if (counter.allocs != counter.frees) return 1;

        /* A failing allocation unwinds without leaking. */
        counter.fail_after = counter.allocs + 1;
        if (cpk_assets_open_ex(&assets, sources, 2, &allocator).status != CPK_ASSET_NO_MEMORY ||
            assets)
            return 1;
        if (counter.allocs != counter.frees) return 1;
    }

    source.fail = false;
    sources[1].archive = 1;
    if (cpk_assets_open(&assets, sources, 2).status != CPK_ASSET_INVALID || assets) return 1;
    sources[1].archive = 2;
    sources[1].file_size = 4;
    if (cpk_assets_open(&assets, sources, 2).status == CPK_ASSET_OK || assets) return 1;
    if (cpk_assets_open(&assets, NULL, 1).status != CPK_ASSET_INVALID ||
        cpk_assets_open(&assets, sources, 0).status != CPK_ASSET_INVALID ||
        cpk_assets_close(NULL))
        return 1;
    return 0;
}

static int file_provider(const char *path, const char *identity)
{
    cpk_file *file = NULL;
    uint64_t size = 0;
    uint32_t id = 0;
    if (!parse_id(identity, &id)) return 2;

    cpk_asset_result result = cpk_file_open(path, &file, &size);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "file open status %u host %" PRIu32 "\n", (unsigned int)result.status,
                result.host_error);
        return 1;
    }

    cpk_archive_source source = {1, cpk_file_read, file, size, cpk_file_error,
                                 CPK_LAYOUT_ID_ORDER, 0, 0};
    cpk_assets *assets = NULL;
    result = cpk_assets_open(&assets, &source, 1);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "provider open status %u host %" PRIu32 "\n",
                (unsigned int)result.status, result.host_error);
        (void)cpk_file_close(file);
        return 1;
    }

    cpk_asset_provider provider = cpk_assets_provider(assets);
    cpk_asset_blob bytes = {0};
    result = cpk_asset_read(&provider, (cpk_asset_key){1, id}, &bytes);
    int ret = 1;
    if (result.status == CPK_ASSET_OK) {
        ret = emit(bytes.data, bytes.size, false, bytes.size);
    } else {
        fprintf(stderr, "provider read status %u host %" PRIu32 "\n",
                (unsigned int)result.status, result.host_error);
    }
    (void)cpk_asset_release(&provider, &bytes);
    if (!cpk_assets_close(&assets) || assets) return 1;
    if (!cpk_file_close(file)) return 1;
    return ret;
}

typedef struct {
    cpk_file *file;
    uint64_t reads;
} counted_file;

static bool counted_read(void *ctx, uint64_t offset, void *out, size_t size)
{
    counted_file *counter = ctx;
    if (!cpk_file_read(counter->file, offset, out, size)) return false;
    counter->reads++;
    return true;
}

static int file_provider_into(const char *path, const char *identity)
{
    cpk_file *file = NULL;
    uint64_t file_size = 0;
    uint32_t id = 0;
    if (!parse_id(identity, &id)) return 2;

    cpk_asset_result result = cpk_file_open(path, &file, &file_size);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "file open status %u host %" PRIu32 "\n", (unsigned int)result.status,
                result.host_error);
        return 1;
    }

    counted_file counted = {file, 0};
    cpk archive = {0};
    cpk_status status = cpk_open(&archive, counted_read, &counted, file_size);
    if (status != CPK_OK) {
        fprintf(stderr, "index: %s\n", cpk_status_name(status));
        (void)cpk_file_close(file);
        return 1;
    }
    const cpk_entry *entry = cpk_find(&archive, id);
    if (!entry) {
        fprintf(stderr, "entry not found\n");
        cpk_close(&archive);
        (void)cpk_file_close(file);
        return 1;
    }

    cpk_archive_source source = {1, counted_read, &counted, file_size, NULL,
                                 CPK_LAYOUT_ID_ORDER, 0, 0};
    cpk_assets *assets = NULL;
    result = cpk_assets_open(&assets, &source, 1);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "provider open status %u host %" PRIu32 "\n",
                (unsigned int)result.status, result.host_error);
        cpk_close(&archive);
        (void)cpk_file_close(file);
        return 1;
    }

    const bool packed = cpk_entry_compressed(entry);
    const size_t extract_size = entry->extract_size;
    const size_t stored_size = entry->stored_size;
    uint8_t *data = malloc(extract_size ? extract_size : 1);
    uint8_t *scratch = packed && stored_size ? malloc(stored_size) : NULL;
    if (!data || (packed && stored_size && !scratch)) {
        free(data);
        free(scratch);
        (void)cpk_assets_close(&assets);
        cpk_close(&archive);
        (void)cpk_file_close(file);
        return 1;
    }

    cpk_asset_provider provider = cpk_assets_provider(assets);
    cpk_asset_buffer buffer = {data, 0, scratch, 0, 0, 0};
    int ret = 1;
    counted.reads = 0;
    /* A too-small descriptor reports the retry sizes and reads no payload. */
    if (cpk_asset_read_into(&provider, (cpk_asset_key){1, id}, &buffer).status !=
            CPK_ASSET_BUFFER_TOO_SMALL ||
        buffer.size != extract_size || buffer.scratch_size != (packed ? stored_size : 0) ||
        counted.reads != 0)
        goto done;
    if (packed && stored_size) {
        buffer.capacity = extract_size - 1;
        buffer.scratch_capacity = stored_size;
        if (cpk_asset_read_into(&provider, (cpk_asset_key){1, id}, &buffer).status !=
                CPK_ASSET_BUFFER_TOO_SMALL ||
            buffer.size != extract_size || buffer.scratch_size != stored_size ||
            counted.reads != 0)
            goto done;
        buffer.capacity = extract_size;
        buffer.scratch_capacity = stored_size - 1;
        if (cpk_asset_read_into(&provider, (cpk_asset_key){1, id}, &buffer).status !=
                CPK_ASSET_BUFFER_TOO_SMALL ||
            buffer.size != extract_size || buffer.scratch_size != stored_size ||
            counted.reads != 0)
            goto done;
    }
    buffer.capacity = extract_size;
    buffer.scratch_capacity = packed ? stored_size : 0;
    if (cpk_asset_read_into(&provider, (cpk_asset_key){1, id}, &buffer).status != CPK_ASSET_OK ||
        buffer.size != extract_size || buffer.scratch_size != (packed ? stored_size : 0))
        goto done;

    /* The exact fit must match the lease path byte for byte. */
    cpk_asset_blob lease = {0};
    if (cpk_asset_read(&provider, (cpk_asset_key){1, id}, &lease).status != CPK_ASSET_OK ||
        lease.size != buffer.size ||
        (lease.size && memcmp(lease.data, data, lease.size) != 0)) {
        (void)cpk_asset_release(&provider, &lease);
        goto done;
    }
    (void)cpk_asset_release(&provider, &lease);
    /* The fill took no lease, so close succeeds without a release. */
    if (!cpk_assets_close(&assets)) goto done;
    ret = 0;
    if (extract_size) {
#ifdef _WIN32
        if (_setmode(_fileno(stdout), _O_BINARY) == -1) ret = 1;
#endif
        if (ret == 0 &&
            (fwrite(data, 1, extract_size, stdout) != extract_size || fflush(stdout) != 0))
            ret = 1;
    }
done:
    free(data);
    free(scratch);
    if (assets && !cpk_assets_close(&assets)) ret = 1;
    cpk_close(&archive);
    if (!cpk_file_close(file)) ret = 1;
    return ret;
}

int main(int argc, char **argv)
{
    FILE *f;
    uint64_t size = 0;
    cpk archive = {0};
    cpk_status status;
    int result = 1;
    if (argc == 2 && strcmp(argv[1], "arguments") == 0) return arguments();
    if (argc < 3) return 2;
    if (strcmp(argv[1], "files") == 0 && argc == 4) return file_provider(argv[2], argv[3]);
    if (strcmp(argv[1], "read_into") == 0 && argc == 4) return file_provider_into(argv[2], argv[3]);
    f = fopen(argv[2], "rb");
    if (f == NULL || !file_size(f, &size)) {
        if (f != NULL) fclose(f);
        return 1;
    }
    if (strcmp(argv[1], "provider_contracts") == 0) {
        result = provider_contracts(f, size);
        fclose(f);
        return result;
    }
    if (strcmp(argv[1], "decode") == 0) {
        uint8_t *bytes;
        if (size == 0 || size > LIMIT) {
            fclose(f);
            return 1;
        }
        bytes = malloc((size_t)size);
        if (bytes != NULL && read_at(f, 0, bytes, (size_t)size))
            result = emit(bytes, (size_t)size, true, 0);
        free(bytes);
        fclose(f);
        return result;
    }
    status = cpk_open_ex(&archive, read_at, f, size,
                         strcmp(argv[1], "table") == 0 ? CPK_LAYOUT_TABLE_ORDER
                                                       : CPK_LAYOUT_ID_ORDER);
    if (status != CPK_OK) {
        fprintf(stderr, "index: %s\n", cpk_status_name(status));
        fclose(f);
        return 1;
    }
    if (strcmp(argv[1], "index") == 0 || strcmp(argv[1], "table") == 0) {
        printf("%zu %" PRIu32 " %" PRIu32 "\n", archive.count, archive.align,
               archive.declared_files);
        for (size_t i = 0; i < archive.count; ++i) {
            const cpk_entry *e = &archive.entries[i];
            printf("%" PRIu32 " %" PRIu32 " %" PRIu64 " %" PRIu32 " %" PRIu32 "\n", e->id,
                   e->table_order, e->offset, e->stored_size, e->extract_size);
        }
        result = 0;
    } else if (strcmp(argv[1], "lifecycle") == 0) {
        cpk garbage;
        result = 0;
        memset(&garbage, 0xa5, sizeof garbage);
        if (cpk_open(&garbage, NULL, f, size) != CPK_INVALID_ARG ||
            garbage.entries != NULL || garbage.count != 0)
            result = 1;
        memset(&garbage, 0xa5, sizeof garbage);
        if (cpk_open_ex(&garbage, read_at, f, size, (cpk_layout)99) != CPK_INVALID_ARG ||
            garbage.entries != NULL || garbage.count != 0)
            result = 1;
        if (cpk_open(NULL, read_at, f, size) != CPK_INVALID_ARG ||
            cpk_open_ex(NULL, read_at, f, size, CPK_LAYOUT_ID_ORDER) != CPK_INVALID_ARG)
            result = 1;
        cpk_close(&archive);
        cpk_close(&archive);
        if (cpk_open(&archive, fail_read, f, size) == CPK_OK || archive.entries != NULL ||
            archive.count != 0)
            result = 1;
        if (cpk_open(&archive, read_at, f, size) != CPK_OK) result = 1;
    } else if (strcmp(argv[1], "extract") == 0 && argc == 4) {
        uint32_t id;
        if (parse_id(argv[3], &id)) {
            const cpk_entry *e = cpk_find(&archive, id);
            if (e != NULL && e->stored_size <= LIMIT && e->extract_size <= LIMIT) {
                uint8_t *bytes = malloc(e->stored_size != 0 ? e->stored_size : 1);
                if (bytes != NULL && read_at(f, e->offset, bytes, e->stored_size))
                    result = emit(bytes, e->stored_size, cpk_entry_compressed(e),
                                  e->extract_size);
                free(bytes);
            }
        }
    }
    cpk_close(&archive);
    fclose(f);
    return result;
}
