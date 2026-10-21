// SPDX-License-Identifier: MIT
#include "cpkrt/asset.h"

static bool empty(const cpk_asset_blob *blob)
{
    return !blob->data && !blob->size && !blob->token;
}

static bool valid(const cpk_asset_provider *provider)
{
    return provider && provider->read && provider->release;
}

cpk_asset_result cpk_asset_read(const cpk_asset_provider *provider, cpk_asset_key key,
                                cpk_asset_blob *output)
{
    if (!valid(provider) || !output || !empty(output))
        return (cpk_asset_result){CPK_ASSET_INVALID, 0};

    cpk_asset_blob next = {0};
    cpk_asset_result result = provider->read(provider->context, key, &next);
    if (result.status == CPK_ASSET_OK && next.data) {
        *output = next;
        return result;
    }
    if (!empty(&next)) provider->release(provider->context, &next);
    if (result.status == CPK_ASSET_OK) result = (cpk_asset_result){CPK_ASSET_INVALID, 0};
    return result;
}

cpk_asset_result cpk_asset_read_into(const cpk_asset_provider *provider, cpk_asset_key key,
                                     cpk_asset_buffer *buffer)
{
    if (!provider || !buffer) return (cpk_asset_result){CPK_ASSET_INVALID, 0};
    if (!provider->read_into) return (cpk_asset_result){CPK_ASSET_UNSUPPORTED, 0};
    if ((!buffer->data && buffer->capacity) ||
        (!buffer->scratch && buffer->scratch_capacity))
        return (cpk_asset_result){CPK_ASSET_INVALID, 0};
    buffer->size = 0;
    buffer->scratch_size = 0;
    cpk_asset_result result = provider->read_into(provider->context, key, buffer);
    if (result.status == CPK_ASSET_OK &&
        (buffer->size > buffer->capacity || buffer->scratch_size > buffer->scratch_capacity))
        result = (cpk_asset_result){CPK_ASSET_INVALID, 0};
    if (result.status != CPK_ASSET_OK && result.status != CPK_ASSET_BUFFER_TOO_SMALL) {
        buffer->size = 0;
        buffer->scratch_size = 0;
    }
    return result;
}

bool cpk_asset_release(const cpk_asset_provider *provider, cpk_asset_blob *blob)
{
    if (!valid(provider) || !blob) return false;
    if (!empty(blob)) provider->release(provider->context, blob);
    *blob = (cpk_asset_blob){0};
    return true;
}
