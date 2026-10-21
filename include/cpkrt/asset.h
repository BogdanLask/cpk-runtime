// SPDX-License-Identifier: MIT
#ifndef CPKRT_ASSET_H
#define CPKRT_ASSET_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Generic asset interface. A lease-based read owns its bytes until release;
 * the optional caller-buffer read writes into caller memory, transfers no
 * ownership, and allocates nothing. The archive identifier is chosen by the
 * caller; the library only compares it for equality. Numeric IDs are local to
 * an archive: the same ID in two archives denotes two different resources. */
typedef struct {
    uint32_t archive;
    uint32_t id;
} cpk_asset_key;

typedef enum {
    CPK_ASSET_OK,
    CPK_ASSET_MISSING,
    CPK_ASSET_INVALID,
    CPK_ASSET_IO_ERROR,
    CPK_ASSET_NO_MEMORY,
    CPK_ASSET_TOO_LARGE,
    CPK_ASSET_UNSUPPORTED,
    CPK_ASSET_BUFFER_TOO_SMALL /* caller capacity smaller than the entry */
} cpk_asset_status;

typedef struct {
    cpk_asset_status status;
    uint32_t host_error; /* optional adapter-defined error code */
} cpk_asset_result;

/* One owned lease. data is immutable and must not be freed by the caller.
 * token is opaque provider bookkeeping. Empty files may have size 0 but still
 * return nonnull data. Do not copy ownership or release through another
 * provider. Parsers may borrow the bytes; the lease must outlive them. */
typedef struct {
    const uint8_t *data;
    size_t size;
    void *token;
} cpk_asset_blob;

typedef struct {
    void *data;              /* decoded output */
    size_t capacity;         /* writable bytes at data */
    void *scratch;           /* stored-entry staging; may be NULL */
    size_t scratch_capacity; /* writable bytes at scratch */
    size_t size;             /* out: decoded size / required size */
    size_t scratch_size;     /* out: staged size / required size */
} cpk_asset_buffer;

typedef struct {
    void *context;
    /* Synchronous full-entry read. Output starts zeroed. On failure any partial
     * lease must still be releasable; clear it if it was already freed. */
    cpk_asset_result (*read)(void *, cpk_asset_key, cpk_asset_blob *);
    /* Must release complete or partial leases; cannot fail. The provider and
     * its context must outlive every lease. */
    void (*release)(void *, const cpk_asset_blob *);
    /* Optional. Fills caller memory without allocating or taking a lease:
     * nothing to release. NULL means unsupported and cpk_asset_read_into()
     * reports CPK_ASSET_UNSUPPORTED. */
    cpk_asset_result (*read_into)(void *, cpk_asset_key, cpk_asset_buffer *);
} cpk_asset_provider;

/* Requires an empty output. Failure preserves it and releases any partial
 * provider output. Never replaces an outstanding lease. */
cpk_asset_result cpk_asset_read(const cpk_asset_provider *, cpk_asset_key, cpk_asset_blob *);
/* Reads one entry into caller memory. Never takes a lease, so
 * cpk_asset_release() does not apply and cpk_assets_close() is not blocked.
 * On CPK_ASSET_BUFFER_TOO_SMALL no payload byte is read from the source and
 * buffer->size / buffer->scratch_size report what a retry needs. The
 * destination is written only on CPK_ASSET_OK. */
cpk_asset_result cpk_asset_read_into(const cpk_asset_provider *, cpk_asset_key, cpk_asset_buffer *);
/* Clears the lease after its provider releases it. Releasing an empty lease is
 * idempotent and returns true. */
bool cpk_asset_release(const cpk_asset_provider *, cpk_asset_blob *);
#endif
