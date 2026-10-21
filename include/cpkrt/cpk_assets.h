// SPDX-License-Identifier: MIT
#ifndef CPKRT_CPK_ASSETS_H
#define CPKRT_CPK_ASSETS_H
#include "cpkrt/asset.h"
#include "cpkrt/cpk.h"

/* Default per-entry cap for both stored and decoded sizes. Apply a smaller
 * library-wide budget by setting the cap fields on each source. */
#define CPK_DEFAULT_ENTRY_CAP ((uint32_t)64u * 1024u * 1024u)

typedef struct cpk_assets cpk_assets;

typedef struct {
    uint32_t archive;      /* caller-defined identifier, unique per source */
    cpk_read_fn read;      /* positional read callback for the archive file */
    void *context;         /* borrowed; must outlive the provider */
    uint64_t file_size;
    uint32_t (*last_error)(void *); /* optional, for host_error reporting */
    cpk_layout layout;
    uint32_t max_stored_size;  /* 0 selects CPK_DEFAULT_ENTRY_CAP */
    uint32_t max_extract_size; /* 0 selects CPK_DEFAULT_ENTRY_CAP */
} cpk_archive_source;

/* Optional allocation hooks for the provider's own structures and read
 * buffers. Both must be nonnull together; alloc is never called with 0;
 * free must accept NULL; the same context must outlive the provider and
 * every lease. NULL selects the C library malloc/free. Index allocations
 * inside cpk_open_ex() are not covered. */
typedef struct {
    void *context;
    void *(*alloc)(void *, size_t);
    void (*free)(void *, void *);
} cpk_allocator;

/* Copies the source descriptions and owns the validated indexes. Positional
 * contexts are borrowed and must outlive this synchronous, nonconcurrent
 * provider. No OS calls and no cache. Any number of distinct registered
 * archives is accepted; partial-open failures unwind all opened indexes.
 * Output starts NULL. Caps apply before allocation. Each successful read owns
 * fresh bytes until release; a partial decode never escapes. Caller-buffer
 * fills write into caller memory and take no lease; caps apply to fills too.
 * The allocator is copied and must stay valid until close; NULL selects the C
 * library malloc/free. */
cpk_asset_result cpk_assets_open_ex(cpk_assets **output, const cpk_archive_source *sources,
                                    size_t count, const cpk_allocator *allocator);
/* Same, with the C library allocator. */
cpk_asset_result cpk_assets_open(cpk_assets **output, const cpk_archive_source *sources,
                                 size_t count);
cpk_asset_provider cpk_assets_provider(cpk_assets *assets);
/* Refuses outstanding leases without destroying the provider. NULL is safe. */
bool cpk_assets_close(cpk_assets **output);
#endif
