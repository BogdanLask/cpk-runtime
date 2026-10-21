// SPDX-License-Identifier: MIT
#ifndef CPKRT_CPK_H
#define CPKRT_CPK_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Index-only reader for CRI CPK archives. It parses the CPK header, the @UTF
 * tables and the ITOC (ID-based) or TOC index, and produces a sorted array of
 * entries with absolute file offsets. It never reads entry payloads and never
 * decompresses; a caller or the optional asset provider does that using these
 * offsets.
 *
 * File access goes through a callback (for example pread, ReadFile, or an mmap
 * wrapper), so the parser has no OS or FILE* dependency. The callback must be
 * a positional read: it may be called with any offset in any order. */

typedef enum {
    CPK_OK,
    CPK_IO,
    CPK_NO_MEMORY,
    CPK_BAD_FORMAT,
    CPK_NO_INDEX,
    CPK_INVALID_ARG
} cpk_status;

/* A standalone legacy DataH/DataL ITOC stores sizes without offsets. Its
 * layout must be selected explicitly; neither order is assumed universal.
 * Archives with a TOC and an ID/TocIndex ITOC map use the TOC offsets and do
 * not depend on this choice. */
typedef enum {
    /* Files stored in ascending ID order, with alignment padding. */
    CPK_LAYOUT_ID_ORDER,
    /* Files stored in index order: every DataH row, then every DataL row,
     * each in table order. */
    CPK_LAYOUT_TABLE_ORDER
} cpk_layout;

/* Reads exactly size bytes at offset into dst. Returns false on any failure. */
typedef bool (*cpk_read_fn)(void *context, uint64_t offset, void *dst, size_t size);

typedef struct {
    uint32_t id;
    uint64_t offset;       /* absolute offset of the stored bytes in the file */
    uint32_t stored_size;  /* bytes on disk */
    uint32_t extract_size; /* bytes after decompression; == stored_size if raw */
    uint32_t table_order;  /* position in the index as stored: ITOC lists the
                              DataH rows first, then DataL; TOC uses its row
                              number. Diagnostics only; not an identity. Do not
                              derive IDs from display names or counters. */
} cpk_entry;

typedef struct {
    cpk_entry *entries; /* sorted by id, ids unique */
    size_t count;
    uint32_t align;          /* Align field from the CPK header */
    uint32_t declared_files; /* Checked against the index count. */
    uint32_t high_files;     /* ITOC: number of DataH rows; 0 for TOC */
    bool id_based;           /* true: ITOC, false: TOC with its ID column */
} cpk;

/* Clears *archive on entry. Callers must pass an uninitialized or closed
 * struct, never one that is already open. NULL arguments and an invalid layout
 * return CPK_INVALID_ARG. Failure leaves an empty output empty. Supports TOC
 * plus an optional ID/TocIndex ITOC map, and standalone DataH/DataL ITOC. TOC
 * requires explicit IDs; unsupported UTF versions and variants are rejected.
 * Host budgets: 16 MiB per UTF packet and 262144 entries (not format limits). */
cpk_status cpk_open_ex(cpk *archive, cpk_read_fn read, void *context, uint64_t file_size,
                       cpk_layout layout);
/* Same, with CPK_LAYOUT_ID_ORDER. */
cpk_status cpk_open(cpk *archive, cpk_read_fn read, void *context, uint64_t file_size);
void cpk_close(cpk *archive);

/* Binary search by ID. The returned pointer is valid until cpk_close. */
const cpk_entry *cpk_find(const cpk *archive, uint32_t id);

static inline bool cpk_entry_compressed(const cpk_entry *entry)
{
    return entry->stored_size != entry->extract_size;
}

/* Human-readable status, or "unknown" for an out-of-range value. */
const char *cpk_status_name(cpk_status status);
#endif
