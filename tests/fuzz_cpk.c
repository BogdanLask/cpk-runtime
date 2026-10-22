// SPDX-License-Identifier: MIT
/* libFuzzer harness: parser plus decoder. Build with CPKRT_BUILD_FUZZERS=ON
 * using Clang. Not part of the default build or CTest. */
#include "cpkrt/cpk.h"
#include "cpkrt/crilayla.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CPK_FUZZ_MAX_OUTPUT ((size_t)64u * 1024u * 1024u)

typedef struct {
    const uint8_t *data;
    size_t size;
} memory_file;

static bool memory_read(void *context, uint64_t offset, void *dst, size_t size)
{
    memory_file *file = context;
    if (offset > file->size || size > file->size - (size_t)offset) return false;
    if (size) memcpy(dst, file->data + (size_t)offset, size);
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;

    memory_file file = {data, size};
    cpk archive = {0};
    for (int variant = 0; variant < 4; variant++) {
        cpk_diag diag = {0};
        bool use_diag = (variant & 2) != 0;
        cpk_open_options options = {
            .layout = (variant & 1) ? CPK_LAYOUT_TABLE_ORDER : CPK_LAYOUT_ID_ORDER,
            .utf_max_version = 0,
            .diag = use_diag ? &diag : NULL,
        };
        cpk_status status = cpk_open_opts(&archive, memory_read, &file, size, &options);
        if (status == CPK_BAD_FORMAT && use_diag && diag.reason == CPK_REASON_NONE)
            abort();
        if (status == CPK_OK) {
            for (size_t i = 0; i < archive.count; i++) {
                const cpk_entry *entry = &archive.entries[i];
                (void)cpk_find(&archive, entry->id);
                (void)cpk_entry_compressed(entry);
            }
        }
        if (use_diag) {
            char text[32];
            (void)cpk_diag_format(&diag, text, sizeof text);
        }
        cpk_close(&archive);
    }

    size_t output_size = 0;
    if (crilayla_output_size(data, size, &output_size) == CRILAYLA_OK &&
        output_size <= CPK_FUZZ_MAX_OUTPUT) {
        uint8_t *output = malloc(output_size ? output_size : 1);
        if (output) {
            (void)crilayla_decode(data, size, output, output_size);
            free(output);
        }
    }
    return 0;
}
