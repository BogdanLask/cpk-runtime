// SPDX-License-Identifier: MIT
/* Print one entry's index metadata to stderr, then write its bytes to stdout.
 *
 * Usage: cpkrt_index <archive.cpk> <entry-id>
 *
 * Uses only the core: cpk_open(), cpk_find(), and the CRILAYLA decoder. The
 * provider path in cpk_assets.h adds size caps and owns the buffers it
 * allocates; this path trusts the index sizes and frees its own buffers.
 */
#include <cpkrt/cpk.h>
#include <cpkrt/crilayla.h>
#include <cpkrt/file.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int dump_entry(const char *path, uint32_t id)
{
    cpk_file *file = NULL;
    uint64_t file_size = 0;
    cpk_asset_result open_result = cpk_file_open(path, &file, &file_size);
    if (open_result.status != CPK_ASSET_OK) {
        fprintf(stderr, "cpk_file_open: status %u\n", (unsigned int)open_result.status);
        return 1;
    }

    cpk archive = {0};
    cpk_diag diag = {0};
    cpk_open_options options = {.layout = CPK_LAYOUT_ID_ORDER, .diag = &diag};
    cpk_status status = cpk_open_opts(&archive, cpk_file_read, file, file_size, &options);
    if (status != CPK_OK) {
        char text[256];
        cpk_diag_format(&diag, text, sizeof text);
        fprintf(stderr, "cpk_open: %s; %s\n", cpk_status_name(status), text);
        cpk_file_close(file);
        return 1;
    }

    const cpk_entry *entry = cpk_find(&archive, id);
    if (!entry) {
        fprintf(stderr, "entry %u not found\n", (unsigned int)id);
        cpk_close(&archive);
        cpk_file_close(file);
        return 1;
    }
    fprintf(stderr, "id=%u offset=%" PRIu64 " stored=%u extract=%u compressed=%s\n",
            entry->id, entry->offset, entry->stored_size, entry->extract_size,
            cpk_entry_compressed(entry) ? "yes" : "no");

    uint8_t *stored = malloc(entry->stored_size ? entry->stored_size : 1);
    if (!stored || (entry->stored_size &&
                    !cpk_file_read(file, entry->offset, stored, entry->stored_size))) {
        fprintf(stderr, "could not read stored bytes\n");
        free(stored);
        cpk_close(&archive);
        cpk_file_close(file);
        return 1;
    }

    uint8_t *decoded = NULL;
    const uint8_t *out = stored;
    size_t out_size = entry->stored_size;
    if (cpk_entry_compressed(entry)) {
        crilayla_status cstatus =
            crilayla_output_size(stored, entry->stored_size, &out_size);
        if (cstatus != CRILAYLA_OK) {
            fprintf(stderr, "crilayla_output_size: %s\n", crilayla_status_name(cstatus));
            free(stored);
            cpk_close(&archive);
            cpk_file_close(file);
            return 1;
        }
        decoded = malloc(out_size ? out_size : 1);
        if (!decoded ||
            crilayla_decode(stored, entry->stored_size, decoded, out_size) != CRILAYLA_OK) {
            fprintf(stderr, "crilayla_decode failed\n");
            free(decoded);
            free(stored);
            cpk_close(&archive);
            cpk_file_close(file);
            return 1;
        }
        out = decoded;
    }

    bool ok = fwrite(out, 1, out_size, stdout) == out_size;
    if (!ok) fprintf(stderr, "short write to stdout\n");
    free(decoded);
    free(stored);
    cpk_close(&archive);
    cpk_file_close(file);
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    char *end = NULL;
    unsigned long long id;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <archive.cpk> <entry-id>\n", argv[0]);
        return 2;
    }
    errno = 0;
    id = strtoull(argv[2], &end, 0);
    if (!argv[2][0] || *end != '\0' || errno == ERANGE || id > UINT32_MAX) {
        fprintf(stderr, "invalid entry id: %s\n", argv[2]);
        return 2;
    }
    return dump_entry(argv[1], (uint32_t)id);
}
