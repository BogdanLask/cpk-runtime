// SPDX-License-Identifier: MIT
/* Write one archive entry to stdout, decoded when compressed.
 *
 * Usage: cpkrt_dump <archive.cpk> <entry-id>
 *
 * The ID is the numeric identifier from the archive index, not a display name.
 * This is the complete version of the quick-start snippet in README.md.
 */
#include <cpkrt/cpk_assets.h>
#include <cpkrt/file.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int dump_entry(const char *path, uint32_t id)
{
    cpk_file *file = NULL;
    uint64_t file_size = 0;
    cpk_asset_result result = cpk_file_open(path, &file, &file_size);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "cpk_file_open: status %u\n", (unsigned int)result.status);
        return 1;
    }

    cpk_diag diag = {0};
    cpk_archive_source source = {
        .archive = 1,              /* any caller-chosen archive identifier */
        .read = cpk_file_read,
        .context = file,
        .file_size = file_size,
        .last_error = cpk_file_error,
        .layout = CPK_LAYOUT_ID_ORDER,
        /* max_stored_size / max_extract_size: 0 selects the 64 MiB default */
        .diag = &diag,
    };

    cpk_assets *assets = NULL;
    result = cpk_assets_open(&assets, &source, 1);
    if (result.status != CPK_ASSET_OK) {
        char text[256];
        cpk_diag_format(&diag, text, sizeof text);
        fprintf(stderr, "cpk_assets_open: status %u; %s\n",
                (unsigned int)result.status, text);
        cpk_file_close(file);
        return 1;
    }

    bool ok = false;
    cpk_asset_provider provider = cpk_assets_provider(assets);
    cpk_asset_blob blob = {0};
    result = cpk_asset_read(&provider, (cpk_asset_key){1, id}, &blob);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "cpk_asset_read: status %u\n", (unsigned int)result.status);
    } else {
        ok = fwrite(blob.data, 1, blob.size, stdout) == blob.size;
        if (!ok) fprintf(stderr, "short write to stdout\n");
        cpk_asset_release(&provider, &blob);
    }

    cpk_assets_close(&assets); /* false while a lease is outstanding */
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
