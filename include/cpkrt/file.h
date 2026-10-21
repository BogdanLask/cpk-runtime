// SPDX-License-Identifier: MIT
#ifndef CPKRT_FILE_H
#define CPKRT_FILE_H
#include "cpkrt/asset.h"

/* Optional positional file adapters for POSIX and Win32. The path is UTF-8;
 * Win32 converts it to UTF-16. Only regular files are accepted. An instance is
 * not safe for concurrent reads because read failures record host_error. */
typedef struct cpk_file cpk_file;

cpk_asset_result cpk_file_open(const char *utf8_path, cpk_file **output, uint64_t *size);
bool cpk_file_read(void *context, uint64_t offset, void *dst, size_t size);
uint32_t cpk_file_error(void *context);
bool cpk_file_close(cpk_file *file);
#endif
