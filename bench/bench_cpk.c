// SPDX-License-Identifier: MIT
/* Synthetic benchmark harness for the public cpkrt API.
 *
 * This is not a correctness test and not a general storage benchmark. It
 * times the index parser, binary-search lookup, provider reads, and the
 * CRILAYLA decoder against a generated archive so changes can be compared
 * on the same machine and build. Use --file to include the platform file
 * adapter; those numbers are warm-cache reads unless the host drops pages.
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#include "cpkrt/cpk.h"
#include "cpkrt/cpk_assets.h"
#include "cpkrt/crilayla.h"
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/types.h>
#include <time.h>
#endif
#ifdef CPKRT_BENCH_FILE_ADAPTER
#include "cpkrt/file.h"
#endif

typedef struct {
    const uint8_t *data;
    uint64_t size;
} memory_file;

typedef struct {
    const char *path;
    size_t index_iterations;
    size_t lookup_iterations;
    size_t read_iterations;
    size_t decode_iterations;
    bool file_io;
    bool file_only;
    bool first;
    bool has_id;
    uint32_t id;
} options;

static volatile uint64_t sink;

static bool memory_read(void *context, uint64_t offset, void *destination, size_t size)
{
    const memory_file *file = context;
    if (!file || (!destination && size) || offset > file->size ||
        size > file->size - offset)
        return false;
    if (size) memcpy(destination, file->data + (size_t)offset, size);
    return true;
}

static uint64_t now_ns(void)
{
#ifdef _WIN32
    static LARGE_INTEGER frequency;
    static bool initialized;
    LARGE_INTEGER counter;
    if (!initialized) {
        if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) return 0;
        initialized = true;
    }
    if (!QueryPerformanceCounter(&counter)) return 0;
    return (uint64_t)((long double)counter.QuadPart * 1000000000.0L /
                      (long double)frequency.QuadPart);
#else
    struct timespec timestamp;
    if (clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0) return 0;
    return (uint64_t)timestamp.tv_sec * UINT64_C(1000000000) +
           (uint64_t)timestamp.tv_nsec;
#endif
}

static void report(const char *name, size_t iterations, uint64_t elapsed_ns,
                   uint64_t bytes_per_operation)
{
    double total_ms = (double)elapsed_ns / 1e6;
    double us_per_operation =
        iterations ? (double)elapsed_ns / (double)iterations / 1e3 : 0.0;
    printf("%-24s %10zu %12.3f %12.3f", name, iterations, total_ms,
           us_per_operation);
    if (bytes_per_operation) {
        double seconds = (double)elapsed_ns / 1e9;
        double mib_per_second =
            seconds > 0.0
                ? ((double)bytes_per_operation * (double)iterations) /
                      (1024.0 * 1024.0) / seconds
                : 0.0;
        printf(" %10.1f\n", mib_per_second);
    } else {
        printf(" %10s\n", "-");
    }
}

static bool load_file(const char *path, uint8_t **output, size_t *size)
{
    FILE *file = fopen(path, "rb");
    int64_t end;
    uint8_t *data;

    if (!file) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return false;
    }
#ifdef _WIN32
    if (_fseeki64(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "seek %s: %s\n", path, strerror(errno));
        fclose(file);
        return false;
    }
    end = _ftelli64(file);
#else
    if (fseeko(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "seek %s: %s\n", path, strerror(errno));
        fclose(file);
        return false;
    }
    end = (int64_t)ftello(file);
#endif
    if (end < 0 || (uint64_t)end > SIZE_MAX) {
        fprintf(stderr, "file too large: %s\n", path);
        fclose(file);
        return false;
    }
#ifdef _WIN32
    if (_fseeki64(file, 0, SEEK_SET) != 0) {
#else
    if (fseeko(file, 0, SEEK_SET) != 0) {
#endif
        fprintf(stderr, "rewind %s: %s\n", path, strerror(errno));
        fclose(file);
        return false;
    }

    *size = (size_t)end;
    data = malloc(*size ? *size : 1);
    if (!data) {
        fprintf(stderr, "out of memory reading %s\n", path);
        fclose(file);
        return false;
    }
    if (*size && fread(data, 1, *size, file) != *size) {
        fprintf(stderr, "read %s: %s\n", path, strerror(errno));
        free(data);
        fclose(file);
        return false;
    }
    if (fclose(file) != 0) {
        fprintf(stderr, "close %s: %s\n", path, strerror(errno));
        free(data);
        return false;
    }
    *output = data;
    return true;
}

static bool parse_count(const char *text, size_t *output)
{
    char *end = NULL;
    unsigned long value;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (!text[0] || !end || *end || errno == ERANGE || value == 0) return false;
    *output = (size_t)value;
    return true;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s <fixture.cpk> [options]\n"
            "  --index-iters N    index open/close repetitions (default: 100)\n"
            "  --lookup-iters N   cpk_find calls (default: 2000000)\n"
            "  --read-iters N     provider read/release repetitions (default: 200)\n"
            "  --decode-iters N   direct CRILAYLA decodes (default: 50)\n"
            "  --file             also benchmark the file adapter (warm cache)\n"
            "  --file-only        use only the file adapter, without loading the archive\n"
            "  --first            use the first matching entry instead of the largest\n"
            "  --id ID            benchmark this entry ID specifically (hex or decimal)\n"
            "  --help             show this help\n",
            program);
}

static bool parse_options(int argc, char **argv, options *opt)
{
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            usage(argv[0]);
            exit(0);
        } else if (strcmp(arg, "--file") == 0) {
            opt->file_io = true;
        } else if (strcmp(arg, "--file-only") == 0) {
            opt->file_io = true;
            opt->file_only = true;
        } else if (strcmp(arg, "--first") == 0) {
            opt->first = true;
        } else if (strcmp(arg, "--id") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long value;
            errno = 0;
            value = strtoul(argv[++i], &end, 0);
            if (!argv[i][0] || !end || *end || errno == ERANGE || value > UINT32_MAX) return false;
            opt->id = (uint32_t)value;
            opt->has_id = true;
        } else if (strcmp(arg, "--index-iters") == 0 && i + 1 < argc) {
            if (!parse_count(argv[++i], &opt->index_iterations)) return false;
        } else if (strcmp(arg, "--lookup-iters") == 0 && i + 1 < argc) {
            if (!parse_count(argv[++i], &opt->lookup_iterations)) return false;
        } else if (strcmp(arg, "--read-iters") == 0 && i + 1 < argc) {
            if (!parse_count(argv[++i], &opt->read_iterations)) return false;
        } else if (strcmp(arg, "--decode-iters") == 0 && i + 1 < argc) {
            if (!parse_count(argv[++i], &opt->decode_iterations)) return false;
        } else if (arg[0] == '-') {
            return false;
        } else if (!opt->path) {
            opt->path = arg;
        } else {
            return false;
        }
    }
    return opt->path != NULL;
}

static bool open_archive(cpk *archive, const memory_file *file)
{
    cpk_status status = cpk_open(archive, memory_read, (void *)file, file->size);
    if (status != CPK_OK)
        fprintf(stderr, "cpk_open: %s\n", cpk_status_name(status));
    return status == CPK_OK;
}

static const cpk_entry *find_raw(const cpk *archive, bool first)
{
    const cpk_entry *best = NULL;
    for (size_t i = 0; i < archive->count; i++) {
        const cpk_entry *entry = &archive->entries[i];
        if (cpk_entry_compressed(entry)) continue;
        if (!best || (!first && entry->extract_size > best->extract_size)) best = entry;
        if (first) break;
    }
    return best;
}

static const cpk_entry *find_packed(const cpk *archive, bool first)
{
    const cpk_entry *best = NULL;
    for (size_t i = 0; i < archive->count; i++) {
        const cpk_entry *entry = &archive->entries[i];
        if (!cpk_entry_compressed(entry)) continue;
        if (!best || (!first && entry->extract_size > best->extract_size)) best = entry;
        if (first) break;
    }
    return best;
}

static bool select_entries(const cpk *archive, const options *opt,
                           const cpk_entry **raw, const cpk_entry **packed)
{
    *raw = find_raw(archive, opt->first);
    *packed = find_packed(archive, opt->first);
    if (opt->has_id) {
        const cpk_entry *entry = cpk_find(archive, opt->id);
        if (!entry) {
            fprintf(stderr, "entry 0x%08" PRIx32 " not found\n", opt->id);
            return false;
        }
        if (cpk_entry_compressed(entry)) *packed = entry;
        else *raw = entry;
    }
    return true;
}

static void print_selection(const cpk_entry *raw, const cpk_entry *packed)
{
    if (!raw && !packed) return;
    printf("selected:");
    if (raw)
        printf(" raw id=0x%08" PRIx32 " stored=%" PRIu32 " extract=%" PRIu32, raw->id,
               raw->stored_size, raw->extract_size);
    if (packed)
        printf(" packed id=0x%08" PRIx32 " stored=%" PRIu32 " extract=%" PRIu32,
               packed->id, packed->stored_size, packed->extract_size);
    printf("\n");
}

static bool bench_index(const memory_file *file, size_t iterations)
{
    cpk warmup = {0};
    uint64_t start, elapsed;
    if (!open_archive(&warmup, file)) return false;
    cpk_close(&warmup);

    start = now_ns();
    for (size_t i = 0; i < iterations; i++) {
        cpk archive = {0};
        if (!open_archive(&archive, file)) return false;
        sink += archive.count;
        cpk_close(&archive);
    }
    elapsed = now_ns() - start;
    report("index_open", iterations, elapsed, 0);
    return true;
}

static bool bench_lookup(const cpk *archive, size_t iterations)
{
    size_t index = 0;
    uint64_t start, elapsed;
    if (archive->count == 0) {
        fprintf(stderr, "fixture has no entries\n");
        return false;
    }

    start = now_ns();
    for (size_t i = 0; i < iterations; i++) {
        uint32_t id = (i & 15u) == 15u ? UINT32_MAX : archive->entries[index].id;
        const cpk_entry *entry = cpk_find(archive, id);
        sink += entry ? 1u : 0u;
        if (++index == archive->count) index = 0;
    }
    elapsed = now_ns() - start;
    report("lookup", iterations, elapsed, 0);
    return true;
}

static bool bench_provider(const char *name, const memory_file *file,
                           const cpk_entry *entry, size_t iterations)
{
    cpk_archive_source source = {
        1,
        memory_read,
        (void *)file,
        file->size,
        NULL,
        CPK_LAYOUT_ID_ORDER,
        entry->stored_size,
        entry->extract_size,
        0,
        NULL,
    };
    cpk_assets *assets = NULL;
    cpk_asset_result result = cpk_assets_open(&assets, &source, 1);
    cpk_asset_provider provider;
    cpk_asset_blob blob = {0};
    uint64_t start, elapsed;

    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "cpk_assets_open: status %u\n", (unsigned int)result.status);
        return false;
    }
    provider = cpk_assets_provider(assets);

    result = cpk_asset_read(&provider, (cpk_asset_key){1, entry->id}, &blob);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "provider warmup: status %u\n", (unsigned int)result.status);
        (void)cpk_assets_close(&assets);
        return false;
    }
    sink += blob.size ? blob.data[0] : 0;
    (void)cpk_asset_release(&provider, &blob);

    start = now_ns();
    for (size_t i = 0; i < iterations; i++) {
        result = cpk_asset_read(&provider, (cpk_asset_key){1, entry->id}, &blob);
        if (result.status != CPK_ASSET_OK) {
            fprintf(stderr, "provider read: status %u\n", (unsigned int)result.status);
            (void)cpk_assets_close(&assets);
            return false;
        }
        sink += blob.size ? blob.data[0] : 0;
        if (!cpk_asset_release(&provider, &blob)) {
            fprintf(stderr, "provider release failed\n");
            (void)cpk_assets_close(&assets);
            return false;
        }
    }
    elapsed = now_ns() - start;
    report(name, iterations, elapsed, entry->extract_size);

    if (!cpk_assets_close(&assets)) {
        fprintf(stderr, "provider close failed\n");
        return false;
    }
    return true;
}

static bool bench_provider_into(const char *name, const memory_file *file,
                                const cpk_entry *entry, size_t iterations)
{
    cpk_archive_source source = {
        1,
        memory_read,
        (void *)file,
        file->size,
        NULL,
        CPK_LAYOUT_ID_ORDER,
        entry->stored_size,
        entry->extract_size,
        0,
        NULL,
    };
    cpk_assets *assets = NULL;
    cpk_asset_result result = cpk_assets_open(&assets, &source, 1);
    cpk_asset_provider provider;
    uint8_t *data = NULL;
    uint8_t *scratch = NULL;
    cpk_asset_buffer buffer;
    uint64_t start, elapsed;

    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "cpk_assets_open: status %u\n", (unsigned int)result.status);
        return false;
    }
    provider = cpk_assets_provider(assets);
    /* Caller buffers are allocated once, outside the timer. */
    data = malloc(entry->extract_size ? entry->extract_size : 1);
    scratch = malloc(entry->stored_size ? entry->stored_size : 1);
    if (!data || !scratch) {
        fprintf(stderr, "out of memory for caller buffers\n");
        free(data);
        free(scratch);
        (void)cpk_assets_close(&assets);
        return false;
    }
    buffer = (cpk_asset_buffer){data, entry->extract_size, scratch, entry->stored_size, 0, 0};

    result = cpk_asset_read_into(&provider, (cpk_asset_key){1, entry->id}, &buffer);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "provider fill warmup: status %u\n", (unsigned int)result.status);
        free(data);
        free(scratch);
        (void)cpk_assets_close(&assets);
        return false;
    }
    sink += buffer.size ? data[0] : 0;

    start = now_ns();
    for (size_t i = 0; i < iterations; i++) {
        result = cpk_asset_read_into(&provider, (cpk_asset_key){1, entry->id}, &buffer);
        if (result.status != CPK_ASSET_OK) {
            fprintf(stderr, "provider fill: status %u\n", (unsigned int)result.status);
            free(data);
            free(scratch);
            (void)cpk_assets_close(&assets);
            return false;
        }
        sink += buffer.size ? data[0] : 0;
    }
    elapsed = now_ns() - start;
    report(name, iterations, elapsed, entry->extract_size);

    free(data);
    free(scratch);
    if (!cpk_assets_close(&assets)) {
        fprintf(stderr, "provider close failed\n");
        return false;
    }
    return true;
}

static bool bench_decode(const memory_file *file, const cpk_entry *entry,
                         size_t iterations)
{
    uint8_t *input = NULL;
    uint8_t *output = NULL;
    size_t output_size = 0;
    crilayla_status status;
    uint64_t start, elapsed;

    if (!entry->stored_size) return true;
    input = malloc(entry->stored_size);
    if (!input) {
        fprintf(stderr, "out of memory reading compressed entry\n");
        return false;
    }
    if (!memory_read((void *)file, entry->offset, input, entry->stored_size)) {
        fprintf(stderr, "could not read compressed entry\n");
        free(input);
        return false;
    }
    status = crilayla_output_size(input, entry->stored_size, &output_size);
    if (status != CRILAYLA_OK || output_size != entry->extract_size) {
        fprintf(stderr, "compressed entry header: %s\n", crilayla_status_name(status));
        free(input);
        return false;
    }
    output = malloc(output_size ? output_size : 1);
    if (!output) {
        fprintf(stderr, "out of memory allocating decode output\n");
        free(input);
        return false;
    }
    status = crilayla_decode(input, entry->stored_size, output, output_size);
    if (status != CRILAYLA_OK) {
        fprintf(stderr, "decode warmup: %s\n", crilayla_status_name(status));
        free(input);
        free(output);
        return false;
    }

    start = now_ns();
    for (size_t i = 0; i < iterations; i++) {
        status = crilayla_decode(input, entry->stored_size, output, output_size);
        if (status != CRILAYLA_OK) {
            fprintf(stderr, "decode: %s\n", crilayla_status_name(status));
            free(input);
            free(output);
            return false;
        }
        sink += output[0] + output[output_size - 1];
    }
    elapsed = now_ns() - start;
    report("crilayla_decode", iterations, elapsed, (uint64_t)output_size);

    free(input);
    free(output);
    return true;
}

#ifdef CPKRT_BENCH_FILE_ADAPTER
static bool bench_file_index(const char *path, size_t iterations)
{
    cpk_file *file = NULL;
    cpk_asset_result result;
    uint64_t size = 0;
    uint64_t start, elapsed;

    result = cpk_file_open(path, &file, &size);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "cpk_file_open: status %u\n", (unsigned int)result.status);
        return false;
    }
    {
        cpk warmup = {0};
        cpk_status status = cpk_open(&warmup, cpk_file_read, file, size);
        if (status != CPK_OK) {
            fprintf(stderr, "file cpk_open: %s\n", cpk_status_name(status));
            (void)cpk_file_close(file);
            return false;
        }
        sink += warmup.count;
        cpk_close(&warmup);
    }
    start = now_ns();
    for (size_t i = 0; i < iterations; i++) {
        cpk archive = {0};
        cpk_status status = cpk_open(&archive, cpk_file_read, file, size);
        if (status != CPK_OK) {
            fprintf(stderr, "file cpk_open: %s\n", cpk_status_name(status));
            (void)cpk_file_close(file);
            return false;
        }
        sink += archive.count;
        cpk_close(&archive);
    }
    elapsed = now_ns() - start;
    report("file_index_open", iterations, elapsed, 0);
    (void)cpk_file_close(file);
    return true;
}

static bool bench_file_provider(const char *name, const char *path,
                                const cpk_entry *entry, size_t iterations)
{
    cpk_file *file = NULL;
    uint64_t file_size = 0;
    cpk_asset_result result = cpk_file_open(path, &file, &file_size);
    cpk_archive_source source;
    cpk_assets *assets = NULL;
    cpk_asset_provider provider;
    cpk_asset_blob blob = {0};
    uint64_t start, elapsed;

    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "cpk_file_open: status %u\n", (unsigned int)result.status);
        return false;
    }
    source = (cpk_archive_source){
        1,
        cpk_file_read,
        file,
        file_size,
        cpk_file_error,
        CPK_LAYOUT_ID_ORDER,
        entry->stored_size,
        entry->extract_size,
        0,
        NULL,
    };
    result = cpk_assets_open(&assets, &source, 1);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "file cpk_assets_open: status %u\n", (unsigned int)result.status);
        (void)cpk_file_close(file);
        return false;
    }
    provider = cpk_assets_provider(assets);

    result = cpk_asset_read(&provider, (cpk_asset_key){1, entry->id}, &blob);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "file provider warmup: status %u\n", (unsigned int)result.status);
        (void)cpk_assets_close(&assets);
        (void)cpk_file_close(file);
        return false;
    }
    sink += blob.size ? blob.data[0] : 0;
    (void)cpk_asset_release(&provider, &blob);

    start = now_ns();
    for (size_t i = 0; i < iterations; i++) {
        result = cpk_asset_read(&provider, (cpk_asset_key){1, entry->id}, &blob);
        if (result.status != CPK_ASSET_OK) {
            fprintf(stderr, "file provider read: status %u\n", (unsigned int)result.status);
            (void)cpk_assets_close(&assets);
            (void)cpk_file_close(file);
            return false;
        }
        sink += blob.size ? blob.data[0] : 0;
        if (!cpk_asset_release(&provider, &blob)) {
            fprintf(stderr, "file provider release failed\n");
            (void)cpk_assets_close(&assets);
            (void)cpk_file_close(file);
            return false;
        }
    }
    elapsed = now_ns() - start;
    report(name, iterations, elapsed, entry->extract_size);

    if (!cpk_assets_close(&assets)) {
        fprintf(stderr, "file provider close failed\n");
        (void)cpk_file_close(file);
        return false;
    }
    if (!cpk_file_close(file)) {
        fprintf(stderr, "cpk_file_close failed\n");
        return false;
    }
    return true;
}

static bool bench_file_provider_into(const char *name, const char *path,
                                     const cpk_entry *entry, size_t iterations)
{
    cpk_file *file = NULL;
    uint64_t file_size = 0;
    cpk_asset_result result = cpk_file_open(path, &file, &file_size);
    cpk_archive_source source;
    cpk_assets *assets = NULL;
    cpk_asset_provider provider;
    uint8_t *data = NULL;
    uint8_t *scratch = NULL;
    cpk_asset_buffer buffer;
    uint64_t start, elapsed;

    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "cpk_file_open: status %u\n", (unsigned int)result.status);
        return false;
    }
    source = (cpk_archive_source){
        1,
        cpk_file_read,
        file,
        file_size,
        cpk_file_error,
        CPK_LAYOUT_ID_ORDER,
        entry->stored_size,
        entry->extract_size,
        0,
        NULL,
    };
    result = cpk_assets_open(&assets, &source, 1);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "file cpk_assets_open: status %u\n", (unsigned int)result.status);
        (void)cpk_file_close(file);
        return false;
    }
    provider = cpk_assets_provider(assets);
    /* Caller buffers are allocated once, outside the timer. */
    data = malloc(entry->extract_size ? entry->extract_size : 1);
    scratch = malloc(entry->stored_size ? entry->stored_size : 1);
    if (!data || !scratch) {
        fprintf(stderr, "out of memory for caller buffers\n");
        free(data);
        free(scratch);
        (void)cpk_assets_close(&assets);
        (void)cpk_file_close(file);
        return false;
    }
    buffer = (cpk_asset_buffer){data, entry->extract_size, scratch, entry->stored_size, 0, 0};

    result = cpk_asset_read_into(&provider, (cpk_asset_key){1, entry->id}, &buffer);
    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "file provider fill warmup: status %u\n", (unsigned int)result.status);
        free(data);
        free(scratch);
        (void)cpk_assets_close(&assets);
        (void)cpk_file_close(file);
        return false;
    }
    sink += buffer.size ? data[0] : 0;

    start = now_ns();
    for (size_t i = 0; i < iterations; i++) {
        result = cpk_asset_read_into(&provider, (cpk_asset_key){1, entry->id}, &buffer);
        if (result.status != CPK_ASSET_OK) {
            fprintf(stderr, "file provider fill: status %u\n", (unsigned int)result.status);
            free(data);
            free(scratch);
            (void)cpk_assets_close(&assets);
            (void)cpk_file_close(file);
            return false;
        }
        sink += buffer.size ? data[0] : 0;
    }
    elapsed = now_ns() - start;
    report(name, iterations, elapsed, entry->extract_size);

    free(data);
    free(scratch);
    if (!cpk_assets_close(&assets)) {
        fprintf(stderr, "file provider close failed\n");
        (void)cpk_file_close(file);
        return false;
    }
    if (!cpk_file_close(file)) {
        fprintf(stderr, "cpk_file_close failed\n");
        return false;
    }
    return true;
}

static bool bench_file_decode(const char *path, const cpk_entry *entry,
                              size_t iterations)
{
    cpk_file *file = NULL;
    uint64_t file_size = 0;
    cpk_asset_result result = cpk_file_open(path, &file, &file_size);
    uint8_t *input = NULL;
    uint8_t *output = NULL;
    size_t output_size = 0;
    crilayla_status status;
    uint64_t start, elapsed;

    if (result.status != CPK_ASSET_OK) {
        fprintf(stderr, "cpk_file_open: status %u\n", (unsigned int)result.status);
        return false;
    }
    if (!entry->stored_size) {
        (void)cpk_file_close(file);
        return true;
    }
    input = malloc(entry->stored_size);
    if (!input) {
        fprintf(stderr, "out of memory reading compressed entry\n");
        (void)cpk_file_close(file);
        return false;
    }
    if (!cpk_file_read(file, entry->offset, input, entry->stored_size)) {
        fprintf(stderr, "could not read compressed entry\n");
        free(input);
        (void)cpk_file_close(file);
        return false;
    }
    status = crilayla_output_size(input, entry->stored_size, &output_size);
    if (status != CRILAYLA_OK || output_size != entry->extract_size) {
        fprintf(stderr, "compressed entry header: %s\n", crilayla_status_name(status));
        free(input);
        (void)cpk_file_close(file);
        return false;
    }
    output = malloc(output_size ? output_size : 1);
    if (!output) {
        fprintf(stderr, "out of memory allocating decode output\n");
        free(input);
        (void)cpk_file_close(file);
        return false;
    }
    status = crilayla_decode(input, entry->stored_size, output, output_size);
    if (status != CRILAYLA_OK) {
        fprintf(stderr, "decode warmup: %s\n", crilayla_status_name(status));
        free(input);
        free(output);
        (void)cpk_file_close(file);
        return false;
    }

    start = now_ns();
    for (size_t i = 0; i < iterations; i++) {
        status = crilayla_decode(input, entry->stored_size, output, output_size);
        if (status != CRILAYLA_OK) {
            fprintf(stderr, "decode: %s\n", crilayla_status_name(status));
            free(input);
            free(output);
            (void)cpk_file_close(file);
            return false;
        }
        sink += output[0] + output[output_size - 1];
    }
    elapsed = now_ns() - start;
    report("file_crilayla_decode", iterations, elapsed, (uint64_t)output_size);

    free(input);
    free(output);
    (void)cpk_file_close(file);
    return true;
}
#endif

int main(int argc, char **argv)
{
    options opt = {
        NULL,
        100,
        2000000,
        200,
        50,
        false,
        false,
        false,
        false,
        0,
    };
    uint8_t *data = NULL;
    size_t size = 0;
    memory_file file;
    cpk archive = {0};
    const cpk_entry *raw;
    const cpk_entry *packed;
    size_t packed_count = 0;
    bool ok = true;

    if (!parse_options(argc, argv, &opt)) {
        usage(argv[0]);
        return 2;
    }

    if (opt.file_only) {
#ifdef CPKRT_BENCH_FILE_ADAPTER
        cpk_file *platform_file = NULL;
        uint64_t platform_size = 0;
        cpk_asset_result open_result = cpk_file_open(opt.path, &platform_file, &platform_size);
        cpk_status index_status;

        if (open_result.status != CPK_ASSET_OK) {
            fprintf(stderr, "cpk_file_open: status %u\n", (unsigned int)open_result.status);
            return 1;
        }
        index_status = cpk_open(&archive, cpk_file_read, platform_file, platform_size);
        if (index_status != CPK_OK) {
            fprintf(stderr, "cpk_open: %s\n", cpk_status_name(index_status));
            (void)cpk_file_close(platform_file);
            return 1;
        }
        if (!select_entries(&archive, &opt, &raw, &packed)) {
            cpk_close(&archive);
            (void)cpk_file_close(platform_file);
            return 1;
        }
        for (size_t i = 0; i < archive.count; i++)
            if (cpk_entry_compressed(&archive.entries[i])) packed_count++;

        printf("fixture: %s (%" PRIu64 " bytes, %zu entries, %zu packed)\n", opt.path,
               platform_size, archive.count, packed_count);
        print_selection(raw, packed);
        printf("%-24s %10s %12s %12s %10s\n", "benchmark", "iterations",
               "total_ms", "us/op", "MiB/s");

        if (!bench_file_index(opt.path, opt.index_iterations)) ok = false;
        if (!bench_lookup(&archive, opt.lookup_iterations)) ok = false;
        if (raw && !bench_file_provider("file_provider_raw", opt.path, raw,
                                        opt.read_iterations))
            ok = false;
        if (packed && !bench_file_provider("file_provider_packed", opt.path, packed,
                                           opt.read_iterations))
            ok = false;
        if (raw && !bench_file_provider_into("file_provider_raw_into", opt.path, raw,
                                             opt.read_iterations))
            ok = false;
        if (packed && !bench_file_provider_into("file_provider_packed_into", opt.path, packed,
                                                opt.read_iterations))
            ok = false;
        if (packed && !bench_file_decode(opt.path, packed, opt.decode_iterations))
            ok = false;

        cpk_close(&archive);
        (void)cpk_file_close(platform_file);
        return ok ? 0 : 1;
#else
        fprintf(stderr, "--file-only requires CPKRT_BUILD_FILE_ADAPTER=ON\n");
        return 2;
#endif
    }

    if (!load_file(opt.path, &data, &size)) return 1;
    file = (memory_file){data, size};
    if (!open_archive(&archive, &file)) {
        free(data);
        return 1;
    }
    if (!select_entries(&archive, &opt, &raw, &packed)) {
        cpk_close(&archive);
        free(data);
        return 1;
    }
    for (size_t i = 0; i < archive.count; i++)
        if (cpk_entry_compressed(&archive.entries[i])) packed_count++;

    printf("fixture: %s (%zu bytes, %zu entries, %zu packed)\n", opt.path, size,
           archive.count, packed_count);
    print_selection(raw, packed);
    printf("%-24s %10s %12s %12s %10s\n", "benchmark", "iterations", "total_ms",
           "us/op", "MiB/s");

    if (!bench_index(&file, opt.index_iterations)) ok = false;
    if (!bench_lookup(&archive, opt.lookup_iterations)) ok = false;
    if (raw && !bench_provider("provider_raw", &file, raw, opt.read_iterations))
        ok = false;
    if (packed && !bench_provider("provider_packed", &file, packed, opt.read_iterations))
        ok = false;
    if (raw && !bench_provider_into("provider_raw_into", &file, raw, opt.read_iterations))
        ok = false;
    if (packed && !bench_provider_into("provider_packed_into", &file, packed,
                                       opt.read_iterations))
        ok = false;
    if (packed && !bench_decode(&file, packed, opt.decode_iterations)) ok = false;

#ifdef CPKRT_BENCH_FILE_ADAPTER
    if (opt.file_io) {
        if (!bench_file_index(opt.path, opt.index_iterations)) ok = false;
        if (raw && !bench_file_provider("file_provider_raw", opt.path, raw,
                                        opt.read_iterations))
            ok = false;
        if (packed && !bench_file_provider("file_provider_packed", opt.path, packed,
                                           opt.read_iterations))
            ok = false;
        if (raw && !bench_file_provider_into("file_provider_raw_into", opt.path, raw,
                                             opt.read_iterations))
            ok = false;
        if (packed && !bench_file_provider_into("file_provider_packed_into", opt.path, packed,
                                                opt.read_iterations))
            ok = false;
    }
#else
    if (opt.file_io) {
        fprintf(stderr, "--file requires CPKRT_BUILD_FILE_ADAPTER=ON\n");
        ok = false;
    }
#endif

    cpk_close(&archive);
    free(data);
    return ok ? 0 : 1;
}
