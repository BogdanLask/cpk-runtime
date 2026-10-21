# cpk-runtime

[![ci](https://github.com/BogdanLask/cpk-runtime/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/BogdanLask/cpk-runtime/actions/workflows/ci.yml)

`cpkrt` is a dependency-free C11 library for reading CRI CPK archives at
runtime: index parsing, by-ID lookup, and CRILAYLA decoding. It is built to be
linked into ports, emulators, and tools, not to be a CLI extractor. The library
target, headers, and CMake package use the short name `cpkrt`.

## Features

- CPK header and `@UTF` table parser, including optional LCG-XOR obfuscation.
- TOC (`CpkTocInfo`) with explicit IDs, plus the `CpkExtendId` ITOC map,
  validated against each other.
- Legacy `DataH`/`DataL` ITOC with explicit layout selection.
- By-ID binary search over a sorted, duplicate-free entry list.
- Bounds-checked CRILAYLA decoder with no globals and no allocation.
- Optional lease-based provider that reads, decodes, and releases one entry at
  a time.
- Zero-allocation fills into caller memory, with caller-provided staging for
  compressed entries.
- Optional POSIX and Win32 positional file adapters.
- Synthetic fixtures only; the test suite needs no game data.

I/O is an injected positional read callback, lookup is by numeric ID, and
nothing is extracted to disk.

## Quick start

Link the file adapter and the CPK-backed provider to go from a path on disk to
decoded bytes:

```c
#include <cpkrt/cpk_assets.h>
#include <cpkrt/file.h>
#include <stdio.h>

static int dump_entry(const char *path, uint32_t id)
{
    cpk_file *file = NULL;
    uint64_t file_size = 0;
    cpk_asset_result result = cpk_file_open(path, &file, &file_size);
    if (result.status != CPK_ASSET_OK) return 1;

    cpk_archive_source source = {
        .archive = 1,              /* any caller-chosen archive identifier */
        .read = cpk_file_read,
        .context = file,
        .file_size = file_size,
        .last_error = cpk_file_error,
        .layout = CPK_LAYOUT_ID_ORDER,
        /* max_stored_size / max_extract_size: 0 selects the 64 MiB default */
    };

    cpk_assets *assets = NULL;
    result = cpk_assets_open(&assets, &source, 1);
    if (result.status != CPK_ASSET_OK) {
        cpk_file_close(file);
        return 1;
    }

    cpk_asset_provider provider = cpk_assets_provider(assets);
    cpk_asset_blob blob = {0};
    result = cpk_asset_read(&provider, (cpk_asset_key){1, id}, &blob);
    if (result.status == CPK_ASSET_OK) {
        fwrite(blob.data, 1, blob.size, stdout);
        cpk_asset_release(&provider, &blob);
    }

    cpk_assets_close(&assets); /* false while a lease is outstanding */
    cpk_file_close(file);
    return result.status == CPK_ASSET_OK ? 0 : 1;
}
```

This program is built as `cpkrt_dump`. Filling caller memory instead takes no
lease, needs no release, and never blocks `cpk_assets_close()`; compressed
entries also need caller staging:

```c
    uint8_t decoded[65536];
    uint8_t staging[8192]; /* compressed entries only; may be NULL */
    cpk_asset_buffer buffer = {decoded, sizeof decoded, staging, sizeof staging, 0, 0};
    result = cpk_asset_read_into(&provider, (cpk_asset_key){1, id}, &buffer);
    if (result.status == CPK_ASSET_BUFFER_TOO_SMALL) {
        /* Retry with decoded >= buffer.size, staging >= buffer.scratch_size. */
    } else if (result.status == CPK_ASSET_OK) {
        fwrite(decoded, 1, buffer.size, stdout);
    }
```

`examples/index_only.c` (built as `cpkrt_index`) shows the lower-level path:
`cpk_open(&index, read_fn, context, file_size)`, `cpk_find(&index, id)` for
offsets and sizes, and `crilayla_decode()` for compressed stored bytes. If you
already have a mapping or platform handle, implement `cpk_read_fn` yourself.

## Building

Requirements: CMake 3.16+ and a C11 compiler. Python 3 is only needed for the
test suite.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

Windows with MSVC (from an x64 Native Tools prompt):

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release
```

| Option | Default | Meaning |
| --- | --- | --- |
| `CPKRT_BUILD_TESTS` | `ON` | Build the probe and register the CTest suite (needs Python 3). |
| `CPKRT_BUILD_BENCHMARKS` | `OFF` | Build the synthetic `cpkrt_bench` executable. |
| `CPKRT_BUILD_EXAMPLES` | `ON` as top level | Build the `cpkrt_dump` and `cpkrt_index` example programs. |
| `CPKRT_BUILD_FILE_ADAPTER` | `ON` | Build the POSIX/Win32 `cpk_file` adapter. |
| `CPKRT_SANITIZE` | `OFF` | Add ASan/UBSan with GCC or Clang. |
| `CPKRT_BUILD_FUZZERS` | `OFF` | Build the libFuzzer harness (Clang only; tests, benchmarks, and examples must be off). |
| `CPKRT_FUZZ_SECONDS` | `20` | Seconds per harness for the `fuzz_smoke` target. |

To consume it from another CMake project, add this directory and link
`cpkrt::cpkrt`, or install with `cmake --install build --prefix /some/prefix`
and use `find_package(cpkrt CONFIG REQUIRED)`.

## Benchmarks

`CPKRT_BUILD_BENCHMARKS=ON` builds `cpkrt_bench`, which runs against a generated
fixture and needs no game data:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCPKRT_BUILD_BENCHMARKS=ON
cmake --build build && python3 bench/make_bench_fixture.py /tmp/cpkrt-bench.cpk
./build/cpkrt_bench /tmp/cpkrt-bench.cpk
```

It reports index-open time, lookup cost, provider reads, and CRILAYLA decode
throughput. `--file-only` runs against a real archive without loading it into
memory; see [bench/README.md](bench/README.md) for options and caveats.

## API summary

| Header | Contents |
| --- | --- |
| `cpkrt/cpk.h` | `cpk_open()` / `cpk_open_ex()`, `cpk_find()`, `cpk_close()`, `cpk_entry`, `cpk_status`. |
| `cpkrt/crilayla.h` | `crilayla_detect()`, `crilayla_output_size()`, `crilayla_decode()`, `crilayla_status`. |
| `cpkrt/asset.h` | `cpk_asset_key`, `cpk_asset_blob`, `cpk_asset_buffer`, `cpk_asset_provider`, `cpk_asset_read()`, `cpk_asset_read_into()`, `cpk_asset_release()`. |
| `cpkrt/cpk_assets.h` | `cpk_archive_source`, `cpk_allocator`, `cpk_assets_open()`, `cpk_assets_open_ex()`, `cpk_assets_provider()`, `cpk_assets_close()`, per-entry caps. |
| `cpkrt/file.h` | Optional `cpk_file_open()` / `cpk_file_read()` / `cpk_file_close()` adapters. |

An archive identifier is a caller-defined `uint32_t` compared by equality; IDs
are local to an archive, so the same ID in two archives is two resources. The
provider caps stored and decoded entries at 64 MiB by default
(`max_stored_size` / `max_extract_size`; 0 keeps the default) and refuses to
close while a lease is outstanding. Fills take no lease and need no release;
`CPK_ASSET_BUFFER_TOO_SMALL` reports the exact retry sizes and reads no payload.
The optional `cpk_allocator` hooks cover the provider's own structures and read
buffers; index parsing inside `cpk_open_ex()` always uses the C library.

## Validation

Before this de-branded release, the parser and decoder were validated against
four archives from one shipped title: **20,908 index entries**, ~2.1 GiB total,
with **31 assets byte-compared** through the public read/decode path (27
CRILAYLA-decoded and 4 raw). The title is intentionally unnamed; the archives
are not part of this repository and are not needed to build or test it. The
provider also served as the default asset backend in a Windows application.

Fuzzing: a libFuzzer harness covers the parser and decoder. The checked-in seed
corpus is synthetic, and CI runs a short `fuzz_smoke`; local commands, corpus
growth, and crash triage are in [docs/fuzzing.md](docs/fuzzing.md).

## Honesty and limits

- Only the observed TOC + `CpkExtendId` ITOC variant is confirmed on real
  files; the legacy `DataH`/`DataL` path is covered by synthetic tests only.
- `@UTF` version 0 is accepted and LCG-XOR table obfuscation is implemented,
  both synthetically tested. Unsupported versions and variants are rejected
  rather than guessed; the obfuscation was not in the real validation set.
- ETOC/GTOC tables, archive-level encryption, and CRILAYLA compression are not
  implemented.
- Entry names are not exposed. Some archives store only placeholder names,
  which extraction tools turn into hex-suffixed filenames; this library never
  depends on filenames and looks entries up by the numeric ID from the index.
- The provider is synchronous and nonconcurrent, not a streaming or async
  loader.
- The probe is a test adapter, not a supported extraction CLI.
- Linux GCC is the toolchain verified for this release. Clang and MSVC are
  configured in CI.

Format details, including header, `@UTF`, TOC/ITOC, and CRILAYLA layouts, are in
[docs/format.md](docs/format.md).

## Related tools

[CriPakTools](https://github.com/esperknight/CriPakTools) and
[QuickBMS](https://aluigi.altervista.org/quickbms.htm) with its CPK scripts are
extraction-focused alternatives. This library is for applications that keep
the archive in place.

## License

MIT. See [LICENSE](LICENSE). CPK and CRILAYLA are formats from CRI Middleware;
this project is independent and is not affiliated with or endorsed by CRI.
