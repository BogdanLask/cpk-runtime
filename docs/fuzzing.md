# Fuzzing cpkrt

`cpkrt_fuzz` is a libFuzzer harness for the public parser and CRILAYLA decoder.
It is built only with Clang and is not part of the default build or CTest.

## Coverage and limits
Each input is tried through `cpk_open_opts()` with both `CPK_LAYOUT_ID_ORDER`
and `CPK_LAYOUT_TABLE_ORDER`, with `diag` both `NULL` and pointing at a
`cpk_diag` (four variants), using the default `utf_max_version` of 0. A
`CPK_BAD_FORMAT` result must record a nonzero reason, and the diagnostic is
formatted through `cpk_diag_format()`. Successfully parsed entries are exercised
with `cpk_find()` and `cpk_entry_compressed()`. The same bytes are also offered
to `crilayla_output_size()` and `crilayla_decode()` when the declared output is
at most 64 MiB.

This covers the header, `@UTF` tables (including LCG-XOR obfuscation), TOC and
extended/legacy ITOC paths, entry lookup, and the decoder. It does not cover
the asset provider, read-into buffers, the file adapter, ETOC/GTOC, or
archive-level encryption. A CRILAYLA-specific harness, an asset/provider
harness, and OSS-Fuzz integration are deliberate follow-ups, not part of this
phase.

## Local build and smoke run
```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Debug -DCPKRT_BUILD_TESTS=OFF \
  -DCPKRT_BUILD_BENCHMARKS=OFF -DCPKRT_BUILD_EXAMPLES=OFF \
  -DCPKRT_BUILD_FUZZERS=ON -DCPKRT_FUZZ_SECONDS=20
cmake --build build-fuzz --parallel
cmake --build build-fuzz --target fuzz_smoke
```

A fuzz configure must disable tests, benchmarks, and examples: the library is
compiled with coverage and sanitizer instrumentation, and normal executables
would need the sanitizer runtime. `CPKRT_SANITIZE=ON` is unnecessary with
fuzzers; the required sanitizers are added automatically.

`fuzz_smoke` copies `tests/corpus/seeds` to `build-fuzz/fuzz-run/corpus` on
every run, creates `build-fuzz/fuzz-run/artifacts_cpkrt_fuzz/`, and runs
`cpkrt_fuzz` for `CPKRT_FUZZ_SECONDS` seconds. The source corpus is never
modified. CI performs this short smoke on Linux with Clang.

## Corpus
The checked-in seeds are synthetic and deterministic. Regenerate and verify
them with:
```sh
python3 tests/make_fuzz_corpus.py
python3 tests/make_fuzz_corpus.py --check
```

`--check` writes nothing and fails on missing, extra, or changed seeds. CTest
runs it as `fuzz_corpus_fresh`. See
[tests/corpus/README.md](../tests/corpus/README.md) for the seed inventory.

To grow the corpus, fuzz into a staging directory and merge interesting units:

```sh
mkdir -p build-fuzz/staging build-fuzz/merged
cp tests/corpus/seeds/*.cpk build-fuzz/staging/
./build-fuzz/cpkrt_fuzz -max_total_time=300 \
  -dict=tests/fuzz_cpk.dict -max_len=65536 build-fuzz/staging
./build-fuzz/cpkrt_fuzz -merge=1 build-fuzz/merged build-fuzz/staging
```

Promote only deterministic, reviewed inputs. Because `seeds/` is generated,
add the input as a builder in `tests/make_fuzz_corpus.py`, regenerate the
corpus, and run `--check`; do not hand-copy files into the seed directory.

## Crash triage
Reproduce the artifact once, then minimize it:
```sh
./build-fuzz/cpkrt_fuzz -runs=1 build-fuzz/fuzz-run/artifacts_cpkrt_fuzz/crash-*
./build-fuzz/cpkrt_fuzz -minimize_crash=1 \
  build-fuzz/fuzz-run/artifacts_cpkrt_fuzz/crash-*
```

Keep the minimized input as a regression seed (through the generator) and add
a focused case to `tests/check_cpk_contract.py` so the normal suite catches the
bug without a fuzzer.

## Resource caps
The smoke target uses `-rss_limit_mb=3072`, `-max_len=65536`, and
`-max_total_time=${CPKRT_FUZZ_SECONDS}`. The harness caps CRILAYLA output at
64 MiB before allocating. ASan and UBSan are enabled for both the library and
the harness, so memory errors and undefined behavior abort with an artifact.
