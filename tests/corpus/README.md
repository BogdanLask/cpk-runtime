# Fuzz seed corpus

`seeds/` holds the starting corpus for `cpkrt_fuzz`. Every seed is generated
deterministically by `../make_fuzz_corpus.py` from the same in-memory builders
used by the contract tests. The corpus is fully synthetic: it contains no game
data, extracted assets, or private archive material.

The seeds cover valid TOC, extended `CpkExtendId` ITOC, legacy `DataH` and
`DataL` ITOC archives, LCG-XOR-obfuscated `@UTF` tables, a CRILAYLA entry, and
deliberately truncated or corrupt inputs. The directory is copied into the
build tree before each fuzzing run; libFuzzer receives the copy, not the
checked-in files, so generated units never dirty the source tree.

Regenerate the corpus after changing the generator:

```sh
python3 tests/make_fuzz_corpus.py
```

Verify that the checked-in files match the generator byte for byte without
writing anything:

```sh
python3 tests/make_fuzz_corpus.py --check
python3 tests/make_fuzz_corpus.py --check tests/corpus/seeds
```

CTest runs the check as `fuzz_corpus_fresh`. The corpus is intentionally small
(well under 256 KiB) so it stays cheap for the CI smoke run and for local
`fuzz_smoke`. Local libFuzzer invocation:

```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Debug -DCPKRT_BUILD_TESTS=OFF \
  -DCPKRT_BUILD_BENCHMARKS=OFF -DCPKRT_BUILD_EXAMPLES=OFF \
  -DCPKRT_BUILD_FUZZERS=ON
cmake --build build-fuzz --target fuzz_smoke
```

See [../../docs/fuzzing.md](../../docs/fuzzing.md) for the full workflow.
