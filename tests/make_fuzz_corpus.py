#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write or check the deterministic synthetic libFuzzer seed corpus.

The seeds are built from the same in-memory helpers as the contract tests and
contain no external data. `--check` compares the checked-in corpus byte for
byte and never writes to disk.
"""
import argparse
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from check_cpk_contract import archive, compressed, packet, utf  # noqa: E402

HERE = Path(__file__).resolve().parent
DEFAULT_SEEDS = HERE / "corpus" / "seeds"

TOC_AT = 0x400
ITOC_AT = 0x800
CONTENT = 0x1000
TOC_COLUMNS = [("ID", "u32"), ("FileSize", "u32"),
               ("ExtractSize", "u32"), ("FileOffset", "u64")]


def toc_archive(ids, sizes, stride=0x40, encrypted=False, extended=False):
    rows = []
    relative = 0
    for identity, size in zip(ids, sizes):
        rows.append(dict(ID=identity, FileSize=size, ExtractSize=size,
                         FileOffset=CONTENT - TOC_AT + relative))
        relative += stride
    itoc = None
    if extended:
        maps = [dict(ID=row["ID"], TocIndex=index)
                for index, row in enumerate(rows)]
        itoc = utf("CpkExtendId", [("ID", "s32"), ("TocIndex", "s32")], maps)
    return container(rows, itoc, len(rows), encrypted,
                     max(relative, 0x100), align=0x100)


def legacy_archive(rows, part):
    if part == "datah":
        table = utf("ItocH", [("ID", "u16"), ("FileSize", "u32"),
                              ("ExtractSize", "u32")], rows)
        itoc = utf("CpkItocInfo", [("DataH", "blob")],
                   [dict(DataH=table)])
    else:
        table = utf("ItocL", [("ID", "u16"), ("FileSize", "u16"),
                              ("ExtractSize", "u16")], rows)
        itoc = utf("CpkItocInfo", [("DataL", "blob")],
                   [dict(DataL=table)])
    return container(None, itoc, len(rows), False, 0x400, align=0x100)


def container(toc_rows, itoc_table, files, encrypted, content_bytes, align):
    toc = (utf("CpkTocInfo", TOC_COLUMNS, toc_rows)
           if toc_rows is not None else None)
    header = dict(ContentOffset=CONTENT,
                  TocOffset=TOC_AT if toc else 0,
                  TocSize=len(toc) + 16 if toc else 0,
                  ItocOffset=ITOC_AT if itoc_table else 0,
                  ItocSize=len(itoc_table) + 16 if itoc_table else 0,
                  Files=files, Align=align)
    hdr = utf("CpkHeader", [(key, "u64") for key in header], [header])
    buf = bytearray(CONTENT + content_bytes)
    for at, tag, table in ((0, b"CPK ", hdr), (TOC_AT, b"TOC ", toc),
                           (ITOC_AT, b"ITOC", itoc_table)):
        if table is None:
            continue
        data = packet(tag, table, encrypted)
        assert at + len(data) <= CONTENT
        buf[at:at + len(data)] = data
    payload = bytes((index * 37 + 11) & 0xff for index in range(content_bytes))
    buf[CONTENT:] = payload
    return bytes(buf)


def crilayla_entry():
    tail = b"ABC" + bytes(b"ABC"[index % 3] for index in range(600))
    tokens = [("literal", value) for value in b"ABC"] + [("ref", 3, 600)]
    payload = compressed(tokens, len(tail))
    return archive(payload=payload, extract_size=256 + len(tail))


def corrupt_toc_utf():
    data = bytearray(archive("toc"))
    struct.pack_into(">I", data, TOC_AT + 16 + 4, 0xffffffff)
    return bytes(data)


def seeds():
    return [
        ("toc_minimal.cpk", archive("toc")),
        ("toc_single_entry.cpk", toc_archive([1], [1])),
        ("extended_itoc.cpk", archive("extended")),
        ("extended_itoc_many.cpk",
         toc_archive([500, 7, 64, 3, 999, 12, 42, 100],
                     [5, 1, 12, 4, 9, 2, 7, 3], stride=0x30, extended=True)),
        ("legacy_datah.cpk",
         legacy_archive([dict(ID=5, FileSize=8, ExtractSize=8),
                         dict(ID=42, FileSize=5, ExtractSize=5),
                         dict(ID=17, FileSize=1, ExtractSize=1)], "datah")),
        ("legacy_datal.cpk",
         legacy_archive([dict(ID=3, FileSize=16, ExtractSize=16),
                         dict(ID=77, FileSize=7, ExtractSize=7),
                         dict(ID=12, FileSize=3, ExtractSize=3)], "datal")),
        ("legacy_datah_datal.cpk", archive("legacy")),
        ("encrypted_utf.cpk", archive("extended", encrypted=True)),
        ("crilayla_entry.cpk", crilayla_entry()),
        ("truncated_header.cpk", archive("toc")[:30]),
        ("corrupt_toc_utf.cpk", corrupt_toc_utf()),
        ("tiny_magic.cpk", b"CPK "),
    ]


def write_corpus(root):
    generated = seeds()
    root.mkdir(parents=True, exist_ok=True)
    for name, data in generated:
        (root / name).write_bytes(data)
    print(f"wrote {len(generated)} seeds to {root} "
          f"({sum(len(data) for _, data in generated)} bytes)")
    for name, data in generated:
        print(f"  {name:28} {len(data):7} bytes")
    return 0


def check_corpus(root):
    generated = seeds()
    expected = {name: data for name, data in generated}
    actual = set()
    if root.is_dir():
        actual = {path.name for path in root.iterdir()}
    problems = []
    for name in sorted(expected.keys() - actual):
        problems.append(f"missing {name}")
    for name in sorted(actual - expected.keys()):
        problems.append(f"extra {name}")
    for name, data in generated:
        path = root / name
        if path.is_file() and path.read_bytes() != data:
            problems.append(f"incorrect {name}")
        elif path.exists() and not path.is_file():
            problems.append(f"not a file {name}")
    if problems:
        for problem in problems:
            print(f"corpus check failed: {problem}", file=sys.stderr)
        return 1
    print(f"corpus check passed: {len(generated)} seeds in {root}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", nargs="?", const=DEFAULT_SEEDS, type=Path,
                        metavar="DIR", help="verify a corpus without writing")
    args = parser.parse_args()
    if args.check is not None:
        return check_corpus(args.check)
    return write_corpus(DEFAULT_SEEDS)


if __name__ == "__main__":
    sys.exit(main())
