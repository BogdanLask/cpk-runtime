#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write a small synthetic CPK archive for manual testing.

The generated file contains no external data. It is produced by the same
in-memory builder used by the independent contract tests.
"""
import argparse
import struct
import sys
from pathlib import Path

from check_cpk_contract import archive, compressed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination .cpk file")
    parser.add_argument("--mode", choices=("extended", "toc", "legacy"), default="extended")
    parser.add_argument("--encrypt", action="store_true", help="XOR-obfuscate the @UTF packets")
    parser.add_argument("--packed", action="store_true", help="make entry 0x2a CRILAYLA-compressed")
    args = parser.parse_args()

    if args.packed and args.mode != "extended":
        parser.error("--packed requires --mode extended")

    payload = None
    extract_size = None
    if args.packed:
        tail = b"cpkrt synthetic payload\n" * 8
        tokens = [("literal", value) for value in tail[::-1]]
        payload = compressed(tokens, len(tail))
        extract_size = 256 + len(tail)

    data = archive(args.mode, args.encrypt, payload=payload, extract_size=extract_size)
    args.output.write_bytes(data)
    kind = "CRILAYLA entry 0x2a" if args.packed else "raw entries"
    print(f"wrote {args.output} ({len(data)} bytes, {kind}; IDs 0x2a and 0x7)")
    if args.packed:
        print(f"expected 0x2a output: {extract_size} bytes ({extract_size - 256} body bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
