#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate a synthetic CPK archive for cpkrt_bench.

The archive contains deterministic, generated data only. It is intentionally
larger than the contract-test fixtures so index, lookup, I/O, and decode paths
can be timed without shipping real assets.
"""
import argparse
import struct
import sys
from pathlib import Path

TYPES = {"u32": (4, ">I"), "u64": (6, ">Q")}
PREFIX = bytes(range(256))


def utf(name, columns, rows):
    strings = bytearray()

    def string(text):
        offset = len(strings)
        strings.extend(text.encode("ascii") + b"\0")
        return offset

    table_name = string(name)
    schema = bytearray()
    for key, kind in columns:
        schema.append(0x50 | (11 if kind == "blob" else TYPES[kind][0]))
        schema.extend(struct.pack(">I", string(key)))

    values, blobs = bytearray(), bytearray()
    width = sum(8 if kind == "blob" else struct.calcsize(TYPES[kind][1]) for _, kind in columns)
    for row in rows:
        for key, kind in columns:
            if kind == "blob":
                value = row[key]
                values.extend(struct.pack(">II", len(blobs), len(value)))
                blobs.extend(value)
            else:
                values.extend(struct.pack(TYPES[kind][1], row[key]))

    at_rows = 32 + len(schema)
    at_strings = at_rows + len(values)
    at_data = at_strings + len(strings)
    total = at_data + len(blobs)
    return (
        b"@UTF"
        + struct.pack(
            ">IHHIIIHHI",
            total - 8,
            0,
            at_rows - 8,
            at_strings - 8,
            at_data - 8,
            table_name,
            len(columns),
            width,
            len(rows),
        )
        + schema
        + values
        + strings
        + blobs
    )


def packet(tag, data):
    return tag + struct.pack("<IQ", 255, len(data)) + data


def compressed(tokens, body_size):
    bits = []
    produced = 0
    for token in tokens:
        if token[0] == "literal":
            bits.append("0" + f"{token[1]:08b}")
            produced += 1
        else:
            _, distance, length = token
            bits.append("1" + f"{distance - 3:013b}")
            remaining = length - 3
            for width in (2, 3, 5):
                chunk = min(remaining, (1 << width) - 1)
                bits.append(f"{chunk:0{width}b}")
                remaining -= chunk
                if chunk < (1 << width) - 1:
                    break
            else:
                while remaining >= 255:
                    bits.append("11111111")
                    remaining -= 255
                bits.append(f"{remaining:08b}")
            produced += length
    if produced != body_size:
        raise ValueError(f"token output {produced} does not match body size {body_size}")

    bit_string = "".join(bits)
    bit_string += "0" * (-len(bit_string) % 8)
    stream = bytes(int(bit_string[i : i + 8], 2) for i in range(0, len(bit_string), 8))[::-1]
    return b"CRILAYLA" + struct.pack("<II", body_size, len(stream)) + stream + PREFIX


def literal_byte(index, seed):
    return (index * 31 + seed) & 0xFF


def make_tokens(body_size, mode, seed):
    if body_size == 0:
        return []
    if mode == "literal":
        return [("literal", literal_byte(i, seed)) for i in range(body_size)]

    tokens = []
    written = 0
    initial = min(3, body_size)
    for i in range(initial):
        tokens.append(("literal", literal_byte(i, seed)))
        written += 1

    while written < body_size:
        length = min(4096, body_size - written)
        if length < 3:
            for i in range(length):
                tokens.append(("literal", literal_byte(written + i, seed)))
            written += length
        else:
            tokens.append(("ref", 3, length))
            written += length
    return tokens


def pattern(size, seed):
    if size == 0:
        return b""
    block = bytes(literal_byte(i, seed) for i in range(256))
    return (block * ((size + 255) // 256))[:size]


def align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def build(entries, raw_size, packed_size, packed_count, packed_mode, seed, base_id):
    rows = []
    raw_payload = pattern(raw_size, seed)
    for i in range(entries):
        if i < packed_count:
            body_size = packed_size - 256
            if body_size < 0:
                raise ValueError("--packed-size must be at least 256")
            payload = compressed(make_tokens(body_size, packed_mode, seed), body_size)
            rows.append(
                {
                    "id": base_id + i,
                    "payload": payload,
                    "stored": len(payload),
                    "extract": packed_size,
                }
            )
        else:
            rows.append(
                {
                    "id": base_id + i,
                    "payload": raw_payload,
                    "stored": raw_size,
                    "extract": raw_size,
                }
            )

    toc_at = 0x400
    toc_columns = [
        ("ID", "u32"),
        ("FileSize", "u32"),
        ("ExtractSize", "u32"),
        ("FileOffset", "u64"),
    ]
    itoc_columns = [("ID", "u32"), ("TocIndex", "u32")]

    placeholder = utf(
        "CpkTocInfo",
        toc_columns,
        [
            {
                "ID": row["id"],
                "FileSize": row["stored"],
                "ExtractSize": row["extract"],
                "FileOffset": 0,
            }
            for row in rows
        ],
    )
    itoc = utf(
        "CpkExtendId",
        itoc_columns,
        [{"ID": row["id"], "TocIndex": i} for i, row in enumerate(rows)],
    )
    itoc_at = align_up(toc_at + 16 + len(placeholder), 0x100)
    content = align_up(itoc_at + 16 + len(itoc), 0x1000)

    offset = content
    for row in rows:
        offset = align_up(offset, 0x100)
        row["offset"] = offset
        offset += row["stored"]
    file_size = offset

    toc = utf(
        "CpkTocInfo",
        toc_columns,
        [
            {
                "ID": row["id"],
                "FileSize": row["stored"],
                "ExtractSize": row["extract"],
                "FileOffset": row["offset"] - toc_at,
            }
            for row in rows
        ],
    )
    if len(toc) != len(placeholder):
        raise AssertionError("TOC size changed between passes")

    header = {
        "ContentOffset": content,
        "TocOffset": toc_at,
        "TocSize": 16 + len(toc),
        "ItocOffset": itoc_at,
        "ItocSize": 16 + len(itoc),
        "Files": entries,
        "Align": 0x100,
    }
    hdr = utf("CpkHeader", [(key, "u64") for key in header], [header])
    header_packet = packet(b"CPK ", hdr)
    toc_packet = packet(b"TOC ", toc)
    itoc_packet = packet(b"ITOC", itoc)

    if len(header_packet) > toc_at:
        raise AssertionError("header packet does not fit before TOC")
    if toc_at + len(toc_packet) > itoc_at:
        raise AssertionError("TOC packet overlaps ITOC")
    if itoc_at + len(itoc_packet) > content:
        raise AssertionError("ITOC packet overlaps content")

    data = bytearray(file_size)
    data[: len(header_packet)] = header_packet
    data[toc_at : toc_at + len(toc_packet)] = toc_packet
    data[itoc_at : itoc_at + len(itoc_packet)] = itoc_packet
    for row in rows:
        start = row["offset"]
        end = start + row["stored"]
        if end > file_size:
            raise AssertionError("payload exceeds file size")
        data[start:end] = row["payload"]
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination .cpk file")
    parser.add_argument("--entries", type=int, default=4096, help="total entries (default: 4096)")
    parser.add_argument("--packed-count", type=int, default=4, help="CRILAYLA entries (default: 4)")
    parser.add_argument("--raw-size", type=int, default=4096, help="bytes per raw entry (default: 4096)")
    parser.add_argument("--packed-size", type=int, default=65536, help="decoded bytes per packed entry (default: 65536)")
    parser.add_argument(
        "--packed-mode",
        choices=("refs", "literal"),
        default="refs",
        help="compressed token mix (default: refs)",
    )
    parser.add_argument("--seed", type=int, default=1, help="payload seed (default: 1)")
    parser.add_argument("--base-id", type=lambda value: int(value, 0), default=0x1000, help="first entry ID (default: 0x1000)")
    args = parser.parse_args()

    if args.entries < 1:
        parser.error("--entries must be positive")
    if not 0 <= args.packed_count <= args.entries:
        parser.error("--packed-count must be between 0 and --entries")
    if args.raw_size < 0:
        parser.error("--raw-size must not be negative")
    if args.packed_size < 256 and args.packed_count:
        parser.error("--packed-size must be at least 256 for packed entries")
    if args.base_id < 0 or args.base_id + args.entries - 1 > 0xFFFFFFFF:
        parser.error("entry IDs must fit in uint32")

    data = build(
        args.entries,
        args.raw_size,
        args.packed_size,
        args.packed_count,
        args.packed_mode,
        args.seed & 0xFF,
        args.base_id,
    )
    args.output.write_bytes(data)
    packed = args.packed_count
    raw = args.entries - packed
    print(
        f"wrote {args.output} ({len(data)} bytes): "
        f"{args.entries} entries, {packed} packed, {raw} raw"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
