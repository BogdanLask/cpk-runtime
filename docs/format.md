# CPK and CRILAYLA format notes

This document describes the parts of the CRI CPK container that `cpkrt`
implements. It is a format-level description, not a specification published by
CRI. The library accepts the layouts below and rejects anything it cannot
validate.

## 1. Conventions

- Multi-byte integers in CPK packets and `@UTF` tables are **big-endian**.
- Header fields inside a CRILAYLA entry are **little-endian**.
- Offsets in a CPK file are absolute unless a field is explicitly described as
  relative.
- An archive has a `ContentOffset` (start of the payload area), an alignment
  value, and an index made of a TOC and/or an ITOC.
- Entry identity is the numeric ID in the index. Names are not part of the
  stable identity model used here.

## 2. Packet framing

A CPK packet starts with a 16-byte frame:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 | Tag: `CPK `, `TOC `, `ITOC`, or another four-character code |
| 4 | 4 | Reserved / unused by this reader |
| 8 | 8 | Size of the `@UTF` table that follows, little-endian |
| 16 | variable | `@UTF` table |

The TOC and ITOC `*Size` fields in the header include the 16-byte frame. The
packet size at offset 8 covers only the table itself.

## 3. The CPK header

The file starts with a `CPK ` packet. Its `@UTF` table has one row. The fields
used by this reader are:

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `ContentOffset` | integer | yes | Absolute start of payload data |
| `Align` | integer | yes | Payload alignment, nonzero |
| `Files` | integer | yes | Declared number of entries |
| `TocOffset` | integer | no | Absolute offset of the TOC packet |
| `TocSize` | integer | with TOC | TOC packet extent, including its frame |
| `ItocOffset` | integer | no | Absolute offset of the ITOC packet |
| `ItocSize` | integer | with ITOC | ITOC packet extent, including its frame |

Additional columns are ignored. `Files` is checked against the number of
entries produced by the selected index path. `TocSize`/`ItocSize` must be
nonzero when the corresponding offset is present, and every referenced range
must lie inside the file.

## 4. `@UTF` tables

An `@UTF` table begins with:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 | Magic `@UTF` |
| 4 | 4 | Table size in bytes, excluding the magic |
| 8 | 2 | Version (0 in observed files) |
| 10 | 2 | Rows offset, relative to byte 8 |
| 12 | 4 | String-pool offset, relative to byte 8 |
| 16 | 4 | Data-area offset, relative to byte 8 |
| 20 | 4 | Table-name offset, relative to the string pool |
| 24 | 2 | Column count |
| 26 | 2 | Row length in bytes |
| 28 | 4 | Row count |

The total table size is `table_size + 8`. Offsets must be ordered
`rows <= strings <= data <= total`, and the row array must fit before the
string pool.

### Column schema

Columns are described immediately after the 32-byte table header. Each entry
has:

1. A one-byte flags/type field.
2. If the name flag is set, a big-endian `u32` string offset.
3. If the constant flag is set, the constant value inline.

The high nibble of the flags byte is `1` (name), `3` (name + constant), or `5`
(name + row). The low nibble is the value type:

| Value | Type | Size |
| --- | --- | --- |
| 0 | `u8` | 1 |
| 1 | `s8` | 1 |
| 2 | `u16` | 2 |
| 3 | `s16` | 2 |
| 4 | `u32` | 4 |
| 5 | `s32` | 4 |
| 6 | `u64` | 8 |
| 7 | `s64` | 8 |
| 8 | `f32` | 4 |
| 10 | string offset | 4 |
| 11 | blob reference | 8 |
| 12 | GUID | 16 |

A column cannot be both constant and per-row. The sum of per-row column sizes
must equal the row length. Column names are matched case-insensitively and must
be unique.

String columns and column names are offsets into the string pool and must
terminate before the data area. A blob value occupies eight bytes: a `u32`
offset relative to the data area and a `u32` length. The referenced bytes must
fit in the data area.

### Optional table obfuscation

Some tables are XOR-obfuscated with a 32-bit LCG byte stream:

```
state = 0x655f
for each byte:
    byte ^= state & 0xff
    state = (state * 0x4115) mod 2^32
```

The reader first tests for a plain `@UTF` magic. If it is absent, it applies
the transform and tests again. This is obfuscation, not encryption. The
transform is applied to the whole table before parsing.

## 5. TOC (`CpkTocInfo`)

The TOC has one row per entry. The reader recognizes these columns:

| Column | Required | Meaning |
| --- | --- | --- |
| `ID` | yes | Numeric entry ID |
| `FileOffset` | yes | Offset of the stored bytes, relative to a base |
| `FileSize` | yes | Stored size in bytes |
| `ExtractSize` | no | Size after decoding; defaults to `FileSize` |

The TOC offset base is `min(TOC packet offset, ContentOffset)`. Tools differ on
which of the two the offsets are relative to; taking the minimum handles both
observed layouts. Every stored range is validated against the file.

The TOC is sorted by ID for lookup. Duplicate IDs are rejected. IDs must be
nonnegative and fit in 32 bits. The original TOC row index is retained as
`table_order` for diagnostics and for validating an extended ITOC map.

## 6. Extended ITOC map (`CpkExtendId`)

This ITOC does not contain sizes or offsets. It maps IDs to TOC rows:

| Column | Meaning |
| --- | --- |
| `ID` | Numeric entry ID |
| `TocIndex` | Row number in the TOC |

The map must have exactly one row per TOC entry. The reader checks that every
`ID` exists in the sorted TOC, that `TocIndex` matches that entry's original
`table_order`, and that no row is referenced twice. The TOC remains the source
of offsets and sizes.

## 7. Legacy ITOC (`CpkItocInfo`)

Older or simpler archives can have an ITOC with two blob columns, `DataH` and
`DataL`. Each blob is itself an `@UTF` table with rows containing `ID`,
`FileSize`, and optional `ExtractSize`. The reader appends DataH rows first,
then DataL rows. `high_files` is the number of DataH rows.

Because this variant stores no offsets, the layout must be selected explicitly:

- `CPK_LAYOUT_ID_ORDER`: sort by ID, then place files back to back starting at
  `align_up(ContentOffset, Align)`, padding each stored size to `Align`.
- `CPK_LAYOUT_TABLE_ORDER`: place files in DataH-then-DataL table order, then
  sort the result for by-ID lookup.

Neither order is assumed to be universal. The legacy path is supported by the
parser but has only synthetic coverage in this repository.

## 8. Alignment and IDs

The payload area starts at `ContentOffset`, rounded up to `Align`. The header's
`Align` must be nonzero. ID values are local to one archive; the same number in
two archives is unrelated. Display names may be placeholders, duplicated, or
absent, so applications should use IDs for lookup and caching keys.

## 9. CRILAYLA

A compressed entry starts with a 16-byte header:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 8 | Magic `CRILAYLA` |
| 8 | 4 | `body_size`, little-endian |
| 12 | 4 | `raw_offset`, little-endian |
| 16 | `raw_offset` | Compressed bitstream |
| 16 + `raw_offset` | 256 | First 256 output bytes, stored raw |

The decoded output is exactly `body_size + 256` bytes. The 256-byte raw prefix
is copied first. The compressed stream is consumed from its **last byte
backwards**, most-significant bit first. The body is produced from the **end of
the output** towards the raw prefix.

The bitstream is a sequence of tokens:

- `0` + 8 bits: literal byte. Write it at the current end position.
- `1` + 13 bits + length chunks: back-reference.
  - `distance = 13-bit value + 3`.
  - `length = 3`, then add a 2-bit chunk. If that chunk is not all ones, stop.
  - Otherwise add a 3-bit chunk, then a 5-bit chunk, then 8-bit chunks, stopping
    at the first chunk that is not all ones. Each stage is skipped when its
    chunk is the maximum value.
  - Copy `length` bytes from `distance` bytes further towards the end of the
    output (already decoded data) to the current position.

Every distance and length is checked against the bytes produced so far. A
reference that would leave the output, or a stream that ends before the body is
complete, is rejected. Bytes after the raw prefix are ignored, so padding is
allowed. The decoder performs no allocation and writes only into a buffer whose
size equals the header's output size; overlapping input and output spans are
rejected.

When a CPK entry's stored size differs from its extract size, the stored bytes
are expected to be CRILAYLA. When the two sizes are equal, the entry is treated
as raw. The provider checks the CRILAYLA header's output size against the
index's `ExtractSize` before decoding. It can also write the decoded bytes into
caller-provided buffers without allocating or taking a lease; a compressed
entry then needs a second caller buffer for the stored bytes, which are staged
before decoding.

## 10. Limits and non-goals

Host-side limits in this implementation, not format limits:

- 16 MiB per `@UTF` packet.
- 262,144 entries per index.
- 64 MiB default cap for stored and decoded provider entries, applied to lease
  reads and to caller-buffer fills alike; configurable per source.

Not implemented: ETOC/GTOC, archive-level encryption, CPK writing/repacking,
CRILAYLA compression, filename recovery, and asynchronous loading. The parser
is integer-only and does not depend on floating-point behavior.

## 11. References

- [CriPakTools](https://github.com/esperknight/CriPakTools)
- [QuickBMS](https://aluigi.altervista.org/quickbms.htm)
- [cpktools](https://github.com/kamikat/cpktools)
