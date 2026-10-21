// SPDX-License-Identifier: MIT
#ifndef CPKRT_CRILAYLA_H
#define CPKRT_CRILAYLA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Decoder for CRI's "CRILAYLA" compression, as used by CPK entries whose
 * stored size is smaller than their extract size.
 *
 * Layout of a compressed entry (header fields little-endian):
 *   0x00  "CRILAYLA"
 *   0x08  u32 body_size       output bytes produced by the compressed stream
 *   0x0C  u32 raw_offset      distance from 0x10 to the raw 0x100 bytes
 *   0x10  compressed stream   raw_offset bytes
 *   0x10+raw_offset  the first 0x100 bytes of the output, stored uncompressed
 * The output is body_size + 0x100 bytes. The stream is consumed from its last
 * byte towards its first and the output is produced from its last byte towards
 * the 0x100 raw bytes. Bits are read most significant first.
 *
 * No allocation, no globals, no OS calls. Every read and write is bounds
 * checked, so it is safe on untrusted or damaged data. Sizes are size_t, and
 * entries whose output does not fit in size_t are rejected, so it is correct
 * on 32-bit targets. Bytes beyond the raw block (padding) are ignored. */

typedef enum {
    CRILAYLA_OK,
    CRILAYLA_INVALID,       /* null output-size pointer or overlapping spans */
    CRILAYLA_NOT_CRILAYLA,   /* too short, or the magic is not "CRILAYLA" */
    CRILAYLA_TRUNCATED,      /* header fields point outside the input */
    CRILAYLA_CORRUPT,        /* stream ran out, or a reference left the output */
    CRILAYLA_SIZE_MISMATCH,  /* output buffer size != body_size + 0x100 */
    CRILAYLA_TOO_LARGE       /* output size does not fit in size_t */
} crilayla_status;

/* True if the bytes start with the CRILAYLA magic and a full header. */
bool crilayla_detect(const uint8_t *in, size_t in_size);

/* Reads the header only and reports the exact output size (body_size + 0x100).
 * Use it to size a buffer when the CPK index's ExtractSize is not trusted. */
crilayla_status crilayla_output_size(const uint8_t *in, size_t in_size, size_t *out_size);

/* Decodes into out, whose size must equal the header's output size exactly
 * (normally the entry's ExtractSize). On any failure the contents of out are
 * unspecified and must not be used. Input/output spans must not overlap. */
crilayla_status crilayla_decode(const uint8_t *in, size_t in_size, uint8_t *out, size_t out_size);

const char *crilayla_status_name(crilayla_status status);
#endif
