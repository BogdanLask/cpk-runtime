// SPDX-License-Identifier: MIT
#include "cpkrt/crilayla.h"
#include <string.h>

#define HEADER_SIZE 0x10u
#define RAW_SIZE 0x100u

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool crilayla_detect(const uint8_t *in, size_t in_size)
{
    return in && in_size >= HEADER_SIZE && memcmp(in, "CRILAYLA", 8) == 0;
}

/* Validates the header. On success: *body is body_size, *stream_len is the
 * number of compressed bytes at in + 0x10, and the raw block follows them. */
static crilayla_status parse_header(const uint8_t *in, size_t in_size,
                                       size_t *total, size_t *body, size_t *stream_len)
{
    if (!crilayla_detect(in, in_size)) return CRILAYLA_NOT_CRILAYLA;

    uint32_t body_size = le32(in + 8);
    uint32_t raw_offset = le32(in + 12);

    /* total = body_size + 0x100 must fit in size_t (matters on 32-bit). */
    if ((uint64_t)body_size + RAW_SIZE > (uint64_t)SIZE_MAX) return CRILAYLA_TOO_LARGE;

    /* The raw block must lie entirely inside the input. */
    uint64_t raw_end = (uint64_t)HEADER_SIZE + raw_offset + RAW_SIZE;
    if (raw_end > (uint64_t)in_size) return CRILAYLA_TRUNCATED;

    *total = (size_t)body_size + RAW_SIZE;
    *body = (size_t)body_size;
    *stream_len = (size_t)raw_offset;
    return CRILAYLA_OK;
}

crilayla_status crilayla_output_size(const uint8_t *in, size_t in_size, size_t *out_size)
{
    size_t total, body, stream_len;
    if(!out_size) return CRILAYLA_INVALID;
    crilayla_status st = parse_header(in, in_size, &total, &body, &stream_len);
    *out_size = (st == CRILAYLA_OK) ? total : 0;
    return st;
}

/* Bit source over the compressed stream, read from its last byte backwards. */
typedef struct {
    const uint8_t *data; /* first byte of the stream */
    size_t remaining;    /* bytes of the stream not yet loaded */
    uint32_t pool;       /* byte currently being consumed */
    uint32_t left;       /* unread bits in pool, taken from the top */
    bool failed;         /* asked for a bit after the stream ended */
} bits;

static uint32_t take(bits *b, uint32_t n)
{
    uint32_t v = 0;
    while (n) {
        if (b->left == 0) {
            if (b->remaining == 0) {
                b->failed = true;
                return 0;
            }
            b->pool = b->data[--b->remaining];
            b->left = 8;
        }
        uint32_t now = n < b->left ? n : b->left;
        v = (v << now) | ((b->pool >> (b->left - now)) & ((1u << now) - 1u));
        b->left -= now;
        n -= now;
    }
    return v;
}

crilayla_status crilayla_decode(const uint8_t *in, size_t in_size, uint8_t *out, size_t out_size)
{
    size_t total, body, stream_len;
    crilayla_status st = parse_header(in, in_size, &total, &body, &stream_len);
    if (st != CRILAYLA_OK) return st;
    if (!out || out_size != total) return CRILAYLA_SIZE_MISMATCH;

    uintptr_t start_in=(uintptr_t)in,start_out=(uintptr_t)out;
    if(in_size>UINTPTR_MAX-start_in || out_size>UINTPTR_MAX-start_out ||
       (start_in<start_out+out_size && start_out<start_in+in_size)) return CRILAYLA_INVALID;
    /* The first 0x100 output bytes are stored as is, after the stream. */
    memcpy(out, in + HEADER_SIZE + stream_len, RAW_SIZE);

    bits b = {in + HEADER_SIZE, stream_len, 0, 0, false};
    size_t written = 0; /* output bytes produced so far, counted from the end */

    while (written < body) {
        if (take(&b, 1)) {
            /* Back reference: copy len bytes from dist positions further on
             * (towards the end of the output, i.e. already decoded data). */
            size_t dist = (size_t)take(&b, 13) + 3;
            size_t len = 3;
            static const uint32_t widths[3] = {2, 3, 5};
            bool done = false;
            for (uint32_t i = 0; i < 3 && !done; i++) {
                uint32_t v = take(&b, widths[i]);
                len += v;
                if (v != (1u << widths[i]) - 1u) done = true;
            }
            while (!done) {
                uint32_t v = take(&b, 8);
                len += v;
                if (v != 255u) done = true;
                if (b.failed || len > body - written) break; /* also bounds the loop */
            }
            if (b.failed || dist > written || len > body - written) return CRILAYLA_CORRUPT;

            size_t dest = total - 1 - written; /* highest byte still unwritten */
            for (size_t i = 0; i < len; i++) out[dest - i] = out[dest - i + dist];
            written += len;
        } else {
            uint32_t v = take(&b, 8);
            if (b.failed) return CRILAYLA_CORRUPT;
            out[total - 1 - written] = (uint8_t)v;
            written++;
        }
    }
    return b.failed ? CRILAYLA_CORRUPT : CRILAYLA_OK;
}

const char *crilayla_status_name(crilayla_status status)
{
    switch (status) {
    case CRILAYLA_INVALID: return "invalid or overlapping buffers";
    case CRILAYLA_OK: return "ok";
    case CRILAYLA_NOT_CRILAYLA: return "not CRILAYLA data";
    case CRILAYLA_TRUNCATED: return "header points outside the entry";
    case CRILAYLA_CORRUPT: return "corrupt compressed stream";
    case CRILAYLA_SIZE_MISMATCH: return "output size does not match the header";
    case CRILAYLA_TOO_LARGE: return "output too large for this platform";
    }
    return "unknown";
}
