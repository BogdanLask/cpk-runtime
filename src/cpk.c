// SPDX-License-Identifier: MIT
#include "cpkrt/cpk.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TABLE_BYTES UINT64_C(16777216)
#define MAX_ENTRIES ((size_t)262144)
#define UTF_NO_NAME UINT32_MAX

typedef struct {
    cpk_read_fn read;
    void *ctx;
    uint64_t file_size;
    cpk_open_options opts;
    cpk_diag *diag;
} open_state;

static cpk_status fail(open_state *s, cpk_status status, int reason,
                       const char *table, const char *column, uint64_t index,
                       uint64_t offset, uint64_t value, uint64_t expected)
{
    if (s->diag && s->diag->reason == CPK_REASON_NONE) {
        s->diag->reason = reason;
        s->diag->table = table;
        s->diag->column = column;
        s->diag->index = index;
        s->diag->offset = offset;
        s->diag->value = value;
        s->diag->expected = expected;
    }
    return status;
}

/* @UTF column flag bits. Low nibble is the value type. */
enum { COL_NAME = 0x10, COL_CONST = 0x20, COL_ROW = 0x40, COL_BAD = 0x80 };
enum {
    T_U8 = 0, T_S8 = 1, T_U16 = 2, T_S16 = 3, T_U32 = 4, T_S32 = 5,
    T_U64 = 6, T_S64 = 7, T_F32 = 8, T_STR = 10, T_BLOB = 11, T_GUID = 12
};

/* ---- byte helpers (all @UTF contents are big-endian) ---- */

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t be64(const uint8_t *p) { return ((uint64_t)be32(p) << 32) | be32(p + 4); }

static bool range_ok(uint64_t total, uint64_t off, uint64_t len)
{
    return off <= total && len <= total - off;
}

static bool align_up(uint64_t v,uint64_t a,uint64_t *out)
{
    if(!a) return false;
    uint64_t remainder=v%a,add=remainder ? a-remainder : 0;
    if(v>UINT64_MAX-add) return false;
    *out=v+add;return true;
}
static uint64_t le64(const uint8_t *p)
{
    uint64_t value=0;for(uint32_t i=0;i<8;i++) value|=(uint64_t)p[i]<<(i*8u);return value;
}

static uint8_t lower(uint8_t c) { return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c; }

/* ---- @UTF table ---- */

typedef struct {
    uint8_t flags;
    uint32_t name_off;  /* into the string pool, or UTF_NO_NAME */
    size_t value_off;   /* const: absolute in table; row: offset inside a row */
} utf_col;

typedef struct {
    uint8_t *buf;       /* start of the "@UTF" magic; decrypted in place */
    size_t size;        /* table_size + 8 */
    size_t rows_off, str_off, data_off;
    uint32_t nrows, row_len;
    uint16_t ncols;
    utf_col *cols;
} utf_table;

/* Optional obfuscation used by some CPKs: XOR with an LCG byte stream. */
static void utf_decrypt(uint8_t *data, size_t size)
{
    uint32_t m = 0x655f, t = 0x4115;
    for (size_t i = 0; i < size; i++) {
        data[i] ^= (uint8_t)m;
        m *= t;
    }
}

static size_t type_size(uint32_t type)
{
    switch (type) {
    case T_U8: case T_S8: return 1;
    case T_U16: case T_S16: return 2;
    case T_U32: case T_S32: case T_F32: case T_STR: return 4;
    case T_U64: case T_S64: case T_BLOB: return 8;
    case T_GUID: return 16;
    default: return 0;
    }
}

static void utf_close(utf_table *t)
{
    free(t->cols);
    memset(t, 0, sizeof *t);
}

/* buf must be writable; size is the number of valid bytes at buf. */
static cpk_status utf_open(open_state *s, utf_table *t, uint8_t *buf, size_t size,
                           const char *table, uint64_t offset)
{
    memset(t, 0, sizeof *t);
    if (!buf || size < 32)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, 0,
                    offset, size, 32);
    if (memcmp(buf, "@UTF", 4) != 0) {
        utf_decrypt(buf, size);
        if (memcmp(buf, "@UTF", 4) != 0)
            return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_MAGIC, table, NULL, 0,
                        offset, 0, 0);
    }

    uint16_t version = be16(buf + 8);
    if(version > s->opts.utf_max_version)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_VERSION, table, NULL, 0,
                    offset, version, s->opts.utf_max_version);
    uint64_t total = (uint64_t)be32(buf + 4) + 8;
    if (total < 32)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, 0,
                    offset, total, 32);
    if (total > size)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, 0,
                    offset, total, size);
    size = (size_t)total;

    /* Bytes 8-9 are a version field; the rows offset is the u16 after it. */
    uint64_t rows = (uint64_t)be16(buf + 10) + 8;
    uint64_t str = (uint64_t)be32(buf + 12) + 8;
    uint64_t data = (uint64_t)be32(buf + 16) + 8;
    uint16_t ncols = be16(buf + 24);
    uint32_t row_len = be16(buf + 26);
    uint32_t nrows = be32(buf + 28);
    if (rows < 32)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, 0,
                    offset, rows, 32);
    if (rows > str)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, 0,
                    offset, rows, str);
    if (str > data)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, 0,
                    offset, str, data);
    if (data > size)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, 0,
                    offset, data, size);
    if (!ncols)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, 0,
                    offset, 0, 1);
    if (nrows > MAX_ENTRIES)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_LIMIT, table, NULL, 0,
                    offset, nrows, MAX_ENTRIES);
    if ((uint64_t)nrows * row_len > str - rows)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_ROW_LENGTH, table, NULL, 0,
                    offset, (uint64_t)nrows * row_len, str - rows);
    uint64_t table_name = (uint64_t)be32(buf + 20) + str;
    if (table_name >= data ||
        !memchr(buf + (size_t)table_name, 0, (size_t)(data - table_name)))
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_TABLE_NAME, table, NULL, 0,
                    offset, table_name, data);

    utf_col *cols = calloc(ncols ? ncols : 1, sizeof *cols);
    if (!cols) return CPK_NO_MEMORY;

    size_t pos = 32, row_cursor = 0;
    for (uint16_t i = 0; i < ncols; i++) {
        utf_col *c = &cols[i];
        if (pos + 1 > rows) {
            (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, i,
                       offset, pos, rows);
            goto bad;
        }
        c->flags = buf[pos++];
        if ((c->flags >> 4) != 1 && (c->flags >> 4) != 3 && (c->flags >> 4) != 5) {
            (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_COLUMN_FLAGS, table, NULL, i,
                       offset, c->flags, 0);
            goto bad;
        }
        if ((c->flags & COL_CONST) && (c->flags & COL_ROW)) {
            (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_COLUMN_FLAGS, table, NULL, i,
                       offset, c->flags, 0);
            goto bad;
        }
        size_t vsz = type_size(c->flags & 0x0F);
        if (!vsz) {
            (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_COLUMN_TYPE, table, NULL, i,
                       offset, c->flags & 0x0F, 0);
            goto bad;
        }

        c->name_off = UTF_NO_NAME;
        if (c->flags & COL_NAME) {
            if (pos + 4 > rows) {
                (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, i,
                           offset, pos, rows);
                goto bad;
            }
            c->name_off = be32(buf + pos);
            pos += 4;
            uint64_t name = str + c->name_off;
            if (name >= data ||
                !memchr(buf + (size_t)name, 0, (size_t)(data - name))) {
                (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_COLUMN_NAME, table, NULL, i,
                           offset, c->name_off, data - str);
                goto bad;
            }
            for (uint16_t j = 0; j < i; j++) {
                const uint8_t *a = buf + (size_t)name;
                const uint8_t *b = buf + (size_t)(str + cols[j].name_off);
                size_t k = 0;
                while (a[k] && b[k] && lower(a[k]) == lower(b[k])) k++;
                if (!a[k] && !b[k]) {
                    (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_COLUMN_NAME, table,
                               (const char *)a, i, offset, j, 0);
                    goto bad;
                }
            }
        }
        if (c->flags & COL_CONST) {
            if (pos + vsz > rows) {
                (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, i,
                           offset, pos, rows);
                goto bad;
            }
            c->value_off = pos;
            pos += vsz;
        } else if (c->flags & COL_ROW) {
            c->value_off = row_cursor;
            row_cursor += vsz;
        }
    }
    if (row_cursor != row_len) {
        (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_ROW_LENGTH, table, NULL, 0,
                   offset, row_cursor, row_len);
        goto bad;
    }
    if (pos > rows) {
        (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, table, NULL, 0,
                   offset, pos, rows);
        goto bad;
    }

    t->buf = buf;
    t->size = size;
    t->rows_off = (size_t)rows;
    t->str_off = (size_t)str;
    t->data_off = (size_t)data;
    t->nrows = nrows;
    t->row_len = row_len;
    t->ncols = ncols;
    t->cols = cols;
    return CPK_OK;
bad:
    free(cols);
    return CPK_BAD_FORMAT;
}

/* Column names are matched ignoring ASCII case because tools disagree on
 * spellings such as "ITocOffset" versus "ItocOffset". */
static bool name_eq(const uint8_t *s, size_t avail, const char *name)
{
    size_t n = strlen(name);
    if (n >= avail) return false;
    for (size_t i = 0; i < n; i++)
        if (lower(s[i]) != lower((uint8_t)name[i])) return false;
    return s[n] == 0;
}

static const utf_col *utf_find_col(const utf_table *t, const char *name)
{
    for (uint16_t i = 0; i < t->ncols; i++) {
        const utf_col *c = &t->cols[i];
        if (c->name_off == UTF_NO_NAME) continue;
        uint64_t s = (uint64_t)t->str_off + c->name_off;
        if (s >= t->data_off) continue;
        if (name_eq(t->buf + s, t->data_off - (size_t)s, name)) return c;
    }
    return NULL;
}

/* Location of a column's value for a row, or NULL for zero-storage columns
 * (name only, no value anywhere: reads as 0 / empty). */
static bool utf_value_ptr(const utf_table *t, const utf_col *c, uint32_t row, const uint8_t **p)
{
    *p = NULL;
    if (c->flags & COL_ROW) {
        if (row >= t->nrows) return false;
        *p = t->buf + t->rows_off + (size_t)row * t->row_len + c->value_off;
    } else if (c->flags & COL_CONST) {
        *p = t->buf + c->value_off;
    }
    return true;
}

/* Nonnegative integer values, including the signed32 columns in CpkExtendId.
 * Reject negative sizes/offsets/IDs instead of reinterpreting their sign bit. */
static bool utf_col_u64(open_state *s, const utf_table *t, const utf_col *c,
                        uint32_t row, const char *table, const char *column,
                        uint64_t offset, uint64_t *out)
{
    uint32_t type = c->flags & 0x0F;
    const uint8_t *p;
    if(type>T_S64) {
        (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_COLUMN_TYPE, table, column, row,
                   offset, type, 0);
        return false;
    }
    if(!utf_value_ptr(t,c,row,&p)) {
        (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_ENTRY_RANGE, table, column, row,
                   offset, row, t->nrows);
        return false;
    }
    if (!p) { *out = 0; return true; }
    switch (type) {
    case T_U8: case T_S8: *out = p[0]; break;
    case T_U16: case T_S16: *out = be16(p); break;
    case T_U32: case T_S32: *out = be32(p); break;
    default: *out = be64(p); break;
    }
    if ((type & 1u) && (*out >> (type_size(type) * 8u - 1u))) {
        (void)fail(s, CPK_BAD_FORMAT, CPK_REASON_INTEGER, table, column, row,
                   offset, *out, 0);
        return false;
    }
    return true;
}

/* Blob column: u32 offset (relative to the data area) + u32 size. */
static bool utf_col_blob(const utf_table *t, const utf_col *c, uint32_t row, uint8_t **ptr, size_t *len)
{
    const uint8_t *p;
    *ptr = NULL;
    *len = 0;
    if ((c->flags & 0x0F) != T_BLOB || !utf_value_ptr(t, c, row, &p)) return false;
    if (!p) return true;
    uint64_t off = be32(p), size = be32(p + 4);
    uint64_t base = t->data_off;
    if (!range_ok(t->size - base, off, size)) return false;
    *ptr = t->buf + base + off;
    *len = (size_t)size;
    return true;
}

static bool utf_number(open_state *s, const utf_table *t, const char *table,
                       uint64_t offset, const char *name, uint64_t fallback,
                       bool required, int missing_reason, uint64_t *out)
{
    const utf_col *column=utf_find_col(t,name);
    if(!column) {
        if(required) {
            (void)fail(s, CPK_BAD_FORMAT, missing_reason, table, name, 0,
                       offset, 0, 0);
            return false;
        }
        *out=fallback;
        return true;
    }
    return utf_col_u64(s,t,column,0,table,name,offset,out);
}

static bool require_col(open_state *s, const utf_table *t, const char *table,
                        uint64_t offset, const char *name, int reason,
                        const utf_col **out)
{
    *out = utf_find_col(t, name);
    if (*out) return true;
    (void)fail(s, CPK_BAD_FORMAT, reason, table, name, 0, offset, 0, 0);
    return false;
}

/* ---- packets ---- */

/* A packet is: 4-byte tag, 12 more header bytes, then one @UTF table. The
 * table length comes from the @UTF header itself, not from the packet header,
 * so only the first 8 table bytes are inspected (and decrypted, if needed). */
static cpk_status read_packet(open_state *s, uint64_t offset, const char *tag,
                                 uint64_t packet_extent, uint8_t **out, size_t *out_size)
{
    uint8_t head[24];
    *out = NULL;
    *out_size = 0;
    if (packet_extent < sizeof head || !range_ok(s->file_size, offset, packet_extent) ||
        !range_ok(s->file_size, offset, sizeof head))
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_PACKET_SIZE, tag, NULL, 0, offset,
                    packet_extent, sizeof head);
    if (!s->read(s->ctx, offset, head, sizeof head))
        return fail(s, CPK_IO, CPK_REASON_IO, tag, NULL, 0, offset, 0, 0);
    if (memcmp(head, tag, 4) != 0)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_PACKET_TAG, tag, NULL, 0, offset,
                    be32(head), 0);

    uint8_t *pre = head + 16;
    if (memcmp(pre, "@UTF", 4) != 0) utf_decrypt(pre, 8);
    if (memcmp(pre, "@UTF", 4) != 0)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_MAGIC, tag, NULL, 0,
                    offset + 16, be32(pre), 0);

    uint64_t total = (uint64_t)be32(pre + 4) + 8;
    if (total < 32)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_UTF_LAYOUT, tag, NULL, 0,
                    offset + 16, total, 32);
    if (total > MAX_TABLE_BYTES)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_LIMIT, tag, NULL, 0,
                    offset + 16, total, MAX_TABLE_BYTES);
    if (offset > UINT64_MAX - 16 ||
        !range_ok(s->file_size, offset + 16, total))
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_PACKET_SIZE, tag, NULL, 0,
                    offset + 16, total, s->file_size);

    uint64_t packet_size=le64(head+8);
    if (packet_size < total || packet_size > packet_extent - 16 ||
        !range_ok(s->file_size, offset + 16, packet_size))
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_PACKET_SIZE, tag, NULL, 0,
                    offset, packet_size, total);
    if (packet_size > MAX_TABLE_BYTES)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_LIMIT, tag, NULL, 0,
                    offset, packet_size, MAX_TABLE_BYTES);
    uint8_t *buf = malloc((size_t)total);
    if (!buf) return CPK_NO_MEMORY;
    if (!s->read(s->ctx, offset + 16, buf, (size_t)total)) {
        free(buf);
        return fail(s, CPK_IO, CPK_REASON_IO, tag, NULL, 0, offset + 16, total, 0);
    }
    *out = buf;
    *out_size = (size_t)total;
    return CPK_OK;
}

/* ---- entry list ---- */

typedef struct {
    cpk_entry *v;
    size_t n, cap;
} entry_list;

static cpk_status list_push(open_state *s, entry_list *l, const char *table, uint32_t row,
                            uint64_t id, uint64_t stored, uint64_t extract)
{
    if (id > UINT32_MAX)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_INTEGER, table, "ID", row, 0,
                    id, UINT32_MAX);
    if (stored > UINT32_MAX)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_INTEGER, table, "FileSize", row, 0,
                    stored, UINT32_MAX);
    if (extract > UINT32_MAX)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_INTEGER, table, "ExtractSize", row, 0,
                    extract, UINT32_MAX);
    if (l->n >= MAX_ENTRIES)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_LIMIT, table, NULL, 0, 0,
                    l->n, MAX_ENTRIES);
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 256;
        if (cap > MAX_ENTRIES) cap = MAX_ENTRIES;
        cpk_entry *v = realloc(l->v, cap * sizeof *v);
        if (!v) return CPK_NO_MEMORY;
        l->v = v;
        l->cap = cap;
    }
    l->v[l->n] = (cpk_entry){.id = (uint32_t)id,
                                .offset = 0,
                                .stored_size = (uint32_t)stored,
                                .extract_size = (uint32_t)extract,
                                .table_order = (uint32_t)l->n};
    l->n++;
    return CPK_OK;
}

static int cmp_entry(const void *a, const void *b)
{
    uint32_t x = ((const cpk_entry *)a)->id, y = ((const cpk_entry *)b)->id;
    return (x > y) - (x < y);
}

static cpk_status sort_unique(open_state *s, entry_list *l, const char *table)
{
    if (l->n > 1) qsort(l->v, l->n, sizeof *l->v, cmp_entry);
    for (size_t i = 1; i < l->n; i++)
        if (l->v[i].id == l->v[i - 1].id)
            return fail(s, CPK_BAD_FORMAT, CPK_REASON_DUPLICATE_ID, table, "ID", i,
                        0, l->v[i].id, 0);
    return CPK_OK;
}

/* ---- ITOC (ID based, offsets implicit) ---- */

static cpk_status load_itoc_part(open_state *s, const utf_table *t, const char *name, entry_list *l)
{
    const utf_col *c = utf_find_col(t, name);
    uint8_t *blob;
    size_t blen;
    if (!c) return CPK_OK;
    if (t->nrows < 1 || !utf_col_blob(t, c, 0, &blob, &blen))
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_ENTRY_RANGE, "ITOC", name, 0, 0,
                    t->nrows, 1);
    if (blen == 0) return CPK_OK;

    utf_table sub;
    cpk_status st = utf_open(s, &sub, blob, blen, name, 0);
    if (st != CPK_OK) return st;

    const utf_col *id, *size, *extract;
    if (!require_col(s, &sub, name, 0, "ID", CPK_REASON_MISSING_TOC_COLUMN, &id) ||
        !require_col(s, &sub, name, 0, "FileSize", CPK_REASON_MISSING_TOC_COLUMN, &size))
        st = CPK_BAD_FORMAT;
    else
        extract = utf_find_col(&sub, "ExtractSize");
    for (uint32_t r = 0; st == CPK_OK && r < sub.nrows; r++) {
        uint64_t vid, vsize, vextract;
        if (!utf_col_u64(s, &sub, id, r, name, "ID", 0, &vid) ||
            !utf_col_u64(s, &sub, size, r, name, "FileSize", 0, &vsize)) {
            st = CPK_BAD_FORMAT;
            break;
        }
        vextract = vsize;
        if (extract &&
            !utf_col_u64(s, &sub, extract, r, name, "ExtractSize", 0, &vextract)) {
            st = CPK_BAD_FORMAT;
            break;
        }
        st = list_push(s, l, name, r, vid, vsize, vextract);
    }
    utf_close(&sub);
    return st;
}

/* Rows are appended DataH first, then DataL, matching the index order.
 * *high receives the number of DataH rows. */
static cpk_status load_itoc(open_state *s, uint64_t offset, uint64_t extent,
                               entry_list *l, size_t *high)
{
    static const char *const parts[2] = {"DataH", "DataL"};
    uint8_t *buf;
    size_t bsize;
    utf_table t;
    cpk_status st = read_packet(s, offset, "ITOC", extent, &buf, &bsize);
    if (st != CPK_OK) return st;
    st = utf_open(s, &t, buf, bsize, "ITOC", offset + 16);
    if (st != CPK_OK) {
        free(buf);
        return st;
    }
    for (uint32_t k = 0; k < 2 && st == CPK_OK; k++) {
        st = load_itoc_part(s, &t, parts[k], l);
        if (k == 0) *high = l->n;
    }
    utf_close(&t);
    free(buf);
    return st;
}

/* Files are stored back to back in the list's current order, each padded up to
 * Align; the first one starts at ContentOffset rounded up to Align. */
static cpk_status layout_itoc(open_state *s, entry_list *l, uint64_t content, uint64_t align)
{
    if (content > s->file_size)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_ENTRY_RANGE, "ITOC",
                    "ContentOffset", 0, content, content, s->file_size);
    uint64_t pos=0;
    if(!align_up(content,align,&pos))
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_INTEGER, "ITOC", "ContentOffset",
                    0, content, content, align);
    for (size_t i = 0; i < l->n; i++) {
        cpk_entry *e = &l->v[i];
        if (!range_ok(s->file_size, pos, e->stored_size))
            return fail(s, CPK_BAD_FORMAT, CPK_REASON_ENTRY_RANGE, "ITOC",
                        "FileSize", (uint64_t)i, pos, e->stored_size, s->file_size);
        e->offset = pos;
        if(i+1<l->n) {
            uint64_t step=0;
            if(!align_up(e->stored_size,align,&step) || step>UINT64_MAX-pos)
                return fail(s, CPK_BAD_FORMAT, CPK_REASON_INTEGER, "ITOC",
                            "FileSize", (uint64_t)i, pos, e->stored_size, 0);
            pos+=step;
        }
    }
    return CPK_OK;
}

/* ---- TOC (name based; ID column required) ---- */

static cpk_status load_toc(open_state *s, uint64_t offset, uint64_t extent, uint64_t content,
                              entry_list *l)
{
    uint8_t *buf;
    size_t bsize;
    utf_table t;
    cpk_status st = read_packet(s, offset, "TOC ", extent, &buf, &bsize);
    if (st != CPK_OK) return st;
    st = utf_open(s, &t, buf, bsize, "TOC ", offset + 16);
    if (st != CPK_OK) {
        free(buf);
        return st;
    }

    uint64_t table_offset = offset + 16;
    const utf_col *foff, *size, *id;
    const utf_col *extract = utf_find_col(&t, "ExtractSize");
    if (!require_col(s, &t, "TOC ", table_offset, "FileOffset",
                     CPK_REASON_MISSING_TOC_COLUMN, &foff) ||
        !require_col(s, &t, "TOC ", table_offset, "FileSize",
                     CPK_REASON_MISSING_TOC_COLUMN, &size) ||
        !require_col(s, &t, "TOC ", table_offset, "ID",
                     CPK_REASON_MISSING_TOC_COLUMN, &id))
        st = CPK_BAD_FORMAT;

    /* TOC offsets are relative to whichever of TOC/content comes first. */
    uint64_t base = content < offset ? content : offset;
    for (uint32_t r = 0; st == CPK_OK && r < t.nrows; r++) {
        uint64_t voff, vsize, vextract, vid = r;
        if (!utf_col_u64(s, &t, foff, r, "TOC ", "FileOffset", table_offset, &voff) ||
            !utf_col_u64(s, &t, size, r, "TOC ", "FileSize", table_offset, &vsize)) {
            st = CPK_BAD_FORMAT;
            break;
        }
        vextract = vsize;
        if (extract &&
            !utf_col_u64(s, &t, extract, r, "TOC ", "ExtractSize", table_offset,
                         &vextract)) {
            st = CPK_BAD_FORMAT;
            break;
        }
        if (!utf_col_u64(s, &t, id, r, "TOC ", "ID", table_offset, &vid)) {
            st = CPK_BAD_FORMAT;
            break;
        }
        if (voff > UINT64_MAX - base) {
            st = fail(s, CPK_BAD_FORMAT, CPK_REASON_INTEGER, "TOC ", "FileOffset", r,
                      table_offset, voff, UINT64_MAX - base);
            break;
        }
        st = list_push(s, l, "TOC ", r, vid, vsize, vextract);
        if (st != CPK_OK) break;
        cpk_entry *e = &l->v[l->n - 1];
        e->offset = base + voff;
        if (!range_ok(s->file_size, e->offset, e->stored_size))
            st = fail(s, CPK_BAD_FORMAT, CPK_REASON_ENTRY_RANGE, "TOC ", "FileOffset", r,
                      e->offset, e->stored_size, s->file_size);
    }
    utf_close(&t);
    free(buf);
    return st;
}

/* Observed extended ITOC maps IDs to TOC rows; it does not supply sizes.
 * Entries are already ID-sorted, with original TOC row in table_order. */
static cpk_status validate_map(open_state *s,uint64_t offset,uint64_t extent,const entry_list *list)
{
    uint8_t *buf=NULL;size_t size=0;utf_table table={0};
    cpk_status status=read_packet(s,offset,"ITOC",extent,&buf,&size);
    if(status!=CPK_OK) return status;
    status=utf_open(s,&table,buf,size,"ITOC",offset+16);
    if(status!=CPK_OK) {free(buf);return status;}
    uint64_t table_offset = offset + 16;
    const utf_col *id, *index;
    if (!require_col(s, &table, "ITOC", table_offset, "ID",
                     CPK_REASON_MISSING_TOC_COLUMN, &id) ||
        !require_col(s, &table, "ITOC", table_offset, "TocIndex",
                     CPK_REASON_MISSING_TOC_COLUMN, &index))
        status = CPK_BAD_FORMAT;
    else if (table.nrows != list->n)
        status = fail(s, CPK_BAD_FORMAT, CPK_REASON_MAP_MISMATCH, "ITOC", NULL, 0,
                      table_offset, table.nrows, list->n);

    uint8_t *seen=NULL;
    if(status==CPK_OK && list->n) {seen=calloc(list->n,1);if(!seen) status=CPK_NO_MEMORY;}
    cpk sorted={0};sorted.entries=list->v;sorted.count=list->n;
    for(uint32_t row=0;status==CPK_OK && row<table.nrows;row++) {
        uint64_t identity=0,to=0;
        if(!utf_col_u64(s,&table,id,row,"ITOC","ID",table_offset,&identity) ||
           !utf_col_u64(s,&table,index,row,"ITOC","TocIndex",table_offset,&to)) {
            status=CPK_BAD_FORMAT;break;
        }
        if (identity > UINT32_MAX) {
            status = fail(s, CPK_BAD_FORMAT, CPK_REASON_INTEGER, "ITOC", "ID", row,
                          table_offset, identity, UINT32_MAX);
            break;
        }
        if (to >= list->n) {
            status = fail(s, CPK_BAD_FORMAT, CPK_REASON_MAP_MISMATCH, "ITOC",
                          "TocIndex", row, table_offset, to, list->n);
            break;
        }
        const cpk_entry *entry=cpk_find(&sorted,(uint32_t)identity);
        if(!entry || entry->table_order!=to || seen[(size_t)to]) {
            status = fail(s, CPK_BAD_FORMAT, CPK_REASON_MAP_MISMATCH, "ITOC",
                          "TocIndex", row, table_offset, identity, to);
            break;
        }
        seen[(size_t)to]=1;
    }
    free(seen);utf_close(&table);free(buf);return status;
}

/* ---- public API ---- */

static cpk_status build_index(open_state *s, const utf_table *hdr,
                                 entry_list *l, bool *id_based,
                                 uint64_t *align_out, size_t *high)
{
    uint64_t content=0,toc_off=0,toc_size=0,itoc_off=0,itoc_size=0,align=0;
    cpk_status st;
    if(!utf_number(s,hdr,"CPK ",16,"ContentOffset",0,true,
                   CPK_REASON_MISSING_HEADER_COLUMN,&content) ||
       !utf_number(s,hdr,"CPK ",16,"Align",0,true,
                   CPK_REASON_MISSING_HEADER_COLUMN,&align) ||
       !utf_number(s,hdr,"CPK ",16,"TocOffset",0,false,0,&toc_off) ||
       !utf_number(s,hdr,"CPK ",16,"TocSize",0,false,0,&toc_size) ||
       !utf_number(s,hdr,"CPK ",16,"ItocOffset",0,false,0,&itoc_off) ||
       !utf_number(s,hdr,"CPK ",16,"ItocSize",0,false,0,&itoc_size))
        return CPK_BAD_FORMAT;
    if(toc_off==UINT64_MAX) toc_off=0;
    if(itoc_off==UINT64_MAX) itoc_off=0;
    if (!align)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_HEADER_VALUE, "CPK ", "Align", 0,
                    16, 0, 1);
    if (align > UINT32_MAX)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_INTEGER, "CPK ", "Align", 0,
                    16, align, UINT32_MAX);
    if (content > s->file_size)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_ENTRY_RANGE, "CPK ",
                    "ContentOffset", 0, 16, content, s->file_size);
    if (toc_off && !toc_size)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_PACKET_SIZE, "TOC ", "TocSize", 0,
                    16, toc_size, 1);
    if (toc_off && !range_ok(s->file_size, toc_off, toc_size))
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_PACKET_SIZE, "TOC ", "TocSize", 0,
                    toc_off, toc_size, s->file_size);
    if (itoc_off && !itoc_size)
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_PACKET_SIZE, "ITOC", "ItocSize", 0,
                    16, itoc_size, 1);
    if (itoc_off && !range_ok(s->file_size, itoc_off, itoc_size))
        return fail(s, CPK_BAD_FORMAT, CPK_REASON_PACKET_SIZE, "ITOC", "ItocSize", 0,
                    itoc_off, itoc_size, s->file_size);
    *align_out=align;
    if(toc_off) {
        *id_based=false;st=load_toc(s,toc_off,toc_size,content,l);
        if(st==CPK_OK) st=sort_unique(s,l,"TOC ");
        if(st==CPK_OK && itoc_off) st=validate_map(s,itoc_off,itoc_size,l);
        return st;
    }
    if (itoc_off && itoc_size) {
        *id_based = true;
        st = load_itoc(s, itoc_off, itoc_size, l, high);
        if (st != CPK_OK) return st;
        if (s->opts.layout == CPK_LAYOUT_TABLE_ORDER) {
            st = layout_itoc(s, l, content, align);
            if (st == CPK_OK) st = sort_unique(s, l, "ITOC");
        } else {
            st = sort_unique(s, l, "ITOC");
            if (st == CPK_OK) st = layout_itoc(s, l, content, align);
        }
        return st;
    }
    return CPK_NO_INDEX;
}

cpk_status cpk_open_opts(cpk *archive, cpk_read_fn read, void *context,
                              uint64_t file_size, const cpk_open_options *opts)
{
    uint8_t *buf;
    size_t bsize;
    utf_table hdr;
    entry_list list = {0};
    bool id_based = false;
    uint64_t align = 0;
    size_t high = 0;
    cpk_status st;
    cpk_open_options options = {0};
    open_state state = {0};

    if(!archive) return CPK_INVALID_ARG;
    memset(archive, 0, sizeof *archive);
    if(opts) options = *opts;
    if(options.diag) memset(options.diag, 0, sizeof *options.diag);
    if(!read || (options.layout!=CPK_LAYOUT_ID_ORDER &&
                 options.layout!=CPK_LAYOUT_TABLE_ORDER))
        return CPK_INVALID_ARG;

    state.read = read;
    state.ctx = context;
    state.file_size = file_size;
    state.opts = options;
    state.diag = options.diag;

    st = read_packet(&state, 0, "CPK ", file_size, &buf, &bsize);
    if (st != CPK_OK) return st;
    st = utf_open(&state, &hdr, buf, bsize, "CPK ", 16);
    if (st != CPK_OK) {
        free(buf);
        return st;
    }

    if (hdr.nrows != 1)
        st = fail(&state, CPK_BAD_FORMAT, CPK_REASON_ROW_COUNT, "CPK ", NULL, 0,
                  16, hdr.nrows, 1);
    else
        st = build_index(&state, &hdr, &list, &id_based, &align, &high);

    uint64_t declared=0;
    if(st==CPK_OK && !utf_number(&state,&hdr,"CPK ",16,"Files",0,true,
                                 CPK_REASON_MISSING_HEADER_COLUMN,&declared))
        st=CPK_BAD_FORMAT;
    if(st==CPK_OK && declared!=list.n)
        st=fail(&state, CPK_BAD_FORMAT, CPK_REASON_FILES_MISMATCH, "CPK ",
                "Files", 0, 16, declared, list.n);
    if (st == CPK_OK) {
        archive->entries = list.v;
        archive->count = list.n;
        archive->align = (uint32_t)align;
        archive->declared_files = (uint32_t)declared;
        archive->high_files = (uint32_t)high;
        archive->id_based = id_based;
    } else {
        free(list.v);
    }
    utf_close(&hdr);
    free(buf);
    return st;
}

cpk_status cpk_open_ex(cpk *archive, cpk_read_fn read, void *context,
                       uint64_t file_size, cpk_layout layout)
{
    cpk_open_options options = {0};
    options.layout = layout;
    return cpk_open_opts(archive, read, context, file_size, &options);
}

cpk_status cpk_open(cpk *archive, cpk_read_fn read, void *context, uint64_t file_size)
{
    return cpk_open_ex(archive, read, context, file_size, CPK_LAYOUT_ID_ORDER);
}

void cpk_close(cpk *archive)
{
    if(!archive) return;
    free(archive->entries);
    memset(archive, 0, sizeof *archive);
}

const cpk_entry *cpk_find(const cpk *archive, uint32_t id)
{
    if(!archive || (!archive->entries && archive->count) || archive->count>MAX_ENTRIES) return NULL;
    size_t lo = 0, hi = archive->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint32_t v = archive->entries[mid].id;
        if (v == id) return &archive->entries[mid];
        if (v < id) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

const char *cpk_status_name(cpk_status status)
{
    switch (status) {
    case CPK_OK: return "ok";
    case CPK_IO: return "I/O error";
    case CPK_NO_MEMORY: return "out of memory";
    case CPK_BAD_FORMAT: return "bad or unsupported format";
    case CPK_NO_INDEX: return "no TOC or ITOC in archive";
    case CPK_INVALID_ARG: return "invalid argument";
    }
    return "unknown";
}

const char *cpk_reason_name(int reason)
{
    switch (reason) {
    case CPK_REASON_NONE: return "no diagnostic";
    case CPK_REASON_UTF_MAGIC: return "bad @UTF magic";
    case CPK_REASON_UTF_VERSION: return "unsupported @UTF version";
    case CPK_REASON_UTF_LAYOUT: return "invalid @UTF table layout";
    case CPK_REASON_TABLE_NAME: return "invalid @UTF table name";
    case CPK_REASON_COLUMN_FLAGS: return "invalid @UTF column flags";
    case CPK_REASON_COLUMN_TYPE: return "unknown @UTF column type";
    case CPK_REASON_COLUMN_NAME: return "duplicate or unterminated @UTF column name";
    case CPK_REASON_ROW_LENGTH: return "row-length mismatch";
    case CPK_REASON_ROW_COUNT: return "unexpected header row count";
    case CPK_REASON_PACKET_TAG: return "packet tag mismatch";
    case CPK_REASON_PACKET_SIZE: return "packet size inconsistent";
    case CPK_REASON_MISSING_HEADER_COLUMN: return "missing required header column";
    case CPK_REASON_MISSING_TOC_COLUMN: return "missing TOC column";
    case CPK_REASON_INTEGER: return "negative or overflowing integer";
    case CPK_REASON_ENTRY_RANGE: return "entry range outside file";
    case CPK_REASON_DUPLICATE_ID: return "duplicate ID";
    case CPK_REASON_MAP_MISMATCH: return "ITOC map mismatch";
    case CPK_REASON_FILES_MISMATCH: return "Files mismatch";
    case CPK_REASON_LIMIT: return "host limit exceeded";
    case CPK_REASON_HEADER_VALUE: return "invalid header value";
    case CPK_REASON_IO: return "I/O failure";
    }
    return "unknown";
}

size_t cpk_diag_format(const cpk_diag *d, char *buf, size_t n)
{
    if (!d) return 0;
    if (n && !buf) return 0;
    const char *table = d->table ? d->table : "-";
    const char *column = d->column ? d->column : "-";
    int written;
    if (n) {
        written = snprintf(buf, n,
                           "reason %d (%s); table [%s]; column [%s]; index %" PRIu64
                           "; offset %" PRIu64 "; value %" PRIu64 "; expected %" PRIu64,
                           d->reason, cpk_reason_name(d->reason), table, column,
                           d->index, d->offset, d->value, d->expected);
    } else {
        char dummy[1];
        written = snprintf(dummy, 0,
                           "reason %d (%s); table [%s]; column [%s]; index %" PRIu64
                           "; offset %" PRIu64 "; value %" PRIu64 "; expected %" PRIu64,
                           d->reason, cpk_reason_name(d->reason), table, column,
                           d->index, d->offset, d->value, d->expected);
    }
    return written < 0 ? 0 : (size_t)written;
}
