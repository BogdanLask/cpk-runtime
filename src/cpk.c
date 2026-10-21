// SPDX-License-Identifier: MIT
#include "cpkrt/cpk.h"
#include <stdlib.h>
#include <string.h>

#define MAX_TABLE_BYTES UINT64_C(16777216)
#define MAX_ENTRIES ((size_t)262144)
#define UTF_NO_NAME UINT32_MAX

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
static cpk_status utf_open(utf_table *t, uint8_t *buf, size_t size)
{
    memset(t, 0, sizeof *t);
    if (!buf || size < 32) return CPK_BAD_FORMAT;
    if (memcmp(buf, "@UTF", 4) != 0) {
        utf_decrypt(buf, size);
        if (memcmp(buf, "@UTF", 4) != 0) return CPK_BAD_FORMAT;
    }

    if(be16(buf+8)!=0) return CPK_BAD_FORMAT;
    uint64_t total = (uint64_t)be32(buf + 4) + 8;
    if (total < 32 || total > size) return CPK_BAD_FORMAT;
    size = (size_t)total;

    /* Bytes 8-9 are a version field; the rows offset is the u16 after it. */
    uint64_t rows = (uint64_t)be16(buf + 10) + 8;
    uint64_t str = (uint64_t)be32(buf + 12) + 8;
    uint64_t data = (uint64_t)be32(buf + 16) + 8;
    uint16_t ncols = be16(buf + 24);
    uint32_t row_len = be16(buf + 26);
    uint32_t nrows = be32(buf + 28);
    if(rows<32 || rows>str || str>data || data>size || !ncols || nrows>MAX_ENTRIES) return CPK_BAD_FORMAT;
    if((uint64_t)nrows*row_len>str-rows) return CPK_BAD_FORMAT;
    uint64_t table_name=(uint64_t)be32(buf+20)+str;
    if(table_name>=data || !memchr(buf+(size_t)table_name,0,(size_t)(data-table_name))) return CPK_BAD_FORMAT;

    utf_col *cols = calloc(ncols ? ncols : 1, sizeof *cols);
    if (!cols) return CPK_NO_MEMORY;

    size_t pos = 32, row_cursor = 0;
    for (uint16_t i = 0; i < ncols; i++) {
        utf_col *c = &cols[i];
        if (pos + 1 > rows) goto bad;
        c->flags = buf[pos++];
        if((c->flags>>4)!=1 && (c->flags>>4)!=3 && (c->flags>>4)!=5) goto bad;
        if ((c->flags & COL_CONST) && (c->flags & COL_ROW)) goto bad;
        size_t vsz = type_size(c->flags & 0x0F);
        if (!vsz) goto bad;

        c->name_off = UTF_NO_NAME;
        if (c->flags & COL_NAME) {
            if (pos + 4 > rows) goto bad;
            c->name_off = be32(buf + pos);
            pos += 4;
            uint64_t name=str+c->name_off;
            if(name>=data || !memchr(buf+(size_t)name,0,(size_t)(data-name))) goto bad;
            for(uint16_t j=0;j<i;j++) {
                const uint8_t *a=buf+(size_t)name,*b=buf+(size_t)(str+cols[j].name_off);
                size_t k=0;while(a[k] && b[k] && lower(a[k])==lower(b[k])) k++;
                if(!a[k] && !b[k]) goto bad;
            }
        }
        if (c->flags & COL_CONST) {
            if (pos + vsz > rows) goto bad;
            c->value_off = pos;
            pos += vsz;
        } else if (c->flags & COL_ROW) {
            c->value_off = row_cursor;
            row_cursor += vsz;
        }
    }
    if(row_cursor!=row_len || pos>rows) goto bad;

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
static bool utf_col_u64(const utf_table *t, const utf_col *c, uint32_t row, uint64_t *out)
{
    uint32_t type = c->flags & 0x0F;
    const uint8_t *p;
    if(type>T_S64 || !utf_value_ptr(t,c,row,&p)) return false;
    if (!p) { *out = 0; return true; }
    switch (type) {
    case T_U8: case T_S8: *out = p[0]; break;
    case T_U16: case T_S16: *out = be16(p); break;
    case T_U32: case T_S32: *out = be32(p); break;
    default: *out = be64(p); break;
    }
    if ((type & 1u) && (*out >> (type_size(type) * 8u - 1u))) return false;
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

static bool utf_number(const utf_table *t,const char *name,uint64_t fallback,bool required,uint64_t *out)
{
    const utf_col *column=utf_find_col(t,name);
    if(!column) {if(required) return false;*out=fallback;return true;}
    return utf_col_u64(t,column,0,out);
}

/* ---- packets ---- */

/* A packet is: 4-byte tag, 12 more header bytes, then one @UTF table. The
 * table length comes from the @UTF header itself, not from the packet header,
 * so only the first 8 table bytes are inspected (and decrypted, if needed). */
static cpk_status read_packet(cpk_read_fn read, void *ctx, uint64_t file_size,
                                 uint64_t offset, const char *tag, uint64_t packet_extent,
                                 uint8_t **out, size_t *out_size)
{
    uint8_t head[24];
    *out = NULL;
    *out_size = 0;
    if(packet_extent<sizeof head || !range_ok(file_size,offset,packet_extent) || !range_ok(file_size, offset, sizeof head)) return CPK_BAD_FORMAT;
    if (!read(ctx, offset, head, sizeof head)) return CPK_IO;
    if (memcmp(head, tag, 4) != 0) return CPK_BAD_FORMAT;

    uint8_t *pre = head + 16;
    if (memcmp(pre, "@UTF", 4) != 0) utf_decrypt(pre, 8);
    if (memcmp(pre, "@UTF", 4) != 0) return CPK_BAD_FORMAT;

    uint64_t total = (uint64_t)be32(pre + 4) + 8;
    if (total < 32 || total > MAX_TABLE_BYTES || !range_ok(file_size, offset + 16, total))
        return CPK_BAD_FORMAT;

    uint64_t packet_size=le64(head+8);
    if(packet_size<total || packet_size>packet_extent-16u || packet_size>MAX_TABLE_BYTES || !range_ok(file_size,offset+16,packet_size)) return CPK_BAD_FORMAT;
    uint8_t *buf = malloc((size_t)total);
    if (!buf) return CPK_NO_MEMORY;
    if (!read(ctx, offset + 16, buf, (size_t)total)) {
        free(buf);
        return CPK_IO;
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

static cpk_status list_push(entry_list *l, uint64_t id, uint64_t stored, uint64_t extract)
{
    if (id > UINT32_MAX || stored > UINT32_MAX || extract > UINT32_MAX) return CPK_BAD_FORMAT;
    if (l->n >= MAX_ENTRIES) return CPK_BAD_FORMAT;
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

static int32_t cmp_entry(const void *a, const void *b)
{
    uint32_t x = ((const cpk_entry *)a)->id, y = ((const cpk_entry *)b)->id;
    return (x > y) - (x < y);
}

static cpk_status sort_unique(entry_list *l)
{
    if (l->n > 1) qsort(l->v, l->n, sizeof *l->v, cmp_entry);
    for (size_t i = 1; i < l->n; i++)
        if (l->v[i].id == l->v[i - 1].id) return CPK_BAD_FORMAT;
    return CPK_OK;
}

/* ---- ITOC (ID based, offsets implicit) ---- */

static cpk_status load_itoc_part(const utf_table *t, const char *name, entry_list *l)
{
    const utf_col *c = utf_find_col(t, name);
    uint8_t *blob;
    size_t blen;
    if (!c) return CPK_OK;
    if (t->nrows < 1 || !utf_col_blob(t, c, 0, &blob, &blen)) return CPK_BAD_FORMAT;
    if (blen == 0) return CPK_OK;

    utf_table sub;
    cpk_status st = utf_open(&sub, blob, blen);
    if (st != CPK_OK) return st;

    const utf_col *id = utf_find_col(&sub, "ID");
    const utf_col *size = utf_find_col(&sub, "FileSize");
    const utf_col *extract = utf_find_col(&sub, "ExtractSize");
    if (!id || !size) st = CPK_BAD_FORMAT;
    for (uint32_t r = 0; st == CPK_OK && r < sub.nrows; r++) {
        uint64_t vid, vsize, vextract;
        if (!utf_col_u64(&sub, id, r, &vid) || !utf_col_u64(&sub, size, r, &vsize)) {
            st = CPK_BAD_FORMAT;
            break;
        }
        vextract = vsize;
        if (extract && !utf_col_u64(&sub, extract, r, &vextract)) {
            st = CPK_BAD_FORMAT;
            break;
        }
        st = list_push(l, vid, vsize, vextract);
    }
    utf_close(&sub);
    return st;
}

/* Rows are appended DataH first, then DataL, matching the index order.
 * *high receives the number of DataH rows. */
static cpk_status load_itoc(cpk_read_fn read, void *ctx, uint64_t file_size,
                               uint64_t offset, uint64_t extent, entry_list *l, size_t *high)
{
    static const char *const parts[2] = {"DataH", "DataL"};
    uint8_t *buf;
    size_t bsize;
    utf_table t;
    cpk_status st = read_packet(read, ctx, file_size, offset, "ITOC", extent, &buf, &bsize);
    if (st != CPK_OK) return st;
    st = utf_open(&t, buf, bsize);
    if (st != CPK_OK) {
        free(buf);
        return st;
    }
    for (uint32_t k = 0; k < 2 && st == CPK_OK; k++) {
        st = load_itoc_part(&t, parts[k], l);
        if (k == 0) *high = l->n;
    }
    utf_close(&t);
    free(buf);
    return st;
}

/* Files are stored back to back in the list's current order, each padded up to
 * Align; the first one starts at ContentOffset rounded up to Align. */
static cpk_status layout_itoc(entry_list *l, uint64_t content, uint64_t align, uint64_t file_size)
{
    if (content > file_size) return CPK_BAD_FORMAT;
    uint64_t pos=0;if(!align_up(content,align,&pos)) return CPK_BAD_FORMAT;
    for (size_t i = 0; i < l->n; i++) {
        cpk_entry *e = &l->v[i];
        if (!range_ok(file_size, pos, e->stored_size)) return CPK_BAD_FORMAT;
        e->offset = pos;
        if(i+1<l->n) {
            uint64_t step=0;
            if(!align_up(e->stored_size,align,&step) || step>UINT64_MAX-pos) return CPK_BAD_FORMAT;
            pos+=step;
        }
    }
    return CPK_OK;
}

/* ---- TOC (name based; ID column required) ---- */

static cpk_status load_toc(cpk_read_fn read, void *ctx, uint64_t file_size,
                              uint64_t offset, uint64_t extent, uint64_t content, entry_list *l)
{
    uint8_t *buf;
    size_t bsize;
    utf_table t;
    cpk_status st = read_packet(read, ctx, file_size, offset, "TOC ", extent, &buf, &bsize);
    if (st != CPK_OK) return st;
    st = utf_open(&t, buf, bsize);
    if (st != CPK_OK) {
        free(buf);
        return st;
    }

    const utf_col *foff = utf_find_col(&t, "FileOffset");
    const utf_col *size = utf_find_col(&t, "FileSize");
    const utf_col *extract = utf_find_col(&t, "ExtractSize");
    const utf_col *id = utf_find_col(&t, "ID");
    if(!foff || !size || !id) st=CPK_BAD_FORMAT;

    /* TOC offsets are relative to whichever of TOC/content comes first. */
    uint64_t base = content < offset ? content : offset;
    for (uint32_t r = 0; st == CPK_OK && r < t.nrows; r++) {
        uint64_t voff, vsize, vextract, vid = r;
        if (!utf_col_u64(&t, foff, r, &voff) || !utf_col_u64(&t, size, r, &vsize)) {
            st = CPK_BAD_FORMAT;
            break;
        }
        vextract = vsize;
        if ((extract && !utf_col_u64(&t, extract, r, &vextract)) ||
            !utf_col_u64(&t,id,r,&vid) || voff>UINT64_MAX-base) {
            st = CPK_BAD_FORMAT;
            break;
        }
        st = list_push(l, vid, vsize, vextract);
        if (st != CPK_OK) break;
        cpk_entry *e = &l->v[l->n - 1];
        e->offset = base + voff;
        if (!range_ok(file_size, e->offset, e->stored_size)) st = CPK_BAD_FORMAT;
    }
    utf_close(&t);
    free(buf);
    return st;
}

/* Observed extended ITOC maps IDs to TOC rows; it does not supply sizes.
 * Entries are already ID-sorted, with original TOC row in table_order. */
static cpk_status validate_map(cpk_read_fn read,void *ctx,uint64_t file_size,uint64_t offset,uint64_t extent,const entry_list *list)
{
    uint8_t *buf=NULL;size_t size=0;utf_table table={0};
    cpk_status status=read_packet(read,ctx,file_size,offset,"ITOC",extent,&buf,&size);
    if(status!=CPK_OK) return status;
    status=utf_open(&table,buf,size);
    if(status!=CPK_OK) {free(buf);return status;}
    const utf_col *id=utf_find_col(&table,"ID"),*index=utf_find_col(&table,"TocIndex");
    if(!id || !index || table.nrows!=list->n) status=CPK_BAD_FORMAT;
    uint8_t *seen=NULL;
    if(status==CPK_OK && list->n) {seen=calloc(list->n,1);if(!seen) status=CPK_NO_MEMORY;}
    cpk sorted={0};sorted.entries=list->v;sorted.count=list->n;
    for(uint32_t row=0;status==CPK_OK && row<table.nrows;row++) {
        uint64_t identity=0,to=0;
        if(!utf_col_u64(&table,id,row,&identity) || !utf_col_u64(&table,index,row,&to) || identity>UINT32_MAX || to>=list->n) {
            status=CPK_BAD_FORMAT;break;
        }
        const cpk_entry *entry=cpk_find(&sorted,(uint32_t)identity);
        if(!entry || entry->table_order!=to || seen[(size_t)to]) {status=CPK_BAD_FORMAT;break;}
        seen[(size_t)to]=1;
    }
    free(seen);utf_close(&table);free(buf);return status;
}

/* ---- public API ---- */

static cpk_status build_index(const utf_table *hdr, cpk_read_fn read, void *ctx,
                                 uint64_t file_size, cpk_layout layout, entry_list *l,
                                 bool *id_based, uint64_t *align_out, size_t *high)
{
    uint64_t content=0,toc_off=0,toc_size=0,itoc_off=0,itoc_size=0,align=0;
    cpk_status st;
    if(!utf_number(hdr,"ContentOffset",0,true,&content) || !utf_number(hdr,"Align",0,true,&align) ||
       !utf_number(hdr,"TocOffset",0,false,&toc_off) || !utf_number(hdr,"TocSize",0,false,&toc_size) ||
       !utf_number(hdr,"ItocOffset",0,false,&itoc_off) || !utf_number(hdr,"ItocSize",0,false,&itoc_size)) return CPK_BAD_FORMAT;
    if(toc_off==UINT64_MAX) toc_off=0;
    if(itoc_off==UINT64_MAX) itoc_off=0;
    if(!align || align>UINT32_MAX || content>file_size ||
       (toc_off && (!toc_size || !range_ok(file_size,toc_off,toc_size))) ||
       (itoc_off && (!itoc_size || !range_ok(file_size,itoc_off,itoc_size)))) return CPK_BAD_FORMAT;
    *align_out=align;
    if(toc_off) {
        *id_based=false;st=load_toc(read,ctx,file_size,toc_off,toc_size,content,l);
        if(st==CPK_OK) st=sort_unique(l);
        if(st==CPK_OK && itoc_off) st=validate_map(read,ctx,file_size,itoc_off,itoc_size,l);
        return st;
    }
    if (itoc_off && itoc_size) {
        *id_based = true;
        st = load_itoc(read, ctx, file_size, itoc_off, itoc_size, l, high);
        if (st != CPK_OK) return st;
        if (layout == CPK_LAYOUT_TABLE_ORDER) {
            st = layout_itoc(l, content, align, file_size);
            if (st == CPK_OK) st = sort_unique(l);
        } else {
            st = sort_unique(l);
            if (st == CPK_OK) st = layout_itoc(l, content, align, file_size);
        }
        return st;
    }
    return CPK_NO_INDEX;
}

cpk_status cpk_open_ex(cpk *archive, cpk_read_fn read, void *context,
                             uint64_t file_size, cpk_layout layout)
{
    uint8_t *buf;
    size_t bsize;
    utf_table hdr;
    entry_list list = {0};
    bool id_based = false;
    uint64_t align = 0;
    size_t high = 0;
    cpk_status st;

    if(!archive || !read || archive->entries || archive->count || archive->align ||
       archive->declared_files || archive->high_files || archive->id_based ||
       (layout!=CPK_LAYOUT_ID_ORDER && layout!=CPK_LAYOUT_TABLE_ORDER)) return CPK_BAD_FORMAT;

    st = read_packet(read, context, file_size, 0, "CPK ", file_size, &buf, &bsize);
    if (st != CPK_OK) return st;
    st = utf_open(&hdr, buf, bsize);
    if (st != CPK_OK) {
        free(buf);
        return st;
    }

    if (hdr.nrows != 1) st = CPK_BAD_FORMAT;
    else st = build_index(&hdr, read, context, file_size, layout, &list, &id_based, &align, &high);

    uint64_t declared=0;
    if(st==CPK_OK && (!utf_number(&hdr,"Files",0,true,&declared) || declared!=list.n)) st=CPK_BAD_FORMAT;
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
    }
    return "unknown";
}
