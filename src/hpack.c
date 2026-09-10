#include <string.h>
#include "hpack.h"

#define HPACK_ERR_TRUNCATED -1
#define HPACK_ERR_INDEX     -2
#define HPACK_ERR_TOOLONG   -3
#define HPACK_ERR_HUFFMAN   -4

// ---------------------------------------------------------------- integers

// RFC 7541 5.1. `prefix_bits` is the width of the value field in the first
// byte. On entry *pos points at that byte; on exit just past the integer.
static int read_int(const uint8_t *in, size_t inlen, size_t *pos,
                    int prefix_bits, uint64_t *out) {
    uint64_t mask = (1u << prefix_bits) - 1;
    uint64_t value;
    int shift = 0;

    if (*pos >= inlen) return HPACK_ERR_TRUNCATED;
    value = in[*pos] & mask;
    (*pos)++;
    if (value < mask) { *out = value; return 0; }

    for (;;) {
        uint8_t b;
        if (*pos >= inlen) return HPACK_ERR_TRUNCATED;
        b = in[*pos];
        (*pos)++;
        if (shift > 56) return HPACK_ERR_TOOLONG;      // absurd continuation
        value += (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    *out = value;
    return 0;
}

static void write_int(hpack_encoder *e, uint8_t first_byte_flags,
                      int prefix_bits, uint64_t value) {
    uint32_t mask = (1u << prefix_bits) - 1;

    if (e->len >= e->cap) { e->overflow = 1; return; }
    if (value < mask) {
        e->buf[e->len++] = (uint8_t)(first_byte_flags | value);
        return;
    }
    e->buf[e->len++] = (uint8_t)(first_byte_flags | mask);
    value -= mask;
    while (value >= 128) {
        if (e->len >= e->cap) { e->overflow = 1; return; }
        e->buf[e->len++] = (uint8_t)((value & 0x7f) | 0x80);
        value >>= 7;
    }
    if (e->len >= e->cap) { e->overflow = 1; return; }
    e->buf[e->len++] = (uint8_t)value;
}

// ---------------------------------------------------------------- huffman

// Bit-by-bit canonical decode. The generator verified that codes of each
// length are consecutive, which is what makes this loop valid.
static int huff_decode(const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t o = 0;
    uint32_t code = 0;
    int len = 0;
    size_t bit, total = inlen * 8;

    for (bit = 0; bit < total; bit++) {
        code = (code << 1) | ((in[bit >> 3] >> (7 - (bit & 7))) & 1);
        len++;
        if (len > HPACK_HUFF_MAX_BITS) return HPACK_ERR_HUFFMAN;
        if (hpack_huff_count[len] == 0) continue;
        if (code - hpack_huff_first_code[len] < hpack_huff_count[len]) {
            uint16_t sym = hpack_huff_symbol[hpack_huff_first_index[len] +
                                             (code - hpack_huff_first_code[len])];
            if (sym == 256) return HPACK_ERR_HUFFMAN;   // EOS is never encoded
            if (o >= out_cap) return HPACK_ERR_TOOLONG;
            out[o++] = (uint8_t)sym;
            code = 0;
            len = 0;
        }
    }

    // Whatever bits remain must be the EOS prefix: at most 7 bits, all ones.
    if (len > 7) return HPACK_ERR_HUFFMAN;
    if (len > 0 && code != ((1u << len) - 1)) return HPACK_ERR_HUFFMAN;

    *out_len = o;
    return 0;
}

// ---------------------------------------------------------- dynamic table

void hpack_decoder_init(hpack_decoder *d, size_t max_size) {
    memset(d, 0, sizeof(*d));
    if (max_size > HPACK_DYN_ARENA) max_size = HPACK_DYN_ARENA;
    d->max_size = max_size;
    d->limit = max_size;
}

static void dyn_evict_oldest(hpack_decoder *d) {
    hpack_dyn_entry *old;
    size_t freed, i;

    if (d->count == 0) return;
    old = &d->ents[d->count - 1];

    // The oldest entry sits at the bottom of the arena; drop it and slide
    // everything else down so the arena stays contiguous.
    freed = (size_t)old->value_off + old->value_len;
    d->size -= (size_t)old->name_len + old->value_len + 32;
    d->count--;

    if (d->count > 0 && freed < d->arena_used) {
        memmove(d->arena, d->arena + freed, d->arena_used - freed);
    }
    d->arena_used -= freed;
    for (i = 0; i < (size_t)d->count; i++) {
        d->ents[i].name_off  = (uint16_t)(d->ents[i].name_off  - freed);
        d->ents[i].value_off = (uint16_t)(d->ents[i].value_off - freed);
    }
}

static void dyn_set_max(hpack_decoder *d, size_t max_size) {
    if (max_size > d->limit) max_size = d->limit;
    d->max_size = max_size;
    while (d->size > d->max_size) dyn_evict_oldest(d);
}

static void dyn_insert(hpack_decoder *d,
                       const uint8_t *name, size_t name_len,
                       const uint8_t *value, size_t value_len) {
    size_t entry_size = name_len + value_len + 32;
    size_t need = name_len + value_len;

    // RFC 7541 4.4: an entry larger than the table empties it and is dropped.
    if (entry_size > d->max_size) {
        while (d->count) dyn_evict_oldest(d);
        return;
    }
    while (d->size + entry_size > d->max_size ||
           d->count == HPACK_DYN_MAX_ENTRIES ||
           d->arena_used + need > HPACK_DYN_ARENA) {
        if (d->count == 0) return;      // cannot happen, but never loop forever
        dyn_evict_oldest(d);
    }

    memmove(&d->ents[1], &d->ents[0], (size_t)d->count * sizeof(d->ents[0]));
    d->ents[0].name_off  = (uint16_t)d->arena_used;
    d->ents[0].name_len  = (uint16_t)name_len;
    memcpy(d->arena + d->arena_used, name, name_len);
    d->arena_used += name_len;
    d->ents[0].value_off = (uint16_t)d->arena_used;
    d->ents[0].value_len = (uint16_t)value_len;
    memcpy(d->arena + d->arena_used, value, value_len);
    d->arena_used += value_len;
    d->count++;
    d->size += entry_size;
}

// Resolves an HPACK index to a name/value pair. Dynamic entries point into
// the arena; static ones into rodata.
static int table_lookup(hpack_decoder *d, uint64_t idx,
                        const char **name, size_t *name_len,
                        const char **value, size_t *value_len) {
    if (idx == 0) return HPACK_ERR_INDEX;
    if (idx <= HPACK_STATIC_COUNT) {
        const hpack_static_entry *e = &hpack_static_table[idx - 1];
        *name = e->name;
        *name_len = strlen(e->name);
        *value = e->value;
        *value_len = strlen(e->value);
        return 0;
    }
    idx -= HPACK_STATIC_COUNT + 1;
    if (idx >= (uint64_t)d->count) return HPACK_ERR_INDEX;
    {
        hpack_dyn_entry *e = &d->ents[idx];
        *name = (const char *)d->arena + e->name_off;
        *name_len = e->name_len;
        *value = (const char *)d->arena + e->value_off;
        *value_len = e->value_len;
    }
    return 0;
}

// ---------------------------------------------------------------- decoding

// Reads a length-prefixed string into `dst`, un-Huffmanning if needed.
static int read_string(hpack_decoder *d, const uint8_t *in, size_t inlen,
                       size_t *pos, uint8_t *dst, size_t dst_cap, size_t *dst_len) {
    uint64_t slen;
    int huffman, rc;

    if (*pos >= inlen) return HPACK_ERR_TRUNCATED;
    huffman = (in[*pos] & 0x80) != 0;
    rc = read_int(in, inlen, pos, 7, &slen);
    if (rc) return rc;
    if (slen > inlen - *pos) return HPACK_ERR_TRUNCATED;

    if (huffman) {
        rc = huff_decode(in + *pos, (size_t)slen, dst, dst_cap, dst_len);
        if (rc) return rc;
    } else {
        if (slen > dst_cap) return HPACK_ERR_TOOLONG;
        memcpy(dst, in + *pos, (size_t)slen);
        *dst_len = (size_t)slen;
    }
    *pos += (size_t)slen;
    (void)d;
    return 0;
}

// `cb` may be NULL: the block is still decoded, because skipping it would
// desynchronise the dynamic table shared by every stream.
int hpack_decode(hpack_decoder *d, const uint8_t *in, size_t inlen,
                 hpack_header_cb cb, void *ctx) {
    size_t pos = 0;

    while (pos < inlen) {
        uint8_t b = in[pos];

        if (b & 0x80) {
            // 1xxxxxxx: fully indexed.
            uint64_t idx;
            const char *n, *v;
            size_t nl, vl;
            int rc = read_int(in, inlen, &pos, 7, &idx);
            if (rc) return rc;
            rc = table_lookup(d, idx, &n, &nl, &v, &vl);
            if (rc) return rc;
            if (cb) cb(ctx, n, nl, v, vl);
            continue;
        }

        if ((b & 0xe0) == 0x20) {
            // 001xxxxx: dynamic table size update.
            uint64_t sz;
            int rc = read_int(in, inlen, &pos, 5, &sz);
            if (rc) return rc;
            if (sz > d->limit) return HPACK_ERR_INDEX;
            dyn_set_max(d, (size_t)sz);
            continue;
        }

        {
            // 01xxxxxx incremental indexing, 0000xxxx / 0001xxxx literal.
            int indexed = (b & 0xc0) == 0x40;
            int prefix = indexed ? 6 : 4;
            uint64_t idx;
            uint8_t *name_buf = d->scratch;
            uint8_t *value_buf = d->scratch + HPACK_SCRATCH / 2;
            const char *n, *v;
            size_t nl, vl;
            int rc = read_int(in, inlen, &pos, prefix, &idx);
            if (rc) return rc;

            if (idx == 0) {
                rc = read_string(d, in, inlen, &pos, name_buf,
                                 HPACK_SCRATCH / 2, &nl);
                if (rc) return rc;
                n = (const char *)name_buf;
            } else {
                const char *sv;
                size_t svl;
                rc = table_lookup(d, idx, &n, &nl, &sv, &svl);
                if (rc) return rc;
                // Copy out: inserting below can move the arena underneath us.
                if (nl > HPACK_SCRATCH / 2) return HPACK_ERR_TOOLONG;
                memcpy(name_buf, n, nl);
                n = (const char *)name_buf;
            }

            rc = read_string(d, in, inlen, &pos, value_buf,
                             HPACK_SCRATCH - HPACK_SCRATCH / 2, &vl);
            if (rc) return rc;
            v = (const char *)value_buf;

            if (indexed) dyn_insert(d, (const uint8_t *)n, nl, (const uint8_t *)v, vl);
            if (cb) cb(ctx, n, nl, v, vl);
        }
    }
    return 0;
}

// ---------------------------------------------------------------- encoding

void hpack_encoder_init(hpack_encoder *e, uint8_t *buf, size_t cap) {
    e->buf = buf;
    e->cap = cap;
    e->len = 0;
    e->overflow = 0;
}

static void write_raw_string(hpack_encoder *e, const char *s, size_t len) {
    write_int(e, 0x00, 7, len);            // H=0: no Huffman on our side
    if (e->len + len > e->cap) { e->overflow = 1; return; }
    memcpy(e->buf + e->len, s, len);
    e->len += len;
}

void hpack_encode_header(hpack_encoder *e, const char *name, const char *value) {
    size_t nlen = strlen(name), vlen = strlen(value);
    int name_idx = 0;
    int i;

    for (i = 0; i < HPACK_STATIC_COUNT; i++) {
        const hpack_static_entry *se = &hpack_static_table[i];
        if (strlen(se->name) != nlen || memcmp(se->name, name, nlen) != 0) continue;
        if (!name_idx) name_idx = i + 1;
        if (strlen(se->value) == vlen && memcmp(se->value, value, vlen) == 0) {
            write_int(e, 0x80, 7, (uint64_t)(i + 1));   // indexed field
            return;
        }
    }

    // Literal without indexing. We deliberately never grow the peer's
    // dynamic table: our request headers are few and mostly static-named.
    write_int(e, 0x00, 4, (uint64_t)name_idx);
    if (name_idx == 0) write_raw_string(e, name, nlen);
    write_raw_string(e, value, vlen);
}

void hpack_encode_table_size_update(hpack_encoder *e, size_t size) {
    write_int(e, 0x20, 5, (uint64_t)size);
}

int hpack_encoder_finish(hpack_encoder *e, size_t *out_len) {
    if (e->overflow) return -1;
    *out_len = e->len;
    return 0;
}
