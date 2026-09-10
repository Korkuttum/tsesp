#include <string.h>
#include "poly1305.h"

static uint32_t ld32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void st32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}


void poly1305_init(poly1305_ctx *st, const uint8_t key[32]) {
    st->r[0] = (ld32le(key +  0)     ) & 0x3ffffff;
    st->r[1] = (ld32le(key +  3) >> 2) & 0x3ffff03;
    st->r[2] = (ld32le(key +  6) >> 4) & 0x3ffc0ff;
    st->r[3] = (ld32le(key +  9) >> 6) & 0x3f03fff;
    st->r[4] = (ld32le(key + 12) >> 8) & 0x00fffff;

    memset(st->h, 0, sizeof(st->h));
    st->pad[0] = ld32le(key + 16);
    st->pad[1] = ld32le(key + 20);
    st->pad[2] = ld32le(key + 24);
    st->pad[3] = ld32le(key + 28);
    st->buflen = 0;
}

static void poly1305_blocks(poly1305_ctx *st, const uint8_t *m, size_t bytes, int final) {
    const uint32_t hibit = final ? 0 : (1UL << 24);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];

    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;

        h0 += (ld32le(m +  0)     ) & 0x3ffffff;
        h1 += (ld32le(m +  3) >> 2) & 0x3ffffff;
        h2 += (ld32le(m +  6) >> 4) & 0x3ffffff;
        h3 += (ld32le(m +  9) >> 6) & 0x3ffffff;
        h4 += (ld32le(m + 12) >> 8) | hibit;

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        m += 16;
        bytes -= 16;
    }

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

void poly1305_update(poly1305_ctx *st, const uint8_t *m, size_t bytes) {
    if (st->buflen) {
        size_t want = 16 - st->buflen;
        if (want > bytes) want = bytes;
        memcpy(st->buf + st->buflen, m, want);
        st->buflen += want;
        m += want;
        bytes -= want;
        if (st->buflen < 16) return;
        poly1305_blocks(st, st->buf, 16, 0);
        st->buflen = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~((size_t)15);
        poly1305_blocks(st, m, want, 0);
        m += want;
        bytes -= want;
    }
    if (bytes) {
        memcpy(st->buf, m, bytes);
        st->buflen = bytes;
    }
}

void poly1305_finish(poly1305_ctx *st, uint8_t mac[16]) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    if (st->buflen) {
        size_t i = st->buflen;
        st->buf[i++] = 1;
        for (; i < 16; i++) st->buf[i] = 0;
        poly1305_blocks(st, st->buf, 16, 1);
    }

    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];

    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    mask = (g4 >> 31) - 1;             // all ones when g >= 2^130-5
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    f = (uint64_t)h0 + st->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    st32le(mac +  0, h0);
    st32le(mac +  4, h1);
    st32le(mac +  8, h2);
    st32le(mac + 12, h3);
}

void poly1305_auth(uint8_t mac[POLY1305_TAG], const uint8_t *m, size_t len,
                   const uint8_t key[POLY1305_KEY]) {
    poly1305_ctx st;
    poly1305_init(&st, key);
    poly1305_update(&st, m, len);
    poly1305_finish(&st, mac);
}
