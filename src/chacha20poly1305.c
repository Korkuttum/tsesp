// ChaCha20-Poly1305 AEAD (RFC 8439). Poly1305 uses the radix-2^26
// 32-bit representation so it stays fast on the ESP32's 32-bit core.
#include <string.h>
#include "tscrypto.h"

// ---------------- ChaCha20 ----------------

static uint32_t rotl32(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

static uint32_t ld32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void st32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void chacha20_block(uint8_t out[64], const uint8_t key[32],
                           uint32_t counter, const uint8_t nonce[12]) {
    static const char sigma[] = "expand 32-byte k";
    uint32_t s[16], x[16];
    int i;

    s[0] = ld32le((const uint8_t *)sigma + 0);
    s[1] = ld32le((const uint8_t *)sigma + 4);
    s[2] = ld32le((const uint8_t *)sigma + 8);
    s[3] = ld32le((const uint8_t *)sigma + 12);
    for (i = 0; i < 8; i++) s[4 + i] = ld32le(key + i * 4);
    s[12] = counter;
    for (i = 0; i < 3; i++) s[13 + i] = ld32le(nonce + i * 4);

    memcpy(x, s, sizeof(s));

#define QR(a, b, c, d)                                    \
    do {                                                  \
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);      \
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);      \
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);       \
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);       \
    } while (0)

    for (i = 0; i < 10; i++) {
        QR(0, 4,  8, 12); QR(1, 5,  9, 13);
        QR(2, 6, 10, 14); QR(3, 7, 11, 15);
        QR(0, 5, 10, 15); QR(1, 6, 11, 12);
        QR(2, 7,  8, 13); QR(3, 4,  9, 14);
    }
#undef QR

    for (i = 0; i < 16; i++) st32le(out + i * 4, x[i] + s[i]);
}

static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12]) {
    uint8_t block[64];
    size_t i = 0;

    while (i < len) {
        size_t n = len - i;
        size_t j;
        if (n > 64) n = 64;
        chacha20_block(block, key, counter, nonce);
        for (j = 0; j < n; j++) out[i + j] = in[i + j] ^ block[j];
        counter++;
        i += n;
    }
}

// ---------------- Poly1305 ----------------

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t  buf[16];
    size_t   buflen;
} poly1305_ctx;

static void poly1305_init(poly1305_ctx *st, const uint8_t key[32]) {
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

static void poly1305_update(poly1305_ctx *st, const uint8_t *m, size_t bytes) {
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

static void poly1305_finish(poly1305_ctx *st, uint8_t mac[16]) {
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

// ---------------- AEAD ----------------

static void poly1305_pad16(poly1305_ctx *st, size_t len) {
    static const uint8_t zeros[16] = {0};
    size_t rem = len % 16;
    if (rem) poly1305_update(st, zeros, 16 - rem);
}

static void poly1305_len(poly1305_ctx *st, size_t len) {
    uint8_t b[8];
    uint64_t v = (uint64_t)len;
    int i;
    for (i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    poly1305_update(st, b, 8);
}

static void aead_tag(uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *ct, size_t ctlen,
                     const uint8_t *ad, size_t adlen) {
    uint8_t block[64], pkey[32];
    poly1305_ctx st;

    chacha20_block(block, key, 0, nonce);
    memcpy(pkey, block, 32);

    poly1305_init(&st, pkey);
    if (adlen) poly1305_update(&st, ad, adlen);
    poly1305_pad16(&st, adlen);
    if (ctlen) poly1305_update(&st, ct, ctlen);
    poly1305_pad16(&st, ctlen);
    poly1305_len(&st, adlen);
    poly1305_len(&st, ctlen);
    poly1305_finish(&st, tag);
}

void chacha20poly1305_seal(uint8_t *out,
                           const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *in, size_t inlen,
                           const uint8_t *ad, size_t adlen) {
    if (inlen) chacha20_xor(out, in, inlen, key, 1, nonce);
    aead_tag(out + inlen, key, nonce, out, inlen, ad, adlen);
}

int chacha20poly1305_open(uint8_t *out,
                          const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *in, size_t inlen,
                          const uint8_t *ad, size_t adlen) {
    uint8_t tag[16];
    size_t ctlen;

    if (inlen < CHACHA20POLY1305_TAG) return -1;
    ctlen = inlen - CHACHA20POLY1305_TAG;

    aead_tag(tag, key, nonce, in, ctlen, ad, adlen);
    if (ts_memcmp_ct(tag, in + ctlen, CHACHA20POLY1305_TAG) != 0) return -1;

    if (ctlen) chacha20_xor(out, in, ctlen, key, 1, nonce);
    return 0;
}
