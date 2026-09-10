// ChaCha20-Poly1305 AEAD (RFC 8439). The authenticator itself lives in
// poly1305.c, because NaCl's secretbox needs the same primitive without this
// construction's padding and length framing.
#include <string.h>
#include "tscrypto.h"
#include "poly1305.h"

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
