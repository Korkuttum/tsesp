// BLAKE2s per RFC 7693, plus HMAC/HKDF wrappers for Noise.
#include <string.h>
#include "tscrypto.h"

static const uint32_t blake2s_iv[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0}
};

static uint32_t load32(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32(void *dst, uint32_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)w; p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
}

static uint32_t rotr32(uint32_t w, unsigned c) {
    return (w >> c) | (w << (32 - c));
}

static void blake2s_compress(blake2s_ctx *ctx, const uint8_t block[BLAKE2S_BLOCK], int last) {
    uint32_t m[16], v[16];
    int i;

    for (i = 0; i < 16; i++) m[i] = load32(block + i * 4);
    for (i = 0; i < 8; i++)  v[i] = ctx->h[i];
    for (i = 0; i < 8; i++)  v[i + 8] = blake2s_iv[i];

    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    if (last) v[14] = ~v[14];

#define G(r, i, a, b, c, d)                                  \
    do {                                                     \
        a = a + b + m[blake2s_sigma[r][2 * i + 0]];          \
        d = rotr32(d ^ a, 16);                               \
        c = c + d;                                           \
        b = rotr32(b ^ c, 12);                               \
        a = a + b + m[blake2s_sigma[r][2 * i + 1]];          \
        d = rotr32(d ^ a, 8);                                \
        c = c + d;                                           \
        b = rotr32(b ^ c, 7);                                \
    } while (0)

    for (i = 0; i < 10; i++) {
        G(i, 0, v[0], v[4], v[ 8], v[12]);
        G(i, 1, v[1], v[5], v[ 9], v[13]);
        G(i, 2, v[2], v[6], v[10], v[14]);
        G(i, 3, v[3], v[7], v[11], v[15]);
        G(i, 4, v[0], v[5], v[10], v[15]);
        G(i, 5, v[1], v[6], v[11], v[12]);
        G(i, 6, v[2], v[7], v[ 8], v[13]);
        G(i, 7, v[3], v[4], v[ 9], v[14]);
    }
#undef G

    for (i = 0; i < 8; i++) ctx->h[i] ^= v[i] ^ v[i + 8];
}

void blake2s_init(blake2s_ctx *ctx, size_t outlen) {
    int i;
    memset(ctx, 0, sizeof(*ctx));
    ctx->outlen = outlen;
    for (i = 0; i < 8; i++) ctx->h[i] = blake2s_iv[i];
    // Parameter block: digest_length | key_length(0) | fanout(1) | depth(1)
    ctx->h[0] ^= 0x01010000UL ^ (uint32_t)outlen;
}

void blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen) {
    const uint8_t *p = (const uint8_t *)in;

    while (inlen > 0) {
        // Only compress a full buffer once we know more input follows;
        // the final block must be compressed with the `last` flag set.
        if (ctx->buflen == BLAKE2S_BLOCK) {
            ctx->t[0] += BLAKE2S_BLOCK;
            if (ctx->t[0] < BLAKE2S_BLOCK) ctx->t[1]++;
            blake2s_compress(ctx, ctx->buf, 0);
            ctx->buflen = 0;
        }
        size_t take = BLAKE2S_BLOCK - ctx->buflen;
        if (take > inlen) take = inlen;
        memcpy(ctx->buf + ctx->buflen, p, take);
        ctx->buflen += take;
        p += take;
        inlen -= take;
    }
}

void blake2s_final(blake2s_ctx *ctx, void *out) {
    uint8_t buf[BLAKE2S_OUT];
    size_t i;

    ctx->t[0] += (uint32_t)ctx->buflen;
    if (ctx->t[0] < ctx->buflen) ctx->t[1]++;
    memset(ctx->buf + ctx->buflen, 0, BLAKE2S_BLOCK - ctx->buflen);
    blake2s_compress(ctx, ctx->buf, 1);

    for (i = 0; i < 8; i++) store32(buf + i * 4, ctx->h[i]);
    memcpy(out, buf, ctx->outlen);
}

void blake2s(void *out, size_t outlen, const void *in, size_t inlen) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, outlen);
    blake2s_update(&ctx, in, inlen);
    blake2s_final(&ctx, out);
}

void hmac_blake2s(uint8_t out[BLAKE2S_OUT],
                  const uint8_t *key, size_t keylen,
                  const uint8_t *msg, size_t msglen) {
    uint8_t k[BLAKE2S_BLOCK], pad[BLAKE2S_BLOCK], inner[BLAKE2S_OUT];
    blake2s_ctx ctx;
    size_t i;

    memset(k, 0, sizeof(k));
    if (keylen > BLAKE2S_BLOCK) {
        blake2s(k, BLAKE2S_OUT, key, keylen);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }

    for (i = 0; i < BLAKE2S_BLOCK; i++) pad[i] = k[i] ^ 0x36;
    blake2s_init(&ctx, BLAKE2S_OUT);
    blake2s_update(&ctx, pad, BLAKE2S_BLOCK);
    blake2s_update(&ctx, msg, msglen);
    blake2s_final(&ctx, inner);

    for (i = 0; i < BLAKE2S_BLOCK; i++) pad[i] = k[i] ^ 0x5c;
    blake2s_init(&ctx, BLAKE2S_OUT);
    blake2s_update(&ctx, pad, BLAKE2S_BLOCK);
    blake2s_update(&ctx, inner, BLAKE2S_OUT);
    blake2s_final(&ctx, out);
}

void hkdf_blake2s(uint8_t *out, size_t outlen,
                  const uint8_t *ikm, size_t ikmlen,
                  const uint8_t *salt, size_t saltlen) {
    uint8_t prk[BLAKE2S_OUT], t[BLAKE2S_OUT];
    uint8_t block[BLAKE2S_OUT + 1];
    size_t done = 0, tlen = 0;
    uint8_t counter = 1;

    // Extract: PRK = HMAC(salt, ikm)
    hmac_blake2s(prk, salt, saltlen, ikm, ikmlen);

    // Expand with an empty info string.
    while (done < outlen) {
        size_t n = 0;
        if (tlen) { memcpy(block, t, tlen); n = tlen; }
        block[n++] = counter;
        hmac_blake2s(t, prk, BLAKE2S_OUT, block, n);
        tlen = BLAKE2S_OUT;

        size_t take = outlen - done;
        if (take > BLAKE2S_OUT) take = BLAKE2S_OUT;
        memcpy(out + done, t, take);
        done += take;
        counter++;
    }
}

int ts_memcmp_ct(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++) d |= (uint8_t)(x[i] ^ y[i]);
    return d != 0;
}
