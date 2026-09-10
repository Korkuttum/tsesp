#include <string.h>
#include "nacl_box.h"
#include "poly1305.h"
#include "tscrypto.h"

// ------------------------------------------------------------- Salsa20

static uint32_t ld32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void st32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t rotl(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

// 20 rounds over the 16-word state, shared by Salsa20 and HSalsa20. The two
// differ only in what they do afterwards: Salsa20 adds the input state back,
// HSalsa20 does not and takes a different set of words.
static void salsa20_rounds(uint32_t x[16]) {
    int i;
    for (i = 0; i < 10; i++) {
        x[ 4] ^= rotl(x[ 0] + x[12],  7);
        x[ 8] ^= rotl(x[ 4] + x[ 0],  9);
        x[12] ^= rotl(x[ 8] + x[ 4], 13);
        x[ 0] ^= rotl(x[12] + x[ 8], 18);
        x[ 9] ^= rotl(x[ 5] + x[ 1],  7);
        x[13] ^= rotl(x[ 9] + x[ 5],  9);
        x[ 1] ^= rotl(x[13] + x[ 9], 13);
        x[ 5] ^= rotl(x[ 1] + x[13], 18);
        x[14] ^= rotl(x[10] + x[ 6],  7);
        x[ 2] ^= rotl(x[14] + x[10],  9);
        x[ 6] ^= rotl(x[ 2] + x[14], 13);
        x[10] ^= rotl(x[ 6] + x[ 2], 18);
        x[ 3] ^= rotl(x[15] + x[11],  7);
        x[ 7] ^= rotl(x[ 3] + x[15],  9);
        x[11] ^= rotl(x[ 7] + x[ 3], 13);
        x[15] ^= rotl(x[11] + x[ 7], 18);

        x[ 1] ^= rotl(x[ 0] + x[ 3],  7);
        x[ 2] ^= rotl(x[ 1] + x[ 0],  9);
        x[ 3] ^= rotl(x[ 2] + x[ 1], 13);
        x[ 0] ^= rotl(x[ 3] + x[ 2], 18);
        x[ 6] ^= rotl(x[ 5] + x[ 4],  7);
        x[ 7] ^= rotl(x[ 6] + x[ 5],  9);
        x[ 4] ^= rotl(x[ 7] + x[ 6], 13);
        x[ 5] ^= rotl(x[ 4] + x[ 7], 18);
        x[11] ^= rotl(x[10] + x[ 9],  7);
        x[ 8] ^= rotl(x[11] + x[10],  9);
        x[ 9] ^= rotl(x[ 8] + x[11], 13);
        x[10] ^= rotl(x[ 9] + x[ 8], 18);
        x[12] ^= rotl(x[15] + x[14],  7);
        x[13] ^= rotl(x[12] + x[15],  9);
        x[14] ^= rotl(x[13] + x[12], 13);
        x[15] ^= rotl(x[14] + x[13], 18);
    }
}

// "expand 32-byte k", spelled out so it is exactly 16 bytes with no NUL.
static const uint8_t kSigma[16] = {
    'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
};

static void salsa20_state(uint32_t x[16], const uint8_t key[32],
                          const uint8_t nonce8[8], uint64_t counter) {
    x[ 0] = ld32le(kSigma + 0);
    x[ 1] = ld32le(key + 0);
    x[ 2] = ld32le(key + 4);
    x[ 3] = ld32le(key + 8);
    x[ 4] = ld32le(key + 12);
    x[ 5] = ld32le(kSigma + 4);
    x[ 6] = ld32le(nonce8 + 0);
    x[ 7] = ld32le(nonce8 + 4);
    x[ 8] = (uint32_t)(counter & 0xffffffffu);
    x[ 9] = (uint32_t)(counter >> 32);
    x[10] = ld32le(kSigma + 8);
    x[11] = ld32le(key + 16);
    x[12] = ld32le(key + 20);
    x[13] = ld32le(key + 24);
    x[14] = ld32le(key + 28);
    x[15] = ld32le(kSigma + 12);
}

static void salsa20_block(uint8_t out[64], const uint8_t key[32],
                          const uint8_t nonce8[8], uint64_t counter) {
    uint32_t s[16], x[16];
    int i;
    salsa20_state(s, key, nonce8, counter);
    memcpy(x, s, sizeof(s));
    salsa20_rounds(x);
    for (i = 0; i < 16; i++) st32le(out + 4 * i, x[i] + s[i]);
}

void hsalsa20(uint8_t out[32], const uint8_t in[16], const uint8_t key[32]) {
    uint32_t x[16];
    // The 16 input bytes take the place of the nonce and counter words.
    salsa20_state(x, key, in, ld32le(in + 8) | ((uint64_t)ld32le(in + 12) << 32));
    salsa20_rounds(x);
    // No feed-forward: this is what makes HSalsa20 a PRF rather than a stream.
    st32le(out +  0, x[ 0]);
    st32le(out +  4, x[ 5]);
    st32le(out +  8, x[10]);
    st32le(out + 12, x[15]);
    st32le(out + 16, x[ 6]);
    st32le(out + 20, x[ 7]);
    st32le(out + 24, x[ 8]);
    st32le(out + 28, x[ 9]);
}

// ------------------------------------------------------------- secretbox

int nacl_box_beforenm(uint8_t shared[NACL_KEY_LEN],
                      const uint8_t their_pub[32], const uint8_t our_priv[32]) {
    uint8_t dh[32];
    static const uint8_t zero16[16] = {0};

    if (x25519(dh, our_priv, their_pub) != 0) return -1;
    hsalsa20(shared, zero16, dh);
    memset(dh, 0, sizeof(dh));
    return 0;
}

// NaCl reserves the first 32 bytes of the keystream for the Poly1305 key, so
// the message starts at offset 32 of block zero.
static void xsalsa20_xor_and_polykey(uint8_t polykey[32],
                                     uint8_t *out, const uint8_t *in, size_t len,
                                     const uint8_t nonce[NACL_NONCE_LEN],
                                     const uint8_t shared[NACL_KEY_LEN]) {
    uint8_t subkey[32], block[64];
    size_t first, i;
    uint64_t counter = 1;

    hsalsa20(subkey, nonce, shared);
    salsa20_block(block, subkey, nonce + 16, 0);
    memcpy(polykey, block, 32);

    first = len < 32 ? len : 32;
    for (i = 0; i < first; i++) out[i] = in[i] ^ block[32 + i];

    for (i = 32; i < len; i += 64) {
        size_t n = len - i;
        size_t j;
        if (n > 64) n = 64;
        salsa20_block(block, subkey, nonce + 16, counter++);
        for (j = 0; j < n; j++) out[i + j] = in[i + j] ^ block[j];
    }
    memset(subkey, 0, sizeof(subkey));
    memset(block, 0, sizeof(block));
}

void nacl_secretbox(uint8_t *out,
                    const uint8_t *m, size_t mlen,
                    const uint8_t nonce[NACL_NONCE_LEN],
                    const uint8_t shared[NACL_KEY_LEN]) {
    uint8_t polykey[32];
    uint8_t *ct = out + NACL_TAG_LEN;

    xsalsa20_xor_and_polykey(polykey, ct, m, mlen, nonce, shared);
    // Unlike RFC 8439, the tag covers the bare ciphertext: no AAD, no padding,
    // no length suffix.
    poly1305_auth(out, ct, mlen, polykey);
    memset(polykey, 0, sizeof(polykey));
}

int nacl_secretbox_open(uint8_t *out,
                        const uint8_t *c, size_t clen,
                        const uint8_t nonce[NACL_NONCE_LEN],
                        const uint8_t shared[NACL_KEY_LEN]) {
    uint8_t polykey[32], subkey[32], block[64], tag[NACL_TAG_LEN];
    size_t mlen, first, i;
    uint64_t counter = 1;
    static const uint8_t zero[32] = {0};

    if (clen < NACL_TAG_LEN) return -1;
    mlen = clen - NACL_TAG_LEN;

    // Derive the Poly1305 key and verify before writing any plaintext.
    hsalsa20(subkey, nonce, shared);
    salsa20_block(block, subkey, nonce + 16, 0);
    memcpy(polykey, block, 32);
    poly1305_auth(tag, c + NACL_TAG_LEN, mlen, polykey);
    if (ts_memcmp_ct(tag, c, NACL_TAG_LEN) != 0) {
        memset(subkey, 0, sizeof(subkey));
        memset(block, 0, sizeof(block));
        memset(polykey, 0, sizeof(polykey));
        return -1;
    }
    (void)zero;

    first = mlen < 32 ? mlen : 32;
    for (i = 0; i < first; i++) out[i] = c[NACL_TAG_LEN + i] ^ block[32 + i];
    for (i = 32; i < mlen; i += 64) {
        size_t n = mlen - i;
        size_t j;
        if (n > 64) n = 64;
        salsa20_block(block, subkey, nonce + 16, counter++);
        for (j = 0; j < n; j++) out[i + j] = c[NACL_TAG_LEN + i + j] ^ block[j];
    }
    memset(subkey, 0, sizeof(subkey));
    memset(block, 0, sizeof(block));
    memset(polykey, 0, sizeof(polykey));
    return 0;
}
