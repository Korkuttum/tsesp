// X25519 (RFC 7748). Compact constant-time ladder derived from TweetNaCl,
// which is public domain. Small enough for a no-PSRAM ESP32; a handshake
// costs a few hundred milliseconds at 240 MHz, which is fine at our rates.
#include <string.h>
#include "tscrypto.h"

typedef int64_t gf[16];

static const gf gf121665 = {0xDB41, 1};

static void car25519(gf o) {
    int i;
    int64_t c;
    for (i = 0; i < 16; i++) {
        o[i] += (int64_t)1 << 16;
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t t, c = ~((int64_t)b - 1);
    int i;
    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i]     = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n) {
    int i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void fadd(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void fsub(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

static void fmul(gf o, const gf a, const gf b) {
    int64_t t[31];
    int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void fsq(gf o, const gf a) { fmul(o, a, a); }

static void finv(gf o, const gf i) {
    gf c;
    int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        fsq(c, c);
        if (a != 2 && a != 4) fmul(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

void x25519_clamp(uint8_t sk[32]) {
    sk[0]  &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
}

int x25519(uint8_t out[32], const uint8_t sk[32], const uint8_t pk[32]) {
    uint8_t z[32];
    int64_t x[80];
    gf a, b, c, d, e, f;
    int i;
    int64_t r;

    for (i = 0; i < 31; i++) z[i] = sk[i];
    z[31] = (sk[31] & 127) | 64;
    z[0] &= 248;

    unpack25519(x, pk);
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    for (i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
        fadd(e, a, c);
        fsub(a, a, c);
        fadd(c, b, d);
        fsub(b, b, d);
        fsq(d, e);
        fsq(f, a);
        fmul(a, c, a);
        fmul(c, b, e);
        fadd(e, a, c);
        fsub(a, a, c);
        fsq(b, a);
        fsub(c, d, f);
        fmul(a, c, gf121665);
        fadd(a, a, d);
        fmul(c, c, a);
        fmul(a, d, f);
        fmul(d, b, x);
        fsq(b, e);
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
    }
    for (i = 0; i < 16; i++) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    finv(x + 32, x + 32);
    fmul(x + 16, x + 16, x + 32);
    pack25519(out, x + 16);

    // Reject an all-zero shared secret (low-order point), as Go's
    // curve25519.X25519 does.
    {
        uint8_t zero[32];
        memset(zero, 0, sizeof(zero));
        if (ts_memcmp_ct(out, zero, 32) == 0) return -1;
    }
    return 0;
}

void x25519_base(uint8_t out[32], const uint8_t sk[32]) {
    static const uint8_t basepoint[32] = {9};
    x25519(out, sk, basepoint);
}
