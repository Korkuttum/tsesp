// Known-answer tests. Portable on purpose: the ESP32 runs exactly these,
// on the CPU that ships, rather than a host-only approximation.
#include <stdio.h>
#include <string.h>
#include "tscrypto.h"
#include "tsesp_selftest.h"

static int fails;

static void hex2bin(const char *hex, uint8_t *out, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void check(const char *name, const uint8_t *got, const char *want_hex, size_t n) {
    uint8_t want[64];
    hex2bin(want_hex, want, n);
    if (memcmp(got, want, n) == 0) {
        printf("  ok   %s\n", name);
    } else {
        size_t i;
        printf("  FAIL %s\n       got  ", name);
        for (i = 0; i < n; i++) printf("%02x", got[i]);
        printf("\n       want %s\n", want_hex);
        fails++;
    }
}

int tsesp_crypto_selftest(void) {
    fails = 0;
    uint8_t out[64];

    printf("BLAKE2s-256 (RFC 7693)\n");
    blake2s(out, 32, "", 0);
    check("empty", out, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", 32);
    blake2s(out, 32, "abc", 3);
    check("abc", out, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", 32);

    printf("X25519 (RFC 7748 sec 6.1)\n");
    {
        uint8_t a[32], b[32], pa[32], pb[32], s1[32], s2[32];
        hex2bin("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a, 32);
        hex2bin("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b, 32);
        x25519_base(pa, a);
        x25519_base(pb, b);
        check("alice pub", pa, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32);
        check("bob pub",   pb, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", 32);
        x25519(s1, a, pb);
        x25519(s2, b, pa);
        check("shared ab", s1, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", 32);
        check("shared ba", s2, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", 32);
    }

    printf("ChaCha20-Poly1305 (RFC 8439 sec 2.8.2)\n");
    {
        const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you "
                         "only one tip for the future, sunscreen would be it.";
        uint8_t key[32], nonce[12], aad[12], ct[256], back[256];
        size_t ptlen = strlen(pt);
        hex2bin("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key, 32);
        hex2bin("070000004041424344454647", nonce, 12);
        hex2bin("50515253c0c1c2c3c4c5c6c7", aad, 12);

        chacha20poly1305_seal(ct, key, nonce, (const uint8_t *)pt, ptlen, aad, 12);
        check("ciphertext head", ct, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6", 32);
        check("tag", ct + ptlen, "1ae10b594f09e26a7e902ecbd0600691", 16);

        if (chacha20poly1305_open(back, key, nonce, ct, ptlen + 16, aad, 12) != 0) {
            printf("  FAIL open rejected a valid tag\n"); fails++;
        } else if (memcmp(back, pt, ptlen) != 0) {
            printf("  FAIL roundtrip mismatch\n"); fails++;
        } else {
            printf("  ok   open roundtrip\n");
        }

        ct[3] ^= 1;
        if (chacha20poly1305_open(back, key, nonce, ct, ptlen + 16, aad, 12) == 0) {
            printf("  FAIL open accepted a corrupted ciphertext\n"); fails++;
        } else {
            printf("  ok   open rejects tampering\n");
        }
    }

    printf("\n%s\n", fails ? "SELFTEST FAILED" : "all crypto self-tests passed");
    return fails;
}
