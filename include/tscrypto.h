// Portable crypto primitives for the Tailscale ts2021 control protocol.
// Builds unchanged on POSIX hosts and on ESP32 (ESP-IDF).
#ifndef TSCRYPTO_H
#define TSCRYPTO_H

#include <stddef.h>
#include <stdint.h>

// ---- BLAKE2s (RFC 7693), 256-bit output ----
#define BLAKE2S_OUT   32
#define BLAKE2S_BLOCK 64

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint8_t  buf[BLAKE2S_BLOCK];
    size_t   buflen;
    size_t   outlen;
} blake2s_ctx;

void blake2s_init(blake2s_ctx *ctx, size_t outlen);
// Keyed mode, as MAC. WireGuard's mac1 is a 16-byte keyed BLAKE2s.
void blake2s_init_key(blake2s_ctx *ctx, size_t outlen,
                      const void *key, size_t keylen);
void blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen);
void blake2s_final(blake2s_ctx *ctx, void *out);
void blake2s(void *out, size_t outlen, const void *in, size_t inlen);
void blake2s_keyed(void *out, size_t outlen, const void *key, size_t keylen,
                   const void *in, size_t inlen);

// HMAC-BLAKE2s and HKDF-BLAKE2s (what Noise's MixKey needs).
void hmac_blake2s(uint8_t out[BLAKE2S_OUT],
                  const uint8_t *key, size_t keylen,
                  const uint8_t *msg, size_t msglen);

// HKDF extract-then-expand, matching Go's hkdf.New(blake2s, ikm, salt, nil).
// Writes `outlen` bytes (we never need more than 64).
void hkdf_blake2s(uint8_t *out, size_t outlen,
                  const uint8_t *ikm, size_t ikmlen,
                  const uint8_t *salt, size_t saltlen);

// ---- X25519 ----
#define X25519_LEN 32
void x25519_base(uint8_t out[32], const uint8_t sk[32]);
int  x25519(uint8_t out[32], const uint8_t sk[32], const uint8_t pk[32]);
// Clamp a 32-byte random buffer into a valid Curve25519 private key.
void x25519_clamp(uint8_t sk[32]);

// ---- ChaCha20-Poly1305 AEAD (RFC 8439) ----
#define CHACHA20POLY1305_TAG 16
void chacha20poly1305_seal(uint8_t *out,               // inlen + 16 bytes
                           const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *in, size_t inlen,
                           const uint8_t *ad, size_t adlen);
// Returns 0 on success, -1 if the tag does not verify.
int  chacha20poly1305_open(uint8_t *out,               // inlen - 16 bytes
                           const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *in, size_t inlen,
                           const uint8_t *ad, size_t adlen);

// Constant-time compare. Returns 0 when equal.
int ts_memcmp_ct(const void *a, const void *b, size_t n);

#endif
