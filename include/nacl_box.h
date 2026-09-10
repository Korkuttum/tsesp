// NaCl crypto_box: Curve25519 + XSalsa20-Poly1305.
//
// Tailscale's DISCO messages are sealed with exactly this, so we need it
// alongside the ChaCha20-Poly1305 used everywhere else. Note the differences
// from the RFC 8439 AEAD: a 24-byte nonce, and the tag comes *before* the
// ciphertext rather than after it.
#ifndef NACL_BOX_H
#define NACL_BOX_H

#include <stddef.h>
#include <stdint.h>

#define NACL_NONCE_LEN 24
#define NACL_TAG_LEN   16
#define NACL_KEY_LEN   32

// HSalsa20 core, exposed for testing.
void hsalsa20(uint8_t out[32], const uint8_t in[16], const uint8_t key[32]);

// Precomputes the shared key for a key pair. Returns 0, or -1 if the DH
// produced an all-zero secret (a low-order peer key).
int nacl_box_beforenm(uint8_t shared[NACL_KEY_LEN],
                      const uint8_t their_pub[32], const uint8_t our_priv[32]);

// Seals `mlen` bytes into `out`, which must have room for mlen + 16:
// the 16-byte tag followed by the ciphertext.
void nacl_secretbox(uint8_t *out,
                    const uint8_t *m, size_t mlen,
                    const uint8_t nonce[NACL_NONCE_LEN],
                    const uint8_t shared[NACL_KEY_LEN]);

// Opens a sealed message. `clen` counts the tag, so `out` needs clen - 16
// bytes. Returns 0 on success, -1 if the tag does not verify.
// Safe to call with out == in + 16 for in-place decryption.
int nacl_secretbox_open(uint8_t *out,
                        const uint8_t *c, size_t clen,
                        const uint8_t nonce[NACL_NONCE_LEN],
                        const uint8_t shared[NACL_KEY_LEN]);

#endif
