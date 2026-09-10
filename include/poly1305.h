// Poly1305 one-time authenticator (RFC 8439 section 2.5).
//
// Exposed on its own because it is used two different ways here: the RFC 8439
// AEAD construction wraps it with padding and length fields, while NaCl's
// secretbox authenticates the raw ciphertext with no framing at all.
#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>

#define POLY1305_TAG 16
#define POLY1305_KEY 32

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t  buf[16];
    size_t   buflen;
} poly1305_ctx;

void poly1305_init(poly1305_ctx *st, const uint8_t key[POLY1305_KEY]);
void poly1305_update(poly1305_ctx *st, const uint8_t *m, size_t len);
void poly1305_finish(poly1305_ctx *st, uint8_t mac[POLY1305_TAG]);

// One-shot over a single buffer.
void poly1305_auth(uint8_t mac[POLY1305_TAG], const uint8_t *m, size_t len,
                   const uint8_t key[POLY1305_KEY]);

#endif
