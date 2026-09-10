#include <string.h>
#include <stdio.h>
#include "ts2021.h"
#include "tscrypto.h"

static const char kProtocolName[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
static const char kVersionPrefix[] = "Tailscale Control Protocol v";

// ---- Noise symmetric state helpers ----

static void mix_hash(uint8_t h[32], const uint8_t *data, size_t len) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, 32);
    blake2s_update(&ctx, h, 32);
    blake2s_update(&ctx, data, len);
    blake2s_final(&ctx, h);
}

// MixKey(X25519(priv, pub)): folds the DH output into ck and returns the
// single-use key for the next EncryptAndHash/DecryptAndHash.
static int mix_dh(uint8_t ck[32], uint8_t key_out[32],
                  const uint8_t priv[32], const uint8_t pub[32]) {
    uint8_t dh[32], okm[64];
    if (x25519(dh, priv, pub) != 0) return -1;
    hkdf_blake2s(okm, 64, dh, 32, ck, 32);
    memcpy(ck, okm, 32);
    memcpy(key_out, okm + 32, 32);
    memset(dh, 0, sizeof(dh));
    memset(okm, 0, sizeof(okm));
    return 0;
}

// Noise handshake messages always use an all-zero nonce; each key is used once.
static const uint8_t kZeroNonce[12] = {0};

static void encrypt_and_hash(uint8_t h[32], const uint8_t key[32],
                             uint8_t *ct, const uint8_t *pt, size_t ptlen) {
    chacha20poly1305_seal(ct, key, kZeroNonce, pt, ptlen, h, 32);
    mix_hash(h, ct, ptlen + 16);
}

static int decrypt_and_hash(uint8_t h[32], const uint8_t key[32],
                            uint8_t *pt, const uint8_t *ct, size_t ctlen) {
    if (chacha20poly1305_open(pt, key, kZeroNonce, ct, ctlen, h, 32) != 0) return -1;
    mix_hash(h, ct, ctlen);
    return 0;
}

// ---- Handshake ----

int ts2021_handshake_start(ts2021_handshake *hs,
                           const uint8_t machine_priv[32],
                           const uint8_t control_pub[32],
                           uint16_t version,
                           const uint8_t eph_priv[32],
                           uint8_t out_init[TS2021_INIT_LEN]) {
    char prologue[sizeof(kVersionPrefix) + 8];
    uint8_t eph_pub[32], machine_pub[32], key[32];
    int prologue_len;

    memset(hs, 0, sizeof(*hs));
    memcpy(hs->machine_priv, machine_priv, 32);
    memcpy(hs->control_pub, control_pub, 32);
    memcpy(hs->eph_priv, eph_priv, 32);
    x25519_clamp(hs->eph_priv);

    // Initialize(): h = ck = BLAKE2s(protocol_name)
    blake2s(hs->h, 32, kProtocolName, sizeof(kProtocolName) - 1);
    memcpy(hs->ck, hs->h, 32);

    // MixHash(prologue) — binds the cleartext version in the header.
    prologue_len = snprintf(prologue, sizeof(prologue), "%s%u", kVersionPrefix, version);
    if (prologue_len < 0 || (size_t)prologue_len >= sizeof(prologue)) return -1;
    mix_hash(hs->h, (const uint8_t *)prologue, (size_t)prologue_len);

    // <- s   (the responder's static key is known in advance: this is IK)
    mix_hash(hs->h, hs->control_pub, 32);

    // Header: version, type, payload length.
    out_init[0] = (uint8_t)(version >> 8);
    out_init[1] = (uint8_t)(version & 0xff);
    out_init[2] = TS2021_MSG_INITIATION;
    out_init[3] = 0;
    out_init[4] = TS2021_INIT_LEN - 5;   // 96

    // -> e
    x25519_base(eph_pub, hs->eph_priv);
    memcpy(out_init + 5, eph_pub, 32);
    mix_hash(hs->h, eph_pub, 32);

    // es
    if (mix_dh(hs->ck, key, hs->eph_priv, hs->control_pub) != 0) return -1;

    // s (our machine key, encrypted under the es key)
    x25519_base(machine_pub, hs->machine_priv);
    encrypt_and_hash(hs->h, key, out_init + 37, machine_pub, 32);

    // ss
    if (mix_dh(hs->ck, key, hs->machine_priv, hs->control_pub) != 0) return -1;

    // Empty payload, authenticating everything so far.
    encrypt_and_hash(hs->h, key, out_init + 85, NULL, 0);

    memset(key, 0, sizeof(key));
    return 0;
}

int ts2021_handshake_finish(ts2021_handshake *hs,
                            const uint8_t resp[TS2021_RESP_LEN],
                            ts2021_conn *conn) {
    uint8_t control_eph[32], key[32], okm[64];
    uint16_t len;

    if (resp[0] != TS2021_MSG_RESPONSE) return -1;
    len = (uint16_t)((resp[1] << 8) | resp[2]);
    if (len != TS2021_RESP_LEN - TS2021_HEADER_LEN) return -1;

    // <- e
    memcpy(control_eph, resp + 3, 32);
    mix_hash(hs->h, control_eph, 32);

    // ee (result discarded; only ck advances)
    if (mix_dh(hs->ck, key, hs->eph_priv, control_eph) != 0) return -1;

    // se
    if (mix_dh(hs->ck, key, hs->machine_priv, control_eph) != 0) return -1;

    // Empty payload; failure here means the server isn't who we pinned.
    if (decrypt_and_hash(hs->h, key, NULL, resp + 35, 16) != 0) return -2;

    // Split(): two directional keys from the final chaining key.
    memset(conn, 0, sizeof(*conn));
    hkdf_blake2s(okm, 64, NULL, 0, hs->ck, 32);
    memcpy(conn->tx_key, okm, 32);        // c1: initiator -> responder
    memcpy(conn->rx_key, okm + 32, 32);   // c2: responder -> initiator
    memcpy(conn->handshake_hash, hs->h, 32);
    conn->tx_nonce = 0;
    conn->rx_nonce = 0;

    memset(okm, 0, sizeof(okm));
    memset(key, 0, sizeof(key));
    memset(hs->eph_priv, 0, sizeof(hs->eph_priv));
    memset(hs->ck, 0, sizeof(hs->ck));
    return 0;
}

// ---- Transport records ----

static void nonce_from_counter(uint8_t nonce[12], uint64_t counter) {
    int i;
    memset(nonce, 0, 4);
    for (i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(counter >> (56 - 8 * i));
}

int ts2021_seal(ts2021_conn *conn,
                const uint8_t *plaintext, size_t ptlen,
                uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t nonce[12];
    size_t frame_len = TS2021_HEADER_LEN + ptlen + 16;

    if (ptlen > TS2021_MAX_PLAINTEXT) return -1;
    if (out_cap < frame_len) return -1;

    out[0] = TS2021_MSG_RECORD;
    out[1] = (uint8_t)((ptlen + 16) >> 8);
    out[2] = (uint8_t)((ptlen + 16) & 0xff);

    nonce_from_counter(nonce, conn->tx_nonce);
    // The header is deliberately not authenticated — it matches Go's Conn.Write.
    chacha20poly1305_seal(out + TS2021_HEADER_LEN, conn->tx_key, nonce,
                          plaintext, ptlen, NULL, 0);
    conn->tx_nonce++;

    *out_len = frame_len;
    return 0;
}

int ts2021_open(ts2021_conn *conn,
                const uint8_t *ciphertext, size_t ctlen,
                uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t nonce[12];

    if (ctlen < 16 || ctlen > TS2021_MAX_CIPHER) return -1;
    if (out_cap < ctlen - 16) return -1;

    nonce_from_counter(nonce, conn->rx_nonce);
    if (chacha20poly1305_open(out, conn->rx_key, nonce, ciphertext, ctlen, NULL, 0) != 0)
        return -2;
    conn->rx_nonce++;

    *out_len = ctlen - 16;
    return 0;
}

// ---- Small helpers ----

size_t ts2021_base64(char *out, size_t out_cap, const uint8_t *in, size_t inlen) {
    static const char abc[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;

    if (out_cap < ((inlen + 2) / 3) * 4 + 1) return 0;

    while (i + 2 < inlen) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = abc[(v >> 18) & 63];
        out[o++] = abc[(v >> 12) & 63];
        out[o++] = abc[(v >> 6) & 63];
        out[o++] = abc[v & 63];
        i += 3;
    }
    if (i < inlen) {
        uint32_t v = (uint32_t)in[i] << 16;
        int rem = (int)(inlen - i);
        if (rem == 2) v |= (uint32_t)in[i + 1] << 8;
        out[o++] = abc[(v >> 18) & 63];
        out[o++] = abc[(v >> 12) & 63];
        out[o++] = (rem == 2) ? abc[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

int ts2021_parse_hex32(uint8_t out[32], const char *hex) {
    int i;
    for (i = 0; i < 32; i++) {
        int hi, lo;
        char a = hex[2 * i], b = hex[2 * i + 1];
        hi = (a >= '0' && a <= '9') ? a - '0' :
             (a >= 'a' && a <= 'f') ? a - 'a' + 10 :
             (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
        lo = (b >= '0' && b <= '9') ? b - '0' :
             (b >= 'a' && b <= 'f') ? b - 'a' + 10 :
             (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
