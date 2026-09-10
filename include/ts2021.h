// Tailscale ts2021 control protocol: Noise_IK_25519_ChaChaPoly_BLAKE2s.
//
// Transport-agnostic on purpose: this module never touches a socket, so the
// same object files serve the POSIX test harness and the ESP32 firmware.
// The caller supplies the ephemeral private key, keeping the RNG choice
// (esp_random vs /dev/urandom) out of here.
//
// Wire format (from tailscale/control/controlbase):
//   initiation: [2b version][1b type=1][2b len=96][32b eph pub][48b enc machine pub][16b tag]
//   response:   [1b type=2][2b len=48][32b eph pub][16b tag]
//   transport:  [1b type=4][2b len][ciphertext || 16b tag]
#ifndef TS2021_H
#define TS2021_H

#include <stddef.h>
#include <stdint.h>

#define TS2021_INIT_LEN      101
#define TS2021_RESP_LEN      51
#define TS2021_HEADER_LEN    3
#define TS2021_MAX_FRAME     4096
#define TS2021_MAX_CIPHER    (TS2021_MAX_FRAME - TS2021_HEADER_LEN)
#define TS2021_MAX_PLAINTEXT (TS2021_MAX_CIPHER - 16)

#define TS2021_MSG_INITIATION 1
#define TS2021_MSG_RESPONSE   2
#define TS2021_MSG_ERROR      3
#define TS2021_MSG_RECORD     4

// The control plane's current public key, from
// https://controlplane.tailscale.com/key?v=<capver> ("publicKey", mkey: prefix
// stripped). Pinned here so the device never needs a TLS stack.
#define TS2021_TAILSCALE_CONTROL_KEY \
    "7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b"

// Deliberately not the newest capability version.
//
// At capver 144 a client takes on the job of advertising its own disco key
// in-band, inside the WireGuard tunnel, and the control plane stops handing
// that key - and the node's endpoints - to peers. Claiming to be that new
// while not doing it leaves the node listed in the tailnet and reachable by
// nobody: peers drop its DISCO packets because they have never seen the key.
//
// 142 is the last version before that change. Raise it only together with an
// implementation of the advertisement.
#define TS2021_PROTOCOL_VERSION 142

typedef struct {
    uint8_t  h[32];
    uint8_t  ck[32];
    uint8_t  eph_priv[32];
    uint8_t  machine_priv[32];
    uint8_t  control_pub[32];
} ts2021_handshake;

typedef struct {
    uint8_t  tx_key[32];
    uint8_t  rx_key[32];
    uint64_t tx_nonce;
    uint64_t rx_nonce;
    uint8_t  handshake_hash[32];  // useful for channel binding / debugging
} ts2021_conn;

// Builds the 101-byte initiation message. `eph_priv` must be 32 random bytes;
// it is clamped internally. Returns 0 on success.
int ts2021_handshake_start(ts2021_handshake *hs,
                           const uint8_t machine_priv[32],
                           const uint8_t control_pub[32],
                           uint16_t version,
                           const uint8_t eph_priv[32],
                           uint8_t out_init[TS2021_INIT_LEN]);

// Consumes the 51-byte server response and derives the session keys.
// Returns 0 on success, -1 on a malformed message, -2 if the tag fails
// (wrong control key, tampering, or version mismatch).
int ts2021_handshake_finish(ts2021_handshake *hs,
                            const uint8_t resp[TS2021_RESP_LEN],
                            ts2021_conn *conn);

// Encrypts one record into out (header included). *out_len gets the total
// frame length. Returns 0 on success, -1 if plaintext is too long or the
// output buffer is too small.
int ts2021_seal(ts2021_conn *conn,
                const uint8_t *plaintext, size_t ptlen,
                uint8_t *out, size_t out_cap, size_t *out_len);

// Decrypts one record payload (the bytes *after* the 3-byte header).
// Returns 0 on success, -1 on a size problem, -2 if the tag fails.
int ts2021_open(ts2021_conn *conn,
                const uint8_t *ciphertext, size_t ctlen,
                uint8_t *out, size_t out_cap, size_t *out_len);

// Base64 (standard alphabet, padded) for the X-Tailscale-Handshake header.
// Returns the number of characters written, not counting the NUL.
size_t ts2021_base64(char *out, size_t out_cap, const uint8_t *in, size_t inlen);

// Parses 64 hex characters into 32 bytes. Returns 0 on success.
int ts2021_parse_hex32(uint8_t out[32], const char *hex);

#endif
