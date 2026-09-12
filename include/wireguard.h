// WireGuard, the layer that finally carries data.
//
// Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, which is the same family as the
// ts2021 control channel with a different pattern and its own framing, so
// the primitives are already here. Tailscale runs stock WireGuard with the
// node keys as the static keys and no preshared key.
//
// Messages (all little-endian where numeric):
//   initiation  148B  type=1, sender, 32B eph, 48B enc static, 28B enc
//                     timestamp, 16B mac1, 16B mac2
//   response     92B  type=2, sender, receiver, 32B eph, 16B enc empty,
//                     16B mac1, 16B mac2
//   transport   16B+  type=4, receiver, 8B counter, ciphertext
#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <stddef.h>
#include <stdint.h>

#define WG_MSG_INITIATION 1
#define WG_MSG_RESPONSE   2
#define WG_MSG_COOKIE     3
#define WG_MSG_TRANSPORT  4

#define WG_INITIATION_SIZE 148
#define WG_RESPONSE_SIZE   92
#define WG_TRANSPORT_HEADER 16
#define WG_TAG_LEN         16

#ifndef WG_MAX_PEERS
#define WG_MAX_PEERS 8
#endif
#ifndef WG_MAX_PACKET
#define WG_MAX_PACKET 1420          // leaves room for the outer headers
#endif

// Timers, from the WireGuard paper.
#define WG_REKEY_AFTER_MS   120000
#define WG_REJECT_AFTER_MS  180000
#define WG_REKEY_TIMEOUT_MS   5000
#define WG_KEEPALIVE_MS      10000
// Ceiling on the handshake retry backoff. Each attempt costs two X25519s,
// about 360 ms on this chip, so a peer that is switched off must not be
// retried every five seconds for as long as it stays off.
#define WG_HANDSHAKE_MAX_MS  60000

typedef enum {
    WG_HS_NONE = 0,
    WG_HS_INITIATION_SENT,
    WG_HS_INITIATION_RECEIVED,
    WG_HS_ESTABLISHED
} wg_hs_state;

// The keypair a rekey is replacing.
//
// WireGuard keeps one generation back on purpose. Without it a rekey
// black-holes the tunnel in both directions for a round trip - inbound
// packets carry an index that no longer exists, outbound has no key to use -
// and if the rekey is never answered the session dies although the old keys
// were good for another sixty seconds (REKEY_AFTER is 120 s, REJECT_AFTER
// is 180 s; that gap exists for exactly this).
typedef struct {
    uint8_t  send_key[32], recv_key[32];
    uint64_t send_counter;
    uint64_t recv_highest, recv_window;
    uint32_t local_index, remote_index;
    uint32_t established_ms;
    int      valid;
} wg_keypair;

typedef struct {
    uint8_t  remote_static[32];
    uint8_t  precomputed_ss[32];    // X25519(our static, their static)
    int      in_use;

    // Handshake in flight.
    uint8_t  ck[32], h[32];
    uint8_t  eph_priv[32];
    uint32_t local_index, remote_index;
    uint8_t  state;
    uint32_t handshake_started_ms;

    // Live session.
    uint8_t  send_key[32], recv_key[32];
    uint64_t send_counter;
    uint64_t recv_highest;
    uint64_t recv_window;           // bitmap of the 64 below recv_highest
    uint32_t established_ms;
    int      initiator;

    // Still usable while the next handshake is in flight.
    wg_keypair prev;

    // Initiations sent since the last completed handshake, so retries can
    // back off instead of repeating at a fixed five seconds forever.
    uint32_t hs_attempts;

    uint32_t tx_packets, rx_packets;
    uint32_t last_send_ms, last_recv_ms;
} wg_peer;

typedef struct {
    uint8_t static_priv[32];
    uint8_t static_pub[32];
    uint8_t mac1_key[32];           // BLAKE2s("mac1----" || our public key)
    wg_peer peers[WG_MAX_PEERS];
    uint32_t (*now_ms)(void *ctx);
    void (*random)(void *ctx, uint8_t *out, size_t n);
    // Real seconds since the Unix epoch, for the handshake timestamp. A
    // peer refuses a timestamp older than the last it saw, so a device that
    // reboots with a bad clock cannot re-handshake.
    uint64_t (*unix_time)(void *ctx);
    void *ctx;
} wg_device;

void wg_device_init(wg_device *d, const uint8_t static_priv[32]);

// Returns the peer index, or -1 if the table is full or the key is unusable.
int  wg_add_peer(wg_device *d, const uint8_t remote_static[32]);
int  wg_find_peer(const wg_device *d, const uint8_t remote_static[32]);
void wg_remove_peer(wg_device *d, int idx);

// True when this peer needs a (re)handshake before it can carry traffic.
int  wg_needs_handshake(wg_device *d, int idx);
int  wg_is_established(wg_device *d, int idx);

// Builds a handshake initiation. `out` must hold WG_INITIATION_SIZE bytes.
int  wg_create_initiation(wg_device *d, int idx, uint8_t *out);

// Handles an inbound message.
//   type 1: writes a WG_RESPONSE_SIZE reply into `reply`
//   type 2: completes a handshake we started
//   type 4: decrypts into `plain`
// Returns the peer index on success, or negative on failure. *plain_len and
// *reply_len say which output was produced.
int  wg_handle(wg_device *d, const uint8_t *msg, size_t len,
               uint8_t *plain, size_t plain_cap, size_t *plain_len,
               uint8_t *reply, size_t reply_cap, size_t *reply_len);

// Encrypts one IP packet for a peer. `out` needs len + 32 bytes.
int  wg_encrypt(wg_device *d, int idx, const uint8_t *plain, size_t len,
                uint8_t *out, size_t out_cap, size_t *out_len);

// A zero-length transport message, which is how WireGuard says "still here".
int  wg_keepalive(wg_device *d, int idx, uint8_t *out, size_t out_cap, size_t *out_len);

#endif
