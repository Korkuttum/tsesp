// Tailscale's DISCO messages: how two nodes find a direct path to each other.
//
// A DISCO packet rides the same UDP socket as WireGuard traffic and is told
// apart by its 6-byte magic. On the wire:
//
//   magic            [6]  "TS<speech balloon>"  54 53 f0 9f 92 ac
//   sender disco pub [32]
//   nonce            [24]
//   nacl box         [..] sealed with the shared disco key
//
// and inside the box:
//
//   type    [1]
//   version [1]  (0; always ignore trailing bytes for forward compatibility)
//   payload [..]
#ifndef DISCO_H
#define DISCO_H

#include <stddef.h>
#include <stdint.h>
#include "nacl_box.h"

#define DISCO_MAGIC_LEN  6
#define DISCO_KEY_LEN    32
#define DISCO_HEADER_LEN (DISCO_MAGIC_LEN + DISCO_KEY_LEN + NACL_NONCE_LEN)
#define DISCO_TXID_LEN   12

#define DISCO_PING          0x01
#define DISCO_PONG          0x02
#define DISCO_CALL_ME_MAYBE 0x03

// Endpoints on the wire are always 16-byte addresses; IPv4 appears v4-mapped.
#define DISCO_EP_LEN 18
#ifndef DISCO_MAX_ENDPOINTS
#define DISCO_MAX_ENDPOINTS 8
#endif
#ifndef DISCO_MAX_INNER
#define DISCO_MAX_INNER 256
#endif

extern const uint8_t disco_magic[DISCO_MAGIC_LEN];

typedef struct {
    uint8_t  type;
    uint8_t  version;

    uint8_t  txid[DISCO_TXID_LEN];      // ping, pong
    uint8_t  node_key[32];              // ping, when the sender included one
    int      has_node_key;
    int      padding;                   // ping: trailing zero bytes, for MTU probing

    uint8_t  src_ip[16];                // pong: where the pinger appeared from
    uint16_t src_port;

    uint8_t  ep_ip[DISCO_MAX_ENDPOINTS][16];   // call-me-maybe
    uint16_t ep_port[DISCO_MAX_ENDPOINTS];
    int      nendpoints;
    int      dropped_endpoints;
} disco_msg;

// Writes ::ffff:a.b.c.d into out, the form IPv4 takes on the DISCO wire.
void disco_ipv4_mapped(uint8_t out[16], const uint8_t v4[4]);
// True if addr is a v4-mapped address; copies the four bytes out when it is.
int  disco_is_ipv4_mapped(const uint8_t addr[16], uint8_t v4[4]);

// --- building inner messages ---
int disco_build_ping(uint8_t *out, size_t cap, size_t *len,
                     const uint8_t txid[DISCO_TXID_LEN],
                     const uint8_t node_pub[32],   // may be NULL
                     size_t padding);
int disco_build_pong(uint8_t *out, size_t cap, size_t *len,
                     const uint8_t txid[DISCO_TXID_LEN],
                     const uint8_t src_ip[16], uint16_t src_port);
int disco_build_call_me_maybe(uint8_t *out, size_t cap, size_t *len,
                              const uint8_t ep_ip[][16], const uint16_t *ep_port,
                              int n);

// --- sealing and opening whole packets ---

// Wraps and seals `inner` into a complete datagram.
int disco_seal(uint8_t *out, size_t cap, size_t *len,
               const uint8_t our_disco_pub[32],
               const uint8_t shared[NACL_KEY_LEN],
               const uint8_t nonce[NACL_NONCE_LEN],
               const uint8_t *inner, size_t inner_len);

int disco_looks_like_disco(const uint8_t *pkt, size_t len);
// Returns a pointer to the sender's disco public key, or NULL.
const uint8_t *disco_sender_key(const uint8_t *pkt, size_t len);

// Opens and parses a datagram. Returns 0, -1 if malformed, -2 if the box does
// not authenticate, -3 if the message type is unknown.
int disco_open(const uint8_t *pkt, size_t len,
               const uint8_t shared[NACL_KEY_LEN], disco_msg *out);

#endif
