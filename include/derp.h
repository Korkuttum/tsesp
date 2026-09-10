// DERP: Tailscale's relay, and the reason a node exists as far as its peers
// are concerned.
//
// It carries packets when no direct path works, but it does more than that:
// the control plane will not hand a node's disco key or endpoints to anyone
// until that node is present on a DERP server. Without this a device is
// listed in the tailnet and reachable by nobody.
//
// Wire format, all frames being [1B type][4B big-endian length][payload]:
//
//   server -> FrameServerKey  (0x01)  8B "DERP<key emoji>" + 32B server key
//   client -> FrameClientInfo (0x02)  32B our key + 24B nonce + naclbox(json)
//   server -> FrameServerInfo (0x03)  24B nonce + naclbox(json)
//   client -> FrameSendPacket (0x04)  32B destination node key + packet
//   server -> FrameRecvPacket (0x05)  32B source node key + packet
//
// Transport-agnostic like everything else here: the caller supplies a ts_io,
// which on the device is a TLS stream and in the tests is OpenSSL.
#ifndef DERP_H
#define DERP_H

#include <stddef.h>
#include <stdint.h>
#include "ts_io.h"

#define DERP_KEY_LEN      32
#define DERP_MAGIC_LEN    8
#define DERP_FRAME_HEADER 5
#define DERP_NONCE_LEN    24
#define DERP_PROTOCOL_VERSION 2

#define DERP_FRAME_SERVER_KEY     0x01
#define DERP_FRAME_CLIENT_INFO    0x02
#define DERP_FRAME_SERVER_INFO    0x03
#define DERP_FRAME_SEND_PACKET    0x04
#define DERP_FRAME_RECV_PACKET    0x05
#define DERP_FRAME_KEEPALIVE      0x06
#define DERP_FRAME_NOTE_PREFERRED 0x07
#define DERP_FRAME_PEER_GONE      0x08
#define DERP_FRAME_PEER_PRESENT   0x09
#define DERP_FRAME_PING           0x12
#define DERP_FRAME_PONG           0x13
#define DERP_FRAME_HEALTH         0x14
#define DERP_FRAME_RESTARTING     0x15

// Frames larger than this are skipped rather than buffered. Real relayed
// packets are one MTU; anything huge is not for us.
#ifndef DERP_MAX_FRAME
#define DERP_MAX_FRAME 1600
#endif

typedef struct {
    ts_io  *io;
    uint8_t server_key[DERP_KEY_LEN];
    uint8_t shared[32];              // naclbox key shared with the server
    uint8_t node_priv[32];
    uint8_t node_pub[32];
    int     server_version;
    int     ready;

    // Counters worth showing on a status page.
    uint32_t sent, received, keepalives, pings, peer_gone;
} derp_conn;

// Everything the caller must supply to reach a relay.
typedef struct {
    const char *host;        // e.g. "derp4h.tailscale.com"
    const uint8_t *node_priv;
    const uint8_t *node_pub;
    // Whether to tell the server this is our home relay. The control plane
    // watches this to decide our HomeDERP.
    int preferred;
} derp_opts;

// Performs the HTTP upgrade and the key exchange on an already-connected
// (and, in production, already-TLS-wrapped) stream.
// Returns 0, -1 on I/O trouble, -2 if the greeting is wrong, -3 if the
// server's reply does not authenticate.
int derp_connect(derp_conn *c, ts_io *io, const derp_opts *opts);

// Relays one packet to a peer, addressed by its node key.
int derp_send(derp_conn *c, const uint8_t dst_node_pub[32],
              const uint8_t *pkt, size_t len);

// Reads the next relayed packet, answering pings and keepalives on the way.
// Returns 1 with a packet, 0 if the frame was housekeeping (call again),
// -1 on error.
int derp_recv(derp_conn *c, uint8_t src_node_pub[32],
              uint8_t *buf, size_t cap, size_t *len);

int derp_note_preferred(derp_conn *c, int preferred);

#endif
