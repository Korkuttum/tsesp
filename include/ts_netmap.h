// Netmap parsing: /machine/map response -> one peer at a time.
//
// The response body is a sequence of [4-byte little-endian length][JSON]
// messages, and each message can be hundreds of kilobytes. Nothing here ever
// holds a whole message: the framer strips lengths incrementally, the JSON
// parser runs in push mode, and each peer is handed to a callback and then
// forgotten. That is what keeps a 300-peer tailnet inside a WROOM-32U.
#ifndef TS_NETMAP_H
#define TS_NETMAP_H

#include <stddef.h>
#include <stdint.h>
#include "json_stream.h"

#ifndef TS_MAX_ADDRS
#define TS_MAX_ADDRS 2          // one IPv4 + one IPv6 per node
#endif
#ifndef TS_MAX_ENDPOINTS
#define TS_MAX_ENDPOINTS 6
#endif
#define TS_ADDR_STR 48
#define TS_NAME_STR 64

typedef struct {
    uint64_t id;                        // NodeID, stable across updates
    char     name[TS_NAME_STR];
    uint8_t  node_key[32];
    uint8_t  disco_key[32];
    int      has_node_key;
    int      has_disco_key;
    char     addrs[TS_MAX_ADDRS][TS_ADDR_STR];
    int      naddrs;
    char     endpoints[TS_MAX_ENDPOINTS][TS_ADDR_STR];
    uint8_t  endpoint_score[TS_MAX_ENDPOINTS];
    int      nendpoints;
    int      dropped_endpoints;      // did not beat anything we already had
    uint16_t home_derp;
    int      online;
    int      has_online;
    int      from_changed;              // arrived in PeersChanged, not Peers
} ts_peer;

#ifndef TS_MAX_DERP_REGIONS
// The whole map. Keeping a prefix of it does not work: the regions arrive in
// no particular order, so the one our peers use may simply not be in the
// first handful. At 58 bytes each this is under 2 KB.
#define TS_MAX_DERP_REGIONS 32
#endif
#define TS_DERP_HOST_STR 48

typedef struct {
    uint16_t region_id;
    char     host[TS_DERP_HOST_STR];   // first node in the region
    char     code[8];                  // "fra", "ams", ...
} ts_derp_region;

typedef struct {
    uint64_t self_id;
    char self_name[TS_NAME_STR];
    char self_addrs[TS_MAX_ADDRS][TS_ADDR_STR];
    int  self_naddrs;
    // What the control plane believes our endpoints are. Empty means peers
    // have been given no way to reach us.
    char self_endpoints[TS_MAX_ENDPOINTS][TS_ADDR_STR];
    int  self_nendpoints;
    int  self_has_disco;      // the server kept the disco key we sent
    char domain[TS_NAME_STR];
    int  peer_count;
    int  message_count;
    // The server sends incremental patches for peers it has already
    // described. We do not apply them yet, so a non-zero count here means
    // some endpoint data is staler than it could be.
    int  unapplied_patches;

    // A handful of relays from the DERP map. The stale derpN.tailscale.com
    // names do not resolve to anything useful any more; these are the real
    // ones and they arrive with every full netmap.
    ts_derp_region derp[TS_MAX_DERP_REGIONS];
    int            nderp;
} ts_netmap_info;

typedef void (*ts_peer_cb)(void *ctx, const ts_peer *peer);

// A peer left the tailnet or is no longer visible to us.
typedef void (*ts_peer_removed_cb)(void *ctx, uint64_t node_id);

// Fired once per complete framed message. Return non-zero to stop reading,
// which is how a one-shot fetch ends a streaming connection.
typedef int (*ts_netmap_msg_cb)(void *ctx, const ts_netmap_info *info);

// Optional: sees each message's raw bytes as they stream past, before
// parsing. Only for logging - the device never keeps them.
typedef void (*ts_netmap_raw_cb)(void *ctx, int message_index,
                                 const uint8_t *data, size_t len);

typedef struct {
    // Length framing.
    uint8_t  size_buf[4];
    int      size_len;
    uint32_t msg_remaining;
    int      in_message;

    json_stream    js;
    ts_netmap_info info;
    ts_peer        peer;
    int            in_peer;

    ts_peer_cb        peer_cb;
    ts_peer_removed_cb removed_cb;
    ts_netmap_msg_cb  msg_cb;
    ts_netmap_raw_cb  raw_cb;
    void             *cb_ctx;
    int               error;
    int               stop;      // a callback asked us to stop
} ts_netmap_parser;

void ts_netmap_parser_init(ts_netmap_parser *p, ts_peer_cb cb, void *ctx);

// Tells the parser which IPv4 network this device sits on, so a peer's
// address on that same network can be ranked above everything else. Without
// it the scoring cannot tell a useful LAN address from a stale one.
void ts_netmap_set_local_v4(const uint8_t v4[4], uint8_t prefix_len);

// Optional: called after each complete message.
void ts_netmap_parser_on_message(ts_netmap_parser *p, ts_netmap_msg_cb cb);
void ts_netmap_parser_on_removed(ts_netmap_parser *p, ts_peer_removed_cb cb);
void ts_netmap_parser_on_raw(ts_netmap_parser *p, ts_netmap_raw_cb cb);

// Feed response body bytes as they arrive. Returns 0 while things look sane,
// 1 once a callback has asked to stop, -1 on a malformed response.
int ts_netmap_feed(ts_netmap_parser *p, const uint8_t *data, size_t len);

#endif
