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
} ts_peer;

typedef struct {
    char self_name[TS_NAME_STR];
    char self_addrs[TS_MAX_ADDRS][TS_ADDR_STR];
    int  self_naddrs;
    char domain[TS_NAME_STR];
    int  peer_count;
    int  message_count;
} ts_netmap_info;

typedef void (*ts_peer_cb)(void *ctx, const ts_peer *peer);

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

    ts_peer_cb  peer_cb;
    void       *cb_ctx;
    int         error;
} ts_netmap_parser;

void ts_netmap_parser_init(ts_netmap_parser *p, ts_peer_cb cb, void *ctx);

// Feed response body bytes as they arrive. Returns 0 while things look sane.
int ts_netmap_feed(ts_netmap_parser *p, const uint8_t *data, size_t len);

#endif
