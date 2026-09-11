// Path discovery: deciding which address actually reaches a peer.
//
// The netmap tells us a peer's candidate endpoints, but most of them do not
// work: LAN addresses from a different network, stale NAT mappings, IPv6 the
// ISP does not carry. The only way to find out is to send a DISCO ping to
// each one and see which answers, then keep sending on the winner so the NAT
// mapping in the middle stays open.
//
// This module owns that decision and nothing else. It never touches a socket
// or a clock: the caller supplies both, which is what makes it testable
// against a simulated network with simulated NATs.
#ifndef TS_PATH_H
#define TS_PATH_H

#include <stddef.h>
#include <stdint.h>
#include "disco.h"
#include "tscrypto.h"

#ifndef TS_MAX_PATHS
#define TS_MAX_PATHS 8          // candidate addresses tracked per peer
#endif
#ifndef TS_MAX_PEERS
#define TS_MAX_PEERS 16
#endif

// Timings. NAT mappings commonly expire after 30 seconds of silence, so the
// keepalive has to be comfortably under that.
#define TS_PROBE_TIMEOUT_MS   1500    // wait for a pong before retrying
#define TS_PROBE_ATTEMPTS     3
#define TS_DEAD_RETRY_MS      30000   // how long a dead path is left alone
#define TS_KEEPALIVE_MS       25000   // ping the winning path this often
#define TS_PATH_STALE_MS      35000   // no pong for this long: path is gone
#define TS_REPROBE_MS         60000   // look for a better path this often

typedef enum {
    TS_PATH_UNTRIED = 0,
    TS_PATH_PROBING,
    TS_PATH_ALIVE,
    TS_PATH_DEAD
} ts_path_state;

typedef struct {
    uint8_t  ip[16];
    uint16_t port;
    uint8_t  score;              // preference from the netmap; ties break on this
    uint8_t  state;
    uint8_t  attempts;
    uint8_t  txid[DISCO_TXID_LEN];
    uint32_t last_ping_ms;
    uint32_t last_pong_ms;
    uint16_t latency_ms;
    uint8_t  discovered;         // learned from a peer's ping, not the netmap
} ts_path;

typedef struct {
    uint64_t id;
    uint8_t  disco_pub[32];
    uint8_t  shared[NACL_KEY_LEN];
    uint8_t  node_key[32];
    int      has_node_key;
    uint16_t home_derp;

    ts_path  paths[TS_MAX_PATHS];
    int      npaths;
    int      best;               // index into paths, or -1
    uint32_t last_reprobe_ms;
    int      in_use;
} ts_path_peer;

// Everything platform-specific the engine needs.
typedef struct {
    // Returns 0 on success. The engine does not care about failures beyond
    // not counting the ping as sent.
    int (*send_udp)(void *ctx, const uint8_t ip[16], uint16_t port,
                    const uint8_t *pkt, size_t len);
    uint32_t (*now_ms)(void *ctx);
    void (*random)(void *ctx, uint8_t *out, size_t n);
    // Optional: called when a peer's chosen path changes, including to none.
    void (*on_path_change)(void *ctx, const ts_path_peer *peer, const ts_path *now_best);
    void *ctx;
} ts_path_env;

typedef struct {
    ts_path_env  env;
    uint8_t      disco_priv[32];
    uint8_t      disco_pub[32];
    uint8_t      node_pub[32];
    ts_path_peer peers[TS_MAX_PEERS];
    int          npeers;

    // Peers tell us where our packets appear to come from. On a network
    // where STUN is blocked this is the only way to learn our public
    // address, and it is more trustworthy anyway: it is the address that
    // actually reached someone.
    uint8_t  observed_ip[16];
    uint16_t observed_port;
    int      has_observed;

    // Counters, useful in tests and in the device's status page.
    uint32_t pings_sent, pongs_sent, pongs_received, unknown_senders;
} ts_path_engine;

int  ts_path_init(ts_path_engine *e, const ts_path_env *env,
                  const uint8_t disco_priv[32], const uint8_t node_pub[32]);

// Adds or updates a peer. Returns the peer index, or -1 if the table is full.
int  ts_path_add_peer(ts_path_engine *e, uint64_t id,
                      const uint8_t disco_pub[32], const uint8_t node_pub[32],
                      uint16_t home_derp);
void ts_path_remove_peer(ts_path_engine *e, uint64_t id);

// Offers a candidate address for a peer. Duplicates are merged.
int  ts_path_add_candidate(ts_path_engine *e, int peer_index,
                           const uint8_t ip[16], uint16_t port, uint8_t score);

// Drives probing, keepalives and expiry. Call it a few times a second.
void ts_path_tick(ts_path_engine *e);

// Feeds one received datagram. Returns 1 if it was a DISCO message the engine
// consumed, 0 if it is for someone else (WireGuard traffic), -1 if malformed.
int  ts_path_on_datagram(ts_path_engine *e,
                         const uint8_t src_ip[16], uint16_t src_port,
                         const uint8_t *pkt, size_t len);

// The address currently believed to reach this peer, or NULL if none does.
const ts_path *ts_path_best(const ts_path_engine *e, int peer_index);
int  ts_path_find_peer(const ts_path_engine *e, uint64_t id);

// Our own address as a peer reported seeing it. Returns 0 if unknown.
int  ts_path_observed_address(const ts_path_engine *e,
                              uint8_t ip[16], uint16_t *port);

#endif
