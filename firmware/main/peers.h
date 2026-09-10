// The peer table: what we know about the other machines in the tailnet.
//
// Netmap updates are incremental. A message saying "this phone woke up"
// carries the peer's identity and nothing else - no addresses, no endpoints.
// Rebuilding the table from each update would therefore throw away the
// endpoints path discovery depends on, so entries are merged, never replaced.
#ifndef PEERS_H
#define PEERS_H

#include <stdint.h>
#include <stdbool.h>
#include "ts_netmap.h"

#ifndef PEERS_MAX
#define PEERS_MAX 16
#endif

typedef struct {
    uint64_t id;
    // Sized to match what the netmap parser can hand us, so a long MagicDNS
    // name is stored whole rather than quietly clipped.
    char     name[TS_NAME_STR];
    char     addr[TS_ADDR_STR];        // the peer's 100.x address
    uint8_t  disco_key[32];
    bool     has_disco;
    uint8_t  node_key[32];      // WireGuard's static key for this peer
    bool     has_node_key;
    int      wg_index;          // into the WireGuard device, or -1
    uint16_t home_derp;
    bool     online;
    char     endpoints[TS_MAX_ENDPOINTS][TS_ADDR_STR];
    int      nendpoints;
    int      path_index;               // into the path engine, or -1
    bool     logged_candidates;        // keeps the log readable
    bool     in_use;
} peer_entry;

void        peers_clear(void);
// Merges one netmap record. Fields the update omits keep their old values.
peer_entry *peers_upsert(const ts_peer *p);
void        peers_remove(uint64_t id);
int         peers_count(void);
peer_entry *peers_at(int i);
peer_entry *peers_find(uint64_t id);

#endif
