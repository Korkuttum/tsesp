// The UDP socket that carries DISCO today and WireGuard later, plus the
// path-discovery engine driven from it.
#ifndef MAGIC_H
#define MAGIC_H

#include <stdint.h>
#include <stdbool.h>
#include "ts_path.h"
#include "peers.h"
#include "wireguard.h"

#define MAGIC_PORT 41641

int  magic_start(const uint8_t disco_priv[32], const uint8_t node_pub[32],
                 const uint8_t node_priv_for_wg[32]);

// Pushes the current peer table into the engine: registers peers that have a
// disco key and offers their endpoints as candidates.
void magic_sync_peers(void);

// Asks for a STUN lookup. The answer is picked up by the receive loop, so
// this returns immediately; read it back with magic_get_public.
void magic_request_stun(void);
bool magic_get_public(char *out, size_t cap);

// How many peers currently have a working direct path.
// Feeds a packet that arrived over the relay rather than the UDP socket.
void magic_handle_relayed(const uint8_t src_node_pub[32],
                          const uint8_t src_ip[16], uint16_t src_port,
                          const uint8_t *pkt, size_t len);

// How many peers have a live WireGuard session.
int  magic_tunnels_up(void);
int  magic_paths_up(void);
const ts_path *magic_best_for(const peer_entry *p);
void magic_stats(uint32_t *pings, uint32_t *pongs);

#endif
