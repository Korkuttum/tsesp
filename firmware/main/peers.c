#include <string.h>
#include <stdio.h>
#include "lwip/inet.h"
#include "peers.h"

static peer_entry s_peers[PEERS_MAX];

void peers_clear(void) {
    memset(s_peers, 0, sizeof(s_peers));
}

int peers_count(void) {
    int i, n = 0;
    for (i = 0; i < PEERS_MAX; i++) if (s_peers[i].in_use) n++;
    return n;
}

peer_entry *peers_at(int i) {
    int k, n = 0;
    for (k = 0; k < PEERS_MAX; k++) {
        if (!s_peers[k].in_use) continue;
        if (n++ == i) return &s_peers[k];
    }
    return NULL;
}

peer_entry *peers_find(uint64_t id) {
    int i;
    for (i = 0; i < PEERS_MAX; i++)
        if (s_peers[i].in_use && s_peers[i].id == id) return &s_peers[i];
    return NULL;
}

void peers_remove(uint64_t id) {
    peer_entry *e = peers_find(id);
    if (e) memset(e, 0, sizeof(*e));
}

peer_entry *peers_upsert(const ts_peer *p) {
    peer_entry *e = p->id ? peers_find(p->id) : NULL;
    int i;

    if (!e) {
        for (i = 0; i < PEERS_MAX; i++) if (!s_peers[i].in_use) { e = &s_peers[i]; break; }
        if (!e) return NULL;                  // table full; ignore the newcomer
        memset(e, 0, sizeof(*e));
        e->in_use = true;
        e->id = p->id;
        e->path_index = -1;
        e->wg_index = -1;
    }

    // Only overwrite what the update actually carried. An incremental record
    // arrives with empty endpoints, and treating that as "no endpoints" would
    // delete the addresses we need to reach this peer.
    if (p->name[0])       snprintf(e->name, sizeof(e->name), "%s", p->name);
    if (p->naddrs) {
        snprintf(e->addr, sizeof(e->addr), "%s", p->addrs[0]);
        // "100.65.96.112/32" -> the address alone, for routing decisions.
        {
            unsigned a, b, c, d;
            if (sscanf(e->addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
                a < 256 && b < 256 && c < 256 && d < 256)
                e->tailnet_ip_be = PP_HTONL(0) |
                    ((uint32_t)a) | ((uint32_t)b << 8) |
                    ((uint32_t)c << 16) | ((uint32_t)d << 24);
        }
    }
    if (p->has_disco_key) { memcpy(e->disco_key, p->disco_key, 32); e->has_disco = true; }
    if (p->has_node_key)  { memcpy(e->node_key, p->node_key, 32); e->has_node_key = true; }
    if (p->home_derp)     e->home_derp = p->home_derp;
    if (p->has_online)    e->online = p->online != 0;
    if (p->nendpoints) {
        for (i = 0; i < p->nendpoints && i < TS_MAX_ENDPOINTS; i++)
            snprintf(e->endpoints[i], TS_ADDR_STR, "%s", p->endpoints[i]);
        e->nendpoints = p->nendpoints;
    }
    return e;
}
