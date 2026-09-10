#include <string.h>
#include "ts_path.h"

static uint32_t now(ts_path_engine *e) { return e->env.now_ms(e->env.ctx); }

// Wrapping-safe elapsed time: the ESP32's millisecond clock wraps every
// 49 days, and a device meant to sit on a shelf will see that happen.
static uint32_t since(uint32_t now_ms, uint32_t then_ms) { return now_ms - then_ms; }

int ts_path_init(ts_path_engine *e, const ts_path_env *env,
                 const uint8_t disco_priv[32], const uint8_t node_pub[32]) {
    memset(e, 0, sizeof(*e));
    e->env = *env;
    memcpy(e->disco_priv, disco_priv, 32);
    x25519_base(e->disco_pub, e->disco_priv);
    if (node_pub) memcpy(e->node_pub, node_pub, 32);
    return 0;
}

int ts_path_find_peer(const ts_path_engine *e, uint64_t id) {
    int i;
    for (i = 0; i < TS_MAX_PEERS; i++)
        if (e->peers[i].in_use && e->peers[i].id == id) return i;
    return -1;
}

static int find_peer_by_disco(const ts_path_engine *e, const uint8_t disco_pub[32]) {
    int i;
    for (i = 0; i < TS_MAX_PEERS; i++)
        if (e->peers[i].in_use && memcmp(e->peers[i].disco_pub, disco_pub, 32) == 0)
            return i;
    return -1;
}

int ts_path_add_peer(ts_path_engine *e, uint64_t id,
                     const uint8_t disco_pub[32], const uint8_t node_pub[32],
                     uint16_t home_derp) {
    int idx = ts_path_find_peer(e, id);
    ts_path_peer *p;

    if (idx < 0) {
        int i;
        for (i = 0; i < TS_MAX_PEERS; i++) if (!e->peers[i].in_use) { idx = i; break; }
        if (idx < 0) return -1;
        memset(&e->peers[idx], 0, sizeof(e->peers[idx]));
        e->peers[idx].in_use = 1;
        e->peers[idx].id = id;
        e->peers[idx].best = -1;
        e->npeers++;
    }
    p = &e->peers[idx];

    // A peer that rotated its disco key invalidates every path we had: the
    // old shared secret cannot open its replies.
    if (memcmp(p->disco_pub, disco_pub, 32) != 0) {
        memcpy(p->disco_pub, disco_pub, 32);
        if (nacl_box_beforenm(p->shared, disco_pub, e->disco_priv) != 0) {
            p->in_use = 0;
            e->npeers--;
            return -1;
        }
        p->npaths = 0;
        p->best = -1;
    }
    if (node_pub) {
        memcpy(p->node_key, node_pub, 32);
        p->has_node_key = 1;
    }
    p->home_derp = home_derp;
    return idx;
}

void ts_path_remove_peer(ts_path_engine *e, uint64_t id) {
    int idx = ts_path_find_peer(e, id);
    if (idx < 0) return;
    memset(&e->peers[idx], 0, sizeof(e->peers[idx]));
    e->npeers--;
}

// ------------------------------------------------------------- candidates

static int path_matches(const ts_path *p, const uint8_t ip[16], uint16_t port) {
    return p->port == port && memcmp(p->ip, ip, 16) == 0;
}

// Replaces the least useful path when the table is full: dead first, then
// untried, then whichever has the lowest score. A live path is never evicted.
static int evict_slot(ts_path_peer *p, uint8_t score) {
    int worst = -1, i;
    uint8_t worst_rank = 0xff;

    for (i = 0; i < p->npaths; i++) {
        uint8_t rank;
        if (i == p->best) continue;
        if (p->paths[i].state == TS_PATH_ALIVE) continue;
        rank = (uint8_t)(p->paths[i].state == TS_PATH_DEAD ? 0 : 1);
        rank = (uint8_t)(rank * 64 + p->paths[i].score);
        if (rank < worst_rank) { worst_rank = rank; worst = i; }
    }
    if (worst < 0) return -1;
    if (worst_rank >= 64 + score) return -1;   // nothing worse than the newcomer
    return worst;
}

static int add_candidate(ts_path_engine *e, ts_path_peer *p,
                         const uint8_t ip[16], uint16_t port,
                         uint8_t score, int discovered) {
    static const uint8_t zero[16] = {0};
    int i, slot;

    // Messages relayed through DERP arrive with no source address. They are
    // still worth reading; they are not worth probing.
    if (port == 0 || memcmp(ip, zero, 16) == 0) return -1;

    for (i = 0; i < p->npaths; i++) {
        if (path_matches(&p->paths[i], ip, port)) {
            if (score > p->paths[i].score) p->paths[i].score = score;
            // A path we had written off is worth retrying when the peer
            // itself tells us about it again.
            if (discovered && p->paths[i].state == TS_PATH_DEAD) {
                p->paths[i].state = TS_PATH_UNTRIED;
                p->paths[i].attempts = 0;
            }
            return i;
        }
    }

    if (p->npaths < TS_MAX_PATHS) {
        slot = p->npaths++;
    } else {
        slot = evict_slot(p, score);
        if (slot < 0) return -1;
        if (slot < p->best) { /* indices stay valid; best is untouched */ }
    }

    memset(&p->paths[slot], 0, sizeof(p->paths[slot]));
    memcpy(p->paths[slot].ip, ip, 16);
    p->paths[slot].port = port;
    p->paths[slot].score = score;
    p->paths[slot].state = TS_PATH_UNTRIED;
    p->paths[slot].discovered = (uint8_t)discovered;
    (void)e;
    return slot;
}

int ts_path_add_candidate(ts_path_engine *e, int peer_index,
                          const uint8_t ip[16], uint16_t port, uint8_t score) {
    if (peer_index < 0 || peer_index >= TS_MAX_PEERS || !e->peers[peer_index].in_use)
        return -1;
    return add_candidate(e, &e->peers[peer_index], ip, port, score, 0);
}

// ------------------------------------------------------------- probing

static void send_ping(ts_path_engine *e, ts_path_peer *p, ts_path *path) {
    uint8_t inner[DISCO_MAX_INNER], pkt[256], nonce[NACL_NONCE_LEN];
    size_t ilen, plen;

    e->env.random(e->env.ctx, path->txid, DISCO_TXID_LEN);
    e->env.random(e->env.ctx, nonce, sizeof(nonce));

    if (disco_build_ping(inner, sizeof(inner), &ilen, path->txid,
                         e->node_pub, 0) != 0) return;
    if (disco_seal(pkt, sizeof(pkt), &plen, e->disco_pub, p->shared,
                   nonce, inner, ilen) != 0) return;
    if (e->env.send_udp(e->env.ctx, path->ip, path->port, pkt, plen) != 0) return;

    path->last_ping_ms = now(e);
    if (path->state != TS_PATH_ALIVE) path->state = TS_PATH_PROBING;
    path->attempts++;
    e->pings_sent++;
}

static void send_pong(ts_path_engine *e, ts_path_peer *p,
                      const uint8_t txid[DISCO_TXID_LEN],
                      const uint8_t src_ip[16], uint16_t src_port) {
    uint8_t inner[DISCO_MAX_INNER], pkt[256], nonce[NACL_NONCE_LEN];
    size_t ilen, plen;

    e->env.random(e->env.ctx, nonce, sizeof(nonce));
    // The pong reports where the ping appeared from, which is how the peer
    // learns its own public address on this path.
    if (disco_build_pong(inner, sizeof(inner), &ilen, txid, src_ip, src_port) != 0) return;
    if (disco_seal(pkt, sizeof(pkt), &plen, e->disco_pub, p->shared,
                   nonce, inner, ilen) != 0) return;
    if (e->env.send_udp(e->env.ctx, src_ip, src_port, pkt, plen) == 0) e->pongs_sent++;
}

// Lowest latency wins; equal latency breaks on the netmap's preference.
static int pick_best(const ts_path_peer *p, uint32_t now_ms) {
    int best = -1, i;
    for (i = 0; i < p->npaths; i++) {
        const ts_path *c = &p->paths[i];
        if (c->state != TS_PATH_ALIVE) continue;
        if (since(now_ms, c->last_pong_ms) > TS_PATH_STALE_MS) continue;
        if (best < 0) { best = i; continue; }
        if (c->latency_ms < p->paths[best].latency_ms) { best = i; continue; }
        if (c->latency_ms == p->paths[best].latency_ms &&
            c->score > p->paths[best].score) best = i;
    }
    return best;
}

static void update_best(ts_path_engine *e, ts_path_peer *p, uint32_t now_ms) {
    int nb = pick_best(p, now_ms);
    if (nb == p->best) return;
    p->best = nb;
    if (e->env.on_path_change)
        e->env.on_path_change(e->env.ctx, p, nb >= 0 ? &p->paths[nb] : NULL);
}

void ts_path_tick(ts_path_engine *e) {
    uint32_t t = now(e);
    int i, j;

    for (i = 0; i < TS_MAX_PEERS; i++) {
        ts_path_peer *p = &e->peers[i];
        int probing_needed;
        if (!p->in_use) continue;

        // Expire anything that has gone quiet, then re-pick.
        for (j = 0; j < p->npaths; j++) {
            ts_path *c = &p->paths[j];
            if (c->state == TS_PATH_ALIVE &&
                since(t, c->last_pong_ms) > TS_PATH_STALE_MS) {
                c->state = TS_PATH_DEAD;
                c->attempts = 0;
            }
            if (c->state == TS_PATH_PROBING &&
                since(t, c->last_ping_ms) > TS_PROBE_TIMEOUT_MS) {
                if (c->attempts >= TS_PROBE_ATTEMPTS) c->state = TS_PATH_DEAD;
                else send_ping(e, p, c);
            }
        }
        update_best(e, p, t);

        if (p->best >= 0) {
            ts_path *b = &p->paths[p->best];
            if (since(t, b->last_ping_ms) >= TS_KEEPALIVE_MS) send_ping(e, p, b);
        }

        // Probe hard while there is no path at all; once one works, look for
        // a better one only occasionally.
        probing_needed = (p->best < 0) ||
                         (since(t, p->last_reprobe_ms) >= TS_REPROBE_MS);
        if (!probing_needed) continue;
        if (p->best >= 0) p->last_reprobe_ms = t;

        for (j = 0; j < p->npaths; j++) {
            ts_path *c = &p->paths[j];
            if (j == p->best) continue;
            if (c->state == TS_PATH_UNTRIED) {
                send_ping(e, p, c);
            } else if (c->state == TS_PATH_DEAD &&
                       since(t, c->last_ping_ms) >= TS_DEAD_RETRY_MS) {
                c->attempts = 0;
                send_ping(e, p, c);
            }
        }
    }
}

// ------------------------------------------------------------- receiving

int ts_path_on_datagram(ts_path_engine *e,
                        const uint8_t src_ip[16], uint16_t src_port,
                        const uint8_t *pkt, size_t len) {
    const uint8_t *sender;
    disco_msg m;
    ts_path_peer *p;
    int pi, j;
    uint32_t t;

    if (!disco_looks_like_disco(pkt, len)) return 0;   // WireGuard, not ours

    sender = disco_sender_key(pkt, len);
    if (!sender) return -1;
    pi = find_peer_by_disco(e, sender);
    if (pi < 0) { e->unknown_senders++; return -1; }
    p = &e->peers[pi];

    if (disco_open(pkt, len, p->shared, &m) != 0) return -1;
    t = now(e);

    switch (m.type) {
    case DISCO_PING:
        // Answering opens our side of the NAT for this address, and the
        // source is itself a candidate we might never have been told about.
        send_pong(e, p, m.txid, src_ip, src_port);
        {
            int idx = add_candidate(e, p, src_ip, src_port, 3, 1);
            if (idx >= 0 && p->paths[idx].state == TS_PATH_UNTRIED)
                send_ping(e, p, &p->paths[idx]);
        }
        return 1;

    case DISCO_PONG:
        for (j = 0; j < p->npaths; j++) {
            ts_path *c = &p->paths[j];
            if (memcmp(c->txid, m.txid, DISCO_TXID_LEN) != 0) continue;
            e->pongs_received++;
            c->last_pong_ms = t;
            c->latency_ms = (uint16_t)since(t, c->last_ping_ms);
            c->state = TS_PATH_ALIVE;
            c->attempts = 0;
            update_best(e, p, t);
            return 1;
        }
        return 1;   // a pong for a transaction we no longer track

    case DISCO_CALL_ME_MAYBE:
        // The peer just opened its firewall towards these addresses and is
        // asking us to try them now.
        for (j = 0; j < m.nendpoints; j++) {
            int idx = add_candidate(e, p, m.ep_ip[j], m.ep_port[j], 2, 1);
            if (idx >= 0 && p->paths[idx].state != TS_PATH_ALIVE) {
                p->paths[idx].attempts = 0;
                send_ping(e, p, &p->paths[idx]);
            }
        }
        return 1;

    default:
        return 1;
    }
}

const ts_path *ts_path_best(const ts_path_engine *e, int peer_index) {
    const ts_path_peer *p;
    if (peer_index < 0 || peer_index >= TS_MAX_PEERS) return NULL;
    p = &e->peers[peer_index];
    if (!p->in_use || p->best < 0) return NULL;
    return &p->paths[p->best];
}
