#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sim_net.h"

void sim_v4(uint8_t out[16], const char *dotted) {
    unsigned a, b, c, d;
    uint8_t v4[4];
    sscanf(dotted, "%u.%u.%u.%u", &a, &b, &c, &d);
    v4[0] = (uint8_t)a; v4[1] = (uint8_t)b; v4[2] = (uint8_t)c; v4[3] = (uint8_t)d;
    disco_ipv4_mapped(out, v4);
}

static uint32_t rng_next(sim_net *n) {
    n->rng = n->rng * 1664525u + 1013904223u;
    return n->rng >> 16;
}

// ------------------------------------------------------------------ NAT

static int same_addr(const uint8_t a[16], uint16_t ap, const uint8_t b[16], uint16_t bp) {
    return ap == bp && memcmp(a, b, 16) == 0;
}

static void map_note_seen(sim_map *m, const uint8_t ip[16], uint16_t port) {
    int i;
    for (i = 0; i < m->nseen; i++)
        if (same_addr(m->seen_ip[i], m->seen_port[i], ip, port)) return;
    if (m->nseen < SIM_MAX_SEEN) {
        memcpy(m->seen_ip[m->nseen], ip, 16);
        m->seen_port[m->nseen] = port;
        m->nseen++;
    }
}

// Finds or creates the outbound mapping, and returns the external port.
static uint16_t nat_outbound(sim_nat *nat, const uint8_t lan_ip[16], uint16_t lan_port,
                             const uint8_t dst_ip[16], uint16_t dst_port) {
    int i, free_slot = -1;

    for (i = 0; i < SIM_MAX_MAPS; i++) {
        sim_map *m = &nat->maps[i];
        if (!m->used) { if (free_slot < 0) free_slot = i; continue; }
        if (!same_addr(m->lan_ip, m->lan_port, lan_ip, lan_port)) continue;
        // A symmetric NAT keys the mapping on the destination too, which is
        // why an address learned from a STUN server does not work for anyone
        // else.
        if (nat->type == NAT_SYMMETRIC &&
            !same_addr(m->dst_ip, m->dst_port, dst_ip, dst_port)) continue;
        map_note_seen(m, dst_ip, dst_port);
        return m->pub_port;
    }
    if (free_slot < 0) return 0;
    {
        sim_map *m = &nat->maps[free_slot];
        memset(m, 0, sizeof(*m));
        m->used = 1;
        memcpy(m->lan_ip, lan_ip, 16);
        m->lan_port = lan_port;
        memcpy(m->dst_ip, dst_ip, 16);
        m->dst_port = dst_port;
        m->pub_port = nat->next_port++;
        map_note_seen(m, dst_ip, dst_port);
        return m->pub_port;
    }
}

// Returns the mapping an inbound packet should be delivered through, or NULL
// when the NAT would drop it.
static sim_map *nat_inbound(sim_nat *nat, uint16_t pub_port,
                            const uint8_t src_ip[16], uint16_t src_port) {
    int i, j;
    for (i = 0; i < SIM_MAX_MAPS; i++) {
        sim_map *m = &nat->maps[i];
        if (!m->used || m->pub_port != pub_port) continue;
        if (nat->type == NAT_FULL_CONE) return m;
        if (nat->type == NAT_SYMMETRIC)
            return same_addr(m->dst_ip, m->dst_port, src_ip, src_port) ? m : NULL;
        for (j = 0; j < m->nseen; j++)            // NAT_RESTRICTED
            if (same_addr(m->seen_ip[j], m->seen_port[j], src_ip, src_port)) return m;
        return NULL;
    }
    return NULL;
}

// ------------------------------------------------------------------ net

void sim_net_init(sim_net *n, uint32_t latency_ms) {
    memset(n, 0, sizeof(*n));
    n->latency_ms = latency_ms;
    n->rng = 12345;
}

sim_nat *sim_add_nat(sim_net *n, nat_type type, const char *pub_ipv4) {
    sim_nat *nat = &n->nats[n->nnats++];
    memset(nat, 0, sizeof(*nat));
    nat->type = type;
    sim_v4(nat->pub_ip, pub_ipv4);
    nat->next_port = 40000;
    return nat;
}

static int find_dest(sim_net *n, const uint8_t ip[16], uint16_t port,
                     sim_map **via) {
    int i;
    *via = NULL;
    // A host on the open internet is addressed directly.
    for (i = 0; i < n->nhosts; i++) {
        sim_host *h = &n->hosts[i];
        if (!h->nat && same_addr(h->lan_ip, h->lan_port, ip, port)) return i;
    }
    // Otherwise the address belongs to a NAT, which decides whether to let
    // the packet through.
    for (i = 0; i < n->nnats; i++) {
        sim_nat *nat = &n->nats[i];
        if (memcmp(nat->pub_ip, ip, 16) != 0) continue;
        return -2 - i;    // caller resolves through the NAT
    }
    return -1;
}

static int send_udp(void *ctx, const uint8_t ip[16], uint16_t port,
                    const uint8_t *pkt, size_t len);

int sim_add_host(sim_net *n, const char *name, const char *lan_ipv4,
                 uint16_t port, sim_nat *nat) {
    sim_host *h = &n->hosts[n->nhosts];
    int i;

    memset(h, 0, sizeof(*h));
    h->net = n;
    h->index = n->nhosts;
    snprintf(h->name, sizeof(h->name), "%s", name);
    sim_v4(h->lan_ip, lan_ipv4);
    h->lan_port = port;
    h->nat = nat;
    for (i = 0; i < 32; i++) h->disco_priv[i] = (uint8_t)(0x11 * (n->nhosts + 1) + i);
    x25519_clamp(h->disco_priv);
    x25519_base(h->disco_pub, h->disco_priv);
    for (i = 0; i < 32; i++) h->node_pub[i] = (uint8_t)(0x55 + n->nhosts * 3 + i);

    if (!nat) { memcpy(h->pub_ip, h->lan_ip, 16); h->pub_port = port; }
    n->nhosts++;
    return h->index;
}

void sim_host_learn_public(sim_net *n, int host) {
    sim_host *h = &n->hosts[host];
    uint8_t stun_ip[16];
    if (!h->nat) return;
    // The address control learns comes from talking to a STUN server, which
    // for a symmetric NAT is a mapping nobody else can use.
    sim_v4(stun_ip, "1.2.3.4");
    h->pub_port = nat_outbound(h->nat, h->lan_ip, h->lan_port, stun_ip, 3478);
    memcpy(h->pub_ip, h->nat->pub_ip, 16);
    (void)n;
}

void sim_introduce(sim_net *n, int a, int b, uint8_t score) {
    sim_host *ha = &n->hosts[a], *hb = &n->hosts[b];
    int pi = ts_path_add_peer(&ha->eng, (uint64_t)(b + 1), hb->disco_pub, hb->node_pub, 0);
    if (pi >= 0) ts_path_add_candidate(&ha->eng, pi, hb->pub_ip, hb->pub_port, score);
}

static void deliver_later(sim_net *n, int dst, const uint8_t src_ip[16],
                          uint16_t src_port, const uint8_t *pkt, size_t len) {
    int i;
    if (len > SIM_MAX_PACKET) return;
    for (i = 0; i < SIM_MAX_QUEUE; i++) {
        sim_packet *q = &n->queue[i];
        if (q->used) continue;
        q->used = 1;
        q->due_ms = n->now_ms + n->latency_ms;
        q->dst_host = dst;
        memcpy(q->src_ip, src_ip, 16);
        q->src_port = src_port;
        memcpy(q->data, pkt, len);
        q->len = len;
        return;
    }
}

static int send_udp(void *ctx, const uint8_t ip[16], uint16_t port,
                    const uint8_t *pkt, size_t len) {
    sim_host *h = (sim_host *)ctx;
    sim_net *n = h->net;
    uint8_t src_ip[16];
    uint16_t src_port;
    sim_map *via;
    int dst;

    h->tx_count++;
    if (n->partitioned) return 0;

    if (h->nat) {
        src_port = nat_outbound(h->nat, h->lan_ip, h->lan_port, ip, port);
        if (src_port == 0) { n->dropped_nat++; return -1; }
        memcpy(src_ip, h->nat->pub_ip, 16);
    } else {
        memcpy(src_ip, h->lan_ip, 16);
        src_port = h->lan_port;
    }

    if (n->loss_permille && (rng_next(n) % 1000) < n->loss_permille) {
        n->dropped_loss++;
        return 0;         // the sender never learns
    }

    dst = find_dest(n, ip, port, &via);
    if (dst == -1) { n->dropped_nat++; return 0; }
    if (dst <= -2) {
        sim_nat *nat = &n->nats[-2 - dst];
        sim_map *m = nat_inbound(nat, port, src_ip, src_port);
        int i;
        if (!m) { n->dropped_nat++; return 0; }   // the NAT swallowed it
        dst = -1;
        for (i = 0; i < n->nhosts; i++)
            if (n->hosts[i].nat == nat &&
                same_addr(n->hosts[i].lan_ip, n->hosts[i].lan_port, m->lan_ip, m->lan_port))
                dst = i;
        if (dst < 0) { n->dropped_nat++; return 0; }
    }

    deliver_later(n, dst, src_ip, src_port, pkt, len);
    return 0;
}

static uint32_t sim_now(void *ctx) { return ((sim_host *)ctx)->net->now_ms; }

static void sim_random(void *ctx, uint8_t *out, size_t n) {
    sim_host *h = (sim_host *)ctx;
    size_t i;
    for (i = 0; i < n; i++) out[i] = (uint8_t)rng_next(h->net);
}

void sim_run(sim_net *n, uint32_t ms) {
    uint32_t end = n->now_ms + ms;
    while (n->now_ms < end) {
        int i;
        for (i = 0; i < SIM_MAX_QUEUE; i++) {
            sim_packet *q = &n->queue[i];
            if (!q->used || q->due_ms > n->now_ms) continue;
            q->used = 0;
            n->delivered++;
            n->hosts[q->dst_host].rx_count++;
            ts_path_on_datagram(&n->hosts[q->dst_host].eng,
                                q->src_ip, q->src_port, q->data, q->len);
        }
        for (i = 0; i < n->nhosts; i++) ts_path_tick(&n->hosts[i].eng);
        n->now_ms += 10;
    }
}

// Wires each host's engine to this network. Called by the test after hosts
// are added, because the env holds a pointer to the host itself.
void sim_start(sim_net *n) {
    int i;
    for (i = 0; i < n->nhosts; i++) {
        sim_host *h = &n->hosts[i];
        ts_path_env env;
        memset(&env, 0, sizeof(env));
        env.send_udp = send_udp;
        env.now_ms = sim_now;
        env.random = sim_random;
        env.ctx = h;
        ts_path_init(&h->eng, &env, h->disco_priv, h->node_pub);
    }
}
