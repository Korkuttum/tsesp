#include <string.h>
#include "nat.h"

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP 17

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void     wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static void     wr32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

// RFC 1624: a checksum can be corrected for a changed 16-bit word without
// walking the packet again. HC' = ~(~HC + ~m + m').
static uint16_t csum_swap16(uint16_t sum, uint16_t old_w, uint16_t new_w) {
    uint32_t s = (uint16_t)~sum;
    s += (uint16_t)~old_w;
    s += new_w;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

// The same for a four-byte address, which is two words.
static uint16_t csum_swap32(uint16_t sum, uint32_t old_a, uint32_t new_a) {
    const uint8_t *o = (const uint8_t *)&old_a, *n = (const uint8_t *)&new_a;
    sum = csum_swap16(sum, rd16(o), rd16(n));
    sum = csum_swap16(sum, rd16(o + 2), rd16(n + 2));
    return sum;
}

static uint32_t elapsed(uint32_t now, uint32_t then) { return now - then; }

void nat_init(nat_table *t) {
    memset(t, 0, sizeof(*t));
    t->next_port = NAT_PORT_FIRST;
}

static int expired(const nat_entry *e, uint32_t now) {
    return !e->in_use || elapsed(now, e->last_ms) > NAT_IDLE_MS;
}

int nat_live(const nat_table *t, uint32_t now_ms) {
    int i, n = 0;
    for (i = 0; i < NAT_MAX; i++)
        if (t->e[i].in_use && !expired(&t->e[i], now_ms)) n++;
    return n;
}

static uint16_t take_port(nat_table *t) {
    uint16_t p = t->next_port;
    if (++t->next_port > NAT_PORT_LAST) t->next_port = NAT_PORT_FIRST;
    return p;
}

// The ports and the identifier a translation has to touch, whatever the
// protocol. ICMP has no ports; its echo id serves the same purpose, which is
// why it is carried in both fields.
static int ports_of(const uint8_t *pkt, size_t len, uint8_t proto,
                    size_t hl, uint16_t *sport, uint16_t *dport) {
    if (proto == IP_PROTO_TCP || proto == IP_PROTO_UDP) {
        if (len < hl + 4) return 0;
        *sport = rd16(pkt + hl);
        *dport = rd16(pkt + hl + 2);
        return 1;
    }
    if (proto == IP_PROTO_ICMP) {
        if (len < hl + 8) return 0;
        // Only echo request and reply carry an identifier to key on.
        if (pkt[hl] != 8 && pkt[hl] != 0) return 0;
        *sport = *dport = rd16(pkt + hl + 4);
        return 1;
    }
    return 0;
}

// Writes the source port (or echo id) and keeps the checksum honest.
static void set_sport(uint8_t *pkt, uint8_t proto, size_t hl, uint16_t v) {
    uint16_t old;
    if (proto == IP_PROTO_ICMP) {
        old = rd16(pkt + hl + 4);
        wr16(pkt + hl + 4, v);
        wr16(pkt + hl + 2, csum_swap16(rd16(pkt + hl + 2), old, v));
        return;
    }
    old = rd16(pkt + hl);
    wr16(pkt + hl, v);
    if (proto == IP_PROTO_TCP)
        wr16(pkt + hl + 16, csum_swap16(rd16(pkt + hl + 16), old, v));
    else if (rd16(pkt + hl + 6))      // a zero UDP checksum means "not computed"
        wr16(pkt + hl + 6, csum_swap16(rd16(pkt + hl + 6), old, v));
}

static void set_dport(uint8_t *pkt, uint8_t proto, size_t hl, uint16_t v) {
    uint16_t old;
    if (proto == IP_PROTO_ICMP) {
        old = rd16(pkt + hl + 4);
        wr16(pkt + hl + 4, v);
        wr16(pkt + hl + 2, csum_swap16(rd16(pkt + hl + 2), old, v));
        return;
    }
    old = rd16(pkt + hl + 2);
    wr16(pkt + hl + 2, v);
    if (proto == IP_PROTO_TCP)
        wr16(pkt + hl + 16, csum_swap16(rd16(pkt + hl + 16), old, v));
    else if (rd16(pkt + hl + 6))
        wr16(pkt + hl + 6, csum_swap16(rd16(pkt + hl + 6), old, v));
}

// The transport checksum covers a pseudo-header made of the addresses, so
// changing one means correcting the other. ICMP's does not, which is why it
// is left alone here.
static void set_addr(uint8_t *pkt, uint8_t proto, size_t hl, int is_src, uint32_t v) {
    size_t off = is_src ? 12 : 16;
    uint32_t old = rd32(pkt + off);
    if (old == v) return;
    wr32(pkt + off, v);
    wr16(pkt + 10, csum_swap32(rd16(pkt + 10), old, v));
    if (proto == IP_PROTO_TCP)
        wr16(pkt + hl + 16, csum_swap32(rd16(pkt + hl + 16), old, v));
    else if (proto == IP_PROTO_UDP && rd16(pkt + hl + 6))
        wr16(pkt + hl + 6, csum_swap32(rd16(pkt + hl + 6), old, v));
}

static nat_entry *find_out(nat_table *t, uint8_t proto, uint32_t src, uint16_t sport,
                           uint32_t dst, uint16_t dport, uint32_t now) {
    int i;
    for (i = 0; i < NAT_MAX; i++) {
        nat_entry *e = &t->e[i];
        if (expired(e, now)) continue;
        if (e->proto == proto && e->peer_ip == src && e->peer_port == sport &&
            e->lan_ip == dst && e->lan_port == dport)
            return e;
    }
    return NULL;
}

static nat_entry *find_in(nat_table *t, uint8_t proto, uint32_t lan_ip,
                          uint16_t lan_port, uint16_t mport, uint32_t now) {
    int i;
    for (i = 0; i < NAT_MAX; i++) {
        nat_entry *e = &t->e[i];
        if (expired(e, now)) continue;
        if (e->proto != proto || e->lan_ip != lan_ip || e->mport != mport) continue;
        // ICMP has one identifier where TCP and UDP have two ports, and we
        // rewrote it on the way out, so the reply carries ours in both
        // places. There is nothing left to match the far side's port against.
        if (proto == IP_PROTO_ICMP) return e;
        if (e->lan_port == lan_port) return e;
    }
    return NULL;
}

static nat_entry *take_slot(nat_table *t, uint32_t now) {
    int i, oldest = -1;
    for (i = 0; i < NAT_MAX; i++)
        if (expired(&t->e[i], now)) return &t->e[i];
    // Nothing free: the least recently used goes, so a burst cannot lock the
    // table against every flow that comes after it.
    for (i = 0; i < NAT_MAX; i++)
        if (oldest < 0 || elapsed(now, t->e[i].last_ms) > elapsed(now, t->e[oldest].last_ms))
            oldest = i;
    t->full++;
    return &t->e[oldest];
}

int nat_out(nat_table *t, uint8_t *pkt, size_t len, uint32_t lan_ip, uint32_t now_ms) {
    size_t hl;
    uint8_t proto;
    uint16_t sport = 0, dport = 0;
    uint32_t src, dst;
    nat_entry *e;

    if (len < 20 || (pkt[0] >> 4) != 4) return 0;
    hl = (size_t)(pkt[0] & 0x0f) * 4;
    if (hl < 20 || len < hl) return 0;
    proto = pkt[9];
    if (!ports_of(pkt, len, proto, hl, &sport, &dport)) return 0;

    src = rd32(pkt + 12);
    dst = rd32(pkt + 16);

    e = find_out(t, proto, src, sport, dst, dport, now_ms);
    if (!e) {
        e = take_slot(t, now_ms);
        e->proto = proto;
        e->peer_ip = src;
        e->peer_port = sport;
        e->lan_ip = dst;
        e->lan_port = dport;
        e->mport = take_port(t);
        e->in_use = 1;
    }
    e->last_ms = now_ms;

    set_sport(pkt, proto, hl, e->mport);
    set_addr(pkt, proto, hl, 1, lan_ip);
    t->rewrites_out++;
    return 1;
}

int nat_in(nat_table *t, uint8_t *pkt, size_t len, uint32_t our_lan_ip,
           uint32_t now_ms, uint32_t *peer_ip) {
    size_t hl;
    uint8_t proto;
    uint16_t sport = 0, dport = 0;
    nat_entry *e;

    if (len < 20 || (pkt[0] >> 4) != 4) return 0;
    hl = (size_t)(pkt[0] & 0x0f) * 4;
    if (hl < 20 || len < hl) return 0;
    if (rd32(pkt + 16) != our_lan_ip) return 0;
    proto = pkt[9];
    if (!ports_of(pkt, len, proto, hl, &sport, &dport)) return 0;

    e = find_in(t, proto, rd32(pkt + 12), sport, dport, now_ms);
    if (!e) { t->misses_in++; return 0; }
    e->last_ms = now_ms;

    set_dport(pkt, proto, hl, e->peer_port);
    set_addr(pkt, proto, hl, 0, e->peer_ip);
    if (peer_ip) *peer_ip = e->peer_ip;
    t->rewrites_in++;
    return 1;
}

// Recomputes the checksums from the whole packet, the way a receiver does.
// The rewrites above correct them incrementally, which is fast and easy to
// get subtly wrong; this is the independent check, and the board counts how
// often it disagrees.
static uint16_t sum_range(const uint8_t *p, size_t n, uint32_t start) {
    uint32_t s = start;
    size_t i;
    for (i = 0; i + 1 < n; i += 2) s += rd16(p + i);
    if (i < n) s += (uint32_t)p[i] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

int nat_csum_ok(const uint8_t *pkt, size_t len) {
    size_t hl, l4;
    uint32_t pseudo;
    uint8_t proto;

    if (len < 20 || (pkt[0] >> 4) != 4) return 1;      /* not ours to judge */
    hl = (size_t)(pkt[0] & 0x0f) * 4;
    if (hl < 20 || len < hl) return 0;
    if (sum_range(pkt, hl, 0) != 0) return 0;          /* header checks itself */

    proto = pkt[9];
    l4 = len - hl;
    if (proto == IP_PROTO_ICMP) return sum_range(pkt + hl, l4, 0) == 0;
    if (proto != IP_PROTO_TCP && proto != IP_PROTO_UDP) return 1;
    if (proto == IP_PROTO_UDP && l4 >= 8 && rd16(pkt + hl + 6) == 0) return 1;

    pseudo = (uint32_t)rd16(pkt + 12) + rd16(pkt + 14) + rd16(pkt + 16) + rd16(pkt + 18)
           + proto + (uint32_t)l4;
    return sum_range(pkt + hl, l4, pseudo) == 0;
}
