#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ts_netmap.h"

// Parses "nodekey:<64 hex>" / "discokey:<64 hex>" into raw bytes.
static int parse_prefixed_key(const char *v, size_t len, const char *prefix,
                              uint8_t out[32]) {
    size_t plen = strlen(prefix);
    size_t i;

    if (len != plen + 64) return -1;
    if (memcmp(v, prefix, plen) != 0) return -1;
    v += plen;
    for (i = 0; i < 32; i++) {
        int hi, lo;
        char a = v[2 * i], b = v[2 * i + 1];
        hi = (a >= '0' && a <= '9') ? a - '0' : (a >= 'a' && a <= 'f') ? a - 'a' + 10 : -1;
        lo = (b >= '0' && b <= '9') ? b - '0' : (b >= 'a' && b <= 'f') ? b - 'a' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void set_str(char *dst, size_t cap, const char *v, size_t len);

// A peer can advertise a dozen endpoints and we only have room for a few, so
// the ones we keep have to be the ones most likely to yield a direct path.
//
// A peer sitting on our own network wins outright: no NAT is involved, the
// latency is a millisecond, and it always works. It also rescues the case
// where a peer shares our public address, since routers commonly refuse to
// hairpin a packet back in through their own external side.
//
// Public IPv4 comes next, because that is what hole punching uses. Private
// addresses on some other network are nearly always stale. IPv6 is last,
// because we cannot even send to it on this build.
#define EP_SCORE_OUR_LAN    4
#define EP_SCORE_PUBLIC_V4  3
#define EP_SCORE_PRIVATE_V4 2
#define EP_SCORE_V6         1

static uint8_t s_local_v4[4];
static uint8_t s_local_prefix;      // 0 means "not known"

void ts_netmap_set_local_v4(const uint8_t v4[4], uint8_t prefix_len) {
    memcpy(s_local_v4, v4, 4);
    s_local_prefix = prefix_len;
}

static int on_our_network(unsigned a, unsigned b, unsigned c, unsigned d) {
    uint32_t ours, theirs, mask;
    if (!s_local_prefix || s_local_prefix > 32) return 0;
    ours = ((uint32_t)s_local_v4[0] << 24) | ((uint32_t)s_local_v4[1] << 16) |
           ((uint32_t)s_local_v4[2] << 8) | s_local_v4[3];
    theirs = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
    mask = s_local_prefix == 32 ? 0xffffffffu
                                : ~((1u << (32 - s_local_prefix)) - 1);
    return (ours & mask) == (theirs & mask);
}

static int endpoint_score(const char *v, size_t len) {
    unsigned a, b, c, d, port;
    char tmp[TS_ADDR_STR];

    if (len >= TS_ADDR_STR) return EP_SCORE_V6;
    memcpy(tmp, v, len);
    tmp[len] = '\0';
    if (tmp[0] == '[') return EP_SCORE_V6;
    if (sscanf(tmp, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &port) != 5) return EP_SCORE_V6;
    if (a == 127) return 0;                                            // useless
    if (on_our_network(a, b, c, d)) return EP_SCORE_OUR_LAN;
    if (a == 10) return EP_SCORE_PRIVATE_V4;
    if (a == 192 && b == 168) return EP_SCORE_PRIVATE_V4;
    if (a == 172 && b >= 16 && b <= 31) return EP_SCORE_PRIVATE_V4;
    if (a == 169 && b == 254) return EP_SCORE_PRIVATE_V4;
    if (a == 100 && b >= 64 && b <= 127) return EP_SCORE_PRIVATE_V4;   // CGNAT
    return EP_SCORE_PUBLIC_V4;
}

// Keeps the best TS_MAX_ENDPOINTS seen so far, evicting the weakest.
static void peer_add_endpoint(ts_peer *pe, const char *v, size_t len) {
    int score = endpoint_score(v, len);
    int i, worst = 0;

    if (score == 0) return;
    if (pe->nendpoints < TS_MAX_ENDPOINTS) {
        pe->endpoint_score[pe->nendpoints] = (uint8_t)score;
        set_str(pe->endpoints[pe->nendpoints], TS_ADDR_STR, v, len);
        pe->nendpoints++;
        return;
    }
    for (i = 1; i < TS_MAX_ENDPOINTS; i++)
        if (pe->endpoint_score[i] < pe->endpoint_score[worst]) worst = i;
    if (pe->endpoint_score[worst] < score) {
        pe->endpoint_score[worst] = (uint8_t)score;
        set_str(pe->endpoints[worst], TS_ADDR_STR, v, len);
    }
    pe->dropped_endpoints++;
}

static void set_str(char *dst, size_t cap, const char *v, size_t len) {
    if (len >= cap) len = cap - 1;
    memcpy(dst, v, len);
    dst[len] = '\0';
}

// A one-shot fetch answers with "Peers"; a streaming session answers with
// "PeersChanged" instead, and sends "Peers" only rarely. Both carry complete
// Node objects, so both are handled the same way here. Getting this wrong is
// invisible in a one-shot test and produces an empty peer list in the mode
// the device actually runs.
static int is_peer_object(const char *path, int *from_changed) {
    if (strcmp(path, "Peers[]") == 0)        { *from_changed = 0; return 1; }
    if (strcmp(path, "PeersChanged[]") == 0) { *from_changed = 1; return 1; }
    return 0;
}

// Returns the field name inside a peer object, or NULL if the path is not
// inside one.
static const char *peer_field(const char *path) {
    if (strncmp(path, "Peers[].", 8) == 0) return path + 8;
    if (strncmp(path, "PeersChanged[].", 15) == 0) return path + 15;
    return NULL;
}

static void on_enter(void *ctx, const char *path, int is_array) {
    ts_netmap_parser *p = (ts_netmap_parser *)ctx;
    int from_changed;
    if (!is_array && is_peer_object(path, &from_changed)) {
        memset(&p->peer, 0, sizeof(p->peer));
        p->peer.from_changed = from_changed;
        p->in_peer = 1;
    }
}

static void on_leave(void *ctx, const char *path, int is_array) {
    ts_netmap_parser *p = (ts_netmap_parser *)ctx;
    int from_changed;
    if (!is_array && is_peer_object(path, &from_changed) && p->in_peer) {
        p->in_peer = 0;
        p->info.peer_count++;
        if (p->peer_cb) p->peer_cb(p->cb_ctx, &p->peer);
    }
}

static uint64_t parse_u64(const char *v, size_t len) {
    char tmp[24];
    if (len >= sizeof(tmp)) return 0;
    memcpy(tmp, v, len);
    tmp[len] = '\0';
    return strtoull(tmp, NULL, 10);
}

static void on_value(void *ctx, const char *path, const char *v, size_t len,
                     json_type type, int truncated) {
    ts_netmap_parser *p = (ts_netmap_parser *)ctx;
    ts_peer *pe = &p->peer;
    const char *field;
    (void)truncated;

    // Peers that went away, so the caller can tear their tunnels down.
    if (strcmp(path, "PeersRemoved[]") == 0 && type == JSON_NUMBER) {
        if (p->removed_cb) p->removed_cb(p->cb_ctx, parse_u64(v, len));
        return;
    }
    if (strncmp(path, "PeersChangedPatch[]", 19) == 0) {
        // Counted, not applied: see ts_netmap_info.unapplied_patches.
        if (strcmp(path, "PeersChangedPatch[].NodeID") == 0) p->info.unapplied_patches++;
        return;
    }
    if (strcmp(path, "Node.ID") == 0 && type == JSON_NUMBER) {
        p->info.self_id = parse_u64(v, len);
        return;
    }

    // --- our own node ---
    if (strcmp(path, "Node.Addresses[]") == 0 && type == JSON_STRING) {
        if (p->info.self_naddrs < TS_MAX_ADDRS)
            set_str(p->info.self_addrs[p->info.self_naddrs++], TS_ADDR_STR, v, len);
        return;
    }
    if (type == JSON_STRING &&
        (strcmp(path, "Node.ComputedName") == 0 ||
         (strcmp(path, "Node.Name") == 0 && p->info.self_name[0] == '\0'))) {
        set_str(p->info.self_name, TS_NAME_STR, v, len);
        return;
    }
    // Whether the control plane took the disco key we sent decides whether
    // any peer will even look at our DISCO packets.
    if (strcmp(path, "Node.DiscoKey") == 0 && type == JSON_STRING) {
        p->info.self_has_disco = 1;
        return;
    }
    // "100.x.y.z/32" and "fd7a:.../128" are our own addresses; a shorter
    // prefix is a network, which means an approved subnet route.
    if (strcmp(path, "Node.AllowedIPs[]") == 0 && type == JSON_STRING) {
        int host_addr = (len > 3 && memcmp(v + len - 3, "/32", 3) == 0) ||
                        (len > 4 && memcmp(v + len - 4, "/128", 4) == 0);
        p->info.self_has_allowed_ips = 1;
        if (!host_addr && p->info.self_nroutes < TS_MAX_SELF_ROUTES)
            set_str(p->info.self_routes[p->info.self_nroutes++], TS_ADDR_STR, v, len);
        return;
    }
    if (strcmp(path, "Node.Endpoints[]") == 0 && type == JSON_STRING) {
        if (p->info.self_nendpoints < TS_MAX_ENDPOINTS)
            set_str(p->info.self_endpoints[p->info.self_nendpoints++],
                    TS_ADDR_STR, v, len);
        return;
    }
    // "DERPMap.Regions.<id>.Nodes[].HostName" - the region id is a map key,
    // so it appears in the path itself.
    if (strncmp(path, "DERPMap.Regions.", 16) == 0 && type == JSON_STRING) {
        const char *rest = path + 16;
        const char *dot = strchr(rest, '.');
        if (dot) {
            char idbuf[8];
            size_t idlen = (size_t)(dot - rest);
            int i, region;
            if (idlen && idlen < sizeof(idbuf)) {
                memcpy(idbuf, rest, idlen);
                idbuf[idlen] = '\0';
                region = atoi(idbuf);
                for (i = 0; i < p->info.nderp; i++)
                    if (p->info.derp[i].region_id == region) break;
                if (i == p->info.nderp && p->info.nderp < TS_MAX_DERP_REGIONS) {
                    memset(&p->info.derp[i], 0, sizeof(p->info.derp[i]));
                    p->info.derp[i].region_id = (uint16_t)region;
                    p->info.nderp++;
                }
                if (i < p->info.nderp) {
                    if (strcmp(dot, ".RegionCode") == 0)
                        set_str(p->info.derp[i].code, sizeof(p->info.derp[i].code), v, len);
                    // Keep the first node only; the others are alternates.
                    else if (strcmp(dot, ".Nodes[].HostName") == 0 &&
                             !p->info.derp[i].host[0])
                        set_str(p->info.derp[i].host, TS_DERP_HOST_STR, v, len);
                }
            }
        }
        return;
    }
    if (strcmp(path, "Domain") == 0 && type == JSON_STRING) {
        set_str(p->info.domain, TS_NAME_STR, v, len);
        return;
    }

    // --- peers ---
    if (!p->in_peer) return;
    field = peer_field(path);
    if (!field) return;

    if (strcmp(field, "ID") == 0 && type == JSON_NUMBER)
        pe->id = parse_u64(v, len);
    else if (strcmp(field, "Key") == 0 && type == JSON_STRING)
        pe->has_node_key = parse_prefixed_key(v, len, "nodekey:", pe->node_key) == 0;
    else if (strcmp(field, "DiscoKey") == 0 && type == JSON_STRING)
        pe->has_disco_key = parse_prefixed_key(v, len, "discokey:", pe->disco_key) == 0;
    else if (strcmp(field, "Addresses[]") == 0 && type == JSON_STRING) {
        if (pe->naddrs < TS_MAX_ADDRS)
            set_str(pe->addrs[pe->naddrs++], TS_ADDR_STR, v, len);
    } else if (strcmp(field, "Endpoints[]") == 0 && type == JSON_STRING) {
        peer_add_endpoint(pe, v, len);
    } else if (strcmp(field, "HomeDERP") == 0 && type == JSON_NUMBER) {
        char tmp[12];
        set_str(tmp, sizeof(tmp), v, len);
        pe->home_derp = (uint16_t)atoi(tmp);
    } else if (strcmp(field, "DERP") == 0 && type == JSON_STRING) {
        // The server still sends the region in the older form: a fake address
        // "127.3.3.40:N" whose port is the DERP region number. Reading only
        // HomeDERP leaves every peer looking like it has no relay at all.
        const char *colon = memchr(v, ':', len);
        if (colon && !pe->home_derp) {
            char tmp[8];
            size_t n = len - (size_t)(colon + 1 - v);
            if (n < sizeof(tmp)) {
                memcpy(tmp, colon + 1, n);
                tmp[n] = '\0';
                pe->home_derp = (uint16_t)atoi(tmp);
            }
        }
    } else if (strcmp(field, "Online") == 0) {
        pe->has_online = 1;
        pe->online = (type == JSON_TRUE);
    } else if (type == JSON_STRING &&
               (strcmp(field, "ComputedName") == 0 ||
                (strcmp(field, "Name") == 0 && pe->name[0] == '\0'))) {
        set_str(pe->name, TS_NAME_STR, v, len);
    }
}

void ts_netmap_parser_init(ts_netmap_parser *p, ts_peer_cb cb, void *ctx) {
    memset(p, 0, sizeof(*p));
    p->peer_cb = cb;
    p->cb_ctx = ctx;
}

void ts_netmap_parser_on_message(ts_netmap_parser *p, ts_netmap_msg_cb cb) {
    p->msg_cb = cb;
}

void ts_netmap_parser_on_raw(ts_netmap_parser *p, ts_netmap_raw_cb cb) {
    p->raw_cb = cb;
}

void ts_netmap_parser_on_removed(ts_netmap_parser *p, ts_peer_removed_cb cb) {
    p->removed_cb = cb;
}

// Each message gets a fresh JSON parser; the framer decides where one ends.
static void start_message(ts_netmap_parser *p) {
    json_stream_cbs cbs;
    // Per-message, not cumulative: each netmap restates our own record.
    p->info.self_nendpoints = 0;
    p->info.self_naddrs = 0;
    p->info.self_nroutes = 0;
    p->info.self_has_allowed_ips = 0;
    p->info.self_has_disco = 0;
    p->info.nderp = 0;
    cbs.on_value = on_value;
    cbs.on_enter = on_enter;
    cbs.on_leave = on_leave;
    cbs.ctx = p;
    json_stream_init(&p->js, &cbs);
    p->in_peer = 0;
}

int ts_netmap_feed(ts_netmap_parser *p, const uint8_t *data, size_t len) {
    size_t i = 0;

    if (p->error) return -1;
    if (p->stop) return 1;

    while (i < len) {
        if (!p->in_message) {
            // Accumulate the 4-byte little-endian length.
            while (i < len && p->size_len < 4) p->size_buf[p->size_len++] = data[i++];
            if (p->size_len < 4) return 0;
            p->msg_remaining = (uint32_t)p->size_buf[0] |
                               ((uint32_t)p->size_buf[1] << 8) |
                               ((uint32_t)p->size_buf[2] << 16) |
                               ((uint32_t)p->size_buf[3] << 24);
            p->size_len = 0;
            p->in_message = 1;
            p->info.message_count++;
            start_message(p);
            if (p->msg_remaining == 0) {      // keep-alive style empty message
                p->in_message = 0;
                if (p->msg_cb && p->msg_cb(p->cb_ctx, &p->info)) { p->stop = 1; return 1; }
                continue;
            }
        }

        {
            size_t take = len - i;
            if (take > p->msg_remaining) take = p->msg_remaining;
            if (p->raw_cb) p->raw_cb(p->cb_ctx, p->info.message_count, data + i, take);
            if (json_stream_feed(&p->js, data + i, take) != 0) {
                p->error = -1;
                return -1;
            }
            i += take;
            p->msg_remaining -= (uint32_t)take;
            if (p->msg_remaining == 0) {
                p->in_message = 0;
                if (json_stream_finish(&p->js) != 0) { p->error = -1; return -1; }
                if (p->msg_cb && p->msg_cb(p->cb_ctx, &p->info)) { p->stop = 1; return 1; }
            }
        }
    }
    return 0;
}
