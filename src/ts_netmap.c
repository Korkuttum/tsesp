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
// Public IPv4 wins: it is what NAT hole punching actually uses. A private
// IPv4 is next, because a peer on the same LAN is the best case of all. IPv6
// is last only because home ISPs here still break it more often than not.
#define EP_SCORE_PUBLIC_V4  3
#define EP_SCORE_PRIVATE_V4 2
#define EP_SCORE_V6         1

static int endpoint_score(const char *v, size_t len) {
    unsigned a, b, c, d, port;
    char tmp[TS_ADDR_STR];

    if (len >= TS_ADDR_STR) return EP_SCORE_V6;
    memcpy(tmp, v, len);
    tmp[len] = '\0';
    if (tmp[0] == '[') return EP_SCORE_V6;
    if (sscanf(tmp, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &port) != 5) return EP_SCORE_V6;
    if (a == 10) return EP_SCORE_PRIVATE_V4;
    if (a == 192 && b == 168) return EP_SCORE_PRIVATE_V4;
    if (a == 172 && b >= 16 && b <= 31) return EP_SCORE_PRIVATE_V4;
    if (a == 169 && b == 254) return EP_SCORE_PRIVATE_V4;
    if (a == 100 && b >= 64 && b <= 127) return EP_SCORE_PRIVATE_V4;   // CGNAT
    if (a == 127) return 0;                                            // useless
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

static void on_enter(void *ctx, const char *path, int is_array) {
    ts_netmap_parser *p = (ts_netmap_parser *)ctx;
    if (!is_array && strcmp(path, "Peers[]") == 0) {
        memset(&p->peer, 0, sizeof(p->peer));
        p->in_peer = 1;
    }
}

static void on_leave(void *ctx, const char *path, int is_array) {
    ts_netmap_parser *p = (ts_netmap_parser *)ctx;
    if (!is_array && strcmp(path, "Peers[]") == 0 && p->in_peer) {
        p->in_peer = 0;
        p->info.peer_count++;
        if (p->peer_cb) p->peer_cb(p->cb_ctx, &p->peer);
    }
}

static void on_value(void *ctx, const char *path, const char *v, size_t len,
                     json_type type, int truncated) {
    ts_netmap_parser *p = (ts_netmap_parser *)ctx;
    ts_peer *pe = &p->peer;
    (void)truncated;

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
    if (strcmp(path, "Domain") == 0 && type == JSON_STRING) {
        set_str(p->info.domain, TS_NAME_STR, v, len);
        return;
    }

    // --- peers ---
    if (!p->in_peer) return;

    if (strcmp(path, "Peers[].Key") == 0 && type == JSON_STRING)
        pe->has_node_key = parse_prefixed_key(v, len, "nodekey:", pe->node_key) == 0;
    else if (strcmp(path, "Peers[].DiscoKey") == 0 && type == JSON_STRING)
        pe->has_disco_key = parse_prefixed_key(v, len, "discokey:", pe->disco_key) == 0;
    else if (strcmp(path, "Peers[].Addresses[]") == 0 && type == JSON_STRING) {
        if (pe->naddrs < TS_MAX_ADDRS)
            set_str(pe->addrs[pe->naddrs++], TS_ADDR_STR, v, len);
    } else if (strcmp(path, "Peers[].Endpoints[]") == 0 && type == JSON_STRING) {
        peer_add_endpoint(pe, v, len);
    } else if (strcmp(path, "Peers[].HomeDERP") == 0 && type == JSON_NUMBER) {
        char tmp[12];
        set_str(tmp, sizeof(tmp), v, len);
        pe->home_derp = (uint16_t)atoi(tmp);
    } else if (strcmp(path, "Peers[].Online") == 0) {
        pe->has_online = 1;
        pe->online = (type == JSON_TRUE);
    } else if (type == JSON_STRING &&
               (strcmp(path, "Peers[].ComputedName") == 0 ||
                (strcmp(path, "Peers[].Name") == 0 && pe->name[0] == '\0'))) {
        set_str(pe->name, TS_NAME_STR, v, len);
    }
}

void ts_netmap_parser_init(ts_netmap_parser *p, ts_peer_cb cb, void *ctx) {
    memset(p, 0, sizeof(*p));
    p->peer_cb = cb;
    p->cb_ctx = ctx;
}

// Each message gets a fresh JSON parser; the framer decides where one ends.
static void start_message(ts_netmap_parser *p) {
    json_stream_cbs cbs;
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
                continue;
            }
        }

        {
            size_t take = len - i;
            if (take > p->msg_remaining) take = p->msg_remaining;
            if (json_stream_feed(&p->js, data + i, take) != 0) {
                p->error = -1;
                return -1;
            }
            i += take;
            p->msg_remaining -= (uint32_t)take;
            if (p->msg_remaining == 0) {
                p->in_message = 0;
                if (json_stream_finish(&p->js) != 0) { p->error = -1; return -1; }
            }
        }
    }
    return 0;
}
