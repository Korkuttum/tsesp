#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "errno.h"
#include "esp_netif.h"
#include "magic.h"
#include "stun.h"
#include "disco.h"

static const char *TAG = "magic";

static int             s_sock = -1;
static ts_path_engine *s_eng;
// The control task feeds peers in while the magic task ticks and receives.
// Both mutate the engine, so every entry point takes this.
static SemaphoreHandle_t s_lock;

// STUN is driven from the magic task rather than the caller's: two tasks
// reading one socket means whoever calls recvfrom first eats the reply, and
// the answer we want would be swallowed by the receive loop.
static volatile bool s_stun_wanted;
static uint8_t       s_stun_txid[STUN_TXID_LEN];
static bool          s_stun_inflight;
static uint32_t      s_stun_sent_ms;
static char          s_public[48];
// Counts every datagram the socket sees, before any parsing. Without it
// "no pongs" cannot be told apart from "nothing arrives at all".
static uint32_t      s_rx_packets;
static int           s_stun_tries;

#define LOCK()   xSemaphoreTake(s_lock, portMAX_DELAY)
#define UNLOCK() xSemaphoreGive(s_lock)

// ------------------------------------------------------------ engine glue

static int env_send(void *ctx, const uint8_t ip[16], uint16_t port,
                    const uint8_t *pkt, size_t len) {
    struct sockaddr_in dst = {0};
    uint8_t v4[4];
    (void)ctx;

    // IPv6 candidates are parsed and scored but not sent: lwIP here is
    // configured for v4 only, and pretending otherwise would waste probes.
    if (!disco_is_ipv4_mapped(ip, v4)) return -1;
    if (s_sock < 0) return -1;

    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    memcpy(&dst.sin_addr, v4, 4);
    if (sendto(s_sock, pkt, len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
        return -1;
    return 0;
}

static uint32_t env_now(void *ctx) {
    (void)ctx;
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static void env_random(void *ctx, uint8_t *out, size_t n) {
    (void)ctx;
    esp_fill_random(out, n);
}

static void on_path_change(void *ctx, const ts_path_peer *peer, const ts_path *best) {
    uint8_t v4[4];
    (void)ctx;
    if (best && disco_is_ipv4_mapped(best->ip, v4)) {
        ESP_LOGI(TAG, "peer %llu: direct path %u.%u.%u.%u:%u (%u ms)",
                 (unsigned long long)peer->id, v4[0], v4[1], v4[2], v4[3],
                 best->port, best->latency_ms);
    } else if (!best) {
        ESP_LOGW(TAG, "peer %llu: no direct path", (unsigned long long)peer->id);
    }
}

// ------------------------------------------------------------- endpoints

// Turns "1.2.3.4:41641" into bytes. IPv6 forms are rejected here rather than
// half-parsed.
static bool parse_endpoint(const char *s, uint8_t ip[16], uint16_t *port) {
    unsigned a, b, c, d, p;
    uint8_t v4[4];

    if (s[0] == '[') return false;
    if (sscanf(s, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &p) != 5) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255 || p == 0 || p > 65535) return false;
    v4[0] = (uint8_t)a; v4[1] = (uint8_t)b; v4[2] = (uint8_t)c; v4[3] = (uint8_t)d;
    disco_ipv4_mapped(ip, v4);
    *port = (uint16_t)p;
    return true;
}

void magic_sync_peers(void) {
    int i, n = peers_count();

    if (!s_eng) return;
    LOCK();
    for (i = 0; i < n; i++) {
        peer_entry *e = peers_at(i);
        int pi, j;
        if (!e || !e->has_disco) continue;

        pi = ts_path_add_peer(s_eng, e->id, e->disco_key, NULL, e->home_derp);
        if (pi < 0) continue;
        e->path_index = pi;

        for (j = 0; j < e->nendpoints; j++) {
            uint8_t ip[16];
            uint16_t port;
            if (parse_endpoint(e->endpoints[j], ip, &port)) {
                ts_path_add_candidate(s_eng, pi, ip, port, 3);
                if (!e->logged_candidates)
                    ESP_LOGI(TAG, "  candidate %-24s for %s",
                             e->endpoints[j], e->name);
            } else if (!e->logged_candidates) {
                ESP_LOGI(TAG, "  skipping  %-24s for %s (not IPv4)",
                         e->endpoints[j], e->name);
            }
        }
        e->logged_candidates = true;
    }
    UNLOCK();
}

int magic_paths_up(void) {
    int i, n = peers_count(), up = 0;
    if (!s_eng) return 0;
    LOCK();
    for (i = 0; i < n; i++) {
        peer_entry *e = peers_at(i);
        if (e && e->path_index >= 0 && ts_path_best(s_eng, e->path_index)) up++;
    }
    UNLOCK();
    return up;
}

const ts_path *magic_best_for(const peer_entry *p) {
    if (!s_eng || !p || p->path_index < 0) return NULL;
    return ts_path_best(s_eng, p->path_index);
}

void magic_stats(uint32_t *pings, uint32_t *pongs) {
    if (pings) *pings = s_eng ? s_eng->pings_sent : 0;
    if (pongs) *pongs = s_eng ? s_eng->pongs_received : 0;
}

// ----------------------------------------------------------------- STUN

void magic_request_stun(void) { s_stun_tries = 0; s_stun_wanted = true; }

bool magic_get_public(char *out, size_t cap) {
    if (!s_public[0]) return false;
    snprintf(out, cap, "%s", s_public);
    return true;
}

// Sends one binding request from the DISCO socket. The reply is picked up by
// the receive loop below, which is the only reader of this socket.
static const struct { const char *host; const char *port; } kStunServers[] = {
    { "derp1.tailscale.com",  "3478"  },
    { "derp2.tailscale.com",  "3478"  },
    // Fallbacks. Some ISPs blackhole Tailscale's DERP hosts on UDP while
    // leaving the rest of the internet alone, and a device that cannot learn
    // its own address cannot be reached from outside.
    { "stun.l.google.com",    "19302" },
    { "stun.cloudflare.com",  "3478"  },
};
#define STUN_SERVER_COUNT (sizeof(kStunServers)/sizeof(kStunServers[0]))

static void stun_send(void) {
    static int which;
    struct addrinfo hints, *res;
    uint8_t req[STUN_HEADER_LEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    {
        int idx = which % (int)STUN_SERVER_COUNT;
        which++;
        if (getaddrinfo(kStunServers[idx].host, kStunServers[idx].port,
                        &hints, &res) != 0)
            return;
        ESP_LOGI(TAG, "STUN -> %s:%s", kStunServers[idx].host, kStunServers[idx].port);
    }

    esp_fill_random(s_stun_txid, sizeof(s_stun_txid));
    stun_build_request(req, s_stun_txid);
    sendto(s_sock, req, sizeof(req), 0, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    s_stun_inflight = true;
    s_stun_sent_ms = env_now(NULL);
}

// ------------------------------------------------------------------ task

// Sends a datagram to our own address. If it does not come back, the fault is
// in the socket or the task, not in anybody's NAT.
static void loopback_probe(void) {
    esp_netif_ip_info_t ip;
    esp_netif_t *nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    struct sockaddr_in dst = {0};
    static const uint8_t probe[8] = { 'l','o','o','p','b','a','c','k' };

    if (!nif || esp_netif_get_ip_info(nif, &ip) != ESP_OK) return;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(MAGIC_PORT);
    dst.sin_addr.s_addr = ip.ip.addr;
    if (sendto(s_sock, probe, sizeof(probe), 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0)
        ESP_LOGW(TAG, "loopback probe send failed: errno %d", errno);
    else
        ESP_LOGI(TAG, "loopback probe sent to self:%d", MAGIC_PORT);
}

static void magic_task(void *arg) {
    uint8_t buf[1600];
    uint32_t last_report = 0;
    bool probed = false;
    (void)arg;

    for (;;) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        int n = recvfrom(s_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
        uint32_t now = env_now(NULL);

        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            ESP_LOGW(TAG, "recvfrom errno %d", errno);
        if (!probed && now > 8000) { probed = true; loopback_probe(); }

        if (n > 0) {
            uint8_t src[16];
            uint8_t addr[16];
            s_rx_packets++;
            ESP_LOGD(TAG, "rx %d bytes from %s:%u", n,
                     inet_ntoa(from.sin_addr), ntohs(from.sin_port));
            int is6 = 0;
            uint16_t port = 0;

            if (s_stun_inflight && stun_looks_like_stun(buf, (size_t)n) &&
                stun_parse_response(buf, (size_t)n, s_stun_txid, addr, &is6, &port) == 0) {
                s_stun_inflight = false;
                stun_format_addr(s_public, sizeof(s_public), addr, is6, port);
                ESP_LOGI(TAG, "this device looks like %s from outside", s_public);
            } else {
                // Everything else is DISCO, or WireGuard once that exists.
                disco_ipv4_mapped(src, (const uint8_t *)&from.sin_addr);
                LOCK();
                ts_path_on_datagram(s_eng, src, ntohs(from.sin_port), buf, (size_t)n);
                UNLOCK();
            }
        }

        if (s_stun_wanted && !s_stun_inflight) {
            s_stun_wanted = false;
            stun_send();
        }
        if (s_stun_inflight && now - s_stun_sent_ms > 3000) {
            s_stun_inflight = false;
            if (++s_stun_tries < (int)STUN_SERVER_COUNT * 2) {
                s_stun_wanted = true;          // try the next server
            } else {
                ESP_LOGW(TAG, "no STUN server answered; peers will only be able "
                              "to reach us on the local network");
            }
        }

        // The engine needs a heartbeat even when nothing arrives: probes,
        // keepalives and expiry all happen here.
        LOCK();
        ts_path_tick(s_eng);
        UNLOCK();

        // Without this the probing is completely silent and a run that finds
        // nothing looks the same as a run that never tried.
        if (now - last_report > 15000) {
            last_report = now;
            ESP_LOGI(TAG, "paths %d/%d up | tx ping %u | rx packets %u (pong %u, unknown %u)",
                     magic_paths_up(), peers_count(),
                     (unsigned)s_eng->pings_sent, (unsigned)s_rx_packets,
                     (unsigned)s_eng->pongs_received,
                     (unsigned)s_eng->unknown_senders);
        }
    }
}

int magic_start(const uint8_t disco_priv[32], const uint8_t node_pub[32]) {
    struct sockaddr_in addr = {0};
    ts_path_env env;
    struct timeval tv = { 0, 250000 };     // wake often enough to tick

    s_eng = calloc(1, sizeof(*s_eng));
    if (!s_eng) return -1;
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) { free(s_eng); s_eng = NULL; return -1; }

    s_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_sock < 0) { free(s_eng); s_eng = NULL; return -1; }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(MAGIC_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "cannot bind udp %d", MAGIC_PORT);
        close(s_sock);
        s_sock = -1;
        free(s_eng);
        s_eng = NULL;
        return -1;
    }
    setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&env, 0, sizeof(env));
    env.send_udp = env_send;
    env.now_ms = env_now;
    env.random = env_random;
    env.on_path_change = on_path_change;
    ts_path_init(s_eng, &env, disco_priv, node_pub);

    xTaskCreate(magic_task, "magic", 4096, NULL, 5, NULL);
    ESP_LOGI(TAG, "udp socket up on port %d", MAGIC_PORT);
    return 0;
}
