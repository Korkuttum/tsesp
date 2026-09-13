#include <string.h>
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/ip4.h"
#include "lwip/pbuf.h"
#include "lwip/lwip_napt.h"
#include "lwip/stats.h"
#include "esp_log.h"
#include "tun.h"

// Both options come from sdkconfig.defaults, which ESP-IDF reads only when it
// creates sdkconfig - so a build tree from before they were added drops them
// silently and subnet routing is compiled out with nothing to say so. It used
// to surface as a link error on ip_napt_enable; this says it sooner, and says
// what to do.
#if !defined(CONFIG_LWIP_IP_FORWARD) || !defined(CONFIG_LWIP_IPV4_NAPT)
#error "CONFIG_LWIP_IP_FORWARD / CONFIG_LWIP_IPV4_NAPT are off. Delete firmware/sdkconfig and build again so sdkconfig.defaults is applied; subnet routing needs both."
#endif

static const char *TAG = "tun";

static struct netif s_netif;
static tun_send_fn  s_send;
static bool         s_up;
static uint32_t     s_in, s_out;
static uint32_t     s_our_ip;        // our own tailnet address, network order

// Subnet routing is the one path that fails silently. A packet for a LAN
// address is handed to lwIP exactly like a packet for us, and from there on
// everything happens inside the stack: if the route was never approved the
// packet never arrives at all, and if the LAN host is off or firewalled the
// reply never comes back - and both look identical from outside, which is
// "ping does not work" with nothing in the log to say which half is broken.
// These three counters separate them.
static uint32_t     s_fwd_in;        // arrived for some address that is not ours
static uint32_t     s_fwd_out;       // left here on behalf of a LAN address
static uint32_t     s_too_big;       // dropped: longer than the tunnel MTU
static bool         s_logged_first_fwd;

// Tailscale's own MTU. Leaves room for the WireGuard header inside a normal
// 1500-byte path without fragmenting.
#define TUN_MTU 1280

static err_t tun_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *dst) {
    uint8_t buf[TUN_MTU];
    uint16_t len;

    (void)netif;
    if (!s_send) return ERR_IF;
    if (p->tot_len > sizeof(buf)) { s_too_big++; return ERR_MEM; }

    len = pbuf_copy_partial(p, buf, p->tot_len, 0);
    if (len != p->tot_len) return ERR_BUF;

    if (s_send(buf, len, dst->addr) != 0) return ERR_RTE;
    s_out++;
    // Runs on the lwIP thread, so this counts and says nothing. A packet
    // whose source is not our own address is one NAPT rewrote on the way
    // back from the LAN: proof the far half of subnet routing answered.
    if (len >= 20) {
        uint32_t src;
        memcpy(&src, buf + 12, 4);
        if (src != s_our_ip) s_fwd_out++;
    }
    return ERR_OK;
}

static err_t tun_netif_init(struct netif *netif) {
    netif->name[0] = 't';
    netif->name[1] = 's';
    netif->output = tun_output;
    netif->linkoutput = NULL;        // not an ethernet interface
    netif->mtu = TUN_MTU;
    // No ARP and no broadcast: this is a point-to-multipoint IP tunnel.
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

int tun_start(uint32_t our_ip_be, tun_send_fn send) {
    ip4_addr_t ip, mask, gw;

    s_send = send;
    s_our_ip = our_ip_be;
    ip.addr = our_ip_be;
    // 255.192.0.0 is 100.64.0.0/10, the whole tailnet range, so packets for
    // any peer are handed to this interface rather than the default route.
    IP4_ADDR(&mask, 255, 192, 0, 0);
    IP4_ADDR(&gw, 0, 0, 0, 0);

    if (!netif_add(&s_netif, &ip, &mask, &gw, NULL, tun_netif_init, tcpip_input)) {
        ESP_LOGE(TAG, "netif_add failed");
        return -1;
    }
    netif_set_up(&s_netif);
    netif_set_link_up(&s_netif);
    s_up = true;

    {
        const uint8_t *b = (const uint8_t *)&ip.addr;
        ESP_LOGI(TAG, "interface up: %u.%u.%u.%u/10, mtu %d",
                 b[0], b[1], b[2], b[3], TUN_MTU);
    }

    // Masquerading goes on THIS interface, not on the Wi-Fi one, and the
    // difference is the whole feature. esp-lwip translates a forwarded packet
    // only when the interface it arrived on carries the flag and the one it
    // leaves by does not: ip4_forward wraps the call in `if (!netif->napt)`
    // with netif the outgoing interface, and ip_napt_forward itself opens with
    // `if (!inp->napt) return ERR_OK`. Traffic for the LAN arrives here, so
    // the flag belongs here; the new source address is then taken from the
    // outgoing interface, which is what lets a LAN machine that has never
    // heard of a tailnet reply to an address on its own network.
    //
    // Setting it on the Wi-Fi side does not merely fail to help - it is the
    // one value that suppresses the translation altogether, and it
    // masquerades the LAN's own traffic into the tailnet instead: the
    // opposite direction, which is not what a subnet router is for.
    ip_napt_enable(our_ip_be, 1);
    ESP_LOGI(TAG, "NAPT on the tunnel side; forwarded packets will leave "
                  "as if they came from this device");

    // ip_napt_enable() finds the interface by its address and says nothing at
    // all when it finds none, so the line above can be a lie. Print what the
    // flags actually are: exactly one interface should carry napt, and it has
    // to be this one. Reading it off the stack beats trusting the call.
    {
        struct netif *n;
        for (n = netif_list; n; n = n->next) {
            uint32_t a = ip4_addr_get_u32(netif_ip4_addr(n));
            const uint8_t *b = (const uint8_t *)&a;
            ESP_LOGI(TAG, "  netif %c%c%d  %u.%u.%u.%u  up=%d  napt=%d",
                     n->name[0], n->name[1], n->num,
                     b[0], b[1], b[2], b[3],
                     netif_is_up(n) ? 1 : 0, n->napt ? 1 : 0);
        }
    }
    return 0;
}

void tun_input(const uint8_t *ip_packet, size_t len) {
    struct pbuf *p;

    if (!s_up || len == 0 || len > TUN_MTU) return;
    // Only IPv4 for now; the device has no IPv6 address on the tailnet side
    // that anything uses yet.
    if ((ip_packet[0] >> 4) != 4) return;

    // Addressed to someone else: a peer is using us as a subnet router. Say
    // so once, because the first such packet is the answer to the only
    // question worth asking when remote access to the LAN does not work -
    // whether the route reached the peer at all. Everything after that is a
    // counter; a log line per forwarded packet would drown the console.
    if (len >= 20) {
        uint32_t dst, src;
        memcpy(&src, ip_packet + 12, 4);
        memcpy(&dst, ip_packet + 16, 4);
        if (dst != s_our_ip) {
            const uint8_t *s = (const uint8_t *)&src, *d = (const uint8_t *)&dst;
            s_fwd_in++;
            if (!s_logged_first_fwd) {
                s_logged_first_fwd = true;
                ESP_LOGI(TAG, "routing for the tailnet: %u.%u.%u.%u -> %u.%u.%u.%u "
                              "(subnet route is in use)",
                         s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]);
            }
        }
    }

    p = pbuf_alloc(PBUF_RAW, (uint16_t)len, PBUF_RAM);
    if (!p) return;
    memcpy(p->payload, ip_packet, len);

    // Posts to the lwIP thread; calling ip_input from here would race.
    if (s_netif.input(p, &s_netif) != ERR_OK) {
        pbuf_free(p);
        return;
    }
    s_in++;
}

bool tun_is_up(void) { return s_up; }

void tun_stats(uint32_t *in, uint32_t *out) {
    if (in) *in = s_in;
    if (out) *out = s_out;
}

void tun_ip_stats(uint32_t *fw, uint32_t *rterr, uint32_t *drop) {
#if LWIP_STATS && IP_STATS
    if (fw)    *fw    = lwip_stats.ip.fw;
    if (rterr) *rterr = lwip_stats.ip.rterr;
    if (drop)  *drop  = lwip_stats.ip.drop;
#else
    if (fw) *fw = 0; if (rterr) *rterr = 0; if (drop) *drop = 0;
#endif
}

void tun_route_stats(uint32_t *fwd_in, uint32_t *fwd_out, uint32_t *too_big) {
    if (fwd_in) *fwd_in = s_fwd_in;
    if (fwd_out) *fwd_out = s_fwd_out;
    if (too_big) *too_big = s_too_big;
}
