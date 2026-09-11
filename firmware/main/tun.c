#include <string.h>
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/ip4.h"
#include "lwip/pbuf.h"
#include "esp_log.h"
#include "tun.h"

static const char *TAG = "tun";

static struct netif s_netif;
static tun_send_fn  s_send;
static bool         s_up;
static uint32_t     s_in, s_out;

// Tailscale's own MTU. Leaves room for the WireGuard header inside a normal
// 1500-byte path without fragmenting.
#define TUN_MTU 1280

static err_t tun_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *dst) {
    uint8_t buf[TUN_MTU];
    uint16_t len;

    (void)netif;
    if (!s_send) return ERR_IF;
    if (p->tot_len > sizeof(buf)) return ERR_MEM;

    len = pbuf_copy_partial(p, buf, p->tot_len, 0);
    if (len != p->tot_len) return ERR_BUF;

    if (s_send(buf, len, dst->addr) != 0) return ERR_RTE;
    s_out++;
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
    return 0;
}

void tun_input(const uint8_t *ip_packet, size_t len) {
    struct pbuf *p;

    if (!s_up || len == 0 || len > TUN_MTU) return;
    // Only IPv4 for now; the device has no IPv6 address on the tailnet side
    // that anything uses yet.
    if ((ip_packet[0] >> 4) != 4) return;

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
