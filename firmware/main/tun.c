#include <string.h>
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/ip4.h"
#include "lwip/pbuf.h"
#include "lwip/lwip_napt.h"
#include "lwip/stats.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_log.h"
#include "tun.h"
#include "nat.h"
#include "esp_timer.h"

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
static uint32_t     s_trace_in, s_trace_out, s_trace_wifi;
static struct netif *s_sta_netif;
static uint32_t     s_sta_ip;
static uint32_t     s_trace_back, s_wifi_replies, s_untranslated;
static uint32_t     s_wifi_out_total, s_wifi_out_lan, s_gw_ip;
static uint32_t     s_fwd_dst_ip, s_fwd_reached_wifi, s_fwd_answered;
static uint32_t     s_port_log, s_port_log_in;
static uint32_t     s_csum_bad_in, s_csum_bad_out;
static uint32_t     s_input_calls;
static uint32_t     s_out_err_log;
static nat_table    s_nat;
// The reverse path rewrites in place, and a received pbuf can point straight
// at driver memory. This runs only in the Wi-Fi receive task, so one buffer
// is enough and it is not on anybody's stack.
static uint8_t      s_rx[1600];
static uint32_t     s_fwd_in;        // arrived for some address that is not ours
static uint32_t     s_fwd_out;       // left here on behalf of a LAN address

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }
static uint16_t     s_fwd_dst_port;
static bool         s_hooked;
static err_t (*s_sta_input)(struct pbuf *, struct netif *);
static err_t (*s_sta_output)(struct netif *, struct pbuf *, const ip4_addr_t *);

// Every packet the Wi-Fi interface is asked to send, after NAPT has had its
// say. A forwarded packet still carrying a 100.x source is one the rewrite
// did not touch, and the LAN machine that receives it will answer to an
// address its router cannot reach.
// Replies coming back off the LAN, before lwIP has looked at them. A web
// server answering a forwarded request sends from port 80, which is exactly
// what distinguishes it from this device's own conversations.
static err_t sta_input_trace(struct pbuf *p, struct netif *netif) {
    // Unconditional: proves the hook itself fires, independent of anything
    // this function goes on to parse.
    s_input_calls++;
    if (p->len >= 40) {
        const uint8_t *h = (const uint8_t *)p->payload;
        const uint8_t *ip = h;
        // esp_netif hands ethernet frames in; step over the header when present.
        if (netif->flags & NETIF_FLAG_ETHARP) {
            if (p->len < 54 || h[12] != 0x08 || h[13] != 0x00) goto out;
            ip = h + 14;
        }
        if ((ip[0] >> 4) == 4 && ip[9] == 6) {
            const uint8_t *tcp = ip + ((ip[0] & 0x0f) * 4);
            uint16_t sport = (uint16_t)((tcp[0] << 8) | tcp[1]);
            {
                // The mirror of "Hedefe ulaşan": a packet coming back from
                // the exact machine the last forwarded one went to. Together
                // the two say whether the target answered at all, which is
                // the question a packet capture on the LAN would answer.
                uint32_t srcip;
                memcpy(&srcip, ip + 12, 4);
                if (srcip == s_fwd_dst_ip) {
                    s_fwd_answered++;
                    if (s_port_log_in < 4) {
                        s_port_log_in++;
                        ESP_LOGW(TAG, "NAT-IN  from %u.%u.%u.%u:%u  dport=%u",
                                 ip[12], ip[13], ip[14], ip[15], (unsigned)sport,
                                 (unsigned)((tcp[2] << 8) | tcp[3]));
                    }
                }
            }
            if (sport == 80 && s_trace_back < 15) {
                s_trace_back++;
                s_wifi_replies++;
                ESP_LOGE(TAG, "WIFI-IN  %u.%u.%u.%u:80 -> %u.%u.%u.%u  "
                              "(a LAN server answered)",
                         ip[12], ip[13], ip[14], ip[15],
                         ip[16], ip[17], ip[18], ip[19]);
            }
        }
    }
    // The answer to something we forwarded. lwIP would see this device's own
    // address in the destination, accept it locally and drop it; instead put
    // the peer's address back and hand it straight to the tunnel.
    if (s_sta_ip && p->len >= 20 && p->len <= sizeof(s_rx)) {
        const uint8_t *h = (const uint8_t *)p->payload;
        size_t off = (netif->flags & NETIF_FLAG_ETHARP) ? 14 : 0;
        if (p->len > off + 20 && (h[off] >> 4) == 4) {
            uint16_t iplen = (uint16_t)(p->len - off);
            uint32_t peer = 0;
            memcpy(s_rx, h + off, iplen);
            if (nat_in(&s_nat, s_rx, iplen, s_sta_ip, now_ms(), &peer)) {
                if (s_send) {
                    s_send(s_rx, iplen, peer);
                    s_out++;
                    s_fwd_out++;
                }
                pbuf_free(p);
                return ERR_OK;
            }
        }
    }
out:
    return s_sta_input(p, netif);
}

static err_t sta_output_trace(struct netif *netif, struct pbuf *p,
                              const ip4_addr_t *dst) {
    // Only packets this device did not originate. Its own traffic carries the
    // station's address as source and would fill the budget in a second
    // without saying anything; a forwarded one whose source is still 100.x is
    // the whole question.
    s_wifi_out_total++;
    // A packet bound for another machine on this LAN - which is what a
    // forwarded one is. Counting only the untranslated ones left "zero"
    // meaning either "all were rewritten" or "none ever got here", and those
    // are not the same answer.
    if (p->len >= 20) {
        const uint8_t *h = (const uint8_t *)p->payload;
        uint32_t dstip;
        memcpy(&dstip, h + 16, 4);
        if ((h[0] >> 4) == 4 && dstip != s_sta_ip && dstip != s_gw_ip &&
            (dstip & 0x00ffffff) == (s_sta_ip & 0x00ffffff)) {
            // Counter only. This runs on the lwIP thread, and a log line per
            // forwarded packet writes to a UART from there - slow enough to
            // stall the stack and trip the watchdog. That is what rolled the
            // last image back.
            s_wifi_out_lan++;
            // The flow we are actually trying to forward, matched on both
            // address and port. Counting LAN-bound packets alone mixed in this
            // device's own HTTP replies and could not tell them apart.
            if (dstip == s_fwd_dst_ip && h[9] == 6 && p->len >= 24) {
                const uint8_t *tcp = h + ((h[0] & 0x0f) * 4);
                if ((uint16_t)((tcp[2] << 8) | tcp[3]) == s_fwd_dst_port) {
                    s_fwd_reached_wifi++;
                    // The source port NAPT picked, and the packet as it will
                    // actually appear on the wire - flags, header lengths,
                    // whatever a strict TCP stack might object to.
                    if (s_port_log < 4) {
                        size_t k, hl2 = (size_t)(h[0] & 0x0f) * 4;
                        size_t thl = (size_t)((tcp[12] >> 4) * 4);
                        char hex[3 * 96 + 1]; size_t hn = 0;
                        s_port_log++;
                        // dst is the address netif->output uses for ARP -
                        // separate from the IP header inside the packet. If
                        // NAT rewrote the header but this still names the old
                        // destination, the frame goes out addressed to the
                        // wrong MAC and nothing on the LAN ever sees it.
                        {
                            const uint8_t *da = (const uint8_t *)&dst->addr;
                            ESP_LOGW(TAG, "NAT-OUT sport=%u -> %u.%u.%u.%u:%u iphl=%u tcphl=%u flags=0x%02x len=%u  ARP-dst=%u.%u.%u.%u",
                                     (unsigned)((tcp[0] << 8) | tcp[1]),
                                     h[16], h[17], h[18], h[19],
                                     (unsigned)s_fwd_dst_port,
                                     (unsigned)hl2, (unsigned)thl, tcp[13], (unsigned)p->len,
                                     da[0], da[1], da[2], da[3]);
                        }
                        for (k = 0; k < p->len && k < 96 && hn < sizeof(hex) - 3; k++)
                            hn += snprintf(hex + hn, sizeof(hex) - hn, "%02x", h[k]);
                        ESP_LOGW(TAG, "NAT-OUT bytes: %s", hex);
                    }
                }
            }
        }
    }
    if (s_trace_wifi < 25 && p->len >= 20) {
        const uint8_t *h = (const uint8_t *)p->payload;
        uint32_t src;
        memcpy(&src, h + 12, 4);
        if ((h[0] >> 4) == 4 && src != s_sta_ip) {
            s_trace_wifi++;
            s_untranslated++;
            ESP_LOGE(TAG, "WIFI-OUT %u.%u.%u.%u -> %u.%u.%u.%u proto=%u"
                          "   <-- source not rewritten",
                     h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[9]);
        }
    }
    {
        // The one thing never checked: whether the driver actually accepted
        // this packet. ARP not yet resolved, a full TX queue, anything else -
        // all of it looks identical to a target that silently ignores us
        // unless the return value is read.
        err_t rc = s_sta_output(netif, p, dst);
        if (rc != ERR_OK && s_out_err_log < 8) {
            s_out_err_log++;
            ESP_LOGE(TAG, "WIFI-OUT driver refused, err=%d", (int)rc);
        }
        return rc;
    }
}
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
        if (src != s_our_ip) {
            s_fwd_out++;
            // Only traffic on behalf of the LAN. Our own tailnet chatter would
            // fill the log ring in a second and tell us nothing.
            if (s_trace_out < 40) {
                const uint8_t *a = buf + 12, *b = buf + 16;
                s_trace_out++;
                ESP_LOGW(TAG, "LAN->TS %u.%u.%u.%u -> %u.%u.%u.%u proto=%u len=%u",
                         a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3],
                         buf[9], (unsigned)len);
            }
        }
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
    // Wrap the Wi-Fi interface's output so we can see a forwarded packet as it
    // finally leaves. ip4_forward runs the NAPT rewrite and only then calls
    // netif->output, so this is the first and only place the source address
    // the LAN will actually see can be read. Everything upstream of here is
    // what we *intended* to send.
    {
        esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        struct netif *n = sta ? (struct netif *)esp_netif_get_netif_impl(sta) : NULL;
        if (n && !s_sta_output) {
            s_sta_netif = n;
            s_sta_ip = ip4_addr_get_u32(netif_ip4_addr(n));
            s_gw_ip = ip4_addr_get_u32(netif_ip4_gw(n));
            s_sta_output = n->output;
            n->output = sta_output_trace;
            s_sta_input = n->input;
            n->input = sta_input_trace;
            s_hooked = true;
            ESP_LOGI(TAG, "watching both directions on the wifi side");
        }
    }

    // esp-lwip's NAPT is deliberately left off. Its forward half worked and
    // its reverse half did not: the answer came back, was not recognised as
    // belonging to a mapping, kept this device's address and was dropped as
    // if it had been addressed here. Measured on the board, repeatedly. The
    // table in nat.c does both halves, and can be tested without a phone.
    // Note: not ip_napt_enable(addr, 0). Disabling what was never enabled
    // sends esp-lwip into ip_napt_deinit(), which calls mem_free() on a table
    // it never allocated and asserts. Leaving it alone is the same thing.
    nat_init(&s_nat);
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
            // Remember where this one was going, so the Wi-Fi side can say
            // whether it ever got there.
            if (ip_packet[9] == 6 && len >= 24) {
                const uint8_t *tcp = ip_packet + ((ip_packet[0] & 0x0f) * 4);
                s_fwd_dst_ip = dst;
                s_fwd_dst_port = (uint16_t)((tcp[2] << 8) | tcp[3]);
            }
            if (s_trace_in < 40) {
                s_trace_in++;
                ESP_LOGW(TAG, "TS->LAN %u.%u.%u.%u -> %u.%u.%u.%u proto=%u len=%u",
                         s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3],
                         ip_packet[9], (unsigned)len);
            }
            if (!s_logged_first_fwd) {
                s_logged_first_fwd = true;
                ESP_LOGI(TAG, "routing for the tailnet: %u.%u.%u.%u -> %u.%u.%u.%u "
                              "(subnet route is in use)",
                         s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]);
            }
        }
    }

    // PBUF_LINK, not PBUF_RAW: this packet may be forwarded rather than
    // delivered locally, and a forwarded packet goes through ip4_forward()
    // into netif->output() -> ethernet_output(), which needs room before the
    // payload to prepend a 14-byte Ethernet header. PBUF_RAW leaves none, so
    // pbuf_add_header() there fails and ethernet_output() returns ERR_BUF -
    // silently, because nothing upstream of this file checked netif->output's
    // return value. That is the actual reason every forwarded packet vanished:
    // it never reached the Wi-Fi driver, not once, all day - both under
    // esp-lwip's own NAPT and under the one written to replace it. A packet
    // addressed to this device's own tailnet address never hit this path, so
    // nothing else here was wrong for that to hide it.
    p = pbuf_alloc(PBUF_LINK, (uint16_t)len, PBUF_RAM);
    if (!p) return;
    memcpy(p->payload, ip_packet, len);

    // Addressed to the LAN: give it this device's address and a source port of
    // ours, so the machine that receives it answers to a neighbour it can
    // reach rather than to a tailnet address its router has never heard of.
    {
        uint32_t dstip;
        memcpy(&dstip, ip_packet + 16, 4);
        if (len >= 20 && dstip != s_our_ip && s_sta_ip) {
            uint8_t *q = (uint8_t *)p->payload;
            // What the phone sent, before we touch it. If this is already
            // wrong the packet was damaged upstream and no rewrite can save
            // it; if only the second check fails, the rewrite is the fault.
            if (!nat_csum_ok(q, len)) s_csum_bad_in++;
            nat_out(&s_nat, q, len, s_sta_ip, now_ms());
            if (!nat_csum_ok(q, len)) s_csum_bad_out++;
        }
    }

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

void tun_trace_stats(bool *hooked, uint32_t *untranslated, uint32_t *replies) {
    if (hooked) *hooked = s_hooked;
    if (untranslated) *untranslated = s_untranslated;
    if (replies) *replies = s_wifi_replies;
}

void tun_wifi_out(uint32_t *total, uint32_t *to_lan) {
    if (total) *total = s_wifi_out_total;
    if (to_lan) *to_lan = s_wifi_out_lan;
}

uint32_t tun_fwd_reached_wifi(void) { return s_fwd_reached_wifi; }
uint32_t tun_fwd_answered(void)     { return s_fwd_answered; }

uint32_t tun_input_calls(void) { return s_input_calls; }

void tun_csum_bad(uint32_t *before, uint32_t *after) {
    if (before) *before = s_csum_bad_in;
    if (after) *after = s_csum_bad_out;
}

void tun_nat_stats(uint32_t *out, uint32_t *back, uint32_t *unmatched, int *live) {
    if (out) *out = s_nat.rewrites_out;
    if (back) *back = s_nat.rewrites_in;
    if (unmatched) *unmatched = s_nat.misses_in;
    if (live) *live = nat_live(&s_nat, now_ms());
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
