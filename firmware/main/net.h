// Wi-Fi bring-up and the setup portal.
#ifndef NET_H
#define NET_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

// Starts Wi-Fi. Tries the stored credentials; if there are none, or they do
// not work, opens an access point named tsesp-xxxx running the setup page.
// Returns true once connected as a station.
bool net_start(void);

bool net_is_connected(void);

// Called from the Wi-Fi task whenever the station comes up on an address it
// did not have before. A modem that was rebooted can hand out a different
// network, and the route this device advertises, the address NAPT rewrites
// to, and the "is this peer on my LAN" test are all derived from it.
// Registering clears any change already pending: the caller is expected to
// apply the current address itself.
void net_on_ip_change(void (*cb)(void));

// How many times the link has been re-established since boot, and how long
// it has been down right now. Zero reconnects after a week is the thing
// worth seeing; a growing number points at the access point, not at us.
void net_get_link_stats(uint32_t *reconnects, uint32_t *down_s);
void net_get_ip(char *out, size_t cap);
void net_get_ap_ssid(char *out, size_t cap);
// Signal quality matters for a box sitting in a corner of a village house:
// a weak link shows up as latency and loss long before it drops.
void net_get_wifi_info(char *ssid, size_t cap, int *rssi, int *channel);

// Runs the setup page. In AP mode it also hijacks DNS so that opening any
// address lands on it, which is what makes a phone pop the page by itself.
esp_err_t portal_start(bool captive);

// What the status page shows. The main task keeps this up to date.
typedef struct {
    const char *state;
    const char *tailnet_addr;
    const char *name;        // MagicDNS adı
    const char *login_url;
    const char *route;       // the LAN we offer to route for
    // Whether control has approved that route: 1 yes, 0 advertised but not
    // approved, -1 not known yet (no netmap has restated our own record).
    // Advertising is half the job; without the approval peers are never told
    // to send LAN traffic here, and nothing about the tunnel looks wrong.
    int         route_approved;
    int         peers;
    int         paths_up;
    unsigned    free_heap;
} portal_status;

void portal_set_status(const portal_status *s);

// Milliseconds since the setup page was last requested. Large when nobody is
// there, which is when the device is free to reboot and retry on its own.
uint32_t portal_idle_ms(void);

#endif
