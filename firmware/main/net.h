// Wi-Fi bring-up and the setup portal.
#ifndef NET_H
#define NET_H

#include <stdbool.h>
#include "esp_err.h"

// Starts Wi-Fi. Tries the stored credentials; if there are none, or they do
// not work, opens an access point named tsesp-xxxx running the setup page.
// Returns true once connected as a station.
bool net_start(void);

bool net_is_connected(void);
void net_get_ip(char *out, size_t cap);
void net_get_ap_ssid(char *out, size_t cap);

// Runs the setup page. In AP mode it also hijacks DNS so that opening any
// address lands on it, which is what makes a phone pop the page by itself.
esp_err_t portal_start(bool captive);

// What the status page shows. The main task keeps this up to date.
typedef struct {
    const char *state;
    const char *tailnet_addr;
    const char *login_url;
    int         peers;
    int         paths_up;
    unsigned    free_heap;
} portal_status;

void portal_set_status(const portal_status *s);

#endif
