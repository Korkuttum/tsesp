#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "lwip/inet.h"
#include "net.h"
#include "device_nvs.h"

static const char *TAG = "net";

#define BIT_CONNECTED BIT0
#define BIT_FAILED    BIT1
// How long the first join may take before the setup portal opens.
//
// A counted number of attempts was the wrong shape: five of them ran out in
// seconds, well before a router that lost power with everything else finishes
// booting, and the device opened the portal with nobody there to see it. Time
// is what actually matters, and ninety seconds covers a router coming up.
//
// A wrong password does not wait this out - see auth_failure() below. This
// budget covers the *first* join only: once a network has worked, giving up
// on it is never the right answer.
#define JOIN_WAIT_MS 90000
// Two in a row, not one: a marginal link drops a four-way handshake now and
// then, and one such event should not send a correctly configured device to
// the setup portal.
#define AUTH_FAILS_BEFORE_PORTAL 2
// Backstop, not a budget. A scan that fails normally takes a second or two,
// so the deadline above runs out long before this does; it exists because
// retries are issued from the event handler, which cannot wait, and a failure
// that returns instantly would spin there and starve everything else.
#define JOIN_MAX_ATTEMPTS 60
// A modem that was just power-cycled needs tens of seconds before it serves
// DHCP again, so retries start quick and back off to a period that can wait
// out a genuinely absent network without keeping the radio busy.
#define RECONNECT_MIN_MS 2000
#define RECONNECT_MAX_MS 30000
// Associated to the access point and still without an address this long
// after: the exchange is not going to finish on its own, and nothing will
// fire an event to say so.
#define DHCP_GRACE_MS 20000

static EventGroupHandle_t s_events;
static int      s_join_tries;
static int      s_auth_fails;
static bool     s_connected;
static bool     s_sta_configured;   // credentials are loaded; connecting means something
static bool     s_joined_once;      // this network has worked at least once
static uint32_t s_down_since_ms;
static uint32_t s_last_try_ms;
static uint32_t s_backoff_ms = RECONNECT_MIN_MS;
static uint32_t s_reconnects;
static uint32_t s_last_ip;          // network order, as the event delivers it
static bool     s_ip_changed;
static void   (*s_ip_cb)(void);
static char     s_ip[16] = "0.0.0.0";
static char     s_ap_ssid[24];

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

// The access point is there and will not let us in. Waiting changes nothing,
// so the setup portal should open now rather than in a minute and a half.
// WIFI_REASON_NO_AP_FOUND and its variants are the opposite case: nothing to
// authenticate against yet, which is exactly what a booting router looks like.
static bool auth_failure(uint8_t reason) {
    return reason == WIFI_REASON_AUTH_FAIL ||
           reason == WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT ||
           reason == WIFI_REASON_HANDSHAKE_TIMEOUT;
}

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg; (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        // While the setup portal is up the station exists only so the page can
        // scan for networks. There is nothing to connect to, and trying anyway
        // leaves the radio in a connect loop that makes those scans fail.
        if (s_sta_configured) esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *e = (wifi_event_sta_disconnected_t *)data;
        uint8_t reason = e ? e->reason : 0;

        if (s_connected) {
            s_connected = false;
            s_down_since_ms = now_ms();
            s_last_try_ms = now_ms();
            s_backoff_ms = RECONNECT_MIN_MS;
            ESP_LOGW(TAG, "wifi link lost (reason %u)", reason);
        }
        strcpy(s_ip, "0.0.0.0");
        if (!s_sta_configured) return;
        // Past the first join, link_task owns the retries: it can wait
        // between attempts, and the event handler cannot. It never gives up
        // on a reason code either - a router nobody is standing next to is
        // not a thing to open a setup portal about.
        if (s_joined_once) return;

        if (auth_failure(reason)) {
            if (++s_auth_fails >= AUTH_FAILS_BEFORE_PORTAL) {
                ESP_LOGW(TAG, "reason %u: the password is not being accepted", reason);
                xEventGroupSetBits(s_events, BIT_FAILED);
                return;
            }
        } else {
            s_auth_fails = 0;
        }
        // Everything else - and NO_AP_FOUND above all - is worth another go
        // until the join deadline: it is what a router that is still booting
        // looks like from here.
        if (++s_join_tries > JOIN_MAX_ATTEMPTS) {
            ESP_LOGW(TAG, "%d join attempts and none took; letting the deadline run out",
                     s_join_tries);
            return;             // the wait in net_start() opens the portal
        }
        ESP_LOGW(TAG, "join attempt %d did not take (reason %u); trying again",
                 s_join_tries, reason);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        snprintf(s_ip, sizeof(s_ip), IPSTR, IP2STR(&e->ip_info.ip));
        if (e->ip_info.ip.addr != s_last_ip) {
            s_last_ip = e->ip_info.ip.addr;
            s_ip_changed = true;
        }
        s_join_tries = 0;
        s_auth_fails = 0;
        s_backoff_ms = RECONNECT_MIN_MS;
        s_connected = true;
        s_joined_once = true;
        {
            // Which access point, not just which network. With a mesh the
            // difference between two nodes of the same SSID is the difference
            // between -46 and -80 dBm, and without this in the log there is
            // no way to tell afterwards which one it settled on.
            wifi_ap_record_t ap;
            if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK)
                ESP_LOGI(TAG, "connected, ip %s via %02x:%02x:%02x:%02x:%02x:%02x "
                              "ch %d, rssi %d", s_ip,
                         ap.bssid[0], ap.bssid[1], ap.bssid[2],
                         ap.bssid[3], ap.bssid[4], ap.bssid[5],
                         ap.primary, ap.rssi);
            else
                ESP_LOGI(TAG, "connected, ip %s", s_ip);
        }
        xEventGroupSetBits(s_events, BIT_CONNECTED);
    }
}

// Keeps the station on its network for as long as the device is running.
//
// This lives in a task rather than in the event handler because the useful
// thing to do about a network that is not back yet is to wait, and the event
// loop is the wrong place to wait. It also covers the failure no event
// reports: associated to the access point, but no address ever arrives.
static void link_task(void *arg) {
    (void)arg;

    for (;;) {
        uint32_t down_ms;
        wifi_ap_record_t ap;
        esp_err_t err;

        vTaskDelay(pdMS_TO_TICKS(1000));

        if (s_ip_changed && s_ip_cb) {
            s_ip_changed = false;
            s_ip_cb();
        }
        if (s_connected || !s_joined_once) continue;
        if ((uint32_t)(now_ms() - s_last_try_ms) < s_backoff_ms) continue;
        s_last_try_ms = now_ms();
        down_ms = now_ms() - s_down_since_ms;

        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK && down_ms > DHCP_GRACE_MS) {
            ESP_LOGW(TAG, "associated for %us with no address; starting the join over",
                     (unsigned)(down_ms / 1000));
            esp_wifi_disconnect();
            vTaskDelay(pdMS_TO_TICKS(200));
        }

        err = esp_wifi_connect();
        s_reconnects++;
        ESP_LOGW(TAG, "wifi down %us; reconnect attempt %u (err %d), next in %us",
                 (unsigned)(down_ms / 1000), (unsigned)s_reconnects, (int)err,
                 (unsigned)(s_backoff_ms / 1000));

        if (s_backoff_ms < RECONNECT_MAX_MS) {
            s_backoff_ms *= 2;
            if (s_backoff_ms > RECONNECT_MAX_MS) s_backoff_ms = RECONNECT_MAX_MS;
        }
    }
}

static void make_ap_ssid(void) {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(s_ap_ssid, sizeof(s_ap_ssid), "tsesp-%02x%02x", mac[4], mac[5]);
    // Every boot, not only when the portal opens: knowing this name before
    // you are standing somewhere with no network saves a trip.
    ESP_LOGI(TAG, "setup network, if it is ever needed: %s", s_ap_ssid);
}

static void start_ap(void) {
    wifi_config_t cfg = {0};

    ESP_LOGI(TAG, "starting setup access point %s", s_ap_ssid);
    // APSTA, not AP: scanning for the user's network needs a station
    // interface, and in pure AP mode the scan returns nothing at all.
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    strncpy((char *)cfg.ap.ssid, s_ap_ssid, sizeof(cfg.ap.ssid));
    cfg.ap.ssid_len = strlen(s_ap_ssid);
    cfg.ap.channel = 1;
    cfg.ap.max_connection = 4;
    // Open on purpose: a password on the setup network is one more thing to
    // tell the user, and the only secret it carries is about to be typed in
    // by them anyway, over a link that is theirs.
    cfg.ap.authmode = WIFI_AUTH_OPEN;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
}

bool net_start(void) {
    char ssid[WIFI_SSID_MAX], pass[WIFI_PASS_MAX];
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();

    s_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi_event, NULL, NULL));
    make_ap_ssid();

    if (!device_wifi_get(ssid, sizeof(ssid), pass, sizeof(pass))) {
        ESP_LOGI(TAG, "no stored network; opening setup portal");
        start_ap();
        return false;
    }

    {
        wifi_config_t cfg = {0};
        strncpy((char *)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid));
        strncpy((char *)cfg.sta.password, pass, sizeof(cfg.sta.password));
        // The default is a fast scan, which stops at the first access point
        // answering to this SSID and joins that one whatever its signal. In a
        // house with a mesh that is a coin flip, and it comes up tails exactly
        // when the modem is rebooting: the node that never lost power answers
        // first, so the device latches onto the far one at -80 dBm, cannot
        // finish DHCP, and beacon-times-out in a loop. Scan every channel and
        // take the strongest instead.
        cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
        cfg.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
        s_sta_configured = true;
        ESP_ERROR_CHECK(esp_wifi_start());
        // Power save has the access point hold packets until the station
        // next wakes, which shows up as latency spikes of a hundred
        // milliseconds and more. A device meant to route for other machines
        // should stay awake.
        ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    }
    ESP_LOGI(TAG, "joining %s", ssid);

    {
        EventBits_t bits = xEventGroupWaitBits(s_events, BIT_CONNECTED | BIT_FAILED,
                                               pdFALSE, pdFALSE,
                                               pdMS_TO_TICKS(JOIN_WAIT_MS));
        if (bits & BIT_CONNECTED) {
            // Nothing below this point may assume the link stays up.
            xTaskCreate(link_task, "link", 3072, NULL, 5, NULL);
            return true;
        }
        // Wrong password, or the network is not within reach. Fall back to
        // the portal rather than rebooting into the same failure forever.
        ESP_LOGW(TAG, "could not join %s in %us (%d attempts); opening setup portal",
                 ssid, (unsigned)(JOIN_WAIT_MS / 1000), s_join_tries);
        s_sta_configured = false;
        esp_wifi_stop();
        start_ap();
        return false;
    }
}

void net_on_ip_change(void (*cb)(void)) {
    // The caller applies the current address itself; only later changes are
    // the callback's business.
    s_ip_changed = false;
    s_ip_cb = cb;
}

void net_get_wifi_info(char *ssid, size_t cap, int *rssi, int *channel) {
    wifi_ap_record_t ap;
    if (ssid && cap) ssid[0] = '\0';
    if (rssi) *rssi = 0;
    if (channel) *channel = 0;
    if (!s_connected || esp_wifi_sta_get_ap_info(&ap) != ESP_OK) return;
    if (ssid && cap) snprintf(ssid, cap, "%s", (const char *)ap.ssid);
    if (rssi) *rssi = ap.rssi;
    if (channel) *channel = ap.primary;
}

void net_get_link_stats(uint32_t *reconnects, uint32_t *down_s) {
    if (reconnects) *reconnects = s_reconnects;
    if (down_s) *down_s = s_connected ? 0 : (now_ms() - s_down_since_ms) / 1000;
}

bool net_is_connected(void) { return s_connected; }
void net_get_ip(char *out, size_t cap) { snprintf(out, cap, "%s", s_ip); }
void net_get_ap_ssid(char *out, size_t cap) { snprintf(out, cap, "%s", s_ap_ssid); }
