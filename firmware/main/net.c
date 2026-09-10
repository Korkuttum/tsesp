#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "lwip/inet.h"
#include "net.h"
#include "device_nvs.h"

static const char *TAG = "net";

#define BIT_CONNECTED BIT0
#define BIT_FAILED    BIT1
// Enough attempts to ride out a slow router, few enough that a wrong password
// does not leave the user staring at nothing.
#define MAX_STA_RETRY 5

static EventGroupHandle_t s_events;
static int      s_retries;
static bool     s_connected;
static char     s_ip[16] = "0.0.0.0";
static char     s_ap_ssid[24];

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg; (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        strcpy(s_ip, "0.0.0.0");
        if (s_retries < MAX_STA_RETRY) {
            s_retries++;
            ESP_LOGW(TAG, "reconnecting (%d/%d)", s_retries, MAX_STA_RETRY);
            esp_wifi_connect();
        } else {
            xEventGroupSetBits(s_events, BIT_FAILED);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        snprintf(s_ip, sizeof(s_ip), IPSTR, IP2STR(&e->ip_info.ip));
        s_retries = 0;
        s_connected = true;
        ESP_LOGI(TAG, "connected, ip %s", s_ip);
        xEventGroupSetBits(s_events, BIT_CONNECTED);
    }
}

static void make_ap_ssid(void) {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(s_ap_ssid, sizeof(s_ap_ssid), "tsesp-%02x%02x", mac[4], mac[5]);
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
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
        ESP_ERROR_CHECK(esp_wifi_start());
    }
    ESP_LOGI(TAG, "joining %s", ssid);

    {
        EventBits_t bits = xEventGroupWaitBits(s_events, BIT_CONNECTED | BIT_FAILED,
                                               pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));
        if (bits & BIT_CONNECTED) return true;
        // Wrong password, or the network moved. Fall back to the portal
        // rather than rebooting into the same failure forever.
        ESP_LOGW(TAG, "could not join %s; opening setup portal", ssid);
        esp_wifi_stop();
        start_ap();
        return false;
    }
}

bool net_is_connected(void) { return s_connected; }
void net_get_ip(char *out, size_t cap) { snprintf(out, cap, "%s", s_ip); }
void net_get_ap_ssid(char *out, size_t cap) { snprintf(out, cap, "%s", s_ap_ssid); }
