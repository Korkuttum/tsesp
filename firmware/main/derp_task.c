#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "derp.h"
#include "tls_io.h"
#include "derp_task.h"
#include "magic.h"

static const char *TAG = "derp";

static uint8_t  s_node_priv[32], s_node_pub[32];
static char     s_host[64];
static char     s_code[8];
static uint16_t s_region;
static volatile uint16_t s_connected_region;
static volatile bool s_have_region;
static volatile bool s_changed;

// derp_conn plus the TLS session is more than a task stack should carry.
static derp_conn *s_conn;
static tls_io    *s_tls;

void derp_task_set_region(uint16_t region_id, const char *host, const char *code) {
    if (!host || !host[0]) return;
    if (s_have_region && s_region == region_id) return;
    s_region = region_id;
    snprintf(s_host, sizeof(s_host), "%s", host);
    snprintf(s_code, sizeof(s_code), "%s", code ? code : "");
    s_have_region = true;
    ESP_LOGI(TAG, "relay for this tailnet: region %u (%s) at %s",
             region_id, s_code, s_host);
}

uint16_t derp_task_region(void) { return s_connected_region; }

bool derp_task_take_changed(void) {
    bool v = s_changed;
    s_changed = false;
    return v;
}
bool derp_task_connected(void)  { return s_connected_region != 0; }

void derp_task_stats(uint32_t *sent, uint32_t *received) {
    if (sent) *sent = s_conn ? s_conn->sent : 0;
    if (received) *received = s_conn ? s_conn->received : 0;
}

static void derp_task(void *arg) {
    uint32_t backoff = 2000;
    (void)arg;

    while (!s_have_region) vTaskDelay(pdMS_TO_TICKS(500));

    for (;;) {
        derp_opts opts;
        int rc;

        ESP_LOGI(TAG, "connecting to %s (heap %u)", s_host,
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));

        if (tls_io_connect(s_tls, s_host, 443, 15) != 0) goto retry;
        ESP_LOGI(TAG, "tls up, heap now %u",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));

        memset(&opts, 0, sizeof(opts));
        opts.host = s_host;
        opts.node_priv = s_node_priv;
        opts.node_pub = s_node_pub;
        opts.preferred = 1;          // this is our home relay

        rc = derp_connect(s_conn, &s_tls->io, &opts);
        if (rc != 0) {
            ESP_LOGW(TAG, "handshake failed (%d)", rc);
            tls_io_close(s_tls);
            goto retry;
        }

        if (s_connected_region != s_region) s_changed = true;
        s_connected_region = s_region;
        backoff = 2000;
        ESP_LOGI(TAG, "connected to region %u (%s); heap %u", s_region, s_code,
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));

        for (;;) {
            uint8_t src[32], pkt[1500];
            size_t len = 0;
            int r = derp_recv(s_conn, src, pkt, sizeof(pkt), &len);
            if (r < 0) break;
            if (r == 1) {
                // A relayed packet has no UDP source, so the path engine is
                // told it came from nowhere: it must not be offered as a
                // candidate address to probe.
                uint8_t nowhere[16];
                memset(nowhere, 0, sizeof(nowhere));
                magic_handle_relayed(src, nowhere, 0, pkt, len);
            }
        }

        ESP_LOGW(TAG, "relay connection lost");
        s_connected_region = 0;
        tls_io_close(s_tls);

    retry:
        vTaskDelay(pdMS_TO_TICKS(backoff));
        if (backoff < 60000) backoff *= 2;
    }
}

void derp_task_start(const uint8_t node_priv[32], const uint8_t node_pub[32]) {
    memcpy(s_node_priv, node_priv, 32);
    memcpy(s_node_pub, node_pub, 32);

    s_conn = calloc(1, sizeof(*s_conn));
    s_tls = calloc(1, sizeof(*s_tls));
    if (!s_conn || !s_tls) {
        ESP_LOGE(TAG, "out of memory for the relay");
        return;
    }
    // TLS wants a roomy stack: the handshake allocates on it.
    xTaskCreate(derp_task, "derp", 8192, NULL, 5, NULL);
}
