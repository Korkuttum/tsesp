#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "esp_tls.h"
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

// Outbound packets from other tasks. The TLS session cannot be read and
// written from two tasks at once, so everything funnels through the relay
// task and the mutex only covers the moments it is actually in esp-tls.
typedef struct {
    uint8_t  dst[32];
    uint16_t len;
    uint8_t *data;
} derp_tx;

static QueueHandle_t     s_txq;
static SemaphoreHandle_t s_iolock;

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

int derp_task_send(const uint8_t dst_node_pub[32], const uint8_t *pkt, size_t len) {
    derp_tx tx;

    if (!s_txq || !s_connected_region || len == 0 || len > 1500) return -1;
    tx.data = malloc(len);
    if (!tx.data) return -1;
    memcpy(tx.data, pkt, len);
    tx.len = (uint16_t)len;
    memcpy(tx.dst, dst_node_pub, 32);

    if (xQueueSend(s_txq, &tx, 0) != pdTRUE) {
        free(tx.data);
        return -1;
    }
    return 0;
}

uint16_t derp_task_region(void) { return s_connected_region; }

const char *derp_task_region_name(void) {
    // Tailscale names its regions with airport-style codes; a person reading
    // a status page wants the city.
    static const struct { const char *code, *city; } kCities[] = {
        { "fra", "Frankfurt" }, { "ams", "Amsterdam" }, { "lhr", "Londra" },
        { "par", "Paris" },     { "nue", "Nürnberg" },  { "waw", "Varşova" },
        { "mad", "Madrid" },    { "hel", "Helsinki" },  { "dbi", "Dubai" },
        { "nyc", "New York" },  { "ist", "İstanbul" },
    };
    size_t i;
    if (!s_connected_region) return "";
    for (i = 0; i < sizeof(kCities) / sizeof(kCities[0]); i++)
        if (!strcmp(s_code, kCities[i].code)) return kCities[i].city;
    return s_code;
}

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
            static uint8_t src[32], pkt[1500];
            size_t len = 0;
            int sockfd = -1, r;
            fd_set rfds;
            struct timeval tv = { 0, 200000 };
            derp_tx tx;

            if (esp_tls_get_conn_sockfd((esp_tls_t *)s_tls->tls, &sockfd) != ESP_OK ||
                sockfd < 0) break;

            // Read only when there is something to read, so the queue below
            // gets serviced instead of waiting out a quiet minute.
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);
            r = select(sockfd + 1, &rfds, NULL, NULL, &tv);
            if (r < 0) break;

            if (r > 0 || esp_tls_get_bytes_avail((esp_tls_t *)s_tls->tls) > 0) {
                int got;
                xSemaphoreTake(s_iolock, portMAX_DELAY);
                got = derp_recv(s_conn, src, pkt, sizeof(pkt), &len);
                xSemaphoreGive(s_iolock);
                if (got < 0) break;
                if (got == 1) {
                    // A relayed packet has no UDP source, so nothing here can
                    // be offered to the path engine as an address to probe.
                    magic_handle_relayed(src, pkt, len);
                }
            }

            while (xQueueReceive(s_txq, &tx, 0) == pdTRUE) {
                xSemaphoreTake(s_iolock, portMAX_DELAY);
                derp_send(s_conn, tx.dst, tx.data, tx.len);
                xSemaphoreGive(s_iolock);
                free(tx.data);
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
    s_txq = xQueueCreate(12, sizeof(derp_tx));
    s_iolock = xSemaphoreCreateMutex();
    if (!s_conn || !s_tls || !s_txq || !s_iolock) {
        ESP_LOGE(TAG, "out of memory for the relay");
        return;
    }
    // TLS wants a roomy stack: the handshake allocates on it.
    xTaskCreate(derp_task, "derp", 8192, NULL, 5, NULL);
}
