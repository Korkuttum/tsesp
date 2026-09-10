// TLS on the device, via esp-tls. The DERP code above it sees only a ts_io,
// the same interface the OpenSSL shim presents in the tests.
//
// This is the only place mbedTLS enters the picture. The control channel
// deliberately avoids it - Noise over plain HTTP - but the relays offer no
// unencrypted port, so here it is unavoidable.
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "tls_io.h"

static const char *TAG = "tls_io";

// A relay is quiet between keepalives, which arrive about once a minute.
// Treating that silence as a dead connection is what made the first version
// reconnect every fifteen seconds.
#define TLS_IDLE_LIMIT_US (150 * 1000000LL)

static int tls_read(void *ctx, uint8_t *buf, size_t len) {
    tls_io *t = (tls_io *)ctx;
    int64_t deadline = esp_timer_get_time() + TLS_IDLE_LIMIT_US;

    for (;;) {
        int r = esp_tls_conn_read((esp_tls_t *)t->tls, buf, len);
        if (r > 0) return r;
        if (r == ESP_TLS_ERR_SSL_WANT_READ || r == ESP_TLS_ERR_SSL_WANT_WRITE ||
            r == 0) {
            if (esp_timer_get_time() > deadline) {
                ESP_LOGW(TAG, "no traffic for %lld s; treating the connection as gone",
                         TLS_IDLE_LIMIT_US / 1000000);
                return -1;
            }
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        return -1;     // a real error
    }
}

static int tls_write(void *ctx, const uint8_t *buf, size_t len) {
    tls_io *t = (tls_io *)ctx;
    size_t sent = 0;
    while (sent < len) {
        int w = esp_tls_conn_write((esp_tls_t *)t->tls, buf + sent, len - sent);
        if (w == ESP_TLS_ERR_SSL_WANT_READ || w == ESP_TLS_ERR_SSL_WANT_WRITE) continue;
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return (int)len;
}

int tls_io_connect(tls_io *t, const char *host, int port, int timeout_s) {
    esp_tls_cfg_t cfg = {
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = timeout_s * 1000,
        .non_block = false,
    };
    esp_tls_t *tls;

    memset(t, 0, sizeof(*t));
    tls = esp_tls_init();
    if (!tls) return -1;

    if (esp_tls_conn_new_sync(host, (int)strlen(host), port, &cfg, tls) != 1) {
        ESP_LOGW(TAG, "TLS to %s:%d failed", host, port);
        esp_tls_conn_destroy(tls);
        return -1;
    }
    t->tls = tls;
    t->io.read = tls_read;
    t->io.write = tls_write;
    t->io.ctx = t;
    return 0;
}

void tls_io_close(tls_io *t) {
    if (t->tls) esp_tls_conn_destroy((esp_tls_t *)t->tls);
    t->tls = NULL;
}
