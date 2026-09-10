// First firmware milestone: prove the protocol code runs on the CPU that
// ships, and measure what it costs there.
//
// Everything this file exercises is the same code the POSIX tests run. If a
// vector matches on a Mac and not here, the difference is the target: word
// size, alignment, or endianness.
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"

#include "tsesp_selftest.h"
#include "tscrypto.h"
#include "ts2021.h"
#include "ts_control.h"
#include "ts_path.h"
#include "ts_client.h"
#include "disco.h"

// mbedtls_ecp_mul refuses to run without an RNG: it randomises the
// projective coordinates to blunt side channels.
static int mbed_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

static void report_heap(const char *when) {
    printf("%-28s free %7u B, largest block %7u B\n", when,
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
           (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}

// Timings decide whether this is practical: a WireGuard handshake needs two
// X25519 operations, and they happen every two minutes per peer.
static void benchmark(void) {
    uint8_t a[32], b[32], out[32], h[32];
    int64_t t0;
    int i;

    esp_fill_random(a, sizeof(a));
    esp_fill_random(b, sizeof(b));
    x25519_clamp(a);
    x25519_base(b, a);

    t0 = esp_timer_get_time();
    for (i = 0; i < 10; i++) x25519(out, a, b);
    printf("X25519                       %6lld us each\n",
           (esp_timer_get_time() - t0) / 10);

    // mbedTLS ships with ESP-IDF and can reach the chip's big-integer
    // accelerator, so it is worth knowing what it costs before deciding to
    // carry our own portable ladder onto the device.
    {
        mbedtls_ecp_group grp;
        mbedtls_mpi d, zA;
        mbedtls_ecp_point Q, P;
        int rc;

        mbedtls_ecp_group_init(&grp);
        mbedtls_mpi_init(&d);
        mbedtls_mpi_init(&zA);
        mbedtls_ecp_point_init(&Q);
        mbedtls_ecp_point_init(&P);

        rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
        if (rc == 0) rc = mbedtls_mpi_read_binary_le(&d, a, 32);
        // Montgomery curves read as a bare little-endian X coordinate.
        if (rc == 0) rc = mbedtls_ecp_point_read_binary(&grp, &P, b, 32);
        if (rc == 0) {
            t0 = esp_timer_get_time();
            for (i = 0; i < 5; i++)
                rc = mbedtls_ecp_mul(&grp, &Q, &d, &P, mbed_rng, NULL);
            if (rc == 0)
                printf("X25519 via mbedTLS           %6lld us each\n",
                       (esp_timer_get_time() - t0) / 5);
            else
                printf("X25519 via mbedTLS           failed (-0x%04x)\n", -rc);
        } else {
            printf("X25519 via mbedTLS           setup failed (-0x%04x)\n", -rc);
        }
        mbedtls_ecp_point_free(&P);
        mbedtls_ecp_point_free(&Q);
        mbedtls_mpi_free(&zA);
        mbedtls_mpi_free(&d);
        mbedtls_ecp_group_free(&grp);
    }

    t0 = esp_timer_get_time();
    for (i = 0; i < 100; i++) blake2s(h, 32, a, 32);
    printf("BLAKE2s (32 B)               %6lld us each\n",
           (esp_timer_get_time() - t0) / 100);

    {
        static uint8_t buf[1024], ct[1024 + 16], key[32], nonce[12];
        esp_fill_random(key, sizeof(key));
        memset(nonce, 0, sizeof(nonce));
        t0 = esp_timer_get_time();
        for (i = 0; i < 100; i++)
            chacha20poly1305_seal(ct, key, nonce, buf, sizeof(buf), NULL, 0);
        {
            int64_t us = (esp_timer_get_time() - t0) / 100;
            printf("ChaCha20-Poly1305 (1 KB)     %6lld us each  (~%lld KB/s)\n",
                   us, us ? 1000000 / us : 0);
        }
    }
}

void app_main(void) {
    int failures;

    printf("\n\n=========================================\n");
    printf(" tsesp on %s, %d MB flash\n", CONFIG_IDF_TARGET, 4);
    printf("=========================================\n\n");

    report_heap("at boot");

    printf("\n--- structure sizes on this target ---\n");
    printf("ts_control        %6u B\n", (unsigned)sizeof(ts_control));
    printf("ts_path_engine    %6u B\n", (unsigned)sizeof(ts_path_engine));
    printf("ts_netmap_parser  %6u B\n", (unsigned)sizeof(ts_netmap_parser));
    printf("ts_client         %6u B\n", (unsigned)sizeof(ts_client));
    printf("disco_msg         %6u B\n", (unsigned)sizeof(disco_msg));

    printf("\n--- known-answer tests ---\n");
    failures = tsesp_crypto_selftest();

    printf("\n--- how fast is this chip at the crypto that matters ---\n");
    benchmark();

    printf("\n--- can we actually hold the control plane ---\n");
    {
        // Allocating it for real is the only honest way to answer this:
        // a heap that says it has 40 KB free may still not have 14 KB
        // contiguous once the WiFi stack has been up for a while.
        ts_control *tc = malloc(sizeof(ts_control));
        if (tc) {
            printf("allocated ts_control (%u B) from the heap: ok\n",
                   (unsigned)sizeof(ts_control));
            report_heap("with ts_control held");
            free(tc);
        } else {
            printf("COULD NOT allocate ts_control (%u B)\n", (unsigned)sizeof(ts_control));
            failures++;
        }
    }

    report_heap("after tests");
    printf("\n%s\n", failures ? "*** SOMETHING FAILED ***" : "*** all good on hardware ***");

    while (1) vTaskDelay(pdMS_TO_TICKS(10000));
}
