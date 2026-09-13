// The last few kilobytes of the log, kept in RAM and served over HTTP.
//
// Every diagnostic in this firmware goes to the serial console, which means
// every diagnostic needs a cable. The device this is written for sits in a
// house fifteen kilometres away. So the log is also kept here, in a ring the
// status page can hand back: the same lines, reachable over the tunnel.
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "logbuf.h"

#define LOGBUF_SIZE 4096

static char     s_buf[LOGBUF_SIZE];
static size_t   s_w;
static bool     s_wrapped;
static vprintf_like_t s_next;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static int hook(const char *fmt, va_list ap) {
    char line[192];
    int n;
    va_list copy;

    // The console still gets everything; this only tees it.
    va_copy(copy, ap);
    n = vsnprintf(line, sizeof(line), fmt, copy);
    va_end(copy);

    if (n > 0) {
        size_t len = (size_t)n < sizeof(line) - 1 ? (size_t)n : sizeof(line) - 1;
        size_t i;
        // A spinlock, not a mutex: this runs in whatever task called ESP_LOG,
        // and blocking one of them behind another is a way to deadlock the
        // system it is meant to explain.
        portENTER_CRITICAL(&s_lock);
        for (i = 0; i < len; i++) {
            s_buf[s_w++] = line[i];
            if (s_w == LOGBUF_SIZE) { s_w = 0; s_wrapped = true; }
        }
        portEXIT_CRITICAL(&s_lock);
    }
    return s_next ? s_next(fmt, ap) : 0;
}

void logbuf_start(void) {
    s_next = esp_log_set_vprintf(hook);
}

size_t logbuf_read(char *out, size_t cap) {
    size_t n = 0;
    portENTER_CRITICAL(&s_lock);
    if (s_wrapped) {
        size_t tail = LOGBUF_SIZE - s_w;
        size_t take = tail < cap ? tail : cap;
        memcpy(out, s_buf + s_w, take);
        n = take;
    }
    {
        size_t take = s_w < cap - n ? s_w : cap - n;
        memcpy(out + n, s_buf, take);
        n += take;
    }
    portEXIT_CRITICAL(&s_lock);
    return n;
}
