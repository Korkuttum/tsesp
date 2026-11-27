// See events.h. 24 entries of 16 bytes: under 400 bytes of RTC slow memory,
// none of the heap this device is short of.
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "esp_attr.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "events.h"

#define EVENTS_MAX   24
#define EVENTS_MAGIC 0x74736576u    // "tsev"

typedef struct {
    uint32_t t_s;       // uptime of that boot, seconds
    uint16_t boot;      // which boot since the history was last cleared
    uint8_t  kind;
    uint8_t  pad;
    int32_t  a, b;
} ev_entry;

typedef struct {
    uint32_t magic;
    uint16_t boot;
    uint16_t next;      // slot the next event goes into
    uint16_t count;
    uint16_t pad;
    ev_entry e[EVENTS_MAX];
    uint32_t check;     // magic ^ boot ^ next ^ count, so half-written state is not trusted
} ev_store;

static RTC_NOINIT_ATTR ev_store s_ev;
static portMUX_TYPE s_ev_lock = portMUX_INITIALIZER_UNLOCKED;

static uint32_t check_of(const ev_store *s) {
    return s->magic ^ s->boot ^ ((uint32_t)s->next << 8) ^ ((uint32_t)s->count << 16);
}

void events_init(void) {
    esp_reset_reason_t why = esp_reset_reason();

    portENTER_CRITICAL(&s_ev_lock);
    if (s_ev.magic != EVENTS_MAGIC || s_ev.check != check_of(&s_ev) ||
        s_ev.next >= EVENTS_MAX || s_ev.count > EVENTS_MAX) {
        memset(&s_ev, 0, sizeof(s_ev));
        s_ev.magic = EVENTS_MAGIC;
    }
    s_ev.boot++;
    s_ev.check = check_of(&s_ev);
    portEXIT_CRITICAL(&s_ev_lock);

    events_add(EV_BOOT, (int32_t)why, 0);
}

void events_add(ev_kind kind, int32_t a, int32_t b) {
    uint32_t t = (uint32_t)(esp_timer_get_time() / 1000000);

    portENTER_CRITICAL(&s_ev_lock);
    if (s_ev.magic == EVENTS_MAGIC) {
        ev_entry *e = &s_ev.e[s_ev.next];
        e->t_s = t;
        e->boot = s_ev.boot;
        e->kind = (uint8_t)kind;
        e->pad = 0;
        e->a = a;
        e->b = b;
        s_ev.next = (uint16_t)((s_ev.next + 1) % EVENTS_MAX);
        if (s_ev.count < EVENTS_MAX) s_ev.count++;
        s_ev.check = check_of(&s_ev);
    }
    portEXIT_CRITICAL(&s_ev_lock);
}

static const char *reset_name(int32_t r) {
    switch (r) {
    case ESP_RST_POWERON:   return "power on";
    case ESP_RST_EXT:       return "external pin";
    case ESP_RST_SW:        return "software restart";
    case ESP_RST_PANIC:     return "PANIC";
    case ESP_RST_INT_WDT:   return "interrupt watchdog";
    case ESP_RST_TASK_WDT:  return "task watchdog";
    case ESP_RST_WDT:       return "watchdog";
    case ESP_RST_DEEPSLEEP: return "deep sleep";
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    case ESP_RST_SDIO:      return "sdio";
    default:                return "unknown";
    }
}

static int format_one(char *out, size_t cap, const ev_entry *e) {
    char head[40];
    snprintf(head, sizeof(head), "boot %u +%luh%02lum%02lus ",
             (unsigned)e->boot, (unsigned long)(e->t_s / 3600),
             (unsigned long)(e->t_s / 60 % 60), (unsigned long)(e->t_s % 60));

    switch ((ev_kind)e->kind) {
    case EV_BOOT:
        return snprintf(out, cap, "%sboot, reset reason %ld (%s)\n", head,
                        (long)e->a, reset_name(e->a));
    case EV_WIFI_LOST:
        return snprintf(out, cap, "%swifi lost, reason %ld, rssi %ld\n", head,
                        (long)e->a, (long)e->b);
    case EV_WIFI_BACK:
        return snprintf(out, cap, "%swifi back after %lds, rssi %ld\n", head,
                        (long)e->a, (long)e->b);
    case EV_RELAY_BACK:
        return snprintf(out, cap, "%srelay connected, region %ld\n", head, (long)e->a);
    case EV_RELAY_LOST:
        return snprintf(out, cap, "%srelay lost after %lds\n", head, (long)e->a);
    case EV_MAP_ENDED:
        return snprintf(out, cap, "%scontrol session ended, rc %ld, http %ld\n", head,
                        (long)e->a, (long)e->b);
    default:
        return snprintf(out, cap, "%sevent %u (%ld, %ld)\n", head,
                        (unsigned)e->kind, (long)e->a, (long)e->b);
    }
}

size_t events_format(char *out, size_t cap) {
    ev_entry copy[EVENTS_MAX];
    uint16_t count, first, i;
    size_t n = 0;

    if (!cap) return 0;
    out[0] = '\0';

    // Copy under the lock, format outside it: snprintf is far too slow to
    // run with interrupts held off.
    portENTER_CRITICAL(&s_ev_lock);
    count = s_ev.magic == EVENTS_MAGIC ? s_ev.count : 0;
    first = (uint16_t)((s_ev.next + EVENTS_MAX - count) % EVENTS_MAX);
    for (i = 0; i < count; i++) copy[i] = s_ev.e[(first + i) % EVENTS_MAX];
    portEXIT_CRITICAL(&s_ev_lock);

    for (i = 0; i < count && n + 1 < cap; i++) {
        int w = format_one(out + n, cap - n, &copy[i]);
        if (w < 0) break;
        if ((size_t)w >= cap - n) {         // truncated: keep what fit
            n = cap - 1;
            break;
        }
        n += (size_t)w;
    }
    return n;
}
