// A short history of the moments the device lost or regained a link.
//
// The log ring in logbuf.c holds about three minutes, so by the time anyone
// looks after a drop, the line that explained it is gone. This keeps only the
// events - a few bytes each - for much longer, and in RTC memory, so a panic
// or watchdog reboot does not take the explanation with it.
#ifndef EVENTS_H
#define EVENTS_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    EV_BOOT = 1,        // a = esp_reset_reason()
    EV_WIFI_LOST,       // a = Wi-Fi reason code, b = RSSI the driver reported with it
    EV_WIFI_BACK,       // a = seconds it was down, b = RSSI of the access point joined
    EV_RELAY_BACK,      // a = DERP region id
    EV_RELAY_LOST,      // a = seconds the relay connection had lasted, b = packets it delivered
    EV_MAP_ENDED,       // a = return code, b = HTTP status of the control session
    EV_RELAY_CHOSEN,    // a = region id, b = peers using it, or -1 when remembered
} ev_kind;

// Call once, early. Keeps what an earlier boot recorded when RTC memory
// survived the reset (software reset, panic, watchdog); a power cut clears it.
void events_init(void);

// Safe from any task, and cheap: no allocation, no logging.
void events_add(ev_kind kind, int32_t a, int32_t b);

// Writes the history as text, oldest first, NUL-terminated. Returns the
// length written, not counting the NUL.
size_t events_format(char *out, size_t cap);

#endif
