// Replacing the firmware over the network, and the trial period that makes
// doing it from far away survivable.
//
// This board sits in a village house. The nearest person who can press reset
// may be an hour's drive and a week away, so an update is never simply
// written and believed: the bootloader keeps the image that was working, the
// new one runs on trial, and it becomes permanent only once it has proved it
// can still be reached. A bad build then costs a reboot instead of a journey.
#ifndef OTA_H
#define OTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// What the bootloader currently thinks of the image that is running.
typedef enum {
    OTA_IMG_STABLE = 0,   // confirmed, or written over the cable: here to stay
    OTA_IMG_TRIAL,        // uploaded; a reboot rolls back unless it confirms
    OTA_IMG_UNKNOWN
} ota_state;

ota_state   ota_running_state(void);
// Which slot is running ("ota_0"), or "?" before the partition table is read.
const char *ota_running_slot(void);

// Confirms the running image, so the previous one is no longer a fallback.
// Only the first call does anything; calling it on an image that is not on
// trial is a no-op. Nothing calls this until the device has shown it can
// reach the tailnet again - that is the whole point of it being separate.
void ota_confirm(void);

// True when the other slot holds an image that never confirmed itself, so the
// bootloader came back here. Without this an update that quietly reverted
// looks exactly like an update that was never uploaded.
bool ota_rolled_back(void);

// One upload, in order: begin, feed every byte, finish. Each returns 0 on
// success; on failure ota_error() says what went wrong and the upload is
// already cleaned up.
int  ota_begin(size_t total_len);
int  ota_feed(const uint8_t *data, size_t len);
int  ota_finish(void);
void ota_abort(void);

const char *ota_error(void);
void        ota_progress(size_t *done, size_t *total);

#endif
