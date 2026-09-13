#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "ota.h"

// Without rollback an update is a bet on the image being good, and losing the
// bet means a car journey. The option lives in sdkconfig.defaults, which
// ESP-IDF reads only when it creates sdkconfig - so a build tree from before
// it was added silently ignores it. Failing here is the whole point: the fix
// is in the message, and the alternative is finding out in the village.
#ifndef CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
#error "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE is off. Delete firmware/sdkconfig and build again so sdkconfig.defaults is applied; without it a bad update cannot be undone remotely."
#endif

static const char *TAG = "ota";

// The image starts with esp_image_header_t (24 bytes) and one
// esp_image_segment_header_t (8), then the app descriptor. Kept as an offset
// rather than pulling in the bootloader's headers, because two fields of it
// are all this needs.
#define DESC_OFFSET 32
#define DESC_MAGIC  0xABCD5432u        /* esp_app_desc_t.magic_word */
#define HEAD_LEN    (DESC_OFFSET + sizeof(esp_app_desc_t))

static esp_ota_handle_t      s_handle;
static const esp_partition_t *s_target;
static bool   s_open;
static bool   s_confirmed;
static size_t s_done, s_total;
static char   s_err[96];

// The head of the image is kept until there is enough of it to check. An
// upload arrives in whatever sized pieces the network feels like.
static uint8_t s_head[HEAD_LEN];
static size_t  s_head_len;
static bool    s_head_ok;

static int fail(const char *why) {
    snprintf(s_err, sizeof(s_err), "%s", why);
    ESP_LOGE(TAG, "%s", why);
    return -1;
}

ota_state ota_running_state(void) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;

    if (s_confirmed) return OTA_IMG_STABLE;
    if (!run) return OTA_IMG_UNKNOWN;
    // No otadata entry at all: this image was written over the cable, and
    // there is nothing to roll back to.
    if (esp_ota_get_state_partition(run, &st) != ESP_OK) return OTA_IMG_STABLE;
    return st == ESP_OTA_IMG_PENDING_VERIFY ? OTA_IMG_TRIAL : OTA_IMG_STABLE;
}

const char *ota_running_slot(void) {
    const esp_partition_t *run = esp_ota_get_running_partition();
    return run ? run->label : "?";
}

void ota_confirm(void) {
    if (s_confirmed) return;
    if (ota_running_state() != OTA_IMG_TRIAL) { s_confirmed = true; return; }

    if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK) {
        s_confirmed = true;
        ESP_LOGW(TAG, "this image is confirmed; the older one is no longer a "
                      "fallback");
    } else {
        // Worth a line every time it fails: until it succeeds, a power cut
        // takes the device back to the previous firmware.
        ESP_LOGW(TAG, "could not confirm this image; a reboot would roll back");
    }
}

bool ota_rolled_back(void) {
    return esp_ota_get_last_invalid_partition() != NULL;
}

int ota_begin(size_t total_len) {
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);

    if (s_open)    return fail("an update is already in progress");
    if (!next)     return fail("no spare app slot in the partition table");
    if (!total_len) return fail("the upload declared no length");
    if (total_len > next->size) return fail("the image is larger than the slot");

    s_err[0] = '\0';
    s_head_len = 0;
    s_head_ok = false;
    s_done = 0;
    s_total = total_len;

    if (esp_ota_begin(next, total_len, &s_handle) != ESP_OK)
        return fail("could not open the slot for writing");

    s_target = next;
    s_open = true;
    ESP_LOGI(TAG, "update started: %u bytes into %s",
             (unsigned)total_len, next->label);
    return 0;
}

// Refuses an upload that is not firmware for this project before any of it is
// believed. Flashing something unrelated to a board nobody can reach is the
// one mistake with no way back, and both checks are in the first 288 bytes.
static int check_head(void) {
    esp_app_desc_t in;
    const esp_app_desc_t *mine = esp_app_get_description();

    memcpy(&in, s_head + DESC_OFFSET, sizeof(in));
    if (s_head[0] != 0xE9)           return fail("not an ESP32 firmware image");
    if (in.magic_word != DESC_MAGIC)  return fail("no app descriptor in the image");
    if (mine && strncmp(in.project_name, mine->project_name,
                        sizeof(in.project_name)) != 0)
        return fail("that image is built for a different project");

    in.version[sizeof(in.version) - 1] = '\0';
    in.idf_ver[sizeof(in.idf_ver) - 1] = '\0';
    ESP_LOGI(TAG, "image says version %s, idf %s", in.version, in.idf_ver);
    s_head_ok = true;
    return 0;
}

int ota_feed(const uint8_t *data, size_t len) {
    if (!s_open) return fail("no update in progress");

    if (!s_head_ok) {
        size_t want = sizeof(s_head) - s_head_len;
        size_t take = len < want ? len : want;
        memcpy(s_head + s_head_len, data, take);
        s_head_len += take;
        if (s_head_len == sizeof(s_head) && check_head() != 0) {
            ota_abort();
            return -1;              // check_head already said why
        }
    }

    if (esp_ota_write(s_handle, data, len) != ESP_OK) {
        ota_abort();
        return fail("writing to flash failed");
    }
    s_done += len;
    return 0;
}

int ota_finish(void) {
    if (!s_open) return fail("no update in progress");
    if (!s_head_ok) {
        ota_abort();
        return fail("the upload ended before the image header was complete");
    }
    if (s_done != s_total) {
        ota_abort();
        return fail("the upload ended early");
    }

    // esp_ota_end verifies the image and invalidates the handle either way,
    // so there is nothing left to abort after this point.
    s_open = false;
    if (esp_ota_end(s_handle) != ESP_OK)
        return fail("the image did not pass verification");
    if (esp_ota_set_boot_partition(s_target) != ESP_OK)
        return fail("could not arm the new image");

    ESP_LOGW(TAG, "update written to %s; it boots next and runs on trial",
             s_target->label);
    return 0;
}

void ota_abort(void) {
    if (!s_open) return;
    esp_ota_abort(s_handle);
    s_open = false;
    ESP_LOGW(TAG, "update abandoned after %u of %u bytes",
             (unsigned)s_done, (unsigned)s_total);
}

const char *ota_error(void) { return s_err; }

void ota_progress(size_t *done, size_t *total) {
    if (done) *done = s_done;
    if (total) *total = s_total;
}
