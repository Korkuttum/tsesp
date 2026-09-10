#include <string.h>
#include "esp_err.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "tscrypto.h"
#include "device_nvs.h"

static const char *TAG = "nvs";
static const char *NS = "tsesp";

static esp_err_t blob_get(const char *key, void *out, size_t len) {
    nvs_handle_t h;
    size_t sz = len;
    esp_err_t err = nvs_open(NS, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    err = nvs_get_blob(h, key, out, &sz);
    nvs_close(h);
    if (err == ESP_OK && sz != len) return ESP_ERR_INVALID_SIZE;
    return err;
}

static esp_err_t blob_set(const char *key, const void *val, size_t len) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, key, val, len);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t device_keys_load(uint8_t machine[32], uint8_t node[32], uint8_t disco[32]) {
    struct { uint8_t machine[32], node[32], disco[32]; } keys;
    esp_err_t err = blob_get("keys", &keys, sizeof(keys));

    if (err == ESP_OK) {
        memcpy(machine, keys.machine, 32);
        memcpy(node, keys.node, 32);
        memcpy(disco, keys.disco, 32);
        ESP_LOGI(TAG, "identity loaded from flash");
        return ESP_OK;
    }
    if (err != ESP_ERR_NVS_NOT_FOUND && err != ESP_ERR_NVS_NOT_INITIALIZED) {
        ESP_LOGW(TAG, "reading identity failed (%s), generating a new one",
                 esp_err_to_name(err));
    }

    // esp_fill_random draws from the hardware RNG, which is only truly random
    // once the RF subsystem is up - and it is, because Wi-Fi starts first.
    esp_fill_random(&keys, sizeof(keys));
    x25519_clamp(keys.machine);
    x25519_clamp(keys.node);
    x25519_clamp(keys.disco);

    err = blob_set("keys", &keys, sizeof(keys));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "could not store identity: %s", esp_err_to_name(err));
        return err;
    }
    memcpy(machine, keys.machine, 32);
    memcpy(node, keys.node, 32);
    memcpy(disco, keys.disco, 32);
    ESP_LOGI(TAG, "new identity generated and stored");
    return ESP_OK;
}

esp_err_t device_keys_erase(void) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    nvs_erase_key(h, "keys");
    nvs_erase_key(h, "reg");
    err = nvs_commit(h);
    nvs_close(h);
    return err;
}

bool device_wifi_get(char *ssid, size_t ssid_cap, char *pass, size_t pass_cap) {
    nvs_handle_t h;
    size_t n;
    esp_err_t err = nvs_open(NS, NVS_READONLY, &h);
    if (err != ESP_OK) return false;

    n = ssid_cap;
    err = nvs_get_str(h, "ssid", ssid, &n);
    if (err != ESP_OK || ssid[0] == '\0') { nvs_close(h); return false; }

    n = pass_cap;
    if (nvs_get_str(h, "pass", pass, &n) != ESP_OK) pass[0] = '\0';
    nvs_close(h);
    return true;
}

esp_err_t device_wifi_set(const char *ssid, const char *pass) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, "ssid", ssid);
    if (err == ESP_OK) err = nvs_set_str(h, "pass", pass ? pass : "");
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t device_wifi_erase(void) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    nvs_erase_key(h, "ssid");
    nvs_erase_key(h, "pass");
    err = nvs_commit(h);
    nvs_close(h);
    return err;
}

bool device_is_registered(void) {
    uint8_t v = 0;
    return blob_get("reg", &v, sizeof(v)) == ESP_OK && v == 1;
}

esp_err_t device_set_registered(bool yes) {
    uint8_t v = yes ? 1 : 0;
    return blob_set("reg", &v, sizeof(v));
}
