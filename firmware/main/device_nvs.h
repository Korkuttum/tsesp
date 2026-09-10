// Persistent device state: the three keys that make this a stable tailnet
// node, and the Wi-Fi credentials the user typed into the setup page.
//
// The keys must survive reboots. Losing them turns the device into a
// different machine that has to be approved again.
#ifndef DEVICE_NVS_H
#define DEVICE_NVS_H

#include <stdint.h>
#include <stdbool.h>

#define WIFI_SSID_MAX 33
#define WIFI_PASS_MAX 65

// Loads the identity, generating and storing it on first boot.
// machine: identifies the device to the control plane
// node:    identifies it inside the tailnet
// disco:   used for peer-to-peer path discovery
esp_err_t device_keys_load(uint8_t machine[32], uint8_t node[32], uint8_t disco[32]);

// Forgets the identity, so the next boot registers as a new device.
esp_err_t device_keys_erase(void);

bool      device_wifi_get(char *ssid, size_t ssid_cap, char *pass, size_t pass_cap);
esp_err_t device_wifi_set(const char *ssid, const char *pass);
esp_err_t device_wifi_erase(void);

bool      device_is_registered(void);
esp_err_t device_set_registered(bool yes);

#endif
