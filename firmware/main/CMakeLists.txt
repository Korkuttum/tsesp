idf_component_register(
    SRCS "main.c" "device_nvs.c" "net.c" "portal.c" "esp_io.c"
    INCLUDE_DIRS "."
    REQUIRES tsesp esp_timer mbedtls nvs_flash esp_wifi esp_netif
             esp_event esp_http_server lwip
)
