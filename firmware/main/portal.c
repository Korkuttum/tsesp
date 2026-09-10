// The setup page, and the DNS trick that makes a phone open it by itself.
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_server.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "lwip/sockets.h"
#include "net.h"
#include "device_nvs.h"

static const char *TAG = "portal";
static httpd_handle_t s_server;
static portal_status s_status = { .state = "starting", .tailnet_addr = "",
                                  .login_url = "", .peers = 0, .paths_up = 0 };

void portal_set_status(const portal_status *s) { s_status = *s; }

// ----------------------------------------------------------------- helpers

static void html_escape(char *out, size_t cap, const char *in) {
    size_t o = 0;
    for (; *in && o + 7 < cap; in++) {
        switch (*in) {
        case '<': memcpy(out + o, "&lt;", 4);   o += 4; break;
        case '>': memcpy(out + o, "&gt;", 4);   o += 4; break;
        case '&': memcpy(out + o, "&amp;", 5);  o += 5; break;
        case '"': memcpy(out + o, "&quot;", 6); o += 6; break;
        default:  out[o++] = *in; break;
        }
    }
    out[o] = '\0';
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Pulls one field out of an application/x-www-form-urlencoded body.
static bool form_field(const char *body, const char *name, char *out, size_t cap) {
    size_t nlen = strlen(name);
    const char *p = body;

    out[0] = '\0';
    while (p && *p) {
        const char *eq = strchr(p, '=');
        const char *amp = strchr(p, '&');
        if (!eq || (amp && eq > amp)) break;
        if ((size_t)(eq - p) == nlen && memcmp(p, name, nlen) == 0) {
            const char *v = eq + 1;
            const char *end = amp ? amp : v + strlen(v);
            size_t o = 0;
            while (v < end && o + 1 < cap) {
                if (*v == '+') { out[o++] = ' '; v++; }
                else if (*v == '%' && v + 2 < end &&
                         hexval(v[1]) >= 0 && hexval(v[2]) >= 0) {
                    out[o++] = (char)(hexval(v[1]) * 16 + hexval(v[2]));
                    v += 3;
                } else out[o++] = *v++;
            }
            out[o] = '\0';
            return true;
        }
        p = amp ? amp + 1 : NULL;
    }
    return false;
}

static const char CSS[] =
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<style>body{font:16px system-ui;margin:0;padding:24px;background:#111;color:#eee}"
    "h1{font-size:20px;margin:0 0 4px}p.sub{color:#999;margin:0 0 20px;font-size:14px}"
    "label{display:block;margin:14px 0 4px;color:#bbb;font-size:14px}"
    "input,select{width:100%;box-sizing:border-box;padding:12px;font-size:16px;"
    "border:1px solid #333;border-radius:8px;background:#1c1c1c;color:#eee}"
    "button{width:100%;margin-top:20px;padding:14px;font-size:16px;border:0;"
    "border-radius:8px;background:#2f6feb;color:#fff}"
    "table{width:100%;border-collapse:collapse}td{padding:8px 0;border-bottom:1px solid #222}"
    "td.k{color:#999;width:45%}a{color:#6ea8ff;word-break:break-all}"
    "code{background:#1c1c1c;padding:2px 6px;border-radius:4px}</style>";

// ------------------------------------------------------------- setup page

static esp_err_t get_setup(httpd_req_t *req) {
    uint16_t n = 0;
    wifi_ap_record_t *aps = NULL;
    char *page = malloc(8192);
    size_t o = 0;

    if (!page) return httpd_resp_send_500(req);

    esp_wifi_scan_start(NULL, true);
    esp_wifi_scan_get_ap_num(&n);
    if (n > 20) n = 20;
    if (n) {
        aps = calloc(n, sizeof(*aps));
        if (aps) esp_wifi_scan_get_ap_records(&n, aps);
        else n = 0;
    }

    o += snprintf(page + o, 8192 - o,
        "<!doctype html><title>tsesp kurulum</title>%s"
        "<h1>tsesp kurulum</h1><p class=sub>Cihazı ev ağına bağla</p>"
        "<form method=POST action=/save>"
        "<label>Ağ</label><select name=ssid>", CSS);

    for (uint16_t i = 0; i < n; i++) {
        char esc[80];
        html_escape(esc, sizeof(esc), (const char *)aps[i].ssid);
        if (esc[0])
            o += snprintf(page + o, 8192 - o, "<option value=\"%s\">%s (%d dBm)</option>",
                          esc, esc, aps[i].rssi);
    }
    free(aps);

    o += snprintf(page + o, 8192 - o,
        "</select>"
        "<label>Parola</label><input type=password name=pass autocomplete=off>"
        "<button type=submit>Bağlan</button></form>"
        "<p class=sub style='margin-top:24px'>Parola sadece bu cihazın flash'ına yazılır.</p>");

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, page, o);
    free(page);
    return ESP_OK;
}

static esp_err_t post_save(httpd_req_t *req) {
    char body[256], ssid[WIFI_SSID_MAX], pass[WIFI_PASS_MAX];
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len
                                                       : (int)sizeof(body) - 1;
    int got = httpd_req_recv(req, body, len);
    if (got <= 0) return httpd_resp_send_500(req);
    body[got] = '\0';

    if (!form_field(body, "ssid", ssid, sizeof(ssid)) || !ssid[0]) {
        httpd_resp_send(req, "ağ seçilmedi", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    form_field(body, "pass", pass, sizeof(pass));

    if (device_wifi_set(ssid, pass) != ESP_OK) return httpd_resp_send_500(req);
    ESP_LOGI(TAG, "credentials stored for %s", ssid);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr(req,
        "<!doctype html><title>tamam</title>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<body style='font:16px system-ui;background:#111;color:#eee;padding:24px'>"
        "<h1 style='font-size:20px'>Kaydedildi</h1>"
        "<p>Cihaz yeniden başlıyor ve ağına bağlanacak. "
        "Bu kurulum ağı birazdan kapanacak.</p>");

    // Give the browser a moment to render before the radio goes away.
    vTaskDelay(pdMS_TO_TICKS(1200));
    esp_restart();
    return ESP_OK;
}

// ------------------------------------------------------------ status page

static esp_err_t get_status(httpd_req_t *req) {
    // Sized for the escaped URL plus its wrapper; the compiler checks this
    // and a login link that gets truncated is a link that does not work.
    char page[2560], ip[16], login[768];
    size_t o = 0;

    net_get_ip(ip, sizeof(ip));
    login[0] = '\0';
    if (s_status.login_url && s_status.login_url[0]) {
        char esc[512];   /* AuthURLs are short, but escaping can grow them */
        html_escape(esc, sizeof(esc), s_status.login_url);
        snprintf(login, sizeof(login),
                 "<tr><td class=k>Tailscale girişi</td><td>"
                 "<a href=\"%s\" target=_blank>onaylamak için aç</a></td></tr>", esc);
    }

    o += snprintf(page + o, sizeof(page) - o,
        "<!doctype html><title>tsesp</title>%s"
        "<h1>tsesp</h1><p class=sub>ESP32 Tailscale düğümü</p><table>"
        "<tr><td class=k>Durum</td><td>%s</td></tr>"
        "<tr><td class=k>Yerel IP</td><td><code>%s</code></td></tr>"
        "<tr><td class=k>Tailnet adresi</td><td><code>%s</code></td></tr>"
        "<tr><td class=k>Peer sayısı</td><td>%d</td></tr>"
        "<tr><td class=k>Doğrudan yol</td><td>%d</td></tr>"
        "<tr><td class=k>Boş bellek</td><td>%u B</td></tr>"
        "%s</table>"
        "<form method=POST action=/forget><button type=submit "
        "style='background:#8b2020'>Ayarları sil ve yeniden kur</button></form>",
        CSS, s_status.state, ip,
        s_status.tailnet_addr && s_status.tailnet_addr[0] ? s_status.tailnet_addr : "-",
        s_status.peers, s_status.paths_up, s_status.free_heap, login);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, page, o);
    return ESP_OK;
}

static esp_err_t post_forget(httpd_req_t *req) {
    device_wifi_erase();
    device_keys_erase();
    httpd_resp_sendstr(req, "silindi, yeniden başlıyor");
    vTaskDelay(pdMS_TO_TICKS(800));
    esp_restart();
    return ESP_OK;
}

// A phone decides it is behind a captive portal by fetching a known URL and
// noticing the answer is not what it expected. Redirecting everything makes
// the setup page open by itself.
static esp_err_t redirect_to_root(httpd_req_t *req, httpd_err_code_t err) {
    (void)err;
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

// --------------------------------------------------------------- DNS trick

// Answers every A query with our own address. Only runs in AP mode.
static void dns_task(void *arg) {
    (void)arg;
    uint8_t buf[512];
    struct sockaddr_in addr = {0};
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) { vTaskDelete(NULL); return; }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    for (;;) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
        if (n < 12) continue;

        // Turn the query into an answer that points at 192.168.4.1.
        buf[2] |= 0x80;                 // response
        buf[3] = 0x00;
        buf[6] = 0; buf[7] = 1;         // one answer
        if (n + 16 > (int)sizeof(buf)) continue;
        buf[n++] = 0xc0; buf[n++] = 0x0c;          // pointer to the question name
        buf[n++] = 0; buf[n++] = 1;                // type A
        buf[n++] = 0; buf[n++] = 1;                // class IN
        buf[n++] = 0; buf[n++] = 0; buf[n++] = 0; buf[n++] = 30;   // ttl
        buf[n++] = 0; buf[n++] = 4;                // rdlength
        buf[n++] = 192; buf[n++] = 168; buf[n++] = 4; buf[n++] = 1;
        sendto(sock, buf, n, 0, (struct sockaddr *)&from, flen);
    }
}

// ------------------------------------------------------------------ start

esp_err_t portal_start(bool captive) {
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    esp_err_t err;

    cfg.max_uri_handlers = 8;
    cfg.lru_purge_enable = true;
    cfg.stack_size = 6144;

    err = httpd_start(&s_server, &cfg);
    if (err != ESP_OK) return err;

    {
        httpd_uri_t root = { .uri = "/", .method = HTTP_GET,
                             .handler = captive ? get_setup : get_status };
        httpd_uri_t setup = { .uri = "/setup", .method = HTTP_GET, .handler = get_setup };
        httpd_uri_t save = { .uri = "/save", .method = HTTP_POST, .handler = post_save };
        httpd_uri_t forget = { .uri = "/forget", .method = HTTP_POST, .handler = post_forget };
        httpd_register_uri_handler(s_server, &root);
        httpd_register_uri_handler(s_server, &setup);
        httpd_register_uri_handler(s_server, &save);
        httpd_register_uri_handler(s_server, &forget);
    }

    if (captive) {
        httpd_register_err_handler(s_server, HTTPD_404_NOT_FOUND, redirect_to_root);
        xTaskCreate(dns_task, "dns", 3072, NULL, 4, NULL);
        ESP_LOGI(TAG, "setup portal up at http://192.168.4.1/");
    } else {
        ESP_LOGI(TAG, "status page up");
    }
    return ESP_OK;
}
