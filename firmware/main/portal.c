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
#include "peers.h"
#include "magic.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

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


// Our own mark, not Tailscale's. Using theirs on a third-party device would
// imply an endorsement that does not exist - the same reason NOTICE.md says
// so in words. A chip outline with a small mesh inside: what this thing is.
static const char LOGO[] =
    "<svg width=44 height=44 viewBox='0 0 44 44' fill=none "
    "style='vertical-align:middle;margin-right:10px'>"
    "<rect x='9' y='9' width='26' height='26' rx='6' stroke='#2f6feb' stroke-width='2'/>"
    "<path d='M15 9V4M22 9V4M29 9V4M15 35v5M22 35v5M29 35v5"
    "M9 15H4M9 22H4M9 29H4M35 15h5M35 22h5M35 29h5' "
    "stroke='#2f6feb' stroke-width='2' stroke-linecap='round' opacity='.55'/>"
    "<path d='M22 16l6 11H16l6-11z' stroke='#6ea8ff' stroke-width='1.6' "
    "stroke-linejoin='round'/>"
    "<circle cx='22' cy='16' r='2.6' fill='#6ea8ff'/>"
    "<circle cx='16' cy='27' r='2.6' fill='#6ea8ff'/>"
    "<circle cx='28' cy='27' r='2.6' fill='#6ea8ff'/>"
    "</svg>";

static const char CSS[] =
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<style>"
    ":root{--bg:#0d1117;--card:#161b22;--line:#21262d;--dim:#8b949e;--fg:#e6edf3;"
    "--blue:#2f6feb;--green:#2ea043;--amber:#d29922;--red:#da3633}"
    "*{box-sizing:border-box}"
    "body{font:15px/1.5 -apple-system,system-ui,sans-serif;margin:0;padding:20px 16px 40px;"
    "background:var(--bg);color:var(--fg)}"
    ".wrap{max-width:900px;margin:0 auto}"
    ".cols{display:grid;grid-template-columns:1fr;gap:22px}"
    "@media(min-width:760px){.cols{grid-template-columns:1fr 1fr;align-items:start}}"
    ".top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}"
    ".gear{color:var(--dim);text-decoration:none;font-size:22px;line-height:1;padding:8px;border:1px solid var(--line);border-radius:10px;background:var(--card)}"
    ".gear:hover{color:var(--fg)}"
    "h1{display:flex;align-items:center;font-size:21px;margin:0 0 2px;letter-spacing:-.2px}"
    "p.sub{color:var(--dim);margin:0 0 22px;font-size:13px}"
    ".state{display:flex;align-items:center;gap:10px;background:var(--card);"
    "border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:14px}"
    ".dot{width:10px;height:10px;border-radius:50%;flex:0 0 10px}"
    ".dot.ok{background:var(--green);box-shadow:0 0 0 4px rgba(46,160,67,.15)}"
    ".dot.warn{background:var(--amber);box-shadow:0 0 0 4px rgba(210,153,34,.15)}"
    ".dot.bad{background:var(--red);box-shadow:0 0 0 4px rgba(218,54,51,.15)}"
    ".dot.none{background:#30363d}"
    ".state b{font-weight:600}"
    ".grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:18px}"
    ".cell{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}"
    ".cell .k{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.6px}"
    ".cell .v{font-size:16px;margin-top:3px;font-variant-numeric:tabular-nums;"
    "font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}"
    "h2{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;"
    "margin:0 0 8px}"
    ".peer{display:flex;align-items:center;gap:10px;background:var(--card);"
    "border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin-bottom:7px}"
    ".peer .nm{flex:1;min-width:0}"
    ".peer .nm b{display:block;font-weight:500;font-size:14px;overflow:hidden;"
    "text-overflow:ellipsis;white-space:nowrap}"
    ".peer .nm span{color:var(--dim);font-size:12px;"
    "font-family:ui-monospace,Menlo,monospace}"
    ".tag{font-size:11px;padding:3px 8px;border-radius:20px;white-space:nowrap}"
    ".tag.direct{background:rgba(46,160,67,.15);color:#3fb950}"
    ".tag.probing{background:rgba(210,153,34,.15);color:#d29922}"
    ".tag.none{background:rgba(139,148,158,.12);color:var(--dim)}"
    ".banner{background:rgba(47,111,235,.12);border:1px solid rgba(47,111,235,.4);"
    "border-radius:12px;padding:14px 16px;margin-bottom:14px}"
    ".banner a{color:#6ea8ff;font-weight:500}"
    "label{display:block;margin:14px 0 5px;color:var(--dim);font-size:13px}"
    "input,select{width:100%;padding:12px;font-size:16px;border:1px solid var(--line);"
    "border-radius:10px;background:var(--card);color:var(--fg)}"
    "button{width:100%;margin-top:20px;padding:13px;font-size:15px;font-weight:500;"
    "border:0;border-radius:10px;background:var(--blue);color:#fff}"
    "button.danger{background:transparent;border:1px solid var(--line);color:#f85149;"
    "font-size:13px;padding:10px}"
    "a{color:#6ea8ff;word-break:break-all}"
    "</style>";

// ------------------------------------------------------------- setup page

static esp_err_t get_setup(httpd_req_t *req) {
    uint16_t n = 0;
    wifi_ap_record_t *aps = NULL;
    char *page = malloc(8192);
    size_t o = 0;

    if (!page) return httpd_resp_send_500(req);

    {
        wifi_scan_config_t scan = { .show_hidden = false };
        esp_err_t serr = esp_wifi_scan_start(&scan, true);
        if (serr != ESP_OK) {
            ESP_LOGW(TAG, "scan failed: %s", esp_err_to_name(serr));
        } else {
            esp_wifi_scan_get_ap_num(&n);
            ESP_LOGI(TAG, "scan found %u networks", n);
        }
    }
    if (n > 20) n = 20;
    if (n) {
        aps = calloc(n, sizeof(*aps));
        if (aps) esp_wifi_scan_get_ap_records(&n, aps);
        else n = 0;
    }

    o += snprintf(page + o, 8192 - o,
        "<!doctype html><html lang=tr><meta charset=utf-8><title>tsesp kurulum</title>%s"
        "<div class=wrap><h1>%s tsesp</h1>"
        "<p class=sub>Cihazi ev agina bagla</p>"
        "<form method=POST action=/save>"
        "<label>Ağ</label><select name=ssid>"
        "<option value=''>-- listeden seç --</option>", CSS, LOGO);

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
        // A scan can come back empty, and hidden networks never show up at
        // all, so typing the name has to stay possible.
        "<label>veya ağ adını yaz</label>"
        "<input name=ssid_manual autocomplete=off placeholder='ağ adı'>"
        "<label>Parola</label><input type=password name=pass autocomplete=off>"
        "<button type=submit>Bağlan</button></form>"
        "<p class=sub style='margin-top:24px'>Bulunan ağ: %u. "
        "Parola sadece bu cihazın flash'ına yazılır.</p>"
        "<p class=sub><a href='/setup'>listeyi yenile</a></p></div>", (unsigned)n);

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

    // The typed name wins when it is filled in; otherwise take the dropdown.
    if (!form_field(body, "ssid_manual", ssid, sizeof(ssid)) || !ssid[0]) {
        if (!form_field(body, "ssid", ssid, sizeof(ssid)) || !ssid[0]) {
            httpd_resp_set_type(req, "text/html; charset=utf-8");
            httpd_resp_sendstr(req,
                "<!doctype html><body style='font:16px system-ui;background:#111;"
                "color:#eee;padding:24px'>Ağ seçilmedi. "
                "<a style='color:#6ea8ff' href='/setup'>geri dön</a>");
            return ESP_OK;
        }
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

static const char *uptime_str(char *out, size_t cap) {
    uint32_t sec = (uint32_t)(esp_timer_get_time() / 1000000);
    if (sec < 90) snprintf(out, cap, "%u sn", (unsigned)sec);
    else if (sec < 5400) snprintf(out, cap, "%u dk", (unsigned)(sec / 60));
    else snprintf(out, cap, "%u sa %u dk", (unsigned)(sec / 3600),
                  (unsigned)((sec % 3600) / 60));
    return out;
}

static esp_err_t get_status(httpd_req_t *req) {
    char *page = malloc(12288);
    char ip[16], up[24], esc[520];
    size_t cap = 12288, o = 0;
    const char *dot = "warn";
    int i, n;
    uint32_t pings = 0, pongs = 0;

    if (!page) return httpd_resp_send_500(req);
    net_get_ip(ip, sizeof(ip));
    magic_stats(&pings, &pongs);
    if (s_status.tailnet_addr && s_status.tailnet_addr[0]) dot = "ok";
    if (!net_is_connected()) dot = "bad";

    o += snprintf(page + o, cap - o,
        "<!doctype html><html lang=tr><meta charset=utf-8><title>tsesp</title>"
        "%s<div class=wrap>"
        "<div class=top><div><h1>%s tsesp</h1>"
        "<p class=sub>ESP32-WROOM-32U uzerinde tailnet dugumu</p></div>"
        "<a class=gear href=/settings title=Ayarlar>&#9881;</a></div>"
        "<div class=state><span class='dot %s'></span><b>%s</b></div>"
        "<div class=cols><div>",
        CSS, LOGO, dot, s_status.state ? s_status.state : "-");

    if (s_status.login_url && s_status.login_url[0]) {
        html_escape(esc, sizeof(esc), s_status.login_url);
        o += snprintf(page + o, cap - o,
            "<div class=banner>Bu cihazi tailnet'ine katmak icin onayla:<br>"
            "<a href=\"%s\" target=_blank rel=noopener>%s</a></div>", esc, esc);
    }

    o += snprintf(page + o, cap - o,
        "<div class=grid>"
        "<div class=cell><div class=k>Tailnet adresi</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>Yerel IP</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>Dogrudan yol</div><div class=v>%d / %d</div></div>"
        "<div class=cell><div class=k>Bos bellek</div><div class=v>%u KB</div></div>"
        "<div class=cell><div class=k>Calisma suresi</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>DISCO ping/pong</div><div class=v>%u/%u</div></div>"
        "</div>",
        s_status.tailnet_addr && s_status.tailnet_addr[0] ? s_status.tailnet_addr : "-",
        ip, s_status.paths_up, peers_count(),
        (unsigned)(heap_caps_get_free_size(MALLOC_CAP_8BIT) / 1024),
        uptime_str(up, sizeof(up)), (unsigned)pings, (unsigned)pongs);

    // Left column ends here; the peer list is the right one.
    n = peers_count();
    o += snprintf(page + o, cap - o, "</div><div><h2>Peer'lar (%d)</h2>", n);
    if (n == 0)
        o += snprintf(page + o, cap - o,
            "<div class=peer><div class=nm><b>henuz yok</b>"
            "<span>netmap bekleniyor</span></div></div>");

    for (i = 0; i < n && cap - o > 512; i++) {
        peer_entry *e = peers_at(i);
        const ts_path *best;
        char nm[TS_NAME_STR * 2], tag[64];
        if (!e) continue;

        best = magic_best_for(e);
        if (best)
            snprintf(tag, sizeof(tag), "<span class='tag direct'>dogrudan %u ms</span>",
                     best->latency_ms);
        else if (e->has_disco && e->nendpoints)
            snprintf(tag, sizeof(tag), "<span class='tag probing'>deneniyor</span>");
        else
            snprintf(tag, sizeof(tag), "<span class='tag none'>yol yok</span>");

        html_escape(nm, sizeof(nm), e->name[0] ? e->name : "(isimsiz)");
        o += snprintf(page + o, cap - o,
            "<div class=peer><span class='dot %s'></span>"
            "<div class=nm><b>%s</b><span>%s</span></div>%s</div>",
            e->online ? "ok" : "none", nm, e->addr[0] ? e->addr : "-", tag);
    }

    // Refresh in the background rather than reloading: a page that reloads
    // under you loses your scroll position and flickers every few seconds.
    o += snprintf(page + o, cap - o,
        "</div></div></div>"
        "<script>"
        "setInterval(async()=>{try{"
        "const r=await fetch('/',{cache:'no-store'});"
        "const d=new DOMParser().parseFromString(await r.text(),'text/html');"
        "const a=document.querySelector('.state'),b=d.querySelector('.state');"
        "if(a&&b)a.innerHTML=b.innerHTML;"
        "const c=document.querySelector('.cols'),e=d.querySelector('.cols');"
        "if(c&&e)c.innerHTML=e.innerHTML;"
        "}catch(_){}} ,4000);"
        "</script>");

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, page, o);
    free(page);
    return ESP_OK;
}

static esp_err_t get_settings(httpd_req_t *req) {
    // The stylesheet alone is larger than a comfortable stack buffer, so the
    // page is built on the heap like the others.
    char *page = malloc(6144), ip[16], pub[64];
    size_t cap = 6144, o = 0;

    if (!page) return httpd_resp_send_500(req);
    net_get_ip(ip, sizeof(ip));
    if (!magic_get_public(pub, sizeof(pub))) snprintf(pub, sizeof(pub), "bilinmiyor");

    o += snprintf(page + o, cap - o,
        "<!doctype html><html lang=tr><meta charset=utf-8><title>tsesp ayarlar</title>%s"
        "<div class=wrap><div class=top><div><h1>%s Ayarlar</h1>"
        "<p class=sub>Cihaz bilgileri ve sifirlama</p></div>"
        "<a class=gear href=/ title=Geri>&#8592;</a></div>"
        "<div class=grid>"
        "<div class=cell><div class=k>Yerel IP</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>Disaridan gorunen</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>UDP portu</div><div class=v>%d</div></div>"
        "<div class=cell><div class=k>Kayit</div><div class=v>%s</div></div>"
        "</div>"
        "<h2>Tailnet</h2>"
        "<p class=sub>Kimligi silip yeniden kaydolur. Wi-Fi ayarlari kalir.</p>"
        "<form method=POST action=/rejoin>"
        "<button type=submit>Tailnet'e yeniden kaydol</button></form>"
        "<h2>Tehlikeli</h2>"
        "<p class=sub>Wi-Fi bilgilerini ve tailnet kimligini siler. Cihaz kurulum "
        "moduna doner ve tailnet'e yeniden onaylanmasi gerekir.</p>"
        "<form method=POST action=/forget onsubmit=\"return confirm('Emin misin?')\">"
        "<button class=danger type=submit>Her seyi sil ve yeniden kur</button></form>"
        "</div>",
        CSS, LOGO, ip, pub, MAGIC_PORT,
        device_is_registered() ? "kayitli" : "kayitli degil");

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, page, o);
    free(page);
    return ESP_OK;
}

// Rejoining the tailnet without redoing Wi-Fi. Useful whenever the node's
// registration needs replacing - a changed capability version, an expired
// key - and much less drastic than forgetting everything.
static esp_err_t post_rejoin(httpd_req_t *req) {
    device_keys_erase();
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr(req,
        "<!doctype html><meta charset=utf-8>"
        "<body style='font:16px system-ui;background:#0d1117;color:#e6edf3;padding:24px'>"
        "Tailnet kimligi silindi. Cihaz yeniden baslayip yeni bir giris "
        "baglantisi uretecek. Wi-Fi ayarlari duruyor.");
    vTaskDelay(pdMS_TO_TICKS(800));
    esp_restart();
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

    cfg.max_uri_handlers = 10;
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
        httpd_uri_t settings = { .uri = "/settings", .method = HTTP_GET, .handler = get_settings };
        httpd_uri_t rejoin = { .uri = "/rejoin", .method = HTTP_POST, .handler = post_rejoin };
        httpd_register_uri_handler(s_server, &root);
        httpd_register_uri_handler(s_server, &setup);
        httpd_register_uri_handler(s_server, &save);
        httpd_register_uri_handler(s_server, &forget);
        if (!captive) httpd_register_uri_handler(s_server, &settings);
        if (!captive) httpd_register_uri_handler(s_server, &rejoin);
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
