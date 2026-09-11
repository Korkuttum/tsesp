// The setup page, and the DNS trick that makes a phone open it by itself.
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_server.h"
#include "esp_wifi.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "lwip/sockets.h"
#include "net.h"
#include "device_nvs.h"
#include "peers.h"
#include "magic.h"
#include "derp_task.h"
#include "tun.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_idf_version.h"
#include "esp_app_desc.h"
#include "esp_wifi.h"
#include "freertos/task.h"

static const char *TAG = "portal";
static httpd_handle_t s_server;
static portal_status s_status = { .state = "starting", .tailnet_addr = "", .name = "",
                                  .login_url = "", .route = "",
                                  .peers = 0, .paths_up = 0 };

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
    /* Nine dots in a three-by-three grid, corners faded, at the owner's
       request. Uses the theme's accent variable so it follows light and dark.
       This is very close to Tailscale's own mark, which is the same grid with
       the top-centre dot also unfilled. That is fine for a private device and
       would not be for anything published or given away; swapping the
       coordinates below for the rotated arrangement is a one-line change:
           11,11  22,4   33,11        ->  22,7   33,11  33,22
       or simply rotate the whole group: transform='rotate(45 22 22)'. */
    "<svg width=46 height=46 viewBox='0 0 44 44' fill='var(--blue)' "
    "style='vertical-align:middle;margin-right:11px;flex:0 0 auto'>"
    "<circle cx='11' cy='11' r='3.3' opacity='.28'/>"
    "<circle cx='22' cy='11' r='3.3'/>"
    "<circle cx='33' cy='11' r='3.3' opacity='.28'/>"
    "<circle cx='11' cy='22' r='3.3'/>"
    "<circle cx='22' cy='22' r='3.3'/>"
    "<circle cx='33' cy='22' r='3.3'/>"
    "<circle cx='11' cy='33' r='3.3' opacity='.28'/>"
    "<circle cx='22' cy='33' r='3.3'/>"
    "<circle cx='33' cy='33' r='3.3' opacity='.28'/>"
    "</svg>";

static const char CSS[] =
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<style>"
    /* Follows whatever the phone or laptop is set to. The dark values stay
       the default, so a browser that ignores the query still gets a readable
       page rather than black text on a black ground. */
    ":root{color-scheme:light dark;"
    "--bg:#0b0f14;--card:#141a21;--line:#1f2831;--dim:#7d8b99;--fg:#e6edf3;"
    "--track:#222c36;--sigoff:#2b3640;--hover:#1d252e;"
    "--blue:#3b82f6;--green:#22c55e;--amber:#f59e0b;--red:#ef4444}"
    "@media(prefers-color-scheme:light){:root{"
    "--bg:#f4f6f8;--card:#ffffff;--line:#e2e6ea;--dim:#68727d;--fg:#111820;"
    "--track:#e6eaee;--sigoff:#d3d9df;--hover:#eef1f4;"
    "--blue:#2563eb;--green:#16a34a;--amber:#b45309;--red:#dc2626}}"
    "*{box-sizing:border-box}"
    "body{font:15px/1.5 -apple-system,system-ui,sans-serif;margin:0;padding:18px 14px 40px;"
    "background:var(--bg);color:var(--fg)}"
    ".wrap{max-width:860px;margin:0 auto}"
    ".top{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}"
    "h1{display:flex;align-items:center;font-size:19px;margin:0;letter-spacing:-.2px}"
    "h1 small{display:block;font-size:12px;color:var(--dim);font-weight:400;letter-spacing:0}"
    ".gear{color:var(--dim);text-decoration:none;font-size:20px;padding:7px 10px;"
    "border:1px solid var(--line);border-radius:9px;background:var(--card)}"
    /* the headline strip */
    ".hero{background:var(--card);border:1px solid var(--line);border-radius:14px;"
    "padding:16px;margin-bottom:14px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}"
    ".dot{width:11px;height:11px;border-radius:50%;flex:0 0 11px}"
    ".dot.ok{background:var(--green);box-shadow:0 0 0 4px rgba(34,197,94,.16)}"
    ".dot.warn{background:var(--amber);box-shadow:0 0 0 4px rgba(245,158,11,.16)}"
    ".dot.bad{background:var(--red);box-shadow:0 0 0 4px rgba(239,68,68,.16)}"
    ".dot.none{background:var(--sigoff)}"
    ".hero .st{font-weight:600}"
    ".hero .addr{margin-left:auto;font-family:ui-monospace,Menlo,monospace;"
    "font-size:14px;color:var(--dim)}"
    /* tabs, done with radios so switching needs no script */
    ".tabs input{position:absolute;opacity:0;pointer-events:none}"
    ".tabbar{display:flex;gap:4px;background:var(--card);border:1px solid var(--line);"
    "border-radius:11px;padding:4px;margin-bottom:14px;overflow-x:auto}"
    ".tabbar label{flex:1;text-align:center;padding:8px 12px;border-radius:8px;"
    "font-size:14px;color:var(--dim);white-space:nowrap;cursor:pointer}"
    ".panel{display:none}"
    "#t1:checked~.tabbar label[for=t1],#t2:checked~.tabbar label[for=t2],"
    "#t3:checked~.tabbar label[for=t3],#t4:checked~.tabbar label[for=t4],"
    "#t5:checked~.tabbar label[for=t5]{background:var(--blue);color:#fff}"
    "#t1:checked~.panels .p1,#t2:checked~.panels .p2,"
    "#t3:checked~.panels .p3,#t4:checked~.panels .p4,"
    "#t5:checked~.panels .p5{display:block}"
    /* cards */
    ".grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}"
    "@media(min-width:620px){.grid{grid-template-columns:1fr 1fr 1fr}}"
    ".cell{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}"
    ".cell .k{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.7px}"
    ".cell .v{font-size:17px;margin-top:4px;font-variant-numeric:tabular-nums;"
    "font-family:ui-monospace,Menlo,monospace;word-break:break-all}"
    ".cell .v small{font-size:12px;color:var(--dim);font-family:inherit}"
    ".cell .v.row{display:flex;align-items:center;gap:6px}"
    /* A hostname broken across lines mid-word reads as a mistake; keep it on
       one line and let it trail off, since the copy button has the whole
       value anyway. */
    ".cell .v.row span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
    ".cell.wide{grid-column:1/-1}"
    ".cp{flex:0 0 auto;background:none;border:0;color:var(--dim);cursor:pointer;"
    "padding:3px;width:auto;margin:0;border-radius:6px;display:inline-flex;"
    "align-items:center}"
    ".cp:hover{color:var(--fg);background:var(--hover)}"
    ".cp.done{color:var(--green)}"
    "h2{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.7px;"
    "margin:18px 0 8px}"
    "h2:first-child{margin-top:0}"
    ".hint{color:var(--dim);font-size:12.5px;margin:-4px 0 10px;line-height:1.45}"
    /* meters */
    ".bar{height:6px;background:var(--track);border-radius:4px;overflow:hidden;margin-top:8px}"
    ".bar i{display:block;height:100%;background:var(--blue);border-radius:4px}"
    ".bar i.hot{background:var(--amber)}.bar i.max{background:var(--red)}"
    /* signal bars */
    ".sig{display:inline-flex;align-items:flex-end;gap:3px;height:18px;margin-right:8px;"
    "vertical-align:-3px}"
    ".sig b{width:4px;border-radius:1px;background:var(--sigoff)}"
    ".sig b:nth-child(1){height:5px}.sig b:nth-child(2){height:8px}"
    ".sig b:nth-child(3){height:11px}.sig b:nth-child(4){height:14px}"
    ".sig b:nth-child(5){height:18px}"
    ".sig b.on{background:var(--green)}.sig.w b.on{background:var(--amber)}"
    ".sig.b b.on{background:var(--red)}"
    /* peers */
    ".peer{display:flex;align-items:center;gap:11px;background:var(--card);"
    "border:1px solid var(--line);border-radius:11px;padding:11px 13px;margin-bottom:7px}"
    ".peer .nm{flex:1;min-width:0}"
    ".peer .nm b{display:block;font-weight:500;font-size:14px;overflow:hidden;"
    "text-overflow:ellipsis;white-space:nowrap}"
    ".peer .nm span{color:var(--dim);font-size:12px;font-family:ui-monospace,Menlo,monospace}"
    ".tag{font-size:11px;padding:4px 9px;border-radius:20px;white-space:nowrap}"
    ".tag.direct{background:rgba(34,197,94,.16);color:var(--green)}"
    ".tag.relay{background:rgba(59,130,246,.16);color:var(--blue)}"
    ".tag.probing{background:rgba(245,158,11,.18);color:var(--amber)}"
    ".tag.none{background:rgba(125,139,153,.12);color:var(--dim)}"
    ".banner{background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.4);"
    "border-radius:12px;padding:14px 16px;margin-bottom:14px}"
    ".banner a{color:var(--blue);font-weight:500}"
    "label.f{display:block;margin:14px 0 5px;color:var(--dim);font-size:13px}"
    "input,select{width:100%;padding:12px;font-size:16px;border:1px solid var(--line);"
    "border-radius:10px;background:var(--card);color:var(--fg)}"
    "button{width:100%;margin-top:20px;padding:13px;font-size:15px;font-weight:500;"
    "border:0;border-radius:10px;background:var(--blue);color:#fff}"
    "button.danger{background:transparent;border:1px solid var(--line);color:var(--red);"
    "font-size:13px;padding:10px}"
    "a{color:var(--blue);word-break:break-all}"
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

// FreeRTOS reports the smallest the stack ever got, in words. A task that
// overflows takes the whole device down and the only warning is this number
// getting close to zero, so it belongs on the page rather than in a log.
static unsigned stack_headroom(const char *task) {
    TaskHandle_t h = xTaskGetHandle(task);
    return h ? (unsigned)(uxTaskGetStackHighWaterMark(h) * sizeof(StackType_t)) : 0;
}

// CPU load, from the idle tasks' share of the runtime counter.
//
// Measured as a delta between calls rather than since boot: a device that has
// been up for a day would otherwise report an average that says nothing about
// what it is doing now. The page refreshes every few seconds, so each reading
// covers that interval.
static void cpu_load(int *core0, int *core1) {
    static uint32_t last_idle[2], last_total;
    UBaseType_t n = uxTaskGetNumberOfTasks();
    TaskStatus_t *tasks;
    uint32_t total = 0, idle[2] = { 0, 0 };
    UBaseType_t i;

    *core0 = *core1 = -1;
    tasks = calloc(n, sizeof(*tasks));
    if (!tasks) return;
    n = uxTaskGetSystemState(tasks, n, &total);

    for (i = 0; i < n; i++) {
        if (strncmp(tasks[i].pcTaskName, "IDLE", 4) != 0) continue;
        {
            int core = tasks[i].pcTaskName[4] == '1' ? 1 : 0;
            idle[core] += tasks[i].ulRunTimeCounter;
        }
    }
    free(tasks);

    if (last_total && total > last_total) {
        uint32_t span = total - last_total;
        int c;
        for (c = 0; c < 2; c++) {
            uint32_t idle_delta = idle[c] - last_idle[c];
            // Each core's idle task accrues time over the same interval, so
            // its share of that interval is the idle fraction directly.
            int pct = 100 - (int)((uint64_t)idle_delta * 100 / span);
            if (pct < 0) pct = 0;
            if (pct > 100) pct = 100;
            if (c == 0) *core0 = pct; else *core1 = pct;
        }
    }
    last_idle[0] = idle[0];
    last_idle[1] = idle[1];
    last_total = total;
}

// Wi-Fi signal as a count of bars, the way a phone shows it.
static int signal_bars(int rssi) {
    if (rssi == 0) return 0;
    if (rssi >= -55) return 5;
    if (rssi >= -65) return 4;
    if (rssi >= -72) return 3;
    if (rssi >= -80) return 2;
    return 1;
}

static const char *signal_word(int bars) {
    switch (bars) {
    case 5: return "mükemmel";
    case 4: return "iyi";
    case 3: return "orta";
    case 2: return "zayıf";
    case 1: return "çok zayıf";
    default: return "-";
    }
}

static const char *reset_reason_name(void) {
    switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return "Güç verildi";
    case ESP_RST_SW:       return "Yazılım";
    case ESP_RST_PANIC:    return "Çökme";
    case ESP_RST_INT_WDT:  return "Kesme zaman aşımı";
    case ESP_RST_TASK_WDT: return "Görev zaman aşımı";
    case ESP_RST_WDT:      return "watchdog";
    case ESP_RST_BROWNOUT: return "Düşük voltaj";
    case ESP_RST_DEEPSLEEP:return "Derin uyku";
    case ESP_RST_EXT:      return "Harici reset";
    default:               return "öğrenilemedi";
    }
}

// The state machine's names are for logs and tests; this is what a person
// should see.
static const char *state_text(const char *s) {
    if (!s) return "—";
    if (!strcmp(s, "running"))          return "Çalışıyor";
    if (!strcmp(s, "connecting"))       return "Bağlanıyor";
    if (!strcmp(s, "registering"))      return "Kaydoluyor";
    if (!strcmp(s, "awaiting-login"))   return "Giriş onayı bekleniyor";
    if (!strcmp(s, "waiting for login"))return "Giriş onayı bekleniyor";
    if (!strcmp(s, "fetching netmap"))  return "Ağ haritası alınıyor";
    if (!strcmp(s, "backoff"))          return "Yeniden denenecek";
    if (!strcmp(s, "start"))            return "Başlatılıyor";
    if (!strcmp(s, "starting"))         return "Başlatılıyor";
    if (!strcmp(s, "stopped"))          return "Durduruldu";
    return s;
}

static const char *chip_name(const esp_chip_info_t *c) {
    switch (c->model) {
    case CHIP_ESP32:   return "ESP32";
    case CHIP_ESP32S2: return "ESP32-S2";
    case CHIP_ESP32S3: return "ESP32-S3";
    case CHIP_ESP32C3: return "ESP32-C3";
    case CHIP_ESP32C6: return "ESP32-C6";
    case CHIP_ESP32H2: return "ESP32-H2";
    default:           return "ESP32 ailesi";
    }
}

static void meter(char *out, size_t cap, int pct) {
    const char *cls = pct >= 90 ? "max" : (pct >= 70 ? "hot" : "");
    if (pct < 0) { if (cap) out[0] = '\0'; return; }
    snprintf(out, cap, "<div class=bar><i class='%s' style='width:%d%%'></i></div>", cls, pct);
}

// A value with a button that copies it. The clipboard API is only available
// in secure contexts, and this page is plain HTTP on a LAN address, so the
// script falls back to the old selection trick.
#define ICON_COPY \
    "<svg viewBox='0 0 24 24' fill=none stroke=currentColor stroke-width=1.8 " \
    "stroke-linejoin=round width=15 height=15>" \
    "<rect x='9' y='9' width='11' height='11' rx='2.5'/>" \
    "<path d='M5 15H4.5A1.5 1.5 0 013 13.5v-9A1.5 1.5 0 014.5 3h9A1.5 1.5 0 0115 4.5V5'/>" \
    "</svg>"
#define ICON_TICK \
    "<svg viewBox='0 0 24 24' fill=none stroke=currentColor stroke-width=2.2 " \
    "stroke-linecap=round stroke-linejoin=round width=15 height=15>" \
    "<path d='M4 12.5l5 5L20 6.5'/></svg>"

// Enough for the wrapper, a label, an escaped value and the icon. Getting
// this wrong is not a cosmetic problem: a cell cut off mid-tag leaves the
// document's divs unbalanced, which nests everything that follows inside it
// and breaks the tab selectors entirely.
#define COPY_CELL_MAX 768

static void copy_cell_ex(char *out, size_t cap, const char *label,
                         const char *value, int wide) {
    char esc[160];
    int n;

    html_escape(esc, sizeof(esc), value);
    n = snprintf(out, cap,
                 "<div class='cell %s'><div class=k>%s</div>"
                 "<div class='v row'><span>%s</span>"
                 "<button class=cp onclick=\"cp(this,'%s')\" title='Kopyala'>"
                 ICON_COPY "</button>"
                 "</div></div>", wide ? "wide" : "", label, esc, esc);
    if (n < 0 || (size_t)n >= cap) {
        // Never emit half a tag. A cell without its button still renders.
        snprintf(out, cap, "<div class=cell><div class=k>%s</div>"
                           "<div class=v>%s</div></div>", label, esc);
    }
}

static void copy_cell(char *out, size_t cap, const char *label, const char *value) {
    copy_cell_ex(out, cap, label, value, 0);
}

static void sig_html(char *out, size_t cap, int bars) {
    const char *cls = bars >= 4 ? "" : (bars >= 2 ? "w" : "b");
    int i;
    size_t o = (size_t)snprintf(out, cap, "<span class='sig %s'>", cls);
    for (i = 1; i <= 5; i++)
        o += (size_t)snprintf(out + o, cap - o, "<b class='%s'></b>", i <= bars ? "on" : "");
    snprintf(out + o, cap - o, "</span>");
}

// "100.115.225.84/32" is how the netmap states it; nobody wants to copy the
// suffix.
static const char *bare_addr(const char *addr, char *buf, size_t cap) {
    const char *slash;
    if (!addr || !addr[0]) return "-";
    slash = strchr(addr, '/');
    if (!slash) return addr;
    snprintf(buf, cap, "%.*s", (int)(slash - addr), addr);
    return buf;
}

static esp_err_t get_status(httpd_req_t *req) {
    char *page = malloc(24576);
    size_t cap = 24576, o = 0;
    char ip[16], up[24], esc[520], pub[64], wifi_ssid[36];
    char sig[240], m1[96], m2[96], m3[96];
    // Static, not on the stack: five of these is nearly 4 KB, and the HTTP
    // server's task does not have that to spare. The server handles one
    // request at a time, so sharing them is safe.
    static char c1[COPY_CELL_MAX], c2[COPY_CELL_MAX], c3[COPY_CELL_MAX];
    static char c4[COPY_CELL_MAX], c5[COPY_CELL_MAX];
    char bare[48];
    const char *dot = "warn";
    int rssi = 0, channel = 0, bars, core0 = -1, core1 = -1;
    int i, n;
    uint32_t pings = 0, pongs = 0, tun_in = 0, tun_out = 0, derp_tx = 0, derp_rx = 0;
    esp_chip_info_t chip;
    uint32_t flash = 0;
    const esp_partition_t *app = esp_ota_get_running_partition();
    const esp_app_desc_t *desc = esp_app_get_description();
    size_t heap_free, heap_min, heap_big, heap_total;

    if (!page) return httpd_resp_send_500(req);

    net_get_ip(ip, sizeof(ip));
    net_get_wifi_info(wifi_ssid, sizeof(wifi_ssid), &rssi, &channel);
    magic_stats(&pings, &pongs);
    tun_stats(&tun_in, &tun_out);
    derp_task_stats(&derp_tx, &derp_rx);
    cpu_load(&core0, &core1);
    esp_chip_info(&chip);
    esp_flash_get_size(NULL, &flash);
    heap_free = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    heap_min = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
    heap_big = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    heap_total = heap_caps_get_total_size(MALLOC_CAP_8BIT);
    bars = signal_bars(rssi);
    sig_html(sig, sizeof(sig), bars);

    if (s_status.tailnet_addr && s_status.tailnet_addr[0]) dot = "ok";
    if (!net_is_connected()) dot = "bad";

    o += snprintf(page + o, cap - o,
        "<!doctype html><html lang=tr><meta charset=utf-8><title>tsesp</title>%s"
        "<div class=wrap>"
        "<div class=top><h1>%s<span>tsesp<small>ESP32 üzerinde tailnet düğümü</small></span></h1>"
        "</div>"
        "<div class=hero><span class='dot %s'></span><span class=st>%s</span>"
        "<span class=addr>%s</span></div>",
        CSS, LOGO, dot, state_text(s_status.state),
        s_status.tailnet_addr && s_status.tailnet_addr[0] ? s_status.tailnet_addr : "");

    if (s_status.login_url && s_status.login_url[0]) {
        html_escape(esc, sizeof(esc), s_status.login_url);
        o += snprintf(page + o, cap - o,
            "<div class=banner>Bu cihazi tailnet'ine katmak icin onayla:<br>"
            "<a href=\"%s\" target=_blank rel=noopener>%s</a></div>", esc, esc);
    }

    o += snprintf(page + o, cap - o,
        "<div class=tabs>"
        "<input type=radio name=tab id=t1 checked><input type=radio name=tab id=t2>"
        "<input type=radio name=tab id=t3><input type=radio name=tab id=t4>"
        "<input type=radio name=tab id=t5>"
        "<div class=tabbar>"
        "<label for=t1>Genel</label><label for=t2>Ağ</label>"
        "<label for=t3>Cihazlar</label><label for=t4>Sistem</label>"
        "<label for=t5>Ayarlar</label></div>"
        "<div class=panels>");

    /* ---- Genel ---- */
    n = peers_count();
    o += snprintf(page + o, cap - o,
        "<div class='panel p1'><div class=grid>"
        "%s%s"
        "<div class=cell><div class=k>Bağlı cihaz</div><div class=v>%d<small> adet</small></div></div>"
        "<div class=cell><div class=k>Doğrudan bağlanan</div><div class=v>%d<small> cihaz</small></div></div>"
        "<div class=cell><div class=k>Şifreli tünel</div><div class=v>%d<small> açık</small></div></div>"
        "<div class=cell><div class=k>Çalışma süresi</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>Tünel trafiği</div><div class=v>%u<small> alınan / %u gönderilen paket</small></div></div>"
        "</div></div>",
        (copy_cell_ex(c5, sizeof(c5), "Cihaz adı",
                      s_status.name && s_status.name[0] ? s_status.name : "-", 1), c5),
        (copy_cell(c1, sizeof(c1), "Tailscale adresi",
                   bare_addr(s_status.tailnet_addr, bare, sizeof(bare))), c1),
        n, s_status.paths_up, magic_tunnels_up(),
        uptime_str(up, sizeof(up)), (unsigned)tun_in, (unsigned)tun_out);

    /* ---- Ag ---- */
    o += snprintf(page + o, cap - o,
        "<div class='panel p2'><h2>Wi-Fi</h2><p class=hint>Cihazın bağlandığı ev ağı. Sinyal zayıfsa bağlantı kopmasa da yavaşlar.</p><div class=grid>"
        "<div class=cell><div class=k>Bağlı olduğu ağ</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>Sinyal</div><div class=v>%s%d<small> dBm, %s</small></div></div>"
        "<div class=cell><div class=k>Kanal</div><div class=v>%d</div></div>"
        "</div>"
        "<h2>Adresler</h2><p class=hint>&quot;Paylaşılan ev ağı&quot;, bu cihaz üzerinden uzaktan erişebileceğin yerel ağdır. Tailscale panelinde onaylanması gerekir.</p><div class=grid>"
        "%s%s%s</div>"
        "<h2>Bağlantı yöntemi</h2><p class=hint>Cihazlar birbirine doğrudan ulaşmayı dener. Modemler buna izin vermezse trafik ortadaki bir Tailscale sunucusundan dolanır: daha yavaş ama her zaman çalışır.</p><div class=grid>"
        "<div class=cell><div class=k>Doğrudan bağlanma denemesi</div><div class=v>%u<small> deneme, %u yanıt</small></div></div>"
        "<div class=cell><div class=k>Ara sunucu</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>Ara sunucudan geçen</div><div class=v>%u<small> gönderildi, %u alındı</small></div></div>"
        "</div></div>",
        wifi_ssid[0] ? wifi_ssid : "-", sig, rssi, signal_word(bars), channel,
        (copy_cell(c2, sizeof(c2), "Ev ağındaki adresi", ip), c2),
        (copy_cell(c3, sizeof(c3), "İnternetten görünen adres",
                   magic_get_public(pub, sizeof(pub)) ? pub : "henüz belirlenmedi"), c3),
        (copy_cell(c4, sizeof(c4), "Paylaşılan ev ağı",
                   s_status.route[0] ? s_status.route : "-"), c4),
        (unsigned)pings, (unsigned)pongs,
        derp_task_connected() ? derp_task_region_name() : "bağlı değil",
        (unsigned)derp_tx, (unsigned)derp_rx);

    /* ---- Peer'lar ---- */
    o += snprintf(page + o, cap - o, "<div class='panel p3'>");
    if (n == 0)
        o += snprintf(page + o, cap - o,
            "<div class=peer><div class=nm><b>Henüz yok</b>"
            "<span>ağ haritası bekleniyor</span></div></div>");
    for (i = 0; i < n && cap - o > 700; i++) {
        peer_entry *e = peers_at(i);
        const ts_path *best;
        char nm[TS_NAME_STR * 2], tag[80];
        if (!e) continue;

        best = magic_best_for(e);
        if (best)
            snprintf(tag, sizeof(tag), "<span class='tag direct'>doğrudan %u ms</span>",
                     best->latency_ms);
        else if (e->has_node_key && derp_task_connected())
            snprintf(tag, sizeof(tag), "<span class='tag relay'>dolaylı</span>");
        else if (e->has_disco && e->nendpoints)
            snprintf(tag, sizeof(tag), "<span class='tag probing'>bağlanıyor</span>");
        else
            snprintf(tag, sizeof(tag), "<span class='tag none'>bağlantı yok</span>");

        html_escape(nm, sizeof(nm), e->name[0] ? e->name : "(isimsiz)");
        o += snprintf(page + o, cap - o,
            "<div class=peer><span class='dot %s'></span>"
            "<div class=nm><b>%s</b><span>%s</span></div>%s</div>",
            e->online ? "ok" : "none", nm, e->addr[0] ? e->addr : "-", tag);
    }
    o += snprintf(page + o, cap - o, "</div>");

    /* ---- Sistem ---- */
    meter(m1, sizeof(m1), core0);
    meter(m2, sizeof(m2), core1);
    meter(m3, sizeof(m3), heap_total ? (int)(100 - heap_free * 100 / heap_total) : 0);

    o += snprintf(page + o, cap - o,
        "<div class='panel p4'>"
        "<h2>İşlemci</h2><p class=hint>Son birkaç saniyedeki ortalama yük.</p>"
        "<div class=grid>"
        "<div class=cell><div class=k>Çekirdek 1</div><div class=v>%d<small> %%</small></div>%s</div>"
        "<div class=cell><div class=k>Çekirdek 2</div><div class=v>%d<small> %%</small></div>%s</div>"
        "<div class=cell><div class=k>Saat hızı</div><div class=v>%d<small> MHz</small></div></div>"
        "</div>",
        core0 < 0 ? 0 : core0, m1, core1 < 0 ? 0 : core1, m2,
        CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);

    o += snprintf(page + o, cap - o,
        "<h2>Bellek</h2>"
        "<p class=hint>Toplam %u KB. Boş bellek tükenirse cihaz yeniden başlar.</p>"
        "<div class=grid>"
        "<div class=cell><div class=k>Kullanılan</div><div class=v>%u<small> KB</small></div>%s</div>"
        "<div class=cell><div class=k>Boş</div><div class=v>%u<small> KB</small></div></div>"
        "<div class=cell><div class=k>En az boş (açılıştan beri)</div>"
        "<div class=v>%u<small> KB</small></div></div>"
        "</div>",
        (unsigned)(heap_total / 1024),
        (unsigned)((heap_total - heap_free) / 1024), m3,
        (unsigned)(heap_free / 1024), (unsigned)(heap_min / 1024));

    o += snprintf(page + o, cap - o,
        "<h2>Donanım</h2><div class=grid>"
        "<div class=cell><div class=k>Kart</div><div class=v>%s<small> v%d.%d</small></div></div>"
        "<div class=cell><div class=k>Depolama</div><div class=v>%u<small> MB</small></div></div>"
        "<div class=cell><div class=k>Yazılıma ayrılan</div><div class=v>%u<small> KB</small></div></div>"
        "<div class=cell><div class=k>Yazılım sürümü</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>Son açılış sebebi</div><div class=v>%s</div></div>"
        "</div>",
        chip_name(&chip), chip.revision / 100, chip.revision % 100,
        (unsigned)(flash / (1024 * 1024)),
        (unsigned)(app ? app->size / 1024 : 0),
        desc ? desc->version : "?", reset_reason_name());

    o += snprintf(page + o, cap - o,
        "<h2>Ayrıntı (teknik)</h2>"
        "<p class=hint>Her görevin yığınında kalan boş yer, ve belleğin en büyük "
        "tek parçası. Sıfıra yaklaşan bir değer yeniden başlamaya yol açar.</p>"
        "<div class=grid>"
        "<div class=cell><div class=k>En büyük tek parça</div><div class=v>%u<small> KB</small></div></div>"
        "<div class=cell><div class=k>Ağ görevi</div><div class=v>%u<small> B</small></div></div>"
        "<div class=cell><div class=k>Kontrol görevi</div><div class=v>%u<small> B</small></div></div>"
        "<div class=cell><div class=k>Ara sunucu görevi</div><div class=v>%u<small> B</small></div></div>"
        "<div class=cell><div class=k>Geliştirme kiti</div><div class=v>%s</div></div>"
        "</div></div>",
        (unsigned)(heap_big / 1024),
        stack_headroom("magic"), stack_headroom("control"), stack_headroom("derp"),
        IDF_VER);

    /* ---- Ayarlar ---- */
    o += snprintf(page + o, cap - o,
        "<div class='panel p5'>"
        "<h2>Tailscale</h2>"
        "<p class=hint>Cihazın tailnet kimliğini siler ve yeni bir giriş bağlantısı "
        "üretir. Wi-Fi ayarları korunur.</p>"
        "<form method=POST action=/rejoin>"
        "<button type=submit>Tailscale'e yeniden kaydol</button></form>"
        "<h2>Wi-Fi ve kimlik</h2>"
        "<p class=hint>Her şeyi siler. Cihaz kurulum moduna döner ve kendi Wi-Fi "
        "ağını açar; baştan kurman gerekir.</p>"
        "<form method=POST action=/forget onsubmit=\"return confirm('Tüm ayarlar silinecek. Emin misin?')\">"
        "<button class=danger type=submit>Her şeyi sil ve baştan kur</button></form>"
        "</div>");

    // Refreshes the panels only. The tab radios live outside them, so the
    // section you are looking at stays put.
    o += snprintf(page + o, cap - o,
        "</div></div></div>"
        "<script>"
        "setInterval(async()=>{try{"
        "const r=await fetch('/',{cache:'no-store'});"
        "const d=new DOMParser().parseFromString(await r.text(),'text/html');"
        "for(const s of ['.hero','.panels']){"
        "const a=document.querySelector(s),b=d.querySelector(s);"
        "if(a&&b)a.innerHTML=b.innerHTML;}"
        "}catch(_){}},4000);"
        /* Double quotes here: the icons use single quotes for their SVG
           attributes, and a single-quoted JS string would end at the first
           one - taking the whole script, and the copy button, with it. */
        "const IC=\"" ICON_COPY "\",IT=\"" ICON_TICK "\";"
        "function cp(b,v){const d=()=>{b.classList.add('done');b.innerHTML=IT;"
        "setTimeout(()=>{b.classList.remove('done');b.innerHTML=IC;},1000)};"
        "if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(v).then(d)}"
        "else{const t=document.createElement('textarea');t.value=v;t.style.position='fixed';"
        "t.style.opacity=0;document.body.appendChild(t);t.select();"
        "try{document.execCommand('copy');d()}catch(e){}document.body.removeChild(t)}}"
        "</script>");

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, page, o);
    free(page);
    return ESP_OK;
}

static esp_err_t get_settings(httpd_req_t *req) {
    // The stylesheet alone is larger than a comfortable stack buffer, so the
    // page is built on the heap like the others.
    // The stylesheet alone runs to several kilobytes now.
    char *page = malloc(14336), ip[16], pub[64];
    size_t cap = 14336, o = 0;

    if (!page) return httpd_resp_send_500(req);
    net_get_ip(ip, sizeof(ip));
    if (!magic_get_public(pub, sizeof(pub))) snprintf(pub, sizeof(pub), "öğrenilemedi");

    o += snprintf(page + o, cap - o,
        "<!doctype html><html lang=tr><meta charset=utf-8><title>tsesp ayarlar</title>%s"
        "<div class=wrap><div class=top><div><h1>%s Ayarlar</h1>"
        "<p class=sub>Cihaz bilgileri ve sifirlama</p></div>"
        "<a class=gear href=/ title=Geri>&#8592;</a></div>"
        "<div class=grid>"
        "<div class=cell><div class=k>Yerel IP</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>İnternetten görünen adres</div><div class=v>%s</div></div>"
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
    // The status page builds several kilobytes of markup.
    cfg.stack_size = 8192;

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
