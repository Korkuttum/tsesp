// The setup page, and the DNS trick that makes a phone open it by itself.
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_server.h"
#include "esp_wifi.h"
#include "lwip/etharp.h"
#include "logbuf.h"
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
#include "ota.h"
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
                                  .login_url = "", .route = "", .route_approved = -1,
                                  .peers = 0, .paths_up = 0 };

// The panel's language. Read once from NVS at startup and kept here rather
// than re-read on every request - it changes only through post_lang below,
// which updates both the flash copy and this one together.
static bool s_lang_en;

// Every user-visible string in this file picks between its Turkish and
// English spelling through this, tr first because that is what the device
// shipped with and what device_lang_is_en() defaults to on a device that
// has never touched /lang.
#define T(tr, en) (s_lang_en ? (en) : (tr))

// Once someone has actually picked a language it always wins - that's what
// device_lang_pref() is for. Before that, the browser's own Accept-Language
// is the only signal there is: "tr" or "tr-TR" (in whatever case, wherever
// it falls in the header's comma list) means Turkish, anything else means
// English. Nothing gets written to flash here; it is decided fresh on every
// request until a POST to /lang settles it.
static void resolve_lang(httpd_req_t *req) {
    bool pref;
    char al[64];

    if (device_lang_pref(&pref)) { s_lang_en = pref; return; }

    s_lang_en = true;
    // A header longer than al[] still starts the same way, so a truncated
    // read is just as usable here as a complete one - only the prefix matters.
    esp_err_t err = httpd_req_get_hdr_value_str(req, "Accept-Language", al, sizeof(al));
    if (err == ESP_OK || err == ESP_ERR_HTTPD_RESULT_TRUNC) {
        // Only the FIRST tag counts - the list is already in preference
        // order, so someone whose primary language is English and who
        // merely lists Turkish as a fallback further down (or vice versa)
        // still gets their actual first choice, not whichever tag a plain
        // substring search happened to notice.
        size_t taglen;
        for (char *p = al; *p; p++) *p = (char)tolower((unsigned char)*p);
        taglen = strcspn(al, ",;");
        if (taglen >= 2 && al[0] == 't' && al[1] == 'r' &&
            (taglen == 2 || al[2] == '-'))
            s_lang_en = false;
    }
}

// A tiny form that flips s_lang_en and lands back on "to". Used on every
// page that has room for it - unlike the theme switch, this can't be a
// client-side toggle, since the language lives in every string the server
// already sent.
#define LANG_TOGGLE_MAX 192
static void lang_toggle(char *out, size_t cap, const char *to) {
    snprintf(out, cap,
        "<form class=langf method=POST action=/lang>"
        "<input type=hidden name=to value='%s'>"
        "<button name=lang value=%s class=langbtn>%s</button></form>",
        to, s_lang_en ? "tr" : "en", s_lang_en ? "TR" : "EN");
}

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

// snprintf returns how much it WOULD have written, not how much fit - so once
// a page's running offset passes its buffer's size, a plain "cap - o" wraps
// past zero (both are size_t) into a huge count, and every call after that
// believes it has nearly unlimited room and writes straight past the
// allocation. A page that outgrows its buffer is expected to just lose its
// last tab, not corrupt the heap; this is what keeps that true.
static inline size_t room(size_t cap, size_t o) { return o < cap ? cap - o : 0; }

// The same overflow, on the way out. o is the sum of what snprintf says it
// WOULD have written, which keeps growing past cap once a page overflows -
// room() only stops the writes themselves from wrapping. Sending o bytes out
// of a cap-byte allocation past that point reads whatever heap sits after it,
// which is a page that discloses stale memory, not just one missing a tab.
static inline size_t clamp_len(size_t cap, size_t o) { return o < cap ? o : cap; }

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
    /* Follows whatever the phone or laptop is set to, unless the header
       switch has set data-theme explicitly - that always wins, since a
       reader who reached for the switch is not asking the OS again. */
    ":root{color-scheme:light dark;"
    "--bg:#0b0f14;--card:#141a21;--line:#1f2831;--dim:#7d8b99;--fg:#e6edf3;"
    "--track:#222c36;--sigoff:#2b3640;--hover:#1d252e;"
    "--blue:#3b82f6;--green:#22c55e;--amber:#f59e0b;--red:#ef4444}"
    "@media(prefers-color-scheme:light){:root{"
    "--bg:#f4f6f8;--card:#ffffff;--line:#e2e6ea;--dim:#68727d;--fg:#111820;"
    "--track:#e6eaee;--sigoff:#d3d9df;--hover:#eef1f4;"
    "--blue:#2563eb;--green:#16a34a;--amber:#b45309;--red:#dc2626}}"
    ":root[data-theme=dark]{"
    "--bg:#0b0f14;--card:#141a21;--line:#1f2831;--dim:#7d8b99;--fg:#e6edf3;"
    "--track:#222c36;--sigoff:#2b3640;--hover:#1d252e;"
    "--blue:#3b82f6;--green:#22c55e;--amber:#f59e0b;--red:#ef4444}"
    ":root[data-theme=light]{"
    "--bg:#f4f6f8;--card:#ffffff;--line:#e2e6ea;--dim:#68727d;--fg:#111820;"
    "--track:#e6eaee;--sigoff:#d3d9df;--hover:#eef1f4;"
    "--blue:#2563eb;--green:#16a34a;--amber:#b45309;--red:#dc2626}"
    "*{box-sizing:border-box}"
    // Keeps the scrollbar's own width part of the layout at all times, so a
    // tab shorter than the viewport (no scrollbar) and one taller than it
    // (scrollbar appears) don't leave .wrap's centering to land in two
    // different places - the jump a reader saw when switching tabs.
    "html{overflow-y:scroll}"
    "body{font:15px/1.5 -apple-system,system-ui,sans-serif;margin:0;padding:0 0 40px;"
    "background:var(--bg);color:var(--fg)}"
    ".wrap{max-width:860px;margin:0 auto;padding:18px 14px 0}"
    ".top{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}"
    "h1{display:flex;align-items:center;font-size:19px;margin:0;letter-spacing:-.2px}"
    "h1 small{display:block;font-size:12px;color:var(--dim);font-weight:400;letter-spacing:0}"
    ".gear{color:var(--dim);text-decoration:none;font-size:20px;padding:7px 10px;"
    "border:1px solid var(--line);border-radius:9px;background:var(--card)}"
    /* the sticky nav, styled after LuCI's - a dark bar in both themes, since
       the page under it is what changes with the reader's theme, not the
       bar telling them which tab they are on. */
    ".luciheader{background:linear-gradient(#333,#222);position:sticky;top:0;z-index:800}"
    ".luciheader-in{display:flex;align-items:stretch;max-width:860px;margin:0 auto;"
    "padding:0 14px;flex-wrap:wrap}"
    ".brand{color:#fff;font-size:17px;font-weight:600;padding:11px 14px 11px 0;"
    "letter-spacing:-.2px;display:flex;align-items:center;gap:8px}"
    ".brand svg{width:34px;height:34px;margin:0}"
    ".luciheader nav{display:flex;align-self:stretch;flex:1}"
    ".tabs input{position:absolute;opacity:0;pointer-events:none}"
    ".luciheader nav label{color:#bfbfbf;padding:0 14px;font-size:13.5px;cursor:pointer;"
    "display:flex;align-items:center;white-space:nowrap;border-radius:12px 12px 0 0;"
    "margin-top:11px;position:relative}"
    "#t1:checked~.luciheader nav label[for=t1],#t2:checked~.luciheader nav label[for=t2],"
    "#t3:checked~.luciheader nav label[for=t3],#t4:checked~.luciheader nav label[for=t4],"
    "#t5:checked~.luciheader nav label[for=t5]{background:var(--bg);color:var(--fg);font-weight:600}"
    "#t1:checked~.luciheader nav label[for=t1]::before,#t1:checked~.luciheader nav label[for=t1]::after,"
    "#t2:checked~.luciheader nav label[for=t2]::before,#t2:checked~.luciheader nav label[for=t2]::after,"
    "#t3:checked~.luciheader nav label[for=t3]::before,#t3:checked~.luciheader nav label[for=t3]::after,"
    "#t4:checked~.luciheader nav label[for=t4]::before,#t4:checked~.luciheader nav label[for=t4]::after,"
    "#t5:checked~.luciheader nav label[for=t5]::before,#t5:checked~.luciheader nav label[for=t5]::after"
    "{content:'';position:absolute;bottom:0;width:12px;height:12px}"
    ".luciheader nav label[for=t1]::before,.luciheader nav label[for=t2]::before,"
    ".luciheader nav label[for=t3]::before,.luciheader nav label[for=t4]::before,"
    ".luciheader nav label[for=t5]::before{left:-12px;"
    "background:radial-gradient(circle at top left,transparent 12px,var(--bg) 12px)}"
    ".luciheader nav label[for=t1]::after,.luciheader nav label[for=t2]::after,"
    ".luciheader nav label[for=t3]::after,.luciheader nav label[for=t4]::after,"
    ".luciheader nav label[for=t5]::after{right:-12px;"
    "background:radial-gradient(circle at top right,transparent 12px,var(--bg) 12px)}"
    /* Narrow enough that brand + tabs + switch cannot share one line: the
       switch used to be whichever item happened to wrap, landing under the
       tabs. Give the tabs their own full-width row instead, so brand and
       switch always keep the first one. */
    // overflow-x:auto turns this row into its own scrollport, and Genel's
    // ::before/Ayarlar's ::after both draw 12px to the OUTSIDE of the first
    // and last tab - past where that scrollport starts and ends. Without
    // this padding the scrollport clips them: Genel's curved left corner
    // came out square, which is what the padding buys back.
    "@media(max-width:640px){.luciheader nav{order:3;flex:0 0 100%;"
    "overflow-x:auto;margin-top:2px;padding:0 12px}}"
    // margin-left:auto, not just nav's own flex:1, pushes this to the far
    // right: on mobile nav drops its flex:1 to wrap onto its own row, which
    // would otherwise leave the switch sitting right next to the brand.
    ".indicators{display:flex;align-items:center;gap:12px;padding:7px 0;margin-left:auto}"
    // The language switch is a real page reload (every string on the page is
    // server-rendered), not a client-side toggle like the theme switch next
    // to it - styled as a small pill so the two don't compete for attention.
    ".langf{margin:0;display:inline}"
    ".langbtn{width:auto;margin:0;padding:5px 11px;font-size:12px;font-weight:600;"
    "border:1px solid var(--line);border-radius:999px;background:var(--card);"
    "color:var(--dim)}"
    // Inside the header bar (Genel/Ağ/... tab strip) the button sits on the
    // fixed dark gradient every theme shares, not on var(--bg) - the same
    // reason the theme switch and nav labels around it use their own fixed
    // colors instead of the page's theme variables.
    ".luciheader .langbtn{color:#fff;border-color:rgba(255,255,255,.35);"
    "background:rgba(255,255,255,.14)}"
    ".theme-switch{position:relative;width:42px;height:23px;display:inline-block;"
    "cursor:pointer;border-radius:999px}"
    ".theme-switch input{position:absolute;opacity:0;width:0;height:0}"
    ".ts-track{position:absolute;inset:0;background:rgba(255,255,255,.28);"
    "border-radius:999px;transition:background .2s}"
    ".ts-knob{position:absolute;left:3px;top:3px;width:17px;height:17px;border-radius:50%;"
    "background:#fff;display:flex;align-items:center;justify-content:center;"
    "transition:transform .25s cubic-bezier(.4,0,.2,1);box-shadow:0 1px 3px rgba(0,0,0,.4)}"
    ".ts-knob svg{position:absolute;width:11px;height:11px;transition:opacity .15s,transform .2s}"
    ".ts-sun{color:#e8a33d;opacity:1;transform:scale(1) rotate(0)}"
    ".ts-moon{color:#5b6b7a;opacity:0;transform:scale(.4) rotate(40deg)}"
    /* checked means dark: the knob slides right and shows the moon, since
       that is the theme now in effect, not the one a tap away. */
    "#theme-toggle:checked~.ts-track{background:#2a8fd8}"
    "#theme-toggle:checked~.ts-track .ts-knob{transform:translateX(19px)}"
    "#theme-toggle:checked~.ts-track .ts-knob .ts-moon{opacity:1;transform:scale(1) rotate(0)}"
    "#theme-toggle:checked~.ts-track .ts-knob .ts-sun{opacity:0;transform:scale(.4) rotate(-40deg)}"
    /* the headline strip */
    ".hero{background:var(--card);border:1px solid var(--line);border-radius:14px;"
    "padding:16px;margin:18px 0 14px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}"
    ".dot{width:11px;height:11px;border-radius:50%;flex:0 0 11px}"
    ".dot.ok{background:var(--green);box-shadow:0 0 0 4px rgba(34,197,94,.16)}"
    ".dot.warn{background:var(--amber);box-shadow:0 0 0 4px rgba(245,158,11,.16)}"
    ".dot.bad{background:var(--red);box-shadow:0 0 0 4px rgba(239,68,68,.16)}"
    ".dot.none{background:var(--sigoff)}"
    ".hero .st{font-weight:600}"
    ".hero .addr{margin-left:auto;font-family:ui-monospace,Menlo,monospace;"
    "font-size:14px;color:var(--dim)}"
    ".panel{display:none}"
    "#t1:checked~.wrap .panels .p1,#t2:checked~.wrap .panels .p2,"
    "#t3:checked~.wrap .panels .p3,#t4:checked~.wrap .panels .p4,"
    "#t5:checked~.wrap .panels .p5{display:block}"
    /* Genel: one card per topic, icon and title on top - an overview, not a
       diagnostic. The detail tabs below use .grid/.cell instead. */
    ".cardgrid{display:grid;grid-template-columns:1fr 1fr;gap:14px}"
    "@media(max-width:640px){.cardgrid{grid-template-columns:1fr}}"
    ".card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px}"
    ".card .ic{display:block;margin:0 auto 10px}"
    ".card h2{margin:0 0 12px;font-size:16px;font-weight:700;text-align:center;"
    "text-transform:none;letter-spacing:-.2px;color:var(--fg)}"
    ".card h2 .count{color:var(--dim);font-weight:400;font-size:13px}"
    ".card hr{border:0;border-top:1px solid var(--line);margin:0}"
    /* Every peer goes in now, not just the first four - once that outgrows a
       comfortable card height it scrolls in place instead of pushing the
       whole cardgrid row out of line with its neighbours. */
    ".scrollList{max-height:230px;overflow-y:auto}"
    ".rowline{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px;padding:8px 0;"
    "font-size:14px;border-bottom:1px solid var(--line)}"
    ".rowline:last-child{border-bottom:0}"
    ".rowline .bar{flex:0 0 100%}"
    ".rowline .k{color:var(--dim)}"
    ".rowline .v{margin-left:auto;text-align:right;font-weight:600;"
    "font-family:ui-monospace,Menlo,monospace;font-size:14px}"
    ".pill{font-size:11px;font-weight:700;color:#fff;padding:3px 9px;border-radius:9px;"
    "white-space:nowrap}"
    ".pill.ok{background:var(--green)}.pill.warn{background:var(--amber)}"
    ".pill.bad{background:var(--red)}"
    /* Ağ/Sistem/Ayarlar: one bordered card of stacked rows rather than a grid
       of little boxes - the same .cell markup the C side already emits, so
       this is a pure reskin with no change to how a panel is built. */
    ".grid{background:var(--card);border:1px solid var(--line);border-radius:14px;"
    "padding:2px 14px;margin-bottom:4px}"
    ".cell{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px;padding:10px 0;"
    "border-bottom:1px solid var(--line)}"
    ".cell:last-child{border-bottom:0}"
    /* A cell with a meter bar has a third child after .k/.v - force it onto
       its own full-width line instead of squeezing into the label/value row. */
    ".cell .bar{flex:0 0 100%}"
    ".cell .k{color:var(--dim);font-size:13.5px}"
    ".cell .v{margin-left:auto;text-align:right;font-size:14px;"
    "font-variant-numeric:tabular-nums;font-family:ui-monospace,Menlo,monospace;"
    "word-break:break-all;font-weight:600}"
    ".cell .v small{font-size:12px;color:var(--dim);font-family:inherit;"
    "font-weight:400;white-space:nowrap}"
    /* A wide cell's value is a long comma-separated list, not a short number -
       give it its own full-width, left-aligned line under the label. */
    ".cell.wide .v{flex:0 0 100%;margin-left:0;text-align:left}"
    ".miniList{flex:0 0 100%;margin:4px 0 0;padding:0;list-style:none}"
    ".miniList li{padding:6px 0;font-family:ui-monospace,Menlo,monospace;"
    "font-size:13px;border-top:1px solid var(--line)}"
    ".miniList li:first-child{border-top:0;padding-top:2px}"
    ".cell .v.row{display:flex;align-items:center;gap:6px}"
    /* A hostname broken across lines mid-word reads as a mistake; keep it on
       one line and let it trail off, since the copy button has the whole
       value anyway. */
    ".cell .v.row span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
    ".cp{flex:0 0 auto;background:none;border:0;color:var(--dim);cursor:pointer;"
    "padding:3px;width:auto;margin:0;border-radius:6px;display:inline-flex;"
    "align-items:center}"
    ".cp:hover{color:var(--fg);background:var(--hover)}"
    ".cp.done{color:var(--green)}"
    ".cp.sm{padding:0 0 0 5px;vertical-align:-2px;opacity:.45}"
    ".cp.sm:hover{opacity:1;background:none}"
    ".cp.sm svg{width:13px;height:13px}"
    "h2{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.7px;"
    "margin:22px 0 8px}"
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
    ".peer .nm b{display:flex;align-items:center;font-weight:500;font-size:14px}"
    ".peer .nm b>button{flex:0 0 auto}"
    ".peer .nm span{display:flex;align-items:center;color:var(--dim);font-size:12px;"
    "font-family:ui-monospace,Menlo,monospace}"
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
    "button:disabled{opacity:.5}"
    /* The browser draws a file input itself, and the generic input rule above
       gives it a padded, bordered box that iOS Safari then renders the picker
       inside - clipped, and on a phone effectively invisible. So the input is
       hidden and this label stands in for it: a control we draw entirely, and
       one that can show which file was chosen, which the real picker does not
       do once the page repaints. */
    ".fpick{display:block;margin-top:16px;padding:13px;border:1px dashed "
    "var(--line);border-radius:10px;background:var(--card);color:var(--dim);"
    "font-size:14px;text-align:center;cursor:pointer}"
    ".fpick.has{color:var(--fg);border-style:solid}"
    "code{font-family:ui-monospace,SFMono-Regular,monospace;font-size:12px;color:var(--fg)}"
    "a{color:var(--blue);word-break:break-all}"
    "</style>";

// ------------------------------------------------------------- setup page

// When the setup page was last touched. A phone joining the setup network
// hits "/" by itself, so this answers "is someone standing here right now",
// which is the one reason not to reboot and retry the stored network.
static volatile uint32_t s_last_req_ms;

static void mark_active(void) {
    s_last_req_ms = (uint32_t)(esp_timer_get_time() / 1000);
}

uint32_t portal_idle_ms(void) {
    // Never opened means nobody is here, which has to read as idle however
    // early it is. Returning the uptime instead would look like a visit that
    // happened "uptime ago", and for the first few minutes after a power cut
    // - the minutes that matter - that reads as somebody standing here.
    if (!s_last_req_ms) return 0xffffffffu;
    return (uint32_t)(esp_timer_get_time() / 1000) - s_last_req_ms;
}

// The log, as plain text. Deliberately not on the dashboard: it is for
// whoever is debugging, and it is the difference between diagnosing this
// device from here and driving to it.
static esp_err_t get_log(httpd_req_t *req) {
    char *buf = malloc(4096);
    size_t n;
    if (!buf) return httpd_resp_send_500(req);
    n = logbuf_read(buf, 4096);
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_send(req, buf, n);
    free(buf);
    return ESP_OK;
}

static esp_err_t get_setup(httpd_req_t *req) {
    mark_active();
    resolve_lang(req);
    uint16_t n = 0;
    wifi_ap_record_t *aps = NULL;
    char *page = malloc(16384);
    size_t o = 0;
    char esc0[64];

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

    {
        char langbtn[LANG_TOGGLE_MAX];
        lang_toggle(langbtn, sizeof(langbtn), "/setup");
        o += snprintf(page + o, room(16384, o),
            "<!doctype html><html lang=%s><meta charset=utf-8><title>tsesp %s</title>%s"
            "<div class=wrap><div class=top><h1>%s tsesp</h1>%s</div>"
            "<p class=sub>%s</p>"
            "<form method=POST action=/save>"
            "<label>%s</label><select name=ssid>"
            "<option value=''>%s</option>", s_lang_en ? "en" : "tr",
            T("kurulum", "setup"), CSS, LOGO, langbtn,
            T("Cihazi ev agina bagla", "Connect the device to your home network"),
            T("Ağ", "Network"), T("-- listeden seç --", "-- pick from the list --"));
    }

    for (uint16_t i = 0; i < n; i++) {
        char esc[80];
        html_escape(esc, sizeof(esc), (const char *)aps[i].ssid);
        if (esc[0])
            o += snprintf(page + o, room(16384, o), "<option value=\"%s\">%s (%d dBm)</option>",
                          esc, esc, aps[i].rssi);
    }
    free(aps);

    o += snprintf(page + o, room(16384, o),
        "</select>"
        // A scan can come back empty, and hidden networks never show up at
        // all, so typing the name has to stay possible.
        "<label>%s</label>"
        "<input name=ssid_manual autocomplete=off placeholder='%s'>"
        "<label>%s</label><input type=password name=pass autocomplete=off>"
        "<button type=submit>%s</button></form>"
        "<p class=sub style='margin-top:24px'>%s"
        "%s</p>"
        "<p class=sub><a href='/setup'>%s</a></p></div>",
        T("veya ağ adını yaz", "or type the network name"),
        T("ağ adı", "network name"),
        T("Parola", "Password"),
        T("Bağlan", "Connect"),
        // Same nested-%s problem as the memory hint above: T() only picks
        // the string, it doesn't touch %u, so the count is folded in first.
        (snprintf(esc0, sizeof(esc0), T("Bulunan ağ: %u.", "Networks found: %u."), (unsigned)n), esc0),
        T(" Parola sadece bu cihazın flash'ına yazılır.",
          " The password is written only to this device's flash."),
        T("listeyi yenile", "refresh the list"));

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, page, clamp_len(16384, o));
    free(page);
    return ESP_OK;
}

static esp_err_t post_save(httpd_req_t *req) {
    mark_active();
    resolve_lang(req);
    char body[256], ssid[WIFI_SSID_MAX], pass[WIFI_PASS_MAX];
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len
                                                       : (int)sizeof(body) - 1;
    int got = httpd_req_recv(req, body, len);
    if (got <= 0) return httpd_resp_send_500(req);
    body[got] = '\0';

    // The typed name wins when it is filled in; otherwise take the dropdown.
    if (!form_field(body, "ssid_manual", ssid, sizeof(ssid)) || !ssid[0]) {
        if (!form_field(body, "ssid", ssid, sizeof(ssid)) || !ssid[0]) {
            char errpage[320];
            httpd_resp_set_type(req, "text/html; charset=utf-8");
            snprintf(errpage, sizeof(errpage),
                "<!doctype html><body style='font:16px system-ui;background:#111;"
                "color:#eee;padding:24px'>%s "
                "<a style='color:#6ea8ff' href='/setup'>%s</a>",
                T("Ağ seçilmedi.", "No network selected."), T("geri dön", "go back"));
            httpd_resp_sendstr(req, errpage);
            return ESP_OK;
        }
    }
    form_field(body, "pass", pass, sizeof(pass));

    if (device_wifi_set(ssid, pass) != ESP_OK) return httpd_resp_send_500(req);
    ESP_LOGI(TAG, "credentials stored for %s", ssid);

    {
        char okpage[400];
        httpd_resp_set_type(req, "text/html; charset=utf-8");
        snprintf(okpage, sizeof(okpage),
            "<!doctype html><title>%s</title>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<body style='font:16px system-ui;background:#111;color:#eee;padding:24px'>"
            "<h1 style='font-size:20px'>%s</h1>"
            "<p>%s</p>",
            T("tamam", "done"), T("Kaydedildi", "Saved"),
            T("Cihaz yeniden başlıyor ve ağına bağlanacak. Bu kurulum ağı birazdan kapanacak.",
              "The device is restarting and will join that network. This setup network "
              "will close shortly."));
        httpd_resp_sendstr(req, okpage);
    }

    // Give the browser a moment to render before the radio goes away.
    vTaskDelay(pdMS_TO_TICKS(1200));
    esp_restart();
    return ESP_OK;
}

// ------------------------------------------------------------ status page

static const char *uptime_str(char *out, size_t cap) {
    uint32_t sec = (uint32_t)(esp_timer_get_time() / 1000000);
    if (sec < 90) snprintf(out, cap, "%u %s", (unsigned)sec, T("sn", "s"));
    else if (sec < 5400) snprintf(out, cap, "%u %s", (unsigned)(sec / 60), T("dk", "m"));
    else snprintf(out, cap, "%u %s %u %s", (unsigned)(sec / 3600), T("sa", "h"),
                  (unsigned)((sec % 3600) / 60), T("dk", "m"));
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
    case 5: return T("mükemmel", "excellent");
    case 4: return T("iyi", "good");
    case 3: return T("orta", "fair");
    case 2: return T("zayıf", "weak");
    case 1: return T("çok zayıf", "very weak");
    default: return "-";
    }
}

static const char *reset_reason_name(void) {
    switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return T("Güç verildi", "Power-on");
    case ESP_RST_SW:       return T("Yazılım", "Software");
    case ESP_RST_PANIC:    return T("Çökme", "Crash");
    case ESP_RST_INT_WDT:  return T("Kesme zaman aşımı", "Interrupt watchdog");
    case ESP_RST_TASK_WDT: return T("Görev zaman aşımı", "Task watchdog");
    case ESP_RST_WDT:      return T("watchdog", "watchdog");
    case ESP_RST_BROWNOUT: return T("Düşük voltaj", "Brownout");
    case ESP_RST_DEEPSLEEP:return T("Derin uyku", "Deep sleep");
    case ESP_RST_EXT:      return T("Harici reset", "External reset");
    default:               return T("öğrenilemedi", "unknown");
    }
}

// The state machine's names are for logs and tests; this is what a person
// should see.
static const char *state_text(const char *s) {
    if (!s) return "—";
    if (!strcmp(s, "running"))          return T("Çalışıyor", "Running");
    if (!strcmp(s, "connecting"))       return T("Bağlanıyor", "Connecting");
    if (!strcmp(s, "registering"))      return T("Kaydoluyor", "Registering");
    if (!strcmp(s, "awaiting-login"))   return T("Giriş onayı bekleniyor", "Waiting for login approval");
    if (!strcmp(s, "waiting for login"))return T("Giriş onayı bekleniyor", "Waiting for login approval");
    if (!strcmp(s, "fetching netmap"))  return T("Ağ haritası alınıyor", "Fetching the netmap");
    if (!strcmp(s, "backoff"))          return T("Yeniden denenecek", "Will retry");
    if (!strcmp(s, "start"))            return T("Başlatılıyor", "Starting");
    if (!strcmp(s, "starting"))         return T("Başlatılıyor", "Starting");
    if (!strcmp(s, "stopped"))          return T("Durduruldu", "Stopped");
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

// The four Genel-tab card icons and the header's day/night toggle. All
// static markup, no data in them, so they cost an argument slot nowhere.
#define ICON_GLOBE \
    "<svg class=ic width=36 height=36 viewBox='0 0 24 24' fill=none stroke=#3fae52 " \
    "stroke-width=1.6 stroke-linecap=round stroke-linejoin=round>" \
    "<circle cx=12 cy=12 r=10 /><path d='M2 12h20'/>" \
    "<path d='M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 " \
    "15.3 15.3 0 0 1 4-10z'/></svg>"
#define ICON_WIFI2 \
    "<svg class=ic width=36 height=36 viewBox='0 0 24 24' fill=none stroke=#2a8fd8 " \
    "stroke-width=1.6 stroke-linecap=round stroke-linejoin=round>" \
    "<path d='M5 13a10 10 0 0 1 14 0'/><path d='M8.5 16.5a5 5 0 0 1 7 0'/>" \
    "<path d='M2 8.82a15 15 0 0 1 20 0'/><line x1=12 y1=20 x2=12.01 y2=20 /></svg>"
#define ICON_SYS \
    "<svg class=ic width=36 height=36 viewBox='0 0 24 24' fill=none stroke=#f0ad4e " \
    "stroke-width=1.6 stroke-linecap=round stroke-linejoin=round>" \
    "<rect x=2 y=2 width=20 height=8 rx=2 /><rect x=2 y=14 width=20 height=8 rx=2 />" \
    "<line x1=6 y1=6 x2=6.01 y2=6 /><line x1=6 y1=18 x2=6.01 y2=18 /></svg>"
#define ICON_DEVS \
    "<svg class=ic width=36 height=36 viewBox='0 0 24 24' fill=none stroke=#14b8a6 " \
    "stroke-width=1.6 stroke-linecap=round stroke-linejoin=round>" \
    "<path d='M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'/><circle cx=9 cy=7 r=4 />" \
    "<path d='M22 21v-2a4 4 0 0 0-3-3.87'/><path d='M16 3.13a4 4 0 0 1 0 7.75'/></svg>"
// Checked means dark. The sun sits still until then, so the icon that shows
// always names the theme you are looking at rather than the one a click away.
#define ICON_SUN \
    "<svg class=ts-sun viewBox='0 0 24 24' fill=none stroke=currentColor " \
    "stroke-width=2.2 stroke-linecap=round><circle cx=12 cy=12 r=4 />" \
    "<path d='M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2" \
    "M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41'/></svg>"
#define ICON_MOON \
    "<svg class=ts-moon viewBox='0 0 24 24' fill=currentColor>" \
    "<path d='M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z'/></svg>"

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
                 "<button class=cp onclick=\"cp(this,'%s')\" title='%s'>"
                 ICON_COPY "</button>"
                 "</div></div>", wide ? "wide" : "", label, esc, esc,
                 T("Kopyala", "Copy"));
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
        o += (size_t)snprintf(out + o, room(cap, o), "<b class='%s'></b>", i <= bars ? "on" : "");
    snprintf(out + o, room(cap, o), "</span>");
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

// The same classification the peer list and the Genel-tab preview both need:
// a direct path beats a relay, a relay beats a disco probe still in flight.
static void peer_tag(char *tag, size_t cap, peer_entry *e) {
    const ts_path *best = magic_best_for(e);
    if (best)
        snprintf(tag, cap, "<span class='tag direct'>%s %u ms</span>",
                 T("doğrudan", "direct"), best->latency_ms);
    else if (e->has_node_key && derp_task_connected())
        snprintf(tag, cap, "<span class='tag relay'>%s</span>", T("dolaylı", "relayed"));
    else if (e->has_disco && e->nendpoints)
        snprintf(tag, cap, "<span class='tag probing'>%s</span>", T("bağlanıyor", "connecting"));
    else
        snprintf(tag, cap, "<span class='tag none'>%s</span>", T("bağlantı yok", "no connection"));
}

static esp_err_t get_status(httpd_req_t *req) {
    // The panels are rendered in order and the settings one is last, so when
    // this runs out it is the update form that disappears - the one control
    // somebody may be reaching for from a long way away. Hence the headroom -
    // bumped twice already: once when a heavier CSS and a real device's own
    // field lengths (a long SSID, an internet address with a port) pushed a
    // live page past the old 28672, and again when the speed-test card's
    // markup and script pushed it past 32768 far enough to cut the script off
    // mid-function - o (see below) had grown past cap by then, so the send
    // at the bottom was reading past the allocation's end, not just losing a
    // tab cleanly the way room() intends.
    char *page = malloc(40960);
    size_t cap = 40960, o = 0;
    char ip[16], up[24], esc[520], pub[64], wifi_ssid[36];
    char sig[240], m1[96], m2[96], m3[96];
    // Static, not on the stack: three of these plus the device row list is
    // nearly 4 KB, and the HTTP server's task does not have that to spare.
    // The server handles one request at a time, so sharing them is safe.
    static char c2[COPY_CELL_MAX], c3[COPY_CELL_MAX], c4[COPY_CELL_MAX];
    static char devrows[2400];
    char langbtn[LANG_TOGGLE_MAX];
    char bare[48];
    const char *dot = "warn";
    int rssi = 0, channel = 0, bars, core0 = -1, core1 = -1;
    uint32_t link_reconnects = 0;
    int i, n;
    uint32_t pings = 0, pongs = 0, tun_in = 0, tun_out = 0, derp_tx = 0, derp_rx = 0;
    uint32_t fwd_in = 0, fwd_out = 0, fwd_big = 0;
    uint32_t ip_fw = 0, ip_rterr = 0, ip_drop = 0;
    uint32_t tr_untrans = 0, tr_replies = 0;
    bool tr_hooked = false;
    uint32_t wo_total = 0, wo_lan = 0, fwd_wifi = 0, fwd_ans = 0;
    uint32_t nat_o = 0, nat_i = 0, nat_miss = 0, cb_in = 0, cb_out = 0, in_calls = 0; int nat_n = 0;
    char arp[320];
    esp_chip_info_t chip;
    uint32_t flash = 0;
    const esp_partition_t *app = esp_ota_get_running_partition();
    const esp_app_desc_t *desc = esp_app_get_description();
    size_t heap_free, heap_min, heap_big, heap_total;

    resolve_lang(req);
    if (!page) return httpd_resp_send_500(req);

    net_get_ip(ip, sizeof(ip));
    net_get_wifi_info(wifi_ssid, sizeof(wifi_ssid), &rssi, &channel);
    // A device that quietly rode out a modem reboot looks identical to one
    // that never lost the link. This is the difference.
    net_get_link_stats(&link_reconnects, NULL);
    magic_stats(&pings, &pongs);
    tun_stats(&tun_in, &tun_out);
    tun_route_stats(&fwd_in, &fwd_out, &fwd_big);
    tun_ip_stats(&ip_fw, &ip_rterr, &ip_drop);
    tun_trace_stats(&tr_hooked, &tr_untrans, &tr_replies);
    tun_wifi_out(&wo_total, &wo_lan);
    fwd_wifi = tun_fwd_reached_wifi();
    fwd_ans = tun_fwd_answered();
    tun_nat_stats(&nat_o, &nat_i, &nat_miss, &nat_n);
    tun_csum_bad(&cb_in, &cb_out);
    in_calls = tun_input_calls();

    // Who this device has actually exchanged a frame with on the LAN. An
    // address here answered an ARP request, so it exists and is reachable at
    // layer 2; one that answers ARP but nothing above it is being filtered,
    // not absent. An empty list means the Wi-Fi is isolating its clients, and
    // no amount of routing code will help.
    {
        size_t i;
        int n = 0, found = 0;
        for (i = 0; i < ARP_TABLE_SIZE; i++) {
            ip4_addr_t *ipa = NULL;
            struct netif *nif = NULL;
            struct eth_addr *eth = NULL;
            if (!etharp_get_entry(i, &ipa, &nif, &eth) || !ipa) continue;
            n += snprintf(arp + n, sizeof(arp) - n, "<li>%s</li>", ip4addr_ntoa(ipa));
            found++;
            if ((size_t)n >= sizeof(arp) - 30) break;
        }
        if (!found) snprintf(arp, sizeof(arp), "<li>%s</li>", T("hiçbiri", "none"));
    }
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
    lang_toggle(langbtn, sizeof(langbtn), "/");

    o += snprintf(page + o, room(cap, o),
        "<!doctype html><html lang=%s><meta charset=utf-8><title>tsesp</title>%s"
        "<div class=tabs>"
        "<input type=radio name=tab id=t1 checked><input type=radio name=tab id=t2>"
        "<input type=radio name=tab id=t3><input type=radio name=tab id=t4>"
        "<input type=radio name=tab id=t5>"
        "<div class=luciheader><div class=luciheader-in>"
        "<span class=brand>%stsesp</span>"
        "<nav><label for=t1>%s</label><label for=t2>%s</label>"
        "<label for=t3>%s</label><label for=t4>%s</label>"
        "<label for=t5>%s</label></nav>"
        "<div class=indicators>%s<label class=theme-switch title='%s'>"
        "<input type=checkbox id=theme-toggle onchange=\"document.documentElement"
        ".setAttribute('data-theme',this.checked?'dark':'light')\">"
        "<span class=ts-track><span class=ts-knob>" ICON_SUN ICON_MOON "</span></span>"
        "</label></div>"
        // The switch itself has no opinion until touched - it should still
        // show the theme the page actually opened in, which is dark unless
        // the browser asked for light (the same rule the CSS above follows).
        // It keeps following the device if that changes while the page is
        // still open, but only until a tap sets data-theme explicitly -
        // from there the switch is the reader's own choice, not the OS's.
        "<script>(function(){"
        "var m=matchMedia('(prefers-color-scheme:light)'),t=document.getElementById('theme-toggle');"
        "t.checked=!m.matches;"
        "m.addEventListener('change',function(e){"
        "if(!document.documentElement.hasAttribute('data-theme'))t.checked=!e.matches});"
        "})()</script>"
        "</div></div>"
        "<div class=wrap>"
        "<div class=hero><span class='dot %s'></span><span class=st>%s</span>"
        "<span class=addr>%s</span></div>",
        s_lang_en ? "en" : "tr", CSS, LOGO,
        T("Genel", "Overview"), T("Ağ", "Network"), T("Cihazlar", "Devices"),
        T("Sistem", "System"), T("Ayarlar", "Settings"),
        langbtn, T("Karanlık tema", "Dark theme"),
        dot, state_text(s_status.state),
        s_status.tailnet_addr && s_status.tailnet_addr[0] ? s_status.tailnet_addr : "");

    if (s_status.login_url && s_status.login_url[0]) {
        html_escape(esc, sizeof(esc), s_status.login_url);
        o += snprintf(page + o, room(cap, o),
            "<div class=banner>%s<br>"
            "<a href=\"%s\" target=_blank rel=noopener>%s</a></div>",
            T("Bu cihazi tailnet'ine katmak icin onayla:", "Approve this device joining your tailnet:"),
            esc, esc);
    }

    o += snprintf(page + o, room(cap, o), "<div class=panels>");

    /* ---- Genel: kart kart özet ---- */
    n = peers_count();
    html_escape(esc, sizeof(esc), s_status.name && s_status.name[0] ? s_status.name : "-");
    {
        // Every peer, not a cap - the card itself scrolls once it runs out
        // of room, instead of this list quietly cutting names off.
        size_t dr = 0;
        devrows[0] = '\0';
        if (n == 0)
            dr += (size_t)snprintf(devrows + dr, sizeof(devrows) - dr,
                "<div class=rowline><span class=k>%s</span>"
                "<span class=v>%s</span></div>",
                T("Henüz yok", "None yet"), T("ağ haritası bekleniyor", "waiting for the netmap"));
        for (i = 0; i < n && sizeof(devrows) - dr > 300; i++) {
            peer_entry *e = peers_at(i);
            char nm2[TS_NAME_STR * 2], tag2[80];
            if (!e) continue;
            peer_tag(tag2, sizeof(tag2), e);
            html_escape(nm2, sizeof(nm2), e->name[0] ? e->name : T("(isimsiz)", "(unnamed)"));
            dr += (size_t)snprintf(devrows + dr, sizeof(devrows) - dr,
                "<div class=rowline><span class=k>%s</span><span class=v>%s</span></div>",
                nm2, tag2);
        }
    }
    // Computed again down in the Sistem tab, from the same core0/core1/heap
    // numbers - cheap, and it means this preview never drifts from the detail
    // tab it is a preview of.
    meter(m1, sizeof(m1), core0);
    meter(m2, sizeof(m2), core1);
    meter(m3, sizeof(m3), heap_total ? (int)(100 - heap_free * 100 / heap_total) : 0);
    o += snprintf(page + o, room(cap, o),
        "<div class='panel p1'><div class=cardgrid>"
        "<div class=card>" ICON_GLOBE "<h2>Tailnet</h2><hr>"
        "<div class=rowline><span class=k>%s</span><span class=v>%s</span></div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%s</span></div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%d</span></div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%s</span></div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%u</span></div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%u</span></div>"
        "</div>"
        "<div class=card>" ICON_WIFI2 "<h2>Wi-Fi</h2><hr>"
        "<div class=rowline><span class=k>%s</span><span class=v>%s</span></div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%s%d<small> dBm, %s</small></span></div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%s</span></div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%s</span></div>"
        "</div>"
        "<div class=card>" ICON_SYS "<h2>%s</h2><hr>"
        "<div class=rowline><span class=k>%s</span><span class=v>%s</span></div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%d<small> %%</small></span>%s</div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%d<small> %%</small></span>%s</div>"
        "<div class=rowline><span class=k>%s</span><span class=v>%u/%u<small> KB</small></span>%s</div>"
        "</div>"
        "<div class=card>" ICON_DEVS "<h2>%s <span class=count>%d</span></h2><hr>"
        "<div class=scrollList>%s</div></div>"
        "</div></div>",
        T("Cihaz adı", "Device name"), esc,
        T("Tailscale adresi", "Tailscale address"), bare_addr(s_status.tailnet_addr, bare, sizeof(bare)),
        T("Bağlı cihaz", "Connected devices"), n,
        T("Çalışma süresi", "Uptime"), uptime_str(up, sizeof(up)),
        T("Alınan paket", "Packets received"), (unsigned)tun_in,
        T("Gönderilen paket", "Packets sent"), (unsigned)tun_out,
        T("Bağlı olduğu ağ", "Connected to"), wifi_ssid[0] ? wifi_ssid : "-",
        T("Sinyal", "Signal"), sig, rssi, signal_word(bars),
        T("Ev ağındaki adresi", "Home network address"), ip,
        T("Paylaşılan ev ağı", "Shared home network"),
        s_status.route[0] ?
            (s_status.route_approved > 0 ? T("<span class='pill ok'>onaylı</span>", "<span class='pill ok'>approved</span>") :
             s_status.route_approved == 0 ? T("<span class='pill warn'>onay bekliyor</span>", "<span class='pill warn'>awaiting approval</span>") :
             T("<span class='pill warn'>bilinmiyor</span>", "<span class='pill warn'>unknown</span>"))
            : "-",
        T("Sistem", "System"),
        T("Yazılım sürümü", "Firmware version"), desc ? desc->version : "?",
        T("Çekirdek 1", "Core 1"), core0 < 0 ? 0 : core0, m1,
        T("Çekirdek 2", "Core 2"), core1 < 0 ? 0 : core1, m2,
        T("Bellek", "Memory"), (unsigned)((heap_total - heap_free) / 1024), (unsigned)(heap_total / 1024), m3,
        T("Bağlı Cihazlar", "Connected Devices"), n, devrows);

    /* ---- Ag ---- */
    o += snprintf(page + o, room(cap, o),
        "<div class='panel p2'><h2>Wi-Fi</h2><p class=hint>%s</p><div class=grid>"
        "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%s%d<small> dBm, %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%d</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small>"
        " %s</small></div></div>"
        "</div>"
        "<h2>%s</h2><p class=hint>%s</p><div class=grid>"
        "%s%s%s</div>"
        "<h2>%s</h2><p class=hint>%s</p><div class=grid>"
        "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell wide><div class=k>%s</div>"
        "<ul class=miniList>%s</ul></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%d</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> %s</small></div></div>"
        "</div>"
        "<h2>%s</h2><p class=hint>%s</p><div class=grid>"
        "<div class=cell><div class=k>%s</div><div class=v>%d</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%d</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u</div></div>"
        "</div>"
        "<h2>%s</h2><p class=hint>%s</p>"
        "<div class=grid id=spdbox style=display:none>"
        "<div class=cell><div class=k>%s</div><div class=v id=spdv>-</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v id=spdt>-</div></div>"
        "</div>"
        "<button id=spdb onclick='spd()'>%s</button>"
        "</div>",
        T("Cihazın bağlandığı ev ağı. Sinyal zayıfsa bağlantı kopmasa da yavaşlar.",
          "The home network this device joined. A weak signal slows things down even when the link doesn't drop."),
        T("Bağlı olduğu ağ", "Connected to"), wifi_ssid[0] ? wifi_ssid : "-",
        T("Sinyal", "Signal"), sig, rssi, signal_word(bars),
        T("Kanal", "Channel"), channel,
        T("Kopma sayısı", "Reconnect count"), (unsigned)link_reconnects,
        T("kez yeniden bağlandı", "reconnects"),
        T("Adresler", "Addresses"),
        T("&quot;Paylaşılan ev ağı&quot;, bu cihaz üzerinden uzaktan erişebileceğin yerel ağdır. Tailscale panelinde onaylanması gerekir.",
          "\"Shared home network\" is the LAN you can reach remotely through this device. It needs approving in the Tailscale admin console."),
        (copy_cell(c2, sizeof(c2), T("Ev ağındaki adresi", "Home network address"), ip), c2),
        (copy_cell(c3, sizeof(c3), T("İnternetten görünen adres", "Public address as seen from the internet"),
                   magic_get_public(pub, sizeof(pub)) ? pub : T("henüz belirlenmedi", "not yet determined")), c3),
        (copy_cell(c4, sizeof(c4), T("Paylaşılan ev ağı", "Shared home network"),
                   s_status.route[0] ? s_status.route : "-"), c4),
        T("Ev ağına uzaktan erişim", "Remote access to the home network"),
        T("Uzaktan bir ev cihazına erişemiyorsan bu bölüm hangi yarının bozuk olduğunu söyler. "
          "Gelen istek sıfır: paket buraya hiç ulaşmıyor (rota onaylanmamış, uzaktaki cihazda "
          "subnet rotaları kapalı, ya da oradaki yerel ağ bu ağla aynı numarada). Gelen var, "
          "yanıt yok: sorun ev ağındaki cihazda.",
          "If you can't reach a home device remotely, this section says which half is broken. "
          "Incoming requests at zero: the packet never gets here at all (the route isn't approved, "
          "the remote device has subnet routes turned off, or its local network shares this one's "
          "number). Incoming but no reply: the problem is on the device on the home network."),
        T("Rota onayı", "Route approval"),
        s_status.route_approved > 0 ? T("onaylandı", "approved") :
            s_status.route_approved == 0 ? T("onay bekliyor", "awaiting approval") : T("bilinmiyor", "unknown"),
        T("Gelen istek", "Incoming requests"), (unsigned)fwd_in, T("paket", "packets"),
        T("Dönen yanıt", "Replies sent back"), (unsigned)fwd_out, T("paket", "packets"),
        T("Boyu aşıp düşen", "Dropped (too large)"), (unsigned)fwd_big, T("paket", "packets"),
        T("Ağa çıkarılan", "Forwarded onto the network"), (unsigned)ip_fw, T("paket", "packets"),
        T("Rotası yok", "No route"), (unsigned)ip_rterr, T("paket", "packets"),
        T("Yığında düşen", "Dropped in the stack"), (unsigned)ip_drop, T("paket", "packets"),
        T("Ev ağında görülen cihazlar", "Devices seen on the home network"), arp,
        T("Wi-Fi izleyici", "Wi-Fi sniffer"), tr_hooked ? T("kurulu", "installed") : T("KURULAMADI", "FAILED TO INSTALL"),
        T("Çevrilmemiş çıkan", "Untranslated outgoing"), (unsigned)tr_untrans, T("paket", "packets"),
        T("LAN'dan dönen yanıt", "Replies back from the LAN"), (unsigned)tr_replies, T("paket", "packets"),
        T("Wi-Fi'dan giden", "Outgoing via Wi-Fi"), (unsigned)wo_total, T("paket", "packets"),
        T("Bunun LAN'a gideni", "Of that, reaching the LAN"), (unsigned)wo_lan, T("paket", "packets"),
        T("Hedefe ulaşan", "Reached the target"), (unsigned)fwd_wifi, T("paket", "packets"),
        T("Hedefin cevabı", "Target's reply"), (unsigned)fwd_ans, T("paket", "packets"),
        T("Çeviri: giden", "Translation: outgoing"), (unsigned)nat_o, T("paket", "packets"),
        T("Çeviri: dönen", "Translation: return"), (unsigned)nat_i, T("paket", "packets"),
        T("Eşleşmeyen dönen", "Unmatched return"), (unsigned)nat_miss, T("paket", "packets"),
        T("Açık eşleme", "Open mappings"), nat_n,
        T("Bozuk gelen", "Corrupt incoming"), (unsigned)cb_in, T("paket", "packets"),
        T("Çeviri bozdu", "Translation broke it"), (unsigned)cb_out, T("paket", "packets"),
        T("Giriş kancası çalıştı", "Input hook ran"), (unsigned)in_calls, T("kez", "times"),
        T("Bağlantı yöntemi", "Connection method"),
        T("Cihazlar birbirine doğrudan ulaşmayı dener. Modemler buna izin vermezse trafik ortadaki "
          "bir Tailscale sunucusundan dolanır: daha yavaş ama her zaman çalışır.",
          "Devices try to reach each other directly. If the modems don't allow it, traffic detours "
          "through a Tailscale server in between: slower, but it always works."),
        T("Doğrudan bağlanan", "Connected directly"), s_status.paths_up,
        T("Şifreli tünel", "Encrypted tunnel"), magic_tunnels_up(),
        T("Ara sunucu", "Relay server"), derp_task_connected() ? derp_task_region_name() : T("bağlı değil", "not connected"),
        T("Bağlantı denemesi", "Connection attempts"), (unsigned)pings,
        T("Gelen yanıt", "Replies received"), (unsigned)pongs,
        T("Röleden giden", "Sent via relay"), (unsigned)derp_tx,
        T("Röleden gelen", "Received via relay"), (unsigned)derp_rx,
        T("Hız testi", "Speed test"),
        T("Bu tarayıcı ile cihaz arasında ölçülen gerçek indirme hızı - Wi-Fi, tünel ve şifrelemenin "
          "tümü dahil. README'deki &quot;1-3 Mbps beklenti&quot; buradan doğrulanır.",
          "The real download speed measured between this browser and the device - Wi-Fi, tunnel and "
          "encryption all included. This is what confirms (or not) the README's guessed range."),
        T("Hız", "Speed"), T("Süre", "Duration"),
        T("Hız testini başlat", "Start speed test"));

    /* ---- Peer'lar ---- */
    o += snprintf(page + o, room(cap, o), "<div class='panel p3'>");
    if (n == 0)
        o += snprintf(page + o, room(cap, o),
            "<div class=peer><div class=nm><b>%s</b>"
            "<span>%s</span></div></div>",
            T("Henüz yok", "None yet"), T("ağ haritası bekleniyor", "waiting for the netmap"));
    for (i = 0; i < n && room(cap, o) > 700; i++) {
        peer_entry *e = peers_at(i);
        char nm[TS_NAME_STR * 2], tag[80];
        if (!e) continue;

        peer_tag(tag, sizeof(tag), e);

        html_escape(nm, sizeof(nm), e->name[0] ? e->name : T("(isimsiz)", "(unnamed)"));
        bare_addr(e->addr, bare, sizeof(bare));
        o += snprintf(page + o, room(cap, o),
            "<div class=peer><span class='dot %s'></span>"
            "<div class=nm>"
            "<b>%s<button class='cp sm' onclick=\"cp(this,'%s')\" "
            "title='%s'>" ICON_COPY "</button></b>"
            "<span>%s<button class='cp sm' onclick=\"cp(this,'%s')\" "
            "title='%s'>" ICON_COPY "</button></span>"
            "</div>%s</div>",
            e->online ? "ok" : "none",
            nm, nm, T("Adı kopyala", "Copy the name"),
            e->addr[0] ? bare : "-", e->addr[0] ? bare : "-", T("Adresi kopyala", "Copy the address"),
            tag);
    }
    o += snprintf(page + o, room(cap, o), "</div>");

    /* ---- Sistem ---- */
    meter(m1, sizeof(m1), core0);
    meter(m2, sizeof(m2), core1);
    meter(m3, sizeof(m3), heap_total ? (int)(100 - heap_free * 100 / heap_total) : 0);

    o += snprintf(page + o, room(cap, o),
        "<div class='panel p4'>"
        "<h2>%s</h2><p class=hint>%s</p>"
        "<div class=grid>"
        "<div class=cell><div class=k>%s</div><div class=v>%d<small> %%</small></div>%s</div>"
        "<div class=cell><div class=k>%s</div><div class=v>%d<small> %%</small></div>%s</div>"
        "<div class=cell><div class=k>%s</div><div class=v>%d<small> MHz</small></div></div>"
        "</div>",
        T("İşlemci", "Processor"), T("Son birkaç saniyedeki ortalama yük.", "The average load over the last few seconds."),
        T("Çekirdek 1", "Core 1"), core0 < 0 ? 0 : core0, m1,
        T("Çekirdek 2", "Core 2"), core1 < 0 ? 0 : core1, m2,
        T("Saat hızı", "Clock speed"), CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);

    o += snprintf(page + o, room(cap, o),
        "<h2>%s</h2>"
        "<p class=hint>%s</p>"
        "<div class=grid>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> KB</small></div>%s</div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> KB</small></div></div>"
        "<div class=cell><div class=k>%s</div>"
        "<div class=v>%u<small> KB</small></div></div>"
        "</div>",
        T("Bellek", "Memory"),
        // A translated string chosen by T() is passed on as a %s argument
        // above, so a %u baked into IT would never see snprintf's real
        // argument list - it has to be resolved here, on its own, first.
        (snprintf(m1, sizeof(m1),
                  T("Toplam %u KB. Boş bellek tükenirse cihaz yeniden başlar.",
                    "%u KB total. The device restarts if it runs out of free memory."),
                  (unsigned)(heap_total / 1024)), m1),
        T("Kullanılan", "Used"), (unsigned)((heap_total - heap_free) / 1024), m3,
        T("Boş", "Free"), (unsigned)(heap_free / 1024),
        T("En az boş", "Lowest free"), (unsigned)(heap_min / 1024));

    o += snprintf(page + o, room(cap, o),
        "<h2>%s</h2><div class=grid>"
        "<div class=cell><div class=k>%s</div><div class=v>%s<small> v%d.%d</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> MB</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> KB</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
        "</div>",
        T("Donanım", "Hardware"),
        T("Kart", "Chip"), chip_name(&chip), chip.revision / 100, chip.revision % 100,
        T("Depolama", "Storage"), (unsigned)(flash / (1024 * 1024)),
        T("Yazılıma ayrılan", "Reserved for firmware"), (unsigned)(app ? app->size / 1024 : 0),
        T("Yazılım sürümü", "Firmware version"), desc ? desc->version : "?",
        T("Son açılış sebebi", "Last restart reason"), reset_reason_name());

    o += snprintf(page + o, room(cap, o),
        "<h2>%s</h2>"
        "<p class=hint>%s</p>"
        "<div class=grid>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> KB</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> B</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> B</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%u<small> B</small></div></div>"
        "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
        "</div></div>",
        T("Ayrıntı (teknik)", "Detail (technical)"),
        T("Her görevin yığınında kalan boş yer, ve belleğin en büyük tek parçası. "
          "Sıfıra yaklaşan bir değer yeniden başlamaya yol açar.",
          "Each task's remaining stack headroom, and memory's single largest free block. "
          "A value approaching zero leads to a restart."),
        T("En büyük tek parça", "Largest single block"), (unsigned)(heap_big / 1024),
        T("Ağ görevi", "Network task"), stack_headroom("magic"),
        T("Kontrol görevi", "Control task"), stack_headroom("control"),
        T("Ara sunucu görevi", "Relay task"), stack_headroom("derp"),
        T("Geliştirme kiti", "SDK"), IDF_VER);

    /* ---- Ayarlar ---- */
    {
        ota_state ost = ota_running_state();
        o += snprintf(page + o, room(cap, o),
            "<div class='panel p5'>"
            "<h2>%s</h2>"
            "<p class=hint>%s</p>"
            "<div class=grid>"
            "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
            "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
            "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
            "</div>"
            "%s"
            "<label class=fpick for=fw id=fwl>%s</label>"
            "<input type=file id=fw accept='.bin' hidden>"
            "<button id=fwb onclick='up()'>%s</button>"
            "<p class=hint id=fws></p>",
            T("Yazılım güncelleme", "Firmware update"),
            T("Bilgisayarda derlenen <code>.bin</code> dosyasını yükle; cihaz onu boştaki "
              "slota yazıp yeniden başlar. Yeni yazılım <b>deneme</b> olarak açılır: "
              "tailnet'e geri bağlanıp iki dakika ayakta kalırsa kalıcı olur, kalamazsa "
              "bir sonraki açılışta önyükleyici eski sürüme döner. Yani bozuk bir güncelleme "
              "en fazla bir yeniden başlamaya mal olur, yola çıkmaya değil.",
              "Upload the <code>.bin</code> built on your computer; the device writes it to "
              "the spare slot and restarts. The new firmware comes up <b>on trial</b>: if it "
              "reconnects to the tailnet and stays up for two minutes it becomes permanent, "
              "and if it can't the bootloader falls back to the old version on the next boot. "
              "So a broken update costs at most one restart, not a trip out to fix it."),
            T("Çalışan slot", "Running slot"), ota_running_slot(),
            T("Durumu", "Status"),
            ost == OTA_IMG_TRIAL ? T("deneme sürümü", "on trial") :
                ost == OTA_IMG_STABLE ? T("kalıcı", "permanent") : T("bilinmiyor", "unknown"),
            T("Sürüm", "Version"), desc ? desc->version : "?",
            // Otherwise a silently reverted update looks like one that never
            // went up at all.
            ota_rolled_back() ?
                T("<p class=hint><b>Not:</b> en son yüklenen yazılım kendini "
                  "onaylayamadı, önyükleyici bu sürüme geri döndü.</p>",
                  "<p class=hint><b>Note:</b> the most recently uploaded firmware could "
                  "not confirm itself, and the bootloader fell back to this version.</p>") : "",
            T(".bin dosyasi sec", "choose a .bin file"),
            T("Yükle ve yeniden başlat", "Upload and restart"));
    }
    o += snprintf(page + o, room(cap, o),
        "<h2>Tailscale</h2>"
        "<p class=hint>%s</p>"
        "<form method=POST action=/rejoin>"
        "<button type=submit>%s</button></form>"
        "<h2>%s</h2>"
        "<p class=hint>%s</p>"
        "<form method=POST action=/forget onsubmit=\"return confirm('%s')\">"
        "<button class=danger type=submit>%s</button></form>"
        "</div>",
        T("Cihazın tailnet kimliğini siler ve yeni bir giriş bağlantısı üretir. "
          "Wi-Fi ayarları korunur.",
          "Erases the device's tailnet identity and generates a new login link. "
          "Wi-Fi settings are kept."),
        T("Tailscale'e yeniden kaydol", "Rejoin Tailscale"),
        T("Wi-Fi ve kimlik", "Wi-Fi and identity"),
        T("Her şeyi siler. Cihaz kurulum moduna döner ve kendi Wi-Fi ağını açar; "
          "baştan kurman gerekir.",
          "Erases everything. The device goes back into setup mode and opens its own "
          "Wi-Fi network again; you'll need to set it up from scratch."),
        T("Tüm ayarlar silinecek. Emin misin?", "This erases all settings. Are you sure?"),
        T("Her şeyi sil ve baştan kur", "Erase everything and start over"));

    // Refreshes the panels only. The tab radios live outside them, so the
    // section you are looking at stays put.
    o += snprintf(page + o, room(cap, o),
        "</div></div></div>"
        "<script>"
        // The refresh replaces the panels wholesale, which would throw away a
        // chosen file or a running upload. OB parks it from the moment a file
        // is picked; reloading the page brings the refresh back.
        /* Picking a file also pauses the four-second repaint below, which would
           otherwise replace the label and lose the name the moment it is set. */
        "document.addEventListener('change',e=>{if(e.target.id!='fw')return;"
        "window.OB=1;const f=e.target.files[0],l=document.getElementById('fwl');"
        "if(f&&l){l.textContent=f.name+' - '+Math.round(f.size/1024)+' KB';"
        "l.classList.add('has')}});"
        // Checking OB only here left a gap the width of the fetch itself: pick
        // a file while a refresh already in flight, and it lands anyway once
        // the awaits resolve, rebuilding <input type=file> from scratch and
        // silently dropping the choice. Checking again after every await
        // closes that window instead of just narrowing it.
        "setInterval(async()=>{if(window.OB)return;try{"
        "const r=await fetch('/',{cache:'no-store'});"
        "const t=await r.text();if(window.OB)return;"
        "const d=new DOMParser().parseFromString(t,'text/html');"
        "if(window.OB)return;"
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
        /* The image goes up as the raw body - the device writes what it reads,
           so there is no multipart wrapper to strip on a chip with 97 KB of
           heap. XMLHttpRequest rather than fetch, for upload progress. */
        "function up(){const f=document.getElementById('fw').files[0];"
        "const b=document.getElementById('fwb'),s=document.getElementById('fws');"
        "if(!f){s.textContent='%s';return}"
        "if(!confirm(f.name+' %s'))return;"
        "window.OB=1;b.disabled=true;"
        "const x=new XMLHttpRequest();x.open('POST','/ota');"
        "x.upload.onprogress=e=>{s.textContent='%s '+"
        "Math.round(e.loaded*100/(e.total||f.size))+'%%'};"
        "x.onload=()=>{if(x.status==200){s.textContent="
        "'%s'}"
        "else{s.textContent='%s: '+x.responseText;b.disabled=false;window.OB=0}};"
        "x.onerror=()=>{s.textContent='%s';b.disabled=false;window.OB=0};"
        "x.send(f)}"
        // 1 MB is long enough to ride out one slow start and short enough that
        // a 1 Mbps link still answers in under ten seconds. The clock starts
        // and stops in the browser, so the number includes everything between
        // here and the device - not just what the firmware thinks it sent.
        "function spd(){const b=document.getElementById('spdb'),bx=document.getElementById('spdbox'),"
        "v=document.getElementById('spdv'),t=document.getElementById('spdt');"
        "window.OB=1;b.disabled=true;const OT=b.textContent;b.textContent='%s';"
        "const t0=performance.now();"
        "fetch('/api/speedtest?bytes=1048576',{cache:'no-store'}).then(x=>x.arrayBuffer())"
        ".then(a=>{const dt=(performance.now()-t0)/1000,"
        "mbps=(a.byteLength*8/1e6)/dt;"
        "v.textContent=mbps.toFixed(2)+' Mbps';"
        "t.textContent=dt.toFixed(1)+' %s, '+Math.round(a.byteLength/1024/dt)+' KB/s';"
        "bx.style.display='block';b.textContent='%s';b.disabled=false;"
        // The 4s auto-refresh below overwrites .panels wholesale with the
        // server's freshly-rendered (result-less) markup - without this, the
        // number this whole button exists to show got wiped within a second
        // of appearing. Fifteen seconds is long enough to read it once.
        "setTimeout(()=>{window.OB=0},15000)})"
        ".catch(()=>{v.textContent='%s';t.textContent='%s';"
        "bx.style.display='block';b.textContent=OT;b.disabled=false;"
        "setTimeout(()=>{window.OB=0},15000)})}"
        "</script>",
        T("önce bir .bin dosyası seç", "pick a .bin file first"),
        T("yüklenecek ve cihaz yeniden başlayacak. Devam?", "will be uploaded and the device will restart. Continue?"),
        T("yükleniyor", "uploading"),
        T("yazıldı, cihaz yeniden başlıyor - sayfayı 1-2 dakika sonra yenile",
          "written, the device is restarting - reload the page in a minute or two"),
        T("olmadı", "failed"),
        T("bağlantı kesildi", "the connection dropped"),
        T("Ölçülüyor...", "Measuring..."),
        T("sn", "s"),
        T("Tekrar ölç", "Measure again"),
        T("olmadı", "failed"), T("bağlantı koptu", "the connection dropped"));

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, page, clamp_len(cap, o));
    free(page);
    return ESP_OK;
}

static esp_err_t get_settings(httpd_req_t *req) {
    // The stylesheet alone is larger than a comfortable stack buffer, so the
    // page is built on the heap like the others.
    // The stylesheet alone runs to several kilobytes now.
    char *page = malloc(14336), ip[16], pub[64];
    size_t cap = 14336, o = 0;

    resolve_lang(req);

    if (!page) return httpd_resp_send_500(req);
    net_get_ip(ip, sizeof(ip));
    if (!magic_get_public(pub, sizeof(pub))) strncpy(pub, T("öğrenilemedi", "not yet determined"), sizeof(pub) - 1);

    {
        char langbtn[LANG_TOGGLE_MAX];
        lang_toggle(langbtn, sizeof(langbtn), "/settings");
        o += snprintf(page + o, room(cap, o),
            "<!doctype html><html lang=%s><meta charset=utf-8><title>tsesp %s</title>%s"
            "<div class=wrap><div class=top><div><h1>%s %s</h1>"
            "<p class=sub>%s</p></div>"
            "<div style='display:flex;align-items:center;gap:8px'>%s"
            "<a class=gear href=/ title='%s'>&#8592;</a></div></div>"
            "<div class=grid>"
            "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
            "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
            "<div class=cell><div class=k>%s</div><div class=v>%d</div></div>"
            "<div class=cell><div class=k>%s</div><div class=v>%s</div></div>"
            "</div>"
            "<h2>Tailnet</h2>"
            "<p class=sub>%s</p>"
            "<form method=POST action=/rejoin>"
            "<button type=submit>%s</button></form>"
            "<h2>%s</h2>"
            "<p class=sub>%s</p>"
            "<form method=POST action=/forget onsubmit=\"return confirm('%s')\">"
            "<button class=danger type=submit>%s</button></form>"
            "</div>",
            s_lang_en ? "en" : "tr", T("ayarlar", "settings"), CSS, LOGO, T("Ayarlar", "Settings"),
            T("Cihaz bilgileri ve sifirlama", "Device info and reset"), langbtn,
            T("Geri", "Back"),
            T("Yerel IP", "Local IP"), ip,
            T("İnternetten görünen adres", "Public address as seen from the internet"), pub,
            T("UDP portu", "UDP port"), MAGIC_PORT,
            T("Kayit", "Registration"), device_is_registered() ? T("kayitli", "registered") : T("kayitli degil", "not registered"),
            T("Kimligi silip yeniden kaydolur. Wi-Fi ayarlari kalir.",
              "Erases the identity and re-registers. Wi-Fi settings are kept."),
            T("Tailnet'e yeniden kaydol", "Rejoin the tailnet"),
            T("Tehlikeli", "Dangerous"),
            T("Wi-Fi bilgilerini ve tailnet kimligini siler. Cihaz kurulum moduna doner ve "
              "tailnet'e yeniden onaylanmasi gerekir.",
              "Erases the Wi-Fi credentials and the tailnet identity. The device goes back "
              "into setup mode and will need approving on the tailnet again."),
            T("Emin misin?", "Are you sure?"),
            T("Her seyi sil ve yeniden kur", "Erase everything and set up again"));
    }

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, page, clamp_len(cap, o));
    free(page);
    return ESP_OK;
}

// Streams a fixed amount of filler as fast as the link allows, so the "Hız
// testi" button can time how long it takes to arrive and turn that into a
// real number. README's "1-3 Mbps beklenti" was never measured against an
// actual client until this - it is a throughput probe, not a diagnostic, so
// it has no opinion about the transport (Wi-Fi vs tunnel vs relay): the
// browser's clock covers whichever path the request actually took.
//
// The pattern byte is fixed and the buffer is static, not because either one
// matters for a speed measurement, but because a fresh 4 KB heap allocation
// per chunk would be its own variable in the result.
#define SPEEDTEST_CHUNK 4096
#define SPEEDTEST_MAX (4 * 1024 * 1024)
#define SPEEDTEST_DEFAULT (1024 * 1024)

static esp_err_t get_speedtest(httpd_req_t *req) {
    static uint8_t chunk[SPEEDTEST_CHUNK];
    static bool filled;
    char qs[32], val[16];
    long total = SPEEDTEST_DEFAULT;

    if (!filled) { memset(chunk, 0xa5, sizeof(chunk)); filled = true; }

    if (httpd_req_get_url_query_str(req, qs, sizeof(qs)) == ESP_OK &&
        httpd_query_key_value(qs, "bytes", val, sizeof(val)) == ESP_OK) {
        long v = atol(val);
        if (v > 0) total = v;
    }
    if (total > SPEEDTEST_MAX) total = SPEEDTEST_MAX;
    if (total < SPEEDTEST_CHUNK) total = SPEEDTEST_CHUNK;

    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    {
        long sent = 0;
        while (sent < total) {
            size_t want = (size_t)((total - sent) < SPEEDTEST_CHUNK ?
                                    (total - sent) : SPEEDTEST_CHUNK);
            if (httpd_resp_send_chunk(req, (const char *)chunk, want) != ESP_OK)
                return ESP_FAIL;
            sent += (long)want;
        }
        httpd_resp_send_chunk(req, NULL, 0);
    }
    return ESP_OK;
}

// Switches the panel's language and sends the browser straight back to
// whichever page it came from ("to"), so the toggle reads as "this page,
// but in the other language" rather than a trip to some settings screen.
static esp_err_t post_lang(httpd_req_t *req) {
    char body[64], lang[8], to[24];
    int len = req->content_len < (int)sizeof(body) - 1 ? req->content_len
                                                       : (int)sizeof(body) - 1;
    int got = httpd_req_recv(req, body, len);
    if (got <= 0) return httpd_resp_send_500(req);
    body[got] = '\0';

    if (form_field(body, "lang", lang, sizeof(lang))) {
        s_lang_en = !strcmp(lang, "en");
        device_set_lang_en(s_lang_en);
    }
    if (!form_field(body, "to", to, sizeof(to)) || !to[0]) strcpy(to, "/");

    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", to);
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

// Rejoining the tailnet without redoing Wi-Fi. Useful whenever the node's
// registration needs replacing - a changed capability version, an expired
// key - and much less drastic than forgetting everything.
static esp_err_t post_rejoin(httpd_req_t *req) {
    char body[400];
    resolve_lang(req);
    device_keys_erase();
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    snprintf(body, sizeof(body),
        "<!doctype html><meta charset=utf-8>"
        "<body style='font:16px system-ui;background:#0d1117;color:#e6edf3;padding:24px'>"
        "%s",
        T("Tailnet kimligi silindi. Cihaz yeniden baslayip yeni bir giris "
          "baglantisi uretecek. Wi-Fi ayarlari duruyor.",
          "The tailnet identity was erased. The device will restart and generate a new "
          "login link. Wi-Fi settings are kept."));
    httpd_resp_sendstr(req, body);
    vTaskDelay(pdMS_TO_TICKS(800));
    esp_restart();
    return ESP_OK;
}

static esp_err_t post_forget(httpd_req_t *req) {
    mark_active();
    resolve_lang(req);
    device_wifi_erase();
    device_keys_erase();
    httpd_resp_sendstr(req, T("silindi, yeniden başlıyor", "erased, restarting"));
    vTaskDelay(pdMS_TO_TICKS(800));
    esp_restart();
    return ESP_OK;
}

// Takes the image as the raw request body: no multipart, so nothing has to be
// unwrapped and nothing sits between the bytes on the wire and the bytes in
// flash. The page uploads with XMLHttpRequest; from a laptop it is one line:
//
//   curl -H 'Expect:' --data-binary @build/tsesp.bin http://100.115.225.84/ota
//
// The empty Expect header is not decoration: curl asks for 100-continue on a
// body this size and then waits a second for an answer this server does not
// send.
//
// Failures answer with the reason in the body, because the person reading it
// is the person who has to decide what to do about it.
static esp_err_t post_ota(httpd_req_t *req) {
    // Static, like the page buffers: the server serves one request at a time,
    // and this is more than the handler task's stack wants to carry.
    static char buf[2048];
    size_t remaining = req->content_len;
    int stalls = 0;

    // An upload must not be cut short by the portal's own retry reboot.
    mark_active();

    if (ota_begin(remaining) != 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, ota_error());
        return ESP_OK;
    }

    while (remaining > 0) {
        size_t want = remaining < sizeof(buf) ? remaining : sizeof(buf);
        int got = httpd_req_recv(req, buf, want);

        // A slow tunnel is not a failed upload - but a silent one must not
        // hold the only web server task open for ever either. Twenty seconds
        // a turn, fifteen turns: five minutes of nothing and it is over.
        if (got == HTTPD_SOCK_ERR_TIMEOUT) {
            if (++stalls <= 15) continue;
            ota_abort();
            httpd_resp_set_status(req, "408 Request Timeout");
            httpd_resp_sendstr(req, "the upload went quiet");
            return ESP_OK;
        }
        stalls = 0;
        if (got <= 0) {
            ota_abort();
            httpd_resp_set_status(req, "400 Bad Request");
            httpd_resp_sendstr(req, "the upload stopped before the end");
            return ESP_OK;
        }
        if (ota_feed((const uint8_t *)buf, (size_t)got) != 0) {
            httpd_resp_set_status(req, "400 Bad Request");
            httpd_resp_sendstr(req, ota_error());
            return ESP_OK;
        }
        remaining -= (size_t)got;
        mark_active();
    }

    if (ota_finish() != 0) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, ota_error());
        return ESP_OK;
    }

    httpd_resp_sendstr(req, "written; rebooting into the new image on trial");
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

    cfg.max_uri_handlers = 12;
    cfg.lru_purge_enable = true;
    // The status page builds several kilobytes of markup.
    cfg.stack_size = 8192;
    // A firmware upload arrives over the tunnel, where a relayed round trip is
    // half a second and a flash erase stalls everything for tens of
    // milliseconds at a time. The default five seconds is enough until it
    // isn't, and losing a 1.9 MB upload to a hiccup is a bad trade.
    cfg.recv_wait_timeout = 20;
    cfg.send_wait_timeout = 20;

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
        httpd_uri_t lang = { .uri = "/lang", .method = HTTP_POST, .handler = post_lang };
        httpd_uri_t speedtest = { .uri = "/api/speedtest", .method = HTTP_GET, .handler = get_speedtest };
        // Registered in setup mode too: a device that cannot join any network
        // can still be re-flashed by joining its own, which is one fewer
        // reason to need a cable.
        httpd_uri_t ota = { .uri = "/ota", .method = HTTP_POST, .handler = post_ota };
        {
            httpd_uri_t lg = { .uri = "/log", .method = HTTP_GET, .handler = get_log };
            httpd_register_uri_handler(s_server, &lg);
        }
        httpd_register_uri_handler(s_server, &root);
        httpd_register_uri_handler(s_server, &setup);
        httpd_register_uri_handler(s_server, &save);
        httpd_register_uri_handler(s_server, &forget);
        httpd_register_uri_handler(s_server, &lang);
        if (!captive) httpd_register_uri_handler(s_server, &settings);
        if (!captive) httpd_register_uri_handler(s_server, &rejoin);
        if (!captive) httpd_register_uri_handler(s_server, &speedtest);
        httpd_register_uri_handler(s_server, &ota);
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
