#include <string.h>
#include <stdio.h>
#include "ts_control.h"
#include "tscrypto.h"
#include "json_stream.h"

// Optional hook so a caller can see exactly what went on the wire.
void (*ts_control_debug_body)(const char *body, size_t len);

static void copy_field(char *dst, size_t cap, const char *v, size_t len) {
    if (len >= cap) len = cap - 1;
    memcpy(dst, v, len);
    dst[len] = '\0';
}

// ------------------------------------------------------- early payload

// Right after the handshake the server sends either an HTTP/2 SETTINGS frame
// or a 9-byte early-payload header: the 5-byte magic, then a big-endian
// length, then that much JSON. Both are 9 bytes, so we read 9 and either
// consume the payload or push the bytes back for the HTTP/2 layer.
#define TS_EARLY_MAGIC "\xff\xff\xffTS"
#define TS_EARLY_MAGIC_LEN 5
#define TS_EARLY_MAX 512

static void early_on_value(void *ctx, const char *path, const char *v, size_t len,
                           json_type type, int truncated) {
    ts_control *tc = (ts_control *)ctx;
    (void)truncated;
    if (type == JSON_STRING && strcmp(path, "nodeKeyChallenge") == 0)
        copy_field(tc->node_key_challenge, sizeof(tc->node_key_challenge), v, len);
}

static int read_early_payload(ts_control *tc) {
    uint8_t hdr[9];
    uint32_t len;

    if (ts_io_read_full(&tc->stream, hdr, sizeof(hdr)) != 0) return -1;
    if (memcmp(hdr, TS_EARLY_MAGIC, TS_EARLY_MAGIC_LEN) != 0)
        return ts_noise_stream_unread(&tc->ns, hdr, sizeof(hdr));

    len = ((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) |
          ((uint32_t)hdr[7] << 8) | hdr[8];
    if (len > TS_EARLY_MAX) return ts_io_skip(&tc->stream, len);

    {
        uint8_t buf[TS_EARLY_MAX];
        json_stream js;
        json_stream_cbs cbs;
        if (ts_io_read_full(&tc->stream, buf, len) != 0) return -1;
        cbs.on_value = early_on_value;
        cbs.on_enter = NULL;
        cbs.on_leave = NULL;
        cbs.ctx = tc;
        json_stream_init(&js, &cbs);
        json_stream_feed(&js, buf, len);
        json_stream_finish(&js);
    }
    return 0;
}

// ------------------------------------------------------------ HTTP upgrade

// Reads the response head one byte at a time. Anything we over-read would be
// the first bytes of the Noise response, so we must not over-read.
static int read_http_head(ts_io *io, char *buf, size_t cap, size_t *len) {
    size_t n = 0;
    int state = 0;                     // counts the \r\n\r\n we have matched

    while (n + 1 < cap) {
        uint8_t c;
        if (ts_io_read_full(io, &c, 1) != 0) return -1;
        buf[n++] = (char)c;
        if ((state == 0 || state == 2) && c == '\r') state++;
        else if ((state == 1 || state == 3) && c == '\n') state++;
        else state = (c == '\r') ? 1 : 0;
        if (state == 4) { buf[n] = '\0'; *len = n; return 0; }
    }
    return -1;
}

int ts_control_connect(ts_control *tc, ts_io *raw, const char *host,
                       const uint8_t machine_priv[32],
                       const uint8_t control_pub[32],
                       const uint8_t eph_priv[32]) {
    uint8_t init[TS2021_INIT_LEN], resp[TS2021_RESP_LEN];
    char b64[((TS2021_INIT_LEN + 2) / 3) * 4 + 1];
    char req[512];
    char head[512];
    size_t head_len;
    ts2021_handshake hs;
    ts2021_conn conn;
    int n, rc;

    memset(tc, 0, sizeof(*tc));
    tc->raw = raw;
    snprintf(tc->host, sizeof(tc->host), "%s", host);

    if (ts2021_handshake_start(&hs, machine_priv, control_pub,
                               TS2021_PROTOCOL_VERSION, eph_priv, init) != 0)
        return -1;
    if (ts2021_base64(b64, sizeof(b64), init, sizeof(init)) == 0) return -1;

    n = snprintf(req, sizeof(req),
                 "POST /ts2021 HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Upgrade: tailscale-control-protocol\r\n"
                 "Connection: upgrade\r\n"
                 "X-Tailscale-Handshake: %s\r\n"
                 "Content-Length: 0\r\n"
                 "\r\n", host, b64);
    if (n < 0 || (size_t)n >= sizeof(req)) return -1;
    if (raw->write(raw->ctx, (const uint8_t *)req, (size_t)n) < 0) return -1;

    if (read_http_head(raw, head, sizeof(head), &head_len) != 0) return -1;
    if (strncmp(head, "HTTP/1.1 101", 12) != 0) return -2;

    if (ts_io_read_full(raw, resp, sizeof(resp)) != 0) return -1;
    if (resp[0] == TS2021_MSG_ERROR) return -3;

    rc = ts2021_handshake_finish(&hs, resp, &conn);
    if (rc != 0) return -4;

    ts_noise_stream_init(&tc->ns, raw, &conn, &tc->stream);

    rc = read_early_payload(tc);
    if (rc != 0) return -5;

    rc = h2_connect(&tc->h2, &tc->stream);
    if (rc != 0) return -100 + rc;
    return 0;
}

// ---------------------------------------------------------------- register

static void hex32(char *out, const uint8_t *b) {
    static const char d[] = "0123456789abcdef";
    int i;
    for (i = 0; i < 32; i++) {
        out[2 * i]     = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[64] = '\0';
}

// Escapes the few characters that can appear in a hostname or auth key.
static void json_escape(char *out, size_t cap, const char *in) {
    size_t o = 0;
    for (; *in && o + 2 < cap; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            if (o + 6 >= cap) break;
            o += (size_t)snprintf(out + o, cap - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

// The control server answers errors with plain text, not JSON, so parsing
// must never abort the request - we keep the head of the body verbatim and
// let the status code decide how to read it.
typedef struct {
    ts_register_resp *r;
    json_stream      *js;
    char              raw[192];
    size_t            raw_len;
    int               json_failed;
} reg_ctx;

static void reg_on_value(void *ctx, const char *path, const char *v, size_t len,
                         json_type type, int truncated) {
    ts_register_resp *r = ((reg_ctx *)ctx)->r;
    (void)truncated;

    if (strcmp(path, "AuthURL") == 0 && type == JSON_STRING)
        copy_field(r->auth_url, sizeof(r->auth_url), v, len);
    else if (strcmp(path, "Error") == 0 && type == JSON_STRING)
        copy_field(r->error, sizeof(r->error), v, len);
    else if (strcmp(path, "Login.LoginName") == 0 && type == JSON_STRING)
        copy_field(r->login_name, sizeof(r->login_name), v, len);
    else if (strcmp(path, "User.DisplayName") == 0 && type == JSON_STRING)
        copy_field(r->user_display, sizeof(r->user_display), v, len);
    else if (strcmp(path, "MachineAuthorized") == 0)
        r->machine_authorized = (type == JSON_TRUE);
    else if (strcmp(path, "NodeKeyExpired") == 0)
        r->node_key_expired = (type == JSON_TRUE);
}

static int reg_on_data(void *ctx, const uint8_t *data, size_t len) {
    reg_ctx *rc = (reg_ctx *)ctx;
    size_t room = sizeof(rc->raw) - 1 - rc->raw_len;

    if (room > 0) {
        size_t take = len < room ? len : room;
        memcpy(rc->raw + rc->raw_len, data, take);
        rc->raw_len += take;
        rc->raw[rc->raw_len] = '\0';
    }
    if (!rc->json_failed && json_stream_feed(rc->js, data, len) != 0)
        rc->json_failed = 1;
    return 0;      // always keep reading
}

int ts_control_register(ts_control *tc, const ts_register_req *req,
                        ts_register_resp *resp) {
    char body[768];
    char nodekey[65];
    char hostname[96];
    char auth[192];
    // Room for the JSON wrapper as well as the URL itself; sizing this to
    // the URL alone truncates a long AuthURL and the poll then never matches.
    char followup[TS_AUTH_URL_MAX + 32];
    json_stream js;
    reg_ctx rctx;
    json_stream_cbs cbs;
    int n, rc, status = 0;

    memset(resp, 0, sizeof(*resp));
    hex32(nodekey, req->node_pub);
    json_escape(hostname, sizeof(hostname), req->hostname ? req->hostname : "tsesp");

    auth[0] = '\0';
    if (req->auth_key && req->auth_key[0]) {
        char esc[128];
        json_escape(esc, sizeof(esc), req->auth_key);
        snprintf(auth, sizeof(auth), ",\"Auth\":{\"AuthKey\":\"%s\"}", esc);
    }
    followup[0] = '\0';
    if (req->followup && req->followup[0]) {
        char esc[TS_AUTH_URL_MAX];
        json_escape(esc, sizeof(esc), req->followup);
        snprintf(followup, sizeof(followup), ",\"Followup\":\"%s\"", esc);
    }

    // Expiry zero-value means "server decides". Hostinfo is the minimum the
    // console needs to show a sensible device entry.
    n = snprintf(body, sizeof(body),
                 "{\"Version\":%d"
                 ",\"NodeKey\":\"nodekey:%s\""
                 ",\"Expiry\":\"0001-01-01T00:00:00Z\""
                 ",\"Hostinfo\":{\"OS\":\"esp32\",\"Hostname\":\"%s\""
                 ",\"IPNVersion\":\"0.1.0\",\"DeviceModel\":\"ESP32-WROOM-32U\"}"
                 "%s%s%s}",
                 TS2021_PROTOCOL_VERSION, nodekey, hostname,
                 req->ephemeral ? ",\"Ephemeral\":true" : "",
                 auth, followup);
    if (n < 0 || (size_t)n >= sizeof(body)) return -1;

    memset(&rctx, 0, sizeof(rctx));
    rctx.r = resp;
    rctx.js = &js;
    cbs.on_value = reg_on_value;
    cbs.on_enter = NULL;
    cbs.on_leave = NULL;
    cbs.ctx = &rctx;
    json_stream_init(&js, &cbs);

    rc = h2_request(&tc->h2, "POST", "https", tc->host, "/machine/register",
                    "application/json", (const uint8_t *)body, (size_t)n,
                    NULL, reg_on_data, &rctx, &status);
    resp->http_status = status;

    // Surface whatever the server said, whether or not it was JSON.
    if (!resp->error[0] && (status != 200 || rctx.json_failed) && rctx.raw_len)
        copy_field(resp->error, sizeof(resp->error), rctx.raw, rctx.raw_len);

    if (rc != 0) return rc;
    if (status != 200) return -10;
    if (rctx.json_failed || json_stream_finish(&js) != 0) return -11;
    return 0;
}

// -------------------------------------------------------------- netmap

typedef struct {
    ts_netmap_parser *parser;
    char   raw[192];
    size_t raw_len;
    int    failed;
    int    stopped;      // a netmap callback asked to stop
} map_ctx;

static int map_on_data(void *ctx, const uint8_t *data, size_t len) {
    map_ctx *m = (map_ctx *)ctx;
    size_t room = sizeof(m->raw) - 1 - m->raw_len;
    int rc;

    // Keep the head of the body only so a plain-text error is still readable.
    if (room > 0) {
        size_t take = len < room ? len : room;
        memcpy(m->raw + m->raw_len, data, take);
        m->raw_len += take;
        m->raw[m->raw_len] = '\0';
    }
    if (m->failed || m->stopped) return 0;

    rc = ts_netmap_feed(m->parser, data, len);
    if (rc < 0) { m->failed = 1; return 0; }
    if (rc > 0) { m->stopped = 1; return 1; }   // stop the request
    return 0;
}

static int build_map_body(const ts_map_req *req, char *body, size_t cap,
                          int stream, int omit_peers) {
    char nodekey[65], discokey[65], hostname[96];
    char endpoints[TS_MAX_SELF_ENDPOINTS * 56 + 24];
    char netinfo[160];
    char routes[80];
    int n, i;

    hex32(nodekey, req->node_pub);
    hex32(discokey, req->disco_pub);
    json_escape(hostname, sizeof(hostname), req->hostname ? req->hostname : "tsesp");

    routes[0] = '\0';
    if (req->nroutes > 0) {
        size_t o = (size_t)snprintf(routes, sizeof(routes), ",\"RoutableIPs\":[");
        for (i = 0; i < req->nroutes && i < 2; i++) {
            if (!req->routes[i] || !req->routes[i][0]) continue;
            o += (size_t)snprintf(routes + o, sizeof(routes) - o, "%s\"%s\"",
                                  i ? "," : "", req->routes[i]);
        }
        snprintf(routes + o, sizeof(routes) - o, "]");
    }

    netinfo[0] = '\0';
    if (req->preferred_derp > 0) {
        snprintf(netinfo, sizeof(netinfo),
                 ",\"NetInfo\":{\"PreferredDERP\":%d,\"WorkingUDP\":%s"
                 ",\"WorkingIPv6\":false,\"HairPinning\":false"
                 ",\"DERPLatency\":{\"%d-v4\":0.05}}",
                 req->preferred_derp, req->working_udp ? "true" : "false",
                 req->preferred_derp);
    }

    endpoints[0] = '\0';
    if (req->nendpoints > 0) {
        size_t o = 0;
        o += (size_t)snprintf(endpoints + o, sizeof(endpoints) - o, ",\"Endpoints\":[");
        for (i = 0; i < req->nendpoints && i < TS_MAX_SELF_ENDPOINTS; i++) {
            char esc[52];
            if (!req->endpoints[i] || !req->endpoints[i][0]) continue;
            json_escape(esc, sizeof(esc), req->endpoints[i]);
            o += (size_t)snprintf(endpoints + o, sizeof(endpoints) - o,
                                  "%s\"%s\"", i ? "," : "", esc);
        }
        snprintf(endpoints + o, sizeof(endpoints) - o, "]");
    }

    // Compress is deliberately absent: zstd would mean carrying a decompressor
    // and, worse, buffering whole messages before they could be parsed.
    n = snprintf(body, cap,
                 "{\"Version\":%d"
                 ",\"NodeKey\":\"nodekey:%s\""
                 ",\"DiscoKey\":\"discokey:%s\""
                 ",\"Hostinfo\":{\"OS\":\"esp32\",\"Hostname\":\"%s\""
                 ",\"IPNVersion\":\"0.1.0\""
                 ",\"DeviceModel\":\"ESP32-WROOM-32U\"%s%s}"
                 "%s%s%s}",
                 req->capver > 0 ? req->capver : TS2021_PROTOCOL_VERSION,
                 nodekey, discokey, hostname, routes, netinfo,
                 stream ? ",\"Stream\":true" : "",
                 omit_peers ? ",\"OmitPeers\":true" : "",
                 endpoints);
    if (n < 0 || (size_t)n >= cap) return -1;
    if (ts_control_debug_body) ts_control_debug_body(body, (size_t)n);
    return n;
}

int ts_control_map(ts_control *tc, const ts_map_req *req,
                   ts_netmap_parser *parser, int *out_status) {
    char body[832];
    map_ctx mctx;
    int n, rc, status = 0;

    n = build_map_body(req, body, sizeof(body), req->stream, req->omit_peers);
    if (n < 0) return -1;

    memset(&mctx, 0, sizeof(mctx));
    mctx.parser = parser;

    rc = h2_request(&tc->h2, "POST", "https", tc->host, "/machine/map",
                    "application/json", (const uint8_t *)body, (size_t)n,
                    NULL, map_on_data, &mctx, &status);
    if (out_status) *out_status = status;
    // Stopping on purpose is a normal end to a streaming fetch, not a failure.
    if (mctx.stopped && rc == H2_ERR_ABORTED) rc = 0;
    if (rc != 0) return rc;
    if (status != 200) return -10;
    if (mctx.failed) return -11;
    return 0;
}

int ts_control_update_endpoints(ts_control *tc, const ts_map_req *req,
                                int *out_status) {
    char body[832];
    map_ctx mctx;
    int n, rc, status = 0;
    ts_netmap_parser throwaway;

    // OmitPeers with Stream off: the documented way to tell control where we
    // are without asking it to describe the tailnet back to us.
    n = build_map_body(req, body, sizeof(body), 0, 1);
    if (n < 0) return -1;

    ts_netmap_parser_init(&throwaway, NULL, NULL);
    memset(&mctx, 0, sizeof(mctx));
    mctx.parser = &throwaway;

    rc = h2_request(&tc->h2, "POST", "https", tc->host, "/machine/map",
                    "application/json", (const uint8_t *)body, (size_t)n,
                    NULL, map_on_data, &mctx, &status);
    if (out_status) *out_status = status;
    if (rc != 0) return rc;
    return status == 200 ? 0 : -10;
}
