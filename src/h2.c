#include <string.h>
#include <stdio.h>
#include "h2.h"

#define FRAME_DATA          0x0
#define FRAME_HEADERS       0x1
#define FRAME_PRIORITY      0x2
#define FRAME_RST_STREAM    0x3
#define FRAME_SETTINGS      0x4
#define FRAME_PUSH_PROMISE  0x5
#define FRAME_PING          0x6
#define FRAME_GOAWAY        0x7
#define FRAME_WINDOW_UPDATE 0x8
#define FRAME_CONTINUATION  0x9

#define FLAG_END_STREAM  0x01
#define FLAG_ACK         0x01
#define FLAG_END_HEADERS 0x04
#define FLAG_PADDED      0x08
#define FLAG_PRIORITY    0x20

#define SETTING_HEADER_TABLE_SIZE      0x1
#define SETTING_ENABLE_PUSH            0x2
#define SETTING_MAX_CONCURRENT_STREAMS 0x3
#define SETTING_INITIAL_WINDOW_SIZE    0x4
#define SETTING_MAX_FRAME_SIZE         0x5
#define SETTING_MAX_HEADER_LIST_SIZE   0x6

#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Largest chunk we hand to the Noise layer at once; keeping it under
// TS2021_MAX_PLAINTEXT means one DATA frame maps to one Noise record.
#define H2_TX_CHUNK 4000

static void put24(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v;
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t get24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}
static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int write_frame(h2_conn *c, uint8_t type, uint8_t flags, uint32_t stream,
                       const uint8_t *payload, size_t len) {
    uint8_t hdr[9];
    put24(hdr, (uint32_t)len);
    hdr[3] = type;
    hdr[4] = flags;
    put32(hdr + 5, stream & 0x7fffffff);
    if (c->io->write(c->io->ctx, hdr, sizeof(hdr)) < 0) return H2_ERR_IO;
    if (len && c->io->write(c->io->ctx, payload, len) < 0) return H2_ERR_IO;
    return 0;
}

static int send_window_update(h2_conn *c, uint32_t stream, uint32_t n) {
    uint8_t p[4];
    if (n == 0) return 0;
    put32(p, n);
    return write_frame(c, FRAME_WINDOW_UPDATE, 0, stream, p, sizeof(p));
}

// ------------------------------------------------------------- frame input

static void on_header(void *ctx, const char *n, size_t nl, const char *v, size_t vl) {
    h2_conn *c = (h2_conn *)ctx;
    if (nl == 7 && memcmp(n, ":status", 7) == 0) {
        int s = 0;
        size_t i;
        for (i = 0; i < vl; i++) {
            if (v[i] < '0' || v[i] > '9') { s = 0; break; }
            s = s * 10 + (v[i] - '0');
        }
        c->status = s;
    }
    if (c->hcb) c->hcb(c->cbctx, n, nl, v, vl);
}

static int handle_settings(h2_conn *c, uint32_t len, uint8_t flags) {
    uint8_t buf[6];
    uint32_t i;

    if (flags & FLAG_ACK) return len == 0 ? 0 : H2_ERR_PROTOCOL;
    if (len % 6) return H2_ERR_PROTOCOL;

    for (i = 0; i < len; i += 6) {
        uint16_t id;
        uint32_t val;
        if (ts_io_read_full(c->io, buf, 6) != 0) return H2_ERR_IO;
        id = (uint16_t)((buf[0] << 8) | buf[1]);
        val = get32(buf + 2);
        switch (id) {
        case SETTING_MAX_FRAME_SIZE:
            if (val < 16384 || val > 0xffffff) return H2_ERR_PROTOCOL;
            c->peer_max_frame = val;
            break;
        case SETTING_INITIAL_WINDOW_SIZE: {
            // Applies retroactively to open streams (RFC 7540 6.9.2).
            int64_t delta = (int64_t)val - (int64_t)c->peer_initial_window;
            if (val > 0x7fffffff) return H2_ERR_PROTOCOL;
            c->peer_initial_window = val;
            if (c->cur_stream) c->stream_send_window += (int32_t)delta;
            break;
        }
        default:
            break;   // the rest do not constrain us
        }
    }
    return write_frame(c, FRAME_SETTINGS, FLAG_ACK, 0, NULL, 0);
}

static int handle_headers(h2_conn *c, uint32_t stream, uint32_t len, uint8_t flags) {
    uint8_t pad_len = 0;
    uint32_t remaining = len;

    if (flags & FLAG_PADDED) {
        if (remaining < 1) return H2_ERR_PROTOCOL;
        if (ts_io_read_full(c->io, &pad_len, 1) != 0) return H2_ERR_IO;
        remaining -= 1;
    }
    if (flags & FLAG_PRIORITY) {
        uint8_t pri[5];
        if (remaining < 5) return H2_ERR_PROTOCOL;
        if (ts_io_read_full(c->io, pri, 5) != 0) return H2_ERR_IO;
        remaining -= 5;
    }
    if (remaining < pad_len) return H2_ERR_PROTOCOL;
    remaining -= pad_len;

    if (c->hdrlen + remaining > sizeof(c->hdrbuf)) return H2_ERR_TOOBIG;
    if (ts_io_read_full(c->io, c->hdrbuf + c->hdrlen, remaining) != 0) return H2_ERR_IO;
    c->hdrlen += remaining;
    if (pad_len && ts_io_skip(c->io, pad_len) != 0) return H2_ERR_IO;

    if (!(flags & FLAG_END_HEADERS)) {
        c->in_headers = 1;
        return 0;
    }
    c->in_headers = 0;

    // HPACK state is per connection, so a block must be decoded even if it
    // belongs to a stream we no longer care about.
    if (hpack_decode(&c->hpack, c->hdrbuf, c->hdrlen,
                     stream == c->cur_stream ? on_header : NULL, c) != 0) {
        return H2_ERR_PROTOCOL;
    }
    c->hdrlen = 0;
    if (stream == c->cur_stream && (flags & FLAG_END_STREAM)) c->stream_done = 1;
    return 0;
}

static int handle_data(h2_conn *c, uint32_t stream, uint32_t len, uint8_t flags) {
    uint8_t pad_len = 0;
    uint32_t remaining = len;
    uint32_t consumed = len;   // padding counts against flow control too
    uint8_t buf[512];

    if (flags & FLAG_PADDED) {
        if (remaining < 1) return H2_ERR_PROTOCOL;
        if (ts_io_read_full(c->io, &pad_len, 1) != 0) return H2_ERR_IO;
        remaining -= 1;
        if (remaining < pad_len) return H2_ERR_PROTOCOL;
        remaining -= pad_len;
    }

    while (remaining > 0) {
        uint32_t take = remaining > sizeof(buf) ? (uint32_t)sizeof(buf) : remaining;
        if (ts_io_read_full(c->io, buf, take) != 0) return H2_ERR_IO;
        if (stream == c->cur_stream && c->dcb && !c->abort) {
            if (c->dcb(c->cbctx, buf, take) != 0) c->abort = 1;
        }
        remaining -= take;
    }
    if (pad_len && ts_io_skip(c->io, pad_len) != 0) return H2_ERR_IO;

    if (stream == c->cur_stream && (flags & FLAG_END_STREAM)) c->stream_done = 1;

    // Give the credit straight back; we never hold the bytes. No stream-level
    // update once the stream is closed - the credit would have nowhere to go.
    if (consumed) {
        int rc = send_window_update(c, 0, consumed);
        if (rc) return rc;
        if (stream == c->cur_stream && !c->stream_done) {
            rc = send_window_update(c, stream, consumed);
            if (rc) return rc;
        }
    }
    return 0;
}

// Reads and processes exactly one frame.
static int h2_pump(h2_conn *c) {
    uint8_t hdr[9];
    uint32_t len, stream;
    uint8_t type, flags;

    if (ts_io_read_full(c->io, hdr, sizeof(hdr)) != 0) return H2_ERR_IO;
    len = get24(hdr);
    type = hdr[3];
    flags = hdr[4];
    stream = get32(hdr + 5) & 0x7fffffff;

    // A CONTINUATION sequence must not be interleaved with anything else.
    if (c->in_headers && type != FRAME_CONTINUATION) return H2_ERR_PROTOCOL;

    switch (type) {
    case FRAME_SETTINGS:
        if (stream != 0) return H2_ERR_PROTOCOL;
        return handle_settings(c, len, flags);

    case FRAME_HEADERS:
        return handle_headers(c, stream, len, flags);

    case FRAME_CONTINUATION:
        if (!c->in_headers) return H2_ERR_PROTOCOL;
        if (c->hdrlen + len > sizeof(c->hdrbuf)) return H2_ERR_TOOBIG;
        if (ts_io_read_full(c->io, c->hdrbuf + c->hdrlen, len) != 0) return H2_ERR_IO;
        c->hdrlen += len;
        if (flags & FLAG_END_HEADERS) {
            c->in_headers = 0;
            if (hpack_decode(&c->hpack, c->hdrbuf, c->hdrlen,
                             stream == c->cur_stream ? on_header : NULL, c) != 0)
                return H2_ERR_PROTOCOL;
            c->hdrlen = 0;
        }
        return 0;

    case FRAME_DATA:
        return handle_data(c, stream, len, flags);

    case FRAME_PING: {
        uint8_t p[8];
        if (len != 8) return H2_ERR_PROTOCOL;
        if (ts_io_read_full(c->io, p, 8) != 0) return H2_ERR_IO;
        if (flags & FLAG_ACK) return 0;
        return write_frame(c, FRAME_PING, FLAG_ACK, 0, p, 8);
    }

    case FRAME_WINDOW_UPDATE: {
        uint8_t p[4];
        uint32_t inc;
        if (len != 4) return H2_ERR_PROTOCOL;
        if (ts_io_read_full(c->io, p, 4) != 0) return H2_ERR_IO;
        inc = get32(p) & 0x7fffffff;
        if (inc == 0) return H2_ERR_PROTOCOL;
        if (stream == 0) c->conn_send_window += (int32_t)inc;
        else if (stream == c->cur_stream) c->stream_send_window += (int32_t)inc;
        return 0;
    }

    case FRAME_RST_STREAM:
        if (len != 4) return H2_ERR_PROTOCOL;
        if (ts_io_skip(c->io, len) != 0) return H2_ERR_IO;
        if (stream == c->cur_stream) { c->stream_done = 1; return H2_ERR_RST; }
        return 0;

    case FRAME_GOAWAY:
        if (ts_io_skip(c->io, len) != 0) return H2_ERR_IO;
        c->goaway = 1;
        return H2_ERR_GOAWAY;

    case FRAME_PUSH_PROMISE:
        return H2_ERR_PROTOCOL;      // we disabled push in SETTINGS

    default:
        // Unknown frame types must be ignored (RFC 7540 4.1).
        if (ts_io_skip(c->io, len) != 0) return H2_ERR_IO;
        return 0;
    }
}

// ------------------------------------------------------------------ public

int h2_connect(h2_conn *c, ts_io *io) {
    uint8_t settings[6 * 4];
    uint8_t *p = settings;
    int rc, seen_settings = 0;

    memset(c, 0, sizeof(*c));
    c->io = io;
    c->next_stream_id = 1;
    c->conn_send_window = 65535;
    c->peer_max_frame = 16384;
    c->peer_initial_window = 65535;
    hpack_decoder_init(&c->hpack, HPACK_DYN_ARENA);

    if (io->write(io->ctx, (const uint8_t *)H2_PREFACE, sizeof(H2_PREFACE) - 1) < 0)
        return H2_ERR_IO;

    // Tell the peer's encoder to stay within the table we can actually hold.
    p[0] = 0; p[1] = SETTING_HEADER_TABLE_SIZE;      put32(p + 2, HPACK_DYN_ARENA);   p += 6;
    p[0] = 0; p[1] = SETTING_ENABLE_PUSH;            put32(p + 2, 0);                 p += 6;
    p[0] = 0; p[1] = SETTING_MAX_CONCURRENT_STREAMS; put32(p + 2, 1);                 p += 6;
    p[0] = 0; p[1] = SETTING_MAX_HEADER_LIST_SIZE;   put32(p + 2, H2_MAX_HEADER_BLOCK); p += 6;

    rc = write_frame(c, FRAME_SETTINGS, 0, 0, settings, (size_t)(p - settings));
    if (rc) return rc;

    // Wait for the server's SETTINGS so we learn its limits before we send.
    while (!seen_settings) {
        uint8_t hdr[9];
        uint32_t len;
        if (ts_io_read_full(io, hdr, sizeof(hdr)) != 0) return H2_ERR_IO;
        len = get24(hdr);
        if (hdr[3] == FRAME_SETTINGS && !(hdr[4] & FLAG_ACK)) {
            rc = handle_settings(c, len, hdr[4]);
            if (rc) return rc;
            seen_settings = 1;
        } else if (hdr[3] == FRAME_WINDOW_UPDATE && len == 4) {
            uint8_t wp[4];
            if (ts_io_read_full(io, wp, 4) != 0) return H2_ERR_IO;
            if (get32(hdr + 5) == 0) c->conn_send_window += (int32_t)(get32(wp) & 0x7fffffff);
        } else {
            if (ts_io_skip(io, len) != 0) return H2_ERR_IO;
        }
    }
    return 0;
}

// Sends the body, pumping incoming frames whenever flow control blocks us.
static int send_body(h2_conn *c, const uint8_t *body, size_t body_len) {
    size_t sent = 0;

    while (sent < body_len) {
        size_t chunk = body_len - sent;
        int32_t window;
        int rc;

        while ((window = c->conn_send_window < c->stream_send_window
                             ? c->conn_send_window : c->stream_send_window) <= 0) {
            rc = h2_pump(c);
            if (rc) return rc;
        }
        if (chunk > (size_t)window) chunk = (size_t)window;
        if (chunk > c->peer_max_frame) chunk = c->peer_max_frame;
        if (chunk > H2_TX_CHUNK) chunk = H2_TX_CHUNK;

        {
            int last = (sent + chunk == body_len);
            rc = write_frame(c, FRAME_DATA, last ? FLAG_END_STREAM : 0,
                             c->cur_stream, body + sent, chunk);
            if (rc) return rc;
        }
        c->conn_send_window -= (int32_t)chunk;
        c->stream_send_window -= (int32_t)chunk;
        sent += chunk;
    }
    return 0;
}

int h2_request(h2_conn *c,
               const char *method, const char *scheme,
               const char *authority, const char *path,
               const char *content_type,
               const uint8_t *body, size_t body_len,
               h2_header_cb hcb, h2_data_cb dcb, void *cbctx,
               int *out_status) {
    uint8_t block[512];
    char clen[24];
    hpack_encoder enc;
    size_t block_len;
    int rc;

    if (c->goaway) return H2_ERR_GOAWAY;

    c->cur_stream = c->next_stream_id;
    c->next_stream_id += 2;
    c->stream_send_window = (int32_t)c->peer_initial_window;
    c->stream_done = 0;
    c->status = 0;
    c->abort = 0;
    c->hcb = hcb;
    c->dcb = dcb;
    c->cbctx = cbctx;
    c->hdrlen = 0;
    c->in_headers = 0;

    hpack_encoder_init(&enc, block, sizeof(block));
    hpack_encode_header(&enc, ":method", method);
    hpack_encode_header(&enc, ":scheme", scheme);
    hpack_encode_header(&enc, ":authority", authority);
    hpack_encode_header(&enc, ":path", path);
    if (content_type) hpack_encode_header(&enc, "content-type", content_type);
    if (body_len) {
        snprintf(clen, sizeof(clen), "%u", (unsigned)body_len);
        hpack_encode_header(&enc, "content-length", clen);
    }
    if (hpack_encoder_finish(&enc, &block_len) != 0) return H2_ERR_TOOBIG;

    rc = write_frame(c, FRAME_HEADERS,
                     (uint8_t)(FLAG_END_HEADERS | (body_len ? 0 : FLAG_END_STREAM)),
                     c->cur_stream, block, block_len);
    if (rc) return rc;

    if (body_len) {
        rc = send_body(c, body, body_len);
        if (rc) return rc;
    }

    while (!c->stream_done) {
        rc = h2_pump(c);
        // Report the status even on failure: an error body is far easier to
        // diagnose when you know whether it came with a 200 or a 400.
        if (out_status) *out_status = c->status;
        if (rc) return rc;
        if (c->abort) return H2_ERR_ABORTED;
    }

    if (out_status) *out_status = c->status;
    return 0;
}
