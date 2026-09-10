#include <string.h>
#include "ts_noise_stream.h"

// Pulls one Noise record and decrypts it in place. chacha20poly1305_open is
// safe with out == in: it authenticates before touching the buffer, and the
// keystream XOR is index-aligned.
static int fill(ts_noise_stream *s) {
    uint8_t hdr[TS2021_HEADER_LEN];
    size_t len, plain_len;

    if (s->failed) return -1;
    if (ts_io_read_full(s->inner, hdr, sizeof(hdr)) != 0) return -1;

    len = ((size_t)hdr[1] << 8) | hdr[2];
    if (hdr[0] == TS2021_MSG_ERROR) {
        // Unauthenticated hint from the server; read it so callers can log it.
        if (len > TS2021_MAX_CIPHER) len = TS2021_MAX_CIPHER;
        if (ts_io_read_full(s->inner, s->rx, len) != 0) return -1;
        s->failed = 1;
        return -1;
    }
    if (hdr[0] != TS2021_MSG_RECORD || len < 16 || len > TS2021_MAX_CIPHER) {
        s->failed = 1;
        return -1;
    }
    if (ts_io_read_full(s->inner, s->rx, len) != 0) return -1;

    if (ts2021_open(&s->conn, s->rx, len, s->rx, sizeof(s->rx), &plain_len) != 0) {
        s->failed = 1;
        return -1;
    }
    s->rx_len = plain_len;
    s->rx_pos = 0;
    return 0;
}

static int stream_read(void *ctx, uint8_t *buf, size_t len) {
    ts_noise_stream *s = (ts_noise_stream *)ctx;
    size_t avail;

    if (s->pushback_pos < s->pushback_len) {
        avail = (size_t)(s->pushback_len - s->pushback_pos);
        if (avail > len) avail = len;
        memcpy(buf, s->pushback + s->pushback_pos, avail);
        s->pushback_pos += (uint8_t)avail;
        return (int)avail;
    }

    while (s->rx_pos >= s->rx_len) {
        if (fill(s) != 0) return -1;
        if (s->rx_len == 0) continue;      // empty record: keep going
    }
    avail = s->rx_len - s->rx_pos;
    if (avail > len) avail = len;
    memcpy(buf, s->rx + s->rx_pos, avail);
    s->rx_pos += avail;
    return (int)avail;
}

static int stream_write(void *ctx, const uint8_t *buf, size_t len) {
    ts_noise_stream *s = (ts_noise_stream *)ctx;
    size_t sent = 0;

    if (s->failed) return -1;
    while (sent < len) {
        size_t chunk = len - sent;
        size_t frame_len;
        if (chunk > TS2021_MAX_PLAINTEXT) chunk = TS2021_MAX_PLAINTEXT;
        if (ts2021_seal(&s->conn, buf + sent, chunk,
                        s->tx, sizeof(s->tx), &frame_len) != 0) {
            s->failed = 1;
            return -1;
        }
        if (s->inner->write(s->inner->ctx, s->tx, frame_len) < 0) {
            s->failed = 1;
            return -1;
        }
        sent += chunk;
    }
    return (int)len;
}

int ts_noise_stream_unread(ts_noise_stream *s, const uint8_t *buf, size_t len) {
    if (len > sizeof(s->pushback)) return -1;
    memcpy(s->pushback, buf, len);
    s->pushback_len = (uint8_t)len;
    s->pushback_pos = 0;
    return 0;
}

void ts_noise_stream_init(ts_noise_stream *s, ts_io *inner,
                          const ts2021_conn *conn, ts_io *out) {
    memset(s, 0, sizeof(*s));
    s->inner = inner;
    s->conn = *conn;
    out->read = stream_read;
    out->write = stream_write;
    out->ctx = s;
}
