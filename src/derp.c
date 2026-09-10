#include <string.h>
#include <stdio.h>
#include "derp.h"
#include "nacl_box.h"
#include "tscrypto.h"

// "DERP" followed by U+1F511 KEY in UTF-8.
static const uint8_t kDerpMagic[DERP_MAGIC_LEN] = {
    0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91
};

static void put32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t get32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

// ---------------------------------------------------------------- framing

static int write_frame(derp_conn *c, uint8_t type,
                       const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen) {
    uint8_t hdr[DERP_FRAME_HEADER];
    hdr[0] = type;
    put32be(hdr + 1, (uint32_t)(alen + blen));
    if (c->io->write(c->io->ctx, hdr, sizeof(hdr)) < 0) return -1;
    if (alen && c->io->write(c->io->ctx, a, alen) < 0) return -1;
    if (blen && c->io->write(c->io->ctx, b, blen) < 0) return -1;
    return 0;
}

// Reads one frame. Payloads that do not fit are discarded and *len is set to
// the full size, so the caller can tell the difference between an empty frame
// and one that was too large.
static int read_frame(derp_conn *c, uint8_t *type, uint8_t *buf, size_t cap,
                      size_t *len, int *truncated) {
    uint8_t hdr[DERP_FRAME_HEADER];
    uint32_t flen;

    if (ts_io_read_full(c->io, hdr, sizeof(hdr)) != 0) return -1;
    *type = hdr[0];
    flen = get32be(hdr + 1);
    *truncated = 0;

    if (flen > cap) {
        if (ts_io_skip(c->io, flen) != 0) return -1;
        *len = flen;
        *truncated = 1;
        return 0;
    }
    if (flen && ts_io_read_full(c->io, buf, flen) != 0) return -1;
    *len = flen;
    return 0;
}

// ------------------------------------------------------------- handshake

// The upgrade must be HTTP/1.1: the relay answers HTTP/2 with 426 and the
// switch never happens.
static int http_upgrade(derp_conn *c, const char *host) {
    char req[320], head[512];
    size_t n = 0;
    int state = 0, len;

    len = snprintf(req, sizeof(req),
                   "GET /derp HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "Connection: Upgrade\r\n"
                   "Upgrade: DERP\r\n"
                   "User-Agent: tsesp/0.1\r\n"
                   "\r\n", host);
    if (len < 0 || (size_t)len >= sizeof(req)) return -1;
    if (c->io->write(c->io->ctx, (const uint8_t *)req, (size_t)len) < 0) return -1;

    // One byte at a time: anything read past the blank line belongs to the
    // first DERP frame.
    while (n + 1 < sizeof(head)) {
        uint8_t ch;
        if (ts_io_read_full(c->io, &ch, 1) != 0) return -1;
        head[n++] = (char)ch;
        if ((state == 0 || state == 2) && ch == '\r') state++;
        else if ((state == 1 || state == 3) && ch == '\n') state++;
        else state = (ch == '\r') ? 1 : 0;
        if (state == 4) break;
    }
    head[n] = '\0';
    if (strncmp(head, "HTTP/1.1 101", 12) != 0) return -2;
    return 0;
}

int derp_connect(derp_conn *c, ts_io *io, const derp_opts *opts) {
    uint8_t buf[512], nonce[DERP_NONCE_LEN];
    uint8_t sealed[256];
    char info[96];
    uint8_t type;
    size_t len;
    int truncated, rc, jlen;

    memset(c, 0, sizeof(*c));
    c->io = io;
    memcpy(c->node_priv, opts->node_priv, 32);
    memcpy(c->node_pub, opts->node_pub, 32);

    rc = http_upgrade(c, opts->host);
    if (rc != 0) return rc;

    // The greeting: magic plus the server's public key.
    if (read_frame(c, &type, buf, sizeof(buf), &len, &truncated) != 0) return -1;
    if (type != DERP_FRAME_SERVER_KEY || truncated ||
        len < DERP_MAGIC_LEN + DERP_KEY_LEN ||
        memcmp(buf, kDerpMagic, DERP_MAGIC_LEN) != 0)
        return -2;
    memcpy(c->server_key, buf + DERP_MAGIC_LEN, DERP_KEY_LEN);

    if (nacl_box_beforenm(c->shared, c->server_key, c->node_priv) != 0) return -2;

    // Our reply: who we are, sealed to the server. CanAckPings has no
    // omitempty in Go, so it is always present; the rest are omitted.
    jlen = snprintf(info, sizeof(info),
                    "{\"version\":%d,\"CanAckPings\":true}", DERP_PROTOCOL_VERSION);
    if (jlen < 0 || (size_t)jlen + NACL_TAG_LEN > sizeof(sealed)) return -1;

    // A fresh nonce per connection is all that is needed: the key is unique
    // to this pair and the box is used once.
    {
        uint8_t seed[32];
        blake2s(seed, sizeof(seed), c->shared, sizeof(c->shared));
        memcpy(nonce, seed, DERP_NONCE_LEN);
        // Mix in the server key so two connections to different relays with
        // the same node key never repeat a nonce.
        for (int i = 0; i < DERP_NONCE_LEN; i++) nonce[i] ^= c->server_key[i];
    }
    nacl_secretbox(sealed, (const uint8_t *)info, (size_t)jlen, nonce, c->shared);

    {
        uint8_t payload[32 + DERP_NONCE_LEN];
        memcpy(payload, c->node_pub, 32);
        memcpy(payload + 32, nonce, DERP_NONCE_LEN);
        if (write_frame(c, DERP_FRAME_CLIENT_INFO, payload, sizeof(payload),
                        sealed, (size_t)jlen + NACL_TAG_LEN) != 0)
            return -1;
    }

    // The server's reply proves it holds the matching private key.
    for (;;) {
        if (read_frame(c, &type, buf, sizeof(buf), &len, &truncated) != 0) return -1;
        if (type == DERP_FRAME_SERVER_INFO) break;
        if (type == DERP_FRAME_HEALTH || type == DERP_FRAME_KEEPALIVE) continue;
        if (truncated) continue;
        return -2;
    }
    if (len < DERP_NONCE_LEN + NACL_TAG_LEN) return -2;
    {
        uint8_t plain[256];
        size_t clen = len - DERP_NONCE_LEN;
        if (clen - NACL_TAG_LEN > sizeof(plain)) return -2;
        if (nacl_secretbox_open(plain, buf + DERP_NONCE_LEN, clen,
                                buf, c->shared) != 0)
            return -3;
        c->server_version = DERP_PROTOCOL_VERSION;
    }

    c->ready = 1;
    if (opts->preferred) derp_note_preferred(c, 1);
    return 0;
}

// ------------------------------------------------------------------ i/o

int derp_note_preferred(derp_conn *c, int preferred) {
    uint8_t v = preferred ? 1 : 0;
    if (!c->ready) return -1;
    return write_frame(c, DERP_FRAME_NOTE_PREFERRED, &v, 1, NULL, 0);
}

int derp_send(derp_conn *c, const uint8_t dst_node_pub[32],
              const uint8_t *pkt, size_t len) {
    if (!c->ready) return -1;
    if (len + 32 > DERP_MAX_FRAME) return -1;
    if (write_frame(c, DERP_FRAME_SEND_PACKET, dst_node_pub, 32, pkt, len) != 0)
        return -1;
    c->sent++;
    return 0;
}

int derp_recv(derp_conn *c, uint8_t src_node_pub[32],
              uint8_t *buf, size_t cap, size_t *len) {
    uint8_t frame[DERP_MAX_FRAME];
    uint8_t type;
    size_t flen;
    int truncated;

    if (!c->ready) return -1;
    if (read_frame(c, &type, frame, sizeof(frame), &flen, &truncated) != 0) return -1;

    switch (type) {
    case DERP_FRAME_RECV_PACKET:
        if (truncated || flen < 32) return 0;      // not something we can use
        if (flen - 32 > cap) return 0;
        memcpy(src_node_pub, frame, 32);
        memcpy(buf, frame + 32, flen - 32);
        *len = flen - 32;
        c->received++;
        return 1;

    case DERP_FRAME_PING:
        // Answering keeps the server from deciding we are gone.
        c->pings++;
        if (flen == 8) write_frame(c, DERP_FRAME_PONG, frame, 8, NULL, 0);
        return 0;

    case DERP_FRAME_KEEPALIVE:
        c->keepalives++;
        return 0;

    case DERP_FRAME_PEER_GONE:
        c->peer_gone++;
        return 0;

    default:
        // Health, restarting, peer-present and anything added later: the
        // protocol is explicitly forward-compatible, so unknown frames are
        // not an error.
        return 0;
    }
}
