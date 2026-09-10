#include <string.h>
#include "disco.h"

// "TS" followed by U+1F4AC SPEECH BALLOON in UTF-8.
const uint8_t disco_magic[DISCO_MAGIC_LEN] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };

static void wr16be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t rd16be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

void disco_ipv4_mapped(uint8_t out[16], const uint8_t v4[4]) {
    memset(out, 0, 10);
    out[10] = 0xff;
    out[11] = 0xff;
    memcpy(out + 12, v4, 4);
}

int disco_is_ipv4_mapped(const uint8_t addr[16], uint8_t v4[4]) {
    static const uint8_t prefix[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
    if (memcmp(addr, prefix, 12) != 0) return 0;
    if (v4) memcpy(v4, addr + 12, 4);
    return 1;
}

// --------------------------------------------------------------- building

static int put_header(uint8_t *out, size_t cap, uint8_t type, size_t payload) {
    if (cap < 2 + payload) return -1;
    out[0] = type;
    out[1] = 0;               // version
    return 0;
}

int disco_build_ping(uint8_t *out, size_t cap, size_t *len,
                     const uint8_t txid[DISCO_TXID_LEN],
                     const uint8_t node_pub[32], size_t padding) {
    size_t payload = DISCO_TXID_LEN + (node_pub ? 32 : 0) + padding;

    if (put_header(out, cap, DISCO_PING, payload) != 0) return -1;
    memcpy(out + 2, txid, DISCO_TXID_LEN);
    if (node_pub) memcpy(out + 2 + DISCO_TXID_LEN, node_pub, 32);
    // Padding is zero bytes; the receiver treats trailing zeros as padding
    // rather than a node key, which is why a zero key is never sent.
    if (padding) memset(out + 2 + DISCO_TXID_LEN + (node_pub ? 32 : 0), 0, padding);
    *len = 2 + payload;
    return 0;
}

int disco_build_pong(uint8_t *out, size_t cap, size_t *len,
                     const uint8_t txid[DISCO_TXID_LEN],
                     const uint8_t src_ip[16], uint16_t src_port) {
    const size_t payload = DISCO_TXID_LEN + 16 + 2;

    if (put_header(out, cap, DISCO_PONG, payload) != 0) return -1;
    memcpy(out + 2, txid, DISCO_TXID_LEN);
    memcpy(out + 2 + DISCO_TXID_LEN, src_ip, 16);
    wr16be(out + 2 + DISCO_TXID_LEN + 16, src_port);
    *len = 2 + payload;
    return 0;
}

int disco_build_call_me_maybe(uint8_t *out, size_t cap, size_t *len,
                              const uint8_t ep_ip[][16], const uint16_t *ep_port,
                              int n) {
    size_t payload = (size_t)n * DISCO_EP_LEN;
    int i;

    if (n < 0) return -1;
    if (put_header(out, cap, DISCO_CALL_ME_MAYBE, payload) != 0) return -1;
    for (i = 0; i < n; i++) {
        uint8_t *p = out + 2 + (size_t)i * DISCO_EP_LEN;
        memcpy(p, ep_ip[i], 16);
        wr16be(p + 16, ep_port[i]);
    }
    *len = 2 + payload;
    return 0;
}

// ------------------------------------------------------- sealing / opening

int disco_seal(uint8_t *out, size_t cap, size_t *len,
               const uint8_t our_disco_pub[32],
               const uint8_t shared[NACL_KEY_LEN],
               const uint8_t nonce[NACL_NONCE_LEN],
               const uint8_t *inner, size_t inner_len) {
    size_t total = DISCO_HEADER_LEN + inner_len + NACL_TAG_LEN;

    if (cap < total) return -1;
    memcpy(out, disco_magic, DISCO_MAGIC_LEN);
    memcpy(out + DISCO_MAGIC_LEN, our_disco_pub, DISCO_KEY_LEN);
    memcpy(out + DISCO_MAGIC_LEN + DISCO_KEY_LEN, nonce, NACL_NONCE_LEN);
    nacl_secretbox(out + DISCO_HEADER_LEN, inner, inner_len, nonce, shared);
    *len = total;
    return 0;
}

int disco_looks_like_disco(const uint8_t *pkt, size_t len) {
    if (len < DISCO_HEADER_LEN) return 0;
    return memcmp(pkt, disco_magic, DISCO_MAGIC_LEN) == 0;
}

const uint8_t *disco_sender_key(const uint8_t *pkt, size_t len) {
    if (!disco_looks_like_disco(pkt, len)) return NULL;
    return pkt + DISCO_MAGIC_LEN;
}

static int parse_inner(const uint8_t *p, size_t len, disco_msg *out) {
    if (len < 2) return -1;
    out->type = p[0];
    out->version = p[1];
    p += 2;
    len -= 2;

    switch (out->type) {
    case DISCO_PING: {
        if (len < DISCO_TXID_LEN) return -1;
        memcpy(out->txid, p, DISCO_TXID_LEN);
        p += DISCO_TXID_LEN;
        len -= DISCO_TXID_LEN;
        out->padding = (int)len;
        // An all-zero key is padding, not a node key - the sender omits zero
        // keys entirely, so this matches how the message was built.
        if (len >= 32) {
            static const uint8_t zero[32] = {0};
            if (memcmp(p, zero, 32) != 0) {
                memcpy(out->node_key, p, 32);
                out->has_node_key = 1;
                out->padding = (int)(len - 32);
            }
        }
        return 0;
    }
    case DISCO_PONG: {
        if (len < DISCO_TXID_LEN + 16 + 2) return -1;
        memcpy(out->txid, p, DISCO_TXID_LEN);
        memcpy(out->src_ip, p + DISCO_TXID_LEN, 16);
        out->src_port = rd16be(p + DISCO_TXID_LEN + 16);
        return 0;
    }
    case DISCO_CALL_ME_MAYBE: {
        size_t i, n;
        // Go returns an empty message rather than an error for a bad length,
        // so a peer that sends one just gets ignored instead of dropped.
        if (len % DISCO_EP_LEN != 0) return 0;
        n = len / DISCO_EP_LEN;
        for (i = 0; i < n; i++) {
            if (out->nendpoints >= DISCO_MAX_ENDPOINTS) {
                out->dropped_endpoints++;
                continue;
            }
            memcpy(out->ep_ip[out->nendpoints], p + i * DISCO_EP_LEN, 16);
            out->ep_port[out->nendpoints] = rd16be(p + i * DISCO_EP_LEN + 16);
            out->nendpoints++;
        }
        return 0;
    }
    default:
        return -3;
    }
}

int disco_open(const uint8_t *pkt, size_t len,
               const uint8_t shared[NACL_KEY_LEN], disco_msg *out) {
    uint8_t inner[DISCO_MAX_INNER];
    size_t box_len, inner_len;

    memset(out, 0, sizeof(*out));
    if (!disco_looks_like_disco(pkt, len)) return -1;

    box_len = len - DISCO_HEADER_LEN;
    if (box_len < NACL_TAG_LEN) return -1;
    inner_len = box_len - NACL_TAG_LEN;
    if (inner_len > sizeof(inner)) return -1;

    if (nacl_secretbox_open(inner, pkt + DISCO_HEADER_LEN, box_len,
                            pkt + DISCO_MAGIC_LEN + DISCO_KEY_LEN, shared) != 0)
        return -2;

    return parse_inner(inner, inner_len, out);
}
