#include <string.h>
#include <stdio.h>
#include "stun.h"

#define STUN_BINDING_REQUEST  0x0001
#define STUN_BINDING_SUCCESS  0x0101
#define STUN_BINDING_ERROR    0x0111

#define ATTR_MAPPED_ADDRESS     0x0001
#define ATTR_XOR_MAPPED_ADDRESS 0x0020

static const uint8_t kMagicCookie[4] = { 0x21, 0x12, 0xa4, 0x42 };

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void     wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

void stun_build_request(uint8_t out[STUN_HEADER_LEN], const uint8_t txid[STUN_TXID_LEN]) {
    wr16(out, STUN_BINDING_REQUEST);
    wr16(out + 2, 0);                       // no attributes
    memcpy(out + 4, kMagicCookie, 4);
    memcpy(out + 8, txid, STUN_TXID_LEN);
}

int stun_looks_like_stun(const uint8_t *buf, size_t len) {
    if (len < STUN_HEADER_LEN) return 0;
    // STUN messages start with two zero bits; WireGuard type bytes are 1..4
    // with three zero bytes after, and DISCO starts with 0x54 ('T').
    if (buf[0] & 0xc0) return 0;
    if (memcmp(buf + 4, kMagicCookie, 4) != 0) return 0;
    // The length field must agree with the datagram and be a multiple of 4.
    return (size_t)rd16(buf + 2) + STUN_HEADER_LEN <= len && (rd16(buf + 2) % 4) == 0;
}

int stun_parse_response(const uint8_t *buf, size_t len,
                        const uint8_t txid[STUN_TXID_LEN],
                        uint8_t addr[16], int *is_ipv6, uint16_t *port) {
    uint16_t type, mlen;
    size_t pos;

    if (!stun_looks_like_stun(buf, len)) return -1;
    type = rd16(buf);
    mlen = rd16(buf + 2);
    if (memcmp(buf + 8, txid, STUN_TXID_LEN) != 0) return -2;
    if (type == STUN_BINDING_ERROR) return -3;
    if (type != STUN_BINDING_SUCCESS) return -1;

    pos = STUN_HEADER_LEN;
    while (pos + 4 <= STUN_HEADER_LEN + (size_t)mlen) {
        uint16_t atype = rd16(buf + pos);
        uint16_t alen = rd16(buf + pos + 2);
        const uint8_t *val = buf + pos + 4;
        size_t padded = ((size_t)alen + 3) & ~(size_t)3;

        if (pos + 4 + padded > STUN_HEADER_LEN + (size_t)mlen) return -1;

        if (atype == ATTR_XOR_MAPPED_ADDRESS || atype == ATTR_MAPPED_ADDRESS) {
            uint8_t family;
            int xored = (atype == ATTR_XOR_MAPPED_ADDRESS);
            if (alen < 4) return -1;
            family = val[1];

            if (family == 0x01) {                 // IPv4
                if (alen < 8) return -1;
                *port = rd16(val + 2);
                memcpy(addr, val + 4, 4);
                if (xored) {
                    int i;
                    *port ^= (uint16_t)((kMagicCookie[0] << 8) | kMagicCookie[1]);
                    for (i = 0; i < 4; i++) addr[i] ^= kMagicCookie[i];
                }
                *is_ipv6 = 0;
                return 0;
            }
            if (family == 0x02) {                 // IPv6
                if (alen < 20) return -1;
                *port = rd16(val + 2);
                memcpy(addr, val + 4, 16);
                if (xored) {
                    int i;
                    *port ^= (uint16_t)((kMagicCookie[0] << 8) | kMagicCookie[1]);
                    for (i = 0; i < 4; i++)  addr[i] ^= kMagicCookie[i];
                    for (i = 0; i < 12; i++) addr[4 + i] ^= buf[8 + i];   // txid
                }
                *is_ipv6 = 1;
                return 0;
            }
            return -1;
        }
        pos += 4 + padded;
    }
    return -1;
}

void stun_format_addr(char *out, size_t cap,
                      const uint8_t addr[16], int is_ipv6, uint16_t port) {
    if (!is_ipv6) {
        snprintf(out, cap, "%u.%u.%u.%u:%u", addr[0], addr[1], addr[2], addr[3], port);
        return;
    }
    snprintf(out, cap,
             "[%x:%x:%x:%x:%x:%x:%x:%x]:%u",
             (addr[0] << 8) | addr[1],   (addr[2] << 8) | addr[3],
             (addr[4] << 8) | addr[5],   (addr[6] << 8) | addr[7],
             (addr[8] << 8) | addr[9],   (addr[10] << 8) | addr[11],
             (addr[12] << 8) | addr[13], (addr[14] << 8) | addr[15],
             port);
}
