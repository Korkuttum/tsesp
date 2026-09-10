// DISCO framing. The wire format is defined only by Tailscale's Go source, so
// the offsets are spelled out here explicitly: if the reading is wrong, it is
// wrong visibly rather than hidden inside a round-trip that agrees with
// itself.
#include <stdio.h>
#include <string.h>
#include "disco.h"
#include "tscrypto.h"

static int fails = 0;

static void fail(const char *what) {
    printf("  FAIL %s\n", what);
    fails++;
}

static void expect(int cond, const char *what) {
    if (cond) printf("  ok   %s\n", what);
    else { printf("  FAIL %s\n", what); fails++; }
}

int main(void) {
    uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32];
    uint8_t shared_ab[32], shared_ba[32];
    uint8_t inner[DISCO_MAX_INNER], pkt[512];
    uint8_t txid[DISCO_TXID_LEN];
    uint8_t nonce[NACL_NONCE_LEN];
    size_t ilen, plen;
    disco_msg m;
    int i;

    // Fixed keys: this test must not depend on entropy.
    for (i = 0; i < 32; i++) { a_priv[i] = (uint8_t)(i + 1); b_priv[i] = (uint8_t)(0x40 + i); }
    x25519_clamp(a_priv);
    x25519_clamp(b_priv);
    x25519_base(a_pub, a_priv);
    x25519_base(b_pub, b_priv);
    for (i = 0; i < DISCO_TXID_LEN; i++) txid[i] = (uint8_t)(0xa0 + i);
    for (i = 0; i < NACL_NONCE_LEN; i++) nonce[i] = (uint8_t)(0x10 + i);

    printf("shared keys\n");
    expect(nacl_box_beforenm(shared_ab, b_pub, a_priv) == 0 &&
           nacl_box_beforenm(shared_ba, a_pub, b_priv) == 0 &&
           memcmp(shared_ab, shared_ba, 32) == 0,
           "both sides derive the same disco shared key");

    printf("magic\n");
    {
        static const uint8_t want[6] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };
        expect(memcmp(disco_magic, want, 6) == 0, "magic is 54 53 f0 9f 92 ac");
    }

    printf("ping layout\n");
    // type(1) version(1) txid(12) nodekey(32) padding(n)
    if (disco_build_ping(inner, sizeof(inner), &ilen, txid, b_pub, 7) != 0) {
        fail("build_ping");
    } else {
        expect(ilen == 2 + 12 + 32 + 7, "length is 2 + 12 + 32 + padding");
        expect(inner[0] == DISCO_PING && inner[1] == 0, "type 0x01, version 0");
        expect(memcmp(inner + 2, txid, 12) == 0, "txid at offset 2");
        expect(memcmp(inner + 14, b_pub, 32) == 0, "node key at offset 14");
        {
            int all_zero = 1;
            size_t k;
            for (k = 46; k < ilen; k++) if (inner[k]) all_zero = 0;
            expect(all_zero, "padding is zero bytes at the end");
        }
    }

    printf("pong layout\n");
    {
        uint8_t src[16], v4[4] = { 203, 0, 113, 9 };
        disco_ipv4_mapped(src, v4);
        expect(src[10] == 0xff && src[11] == 0xff && src[12] == 203 && src[15] == 9,
               "IPv4 becomes ::ffff:203.0.113.9");
        if (disco_build_pong(inner, sizeof(inner), &ilen, txid, src, 41641) != 0) {
            fail("build_pong");
        } else {
            expect(ilen == 2 + 12 + 16 + 2, "length is 2 + 12 + 16 + 2");
            expect(inner[0] == DISCO_PONG, "type 0x02");
            expect(inner[30] == (41641 >> 8) && inner[31] == (41641 & 0xff),
                   "port is big-endian at the end");
        }
    }

    printf("call-me-maybe round trip\n");
    {
        uint8_t eps[3][16];
        uint16_t ports[3] = { 41641, 1234, 65535 };
        uint8_t v4a[4] = { 78, 190, 240, 153 }, v4b[4] = { 192, 168, 1, 73 };
        disco_ipv4_mapped(eps[0], v4a);
        disco_ipv4_mapped(eps[1], v4b);
        memset(eps[2], 0, 16);
        eps[2][0] = 0x2a; eps[2][1] = 0x00; eps[2][15] = 1;

        if (disco_build_call_me_maybe(inner, sizeof(inner), &ilen,
                                      (const uint8_t (*)[16])eps, ports, 3) != 0) {
            fail("build_call_me_maybe");
        } else if (disco_seal(pkt, sizeof(pkt), &plen, a_pub, shared_ab,
                              nonce, inner, ilen) != 0) {
            fail("seal");
        } else {
            expect(plen == DISCO_HEADER_LEN + ilen + NACL_TAG_LEN,
                   "packet is header + inner + 16-byte tag");
            expect(disco_looks_like_disco(pkt, plen), "recognised as disco");
            expect(disco_sender_key(pkt, plen) != NULL &&
                   memcmp(disco_sender_key(pkt, plen), a_pub, 32) == 0,
                   "sender disco key readable without decrypting");

            if (disco_open(pkt, plen, shared_ba, &m) != 0) {
                fail("open with the peer's shared key");
            } else {
                uint8_t v4[4];
                expect(m.type == DISCO_CALL_ME_MAYBE, "type survives");
                expect(m.nendpoints == 3, "all three endpoints survive");
                expect(disco_is_ipv4_mapped(m.ep_ip[0], v4) && v4[0] == 78 &&
                       m.ep_port[0] == 41641, "first endpoint is 78.190.240.153:41641");
                expect(!disco_is_ipv4_mapped(m.ep_ip[2], NULL),
                       "IPv6 endpoint not mistaken for v4-mapped");
            }
        }
    }

    printf("ping round trip and padding\n");
    {
        disco_build_ping(inner, sizeof(inner), &ilen, txid, b_pub, 20);
        disco_seal(pkt, sizeof(pkt), &plen, a_pub, shared_ab, nonce, inner, ilen);
        if (disco_open(pkt, plen, shared_ba, &m) != 0) {
            fail("open ping");
        } else {
            expect(m.type == DISCO_PING && memcmp(m.txid, txid, 12) == 0, "txid survives");
            expect(m.has_node_key && memcmp(m.node_key, b_pub, 32) == 0, "node key survives");
            expect(m.padding == 20, "padding counted correctly");
        }
        // Without a node key, 32 zero bytes of padding must not be read as one.
        disco_build_ping(inner, sizeof(inner), &ilen, txid, NULL, 32);
        disco_seal(pkt, sizeof(pkt), &plen, a_pub, shared_ab, nonce, inner, ilen);
        disco_open(pkt, plen, shared_ba, &m);
        expect(!m.has_node_key && m.padding == 32,
               "32 zero padding bytes are not read as a node key");
    }

    printf("rejection\n");
    {
        uint8_t wrong_priv[32], wrong_pub[32], shared_wrong[32];
        for (i = 0; i < 32; i++) wrong_priv[i] = (uint8_t)(0x90 + i);
        x25519_clamp(wrong_priv);
        x25519_base(wrong_pub, wrong_priv);
        nacl_box_beforenm(shared_wrong, wrong_pub, a_priv);

        disco_build_ping(inner, sizeof(inner), &ilen, txid, NULL, 0);
        disco_seal(pkt, sizeof(pkt), &plen, a_pub, shared_ab, nonce, inner, ilen);

        expect(disco_open(pkt, plen, shared_wrong, &m) == -2,
               "a third party cannot open the box");
        pkt[plen - 1] ^= 1;
        expect(disco_open(pkt, plen, shared_ba, &m) == -2, "tampering is caught");
        pkt[plen - 1] ^= 1;
        pkt[0] ^= 1;
        expect(disco_open(pkt, plen, shared_ba, &m) == -1, "bad magic is rejected");
        expect(!disco_looks_like_disco(pkt, 4), "a short datagram is not disco");
    }

    printf("\n%s\n", fails ? "DISCO TESTS FAILED" : "all DISCO tests passed");
    return fails ? 1 : 0;
}
