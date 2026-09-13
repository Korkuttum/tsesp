// Address translation, checked against packets built here and checksums
// recomputed from scratch rather than by the same incremental code that
// wrote them.
#include <stdio.h>
#include <string.h>
#include "nat.h"

static int fails = 0;
static void ok(int cond, const char *what) {
    printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond) fails++;
}

#define PEER  0x0A0B0C64u      /* 100.12.11.10 in network order, little-endian host */
#define LAN   0x4B01A8C0u      /* 192.168.1.75 */
#define OURS  0x4901A8C0u      /* 192.168.1.73 */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

// Independent checksum, so a wrong incremental update cannot agree with itself.
static uint16_t sum16(const uint8_t *p, size_t n, uint32_t start) {
    uint32_t s = start;
    size_t i;
    for (i = 0; i + 1 < n; i += 2) s += rd16(p + i);
    if (i < n) s += (uint32_t)p[i] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static uint16_t ip_csum(const uint8_t *pkt) {
    uint8_t h[20];
    memcpy(h, pkt, 20);
    wr16(h + 10, 0);
    return sum16(h, 20, 0);
}

// ICMP's checksum covers only its own header and payload - no pseudo-header,
// which is why a changed IP address does not disturb it.
static uint16_t icmp_csum(const uint8_t *pkt, size_t len) {
    uint8_t buf[1600];
    size_t hl = (size_t)(pkt[0] & 0x0f) * 4, l4 = len - hl;
    memcpy(buf, pkt + hl, l4);
    wr16(buf + 2, 0);
    return sum16(buf, l4, 0);
}

static uint16_t l4_csum(const uint8_t *pkt, size_t len, int off) {
    uint8_t buf[1600];
    size_t hl = (size_t)(pkt[0] & 0x0f) * 4, l4 = len - hl;
    uint32_t pseudo;
    memcpy(buf, pkt + hl, l4);
    wr16(buf + off, 0);
    pseudo = (uint32_t)rd16(pkt + 12) + rd16(pkt + 14) + rd16(pkt + 16) + rd16(pkt + 18)
           + pkt[9] + (uint32_t)l4;
    return sum16(buf, l4, pseudo);
}

// A TCP SYN from `src`:`sp` to `dst`:`dp`, checksums filled in properly.
static size_t mk_tcp(uint8_t *p, uint32_t src, uint32_t dst, uint16_t sp, uint16_t dp) {
    memset(p, 0, 40);
    p[0] = 0x45; wr16(p + 2, 40); p[8] = 64; p[9] = 6;
    memcpy(p + 12, &src, 4); memcpy(p + 16, &dst, 4);
    wr16(p, rd16(p));                       /* no-op, keeps the shape explicit */
    wr16(p + 20, sp); wr16(p + 22, dp);
    p[32] = 0x50; p[33] = 0x02;             /* data offset 5, SYN */
    wr16(p + 34, 8192);
    wr16(p + 10, ip_csum(p));
    wr16(p + 36, l4_csum(p, 40, 16));
    return 40;
}

static size_t mk_icmp(uint8_t *p, uint32_t src, uint32_t dst, uint16_t id, uint8_t type) {
    memset(p, 0, 28);
    p[0] = 0x45; wr16(p + 2, 28); p[8] = 64; p[9] = 1;
    memcpy(p + 12, &src, 4); memcpy(p + 16, &dst, 4);
    p[20] = type; p[21] = 0;
    wr16(p + 24, id); wr16(p + 26, 1);
    wr16(p + 10, ip_csum(p));
    wr16(p + 22, sum16(p + 20, 8, 0));
    return 28;
}

int main(void) {
    static nat_table t;
    uint8_t pkt[1600];
    size_t len;
    uint32_t peer = 0;
    uint16_t mport;

    nat_init(&t);

    printf("a tcp flow out and back\n");
    len = mk_tcp(pkt, PEER, LAN, 54340, 80);
    ok(ip_csum(pkt) == rd16(pkt + 10) && l4_csum(pkt, len, 16) == rd16(pkt + 36),
       "the packet we built is well formed");

    ok(nat_out(&t, pkt, len, OURS, 1000) == 1, "rewritten on the way out");
    ok(memcmp(pkt + 12, &(uint32_t){OURS}, 4) == 0, "source is now this device");
    mport = rd16(pkt + 20);
    ok(mport >= NAT_PORT_FIRST && mport <= NAT_PORT_LAST, "source port came from our range");
    ok(rd16(pkt + 22) == 80, "destination port untouched");
    ok(ip_csum(pkt) == rd16(pkt + 10), "ip checksum still correct");
    ok(l4_csum(pkt, len, 16) == rd16(pkt + 36), "tcp checksum still correct");

    // The answer: from the LAN machine, to us, on the port we handed out.
    len = mk_tcp(pkt, LAN, OURS, 80, mport);
    ok(nat_in(&t, pkt, len, OURS, 1100, &peer) == 1, "the answer is recognised");
    ok(peer == PEER, "and points back at the peer that started it");
    ok(memcmp(pkt + 16, &(uint32_t){PEER}, 4) == 0, "destination restored");
    ok(rd16(pkt + 22) == 54340, "destination port restored");
    ok(ip_csum(pkt) == rd16(pkt + 10), "ip checksum correct after the reverse");
    ok(l4_csum(pkt, len, 16) == rd16(pkt + 36), "tcp checksum correct after the reverse");

    printf("the checker agrees with the rewrites\n");
    {
        uint8_t q[64];
        size_t lq = mk_tcp(q, PEER, LAN, 4321, 443);
        ok(nat_csum_ok(q, lq), "a freshly built packet passes");
        nat_out(&t, q, lq, OURS, 1150);
        ok(nat_csum_ok(q, lq), "and still passes after translation out");
        q[36] ^= 0x01;
        ok(!nat_csum_ok(q, lq), "a flipped checksum bit is caught");
    }

    printf("an answer nobody asked for\n");
    len = mk_tcp(pkt, LAN, OURS, 80, 40001);
    {
        uint32_t before = t.misses_in;
        ok(nat_in(&t, pkt, len, OURS, 1200, &peer) == 0, "an unmapped port is not ours");
        ok(t.misses_in == before + 1, "and is counted as a miss");
    }

    printf("the same flow twice keeps one mapping\n");
    {
        int live;
        len = mk_tcp(pkt, PEER, LAN, 54340, 80);
        nat_out(&t, pkt, len, OURS, 1300);
        live = nat_live(&t, 1300);
        len = mk_tcp(pkt, PEER, LAN, 54340, 80);
        nat_out(&t, pkt, len, OURS, 1400);
        ok(nat_live(&t, 1400) == live, "no second entry for a retransmitted syn");
        ok(rd16(pkt + 20) == mport, "and the same source port is reused");
    }

    printf("two peers, same source port\n");
    {
        uint8_t a[64], b[64];
        uint16_t ma, mb;
        size_t la = mk_tcp(a, PEER, LAN, 12345, 80);
        size_t lb = mk_tcp(b, PEER + 0x01000000u, LAN, 12345, 80);
        nat_out(&t, a, la, OURS, 2000);
        nat_out(&t, b, lb, OURS, 2000);
        ma = rd16(a + 20); mb = rd16(b + 20);
        ok(ma != mb, "each gets its own source port");

        la = mk_tcp(a, LAN, OURS, 80, ma);
        lb = mk_tcp(b, LAN, OURS, 80, mb);
        nat_in(&t, a, la, OURS, 2100, &peer);
        ok(peer == PEER, "the first answer goes to the first peer");
        nat_in(&t, b, lb, OURS, 2100, &peer);
        ok(peer == PEER + 0x01000000u, "and the second to the second");
    }

    printf("icmp echo\n");
    {
        uint16_t id;
        len = mk_icmp(pkt, PEER, LAN, 0x1234, 8);
        ok(icmp_csum(pkt, len) == rd16(pkt + 22), "the echo we built is well formed");
        ok(nat_out(&t, pkt, len, OURS, 3000) == 1, "echo request rewritten");
        id = rd16(pkt + 24);
        ok(id != 0x1234, "the identifier became ours");
        ok(ip_csum(pkt) == rd16(pkt + 10), "ip checksum correct");
        ok(icmp_csum(pkt, len) == rd16(pkt + 22), "icmp checksum correct");

        len = mk_icmp(pkt, LAN, OURS, id, 0);
        ok(nat_in(&t, pkt, len, OURS, 3100, &peer) == 1, "echo reply recognised");
        ok(peer == PEER, "and belongs to the right peer");
        ok(rd16(pkt + 24) == 0x1234, "the original identifier is restored");
        ok(icmp_csum(pkt, len) == rd16(pkt + 22), "icmp checksum correct after reverse");
    }

    printf("mappings do not live forever\n");
    {
        len = mk_tcp(pkt, PEER, LAN, 9999, 80);
        nat_out(&t, pkt, len, OURS, 10000);
        ok(nat_live(&t, 10000) > 0, "a fresh mapping is live");
        ok(nat_live(&t, 10000 + NAT_IDLE_MS + 1) == 0, "and all of them age out");
    }

    printf("\n%s\n", fails ? "NAT TESTS FAILED" : "all NAT tests passed");
    return fails ? 1 : 0;
}
