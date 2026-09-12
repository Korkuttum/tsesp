// Two devices handshaking with each other, then carrying traffic.
//
// This catches gross errors cheaply. It cannot prove the wire format matches
// WireGuard's, because both sides here are the same code - only a real peer
// can say that, and the device does exactly that against a Tailscale node.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wireguard.h"
#include "tscrypto.h"

static int fails = 0;
static uint32_t clock_ms = 1000;

static void ok(int cond, const char *what) {
    printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond) fails++;
}

static uint32_t now_cb(void *ctx) { (void)ctx; return clock_ms; }
static uint64_t time_cb(void *ctx) { (void)ctx; return 1788000000ULL + clock_ms / 1000; }

// Deterministic, so a failure is reproducible.
static uint32_t rng_state = 0x1234567;
static void rng_cb(void *ctx, uint8_t *out, size_t n) {
    size_t i;
    (void)ctx;
    for (i = 0; i < n; i++) {
        rng_state = rng_state * 1103515245u + 12345u;
        out[i] = (uint8_t)(rng_state >> 16);
    }
}

static void wire(wg_device *d) {
    d->now_ms = now_cb;
    d->random = rng_cb;
    d->unix_time = time_cb;
    d->ctx = NULL;
}

int main(void) {
    static wg_device A, B;
    uint8_t a_priv[32], b_priv[32];
    uint8_t init[WG_INITIATION_SIZE], resp[WG_RESPONSE_SIZE];
    uint8_t plain[2048], out[2048], reply[256];
    size_t plain_len = 0, out_len = 0, reply_len = 0;
    int ia, ib, rc;

    rng_cb(NULL, a_priv, 32); x25519_clamp(a_priv);
    rng_cb(NULL, b_priv, 32); x25519_clamp(b_priv);

    wg_device_init(&A, a_priv); wire(&A);
    wg_device_init(&B, b_priv); wire(&B);

    printf("handshake\n");
    ia = wg_add_peer(&A, B.static_pub);
    ib = wg_add_peer(&B, A.static_pub);
    ok(ia >= 0 && ib >= 0, "peers added");
    ok(wg_needs_handshake(&A, ia), "a fresh peer needs a handshake");

    ok(wg_create_initiation(&A, ia, init) == 0, "initiation built");
    ok(init[0] == WG_MSG_INITIATION, "type byte is 1");

    rc = wg_handle(&B, init, sizeof(init), plain, sizeof(plain), &plain_len,
                   resp, sizeof(resp), &reply_len);
    ok(rc == ib && reply_len == WG_RESPONSE_SIZE, "responder accepted and replied");
    ok(!wg_is_established(&A, ia), "initiator not established yet");
    ok(wg_is_established(&B, ib), "responder established");

    rc = wg_handle(&A, resp, reply_len, plain, sizeof(plain), &plain_len,
                   reply, sizeof(reply), &reply_len);
    ok(rc == ia, "initiator accepted the response");
    ok(wg_is_established(&A, ia), "both sides now established");
    ok(!wg_needs_handshake(&A, ia), "no rehandshake wanted straight away");

    printf("traffic\n");
    {
        static const uint8_t packet[] =
            "\x45\x00\x00\x54the rest of an IP packet would go here";
        ok(wg_encrypt(&A, ia, packet, sizeof(packet), out, sizeof(out), &out_len) == 0,
           "encrypted");
        ok(out[0] == WG_MSG_TRANSPORT, "type byte is 4");
        ok(out_len == WG_TRANSPORT_HEADER + sizeof(packet) + WG_TAG_LEN, "size adds up");

        rc = wg_handle(&B, out, out_len, plain, sizeof(plain), &plain_len,
                       reply, sizeof(reply), &reply_len);
        ok(rc == ib && plain_len == sizeof(packet) &&
           memcmp(plain, packet, sizeof(packet)) == 0, "decrypted intact");

        // And back the other way, which uses the opposite key.
        ok(wg_encrypt(&B, ib, packet, sizeof(packet), out, sizeof(out), &out_len) == 0,
           "reply encrypted");
        rc = wg_handle(&A, out, out_len, plain, sizeof(plain), &plain_len,
                       reply, sizeof(reply), &reply_len);
        ok(rc == ia && plain_len == sizeof(packet), "decrypted the other direction");
    }

    printf("keepalive\n");
    {
        ok(wg_keepalive(&A, ia, out, sizeof(out), &out_len) == 0, "keepalive built");
        rc = wg_handle(&B, out, out_len, plain, sizeof(plain), &plain_len,
                       reply, sizeof(reply), &reply_len);
        ok(rc == ib && plain_len == 0, "an empty transport message decodes to nothing");
    }

    printf("replay and tampering\n");
    {
        uint8_t saved[2048];
        size_t saved_len;
        wg_encrypt(&A, ia, (const uint8_t *)"x", 1, out, sizeof(out), &out_len);
        memcpy(saved, out, out_len);
        saved_len = out_len;

        rc = wg_handle(&B, saved, saved_len, plain, sizeof(plain), &plain_len,
                       reply, sizeof(reply), &reply_len);
        ok(rc == ib, "first copy accepted");
        rc = wg_handle(&B, saved, saved_len, plain, sizeof(plain), &plain_len,
                       reply, sizeof(reply), &reply_len);
        ok(rc == -4, "the same packet a second time is refused");

        saved[saved_len - 1] ^= 1;
        rc = wg_handle(&B, saved, saved_len, plain, sizeof(plain), &plain_len,
                       reply, sizeof(reply), &reply_len);
        ok(rc == -2, "a tampered packet is refused");
    }

    printf("out-of-order delivery\n");
    {
        uint8_t p1[2048], p2[2048], p3[2048];
        size_t l1, l2, l3;
        wg_encrypt(&A, ia, (const uint8_t *)"one", 3, p1, sizeof(p1), &l1);
        wg_encrypt(&A, ia, (const uint8_t *)"two", 3, p2, sizeof(p2), &l2);
        wg_encrypt(&A, ia, (const uint8_t *)"three", 5, p3, sizeof(p3), &l3);

        // Arrive 3, 1, 2: a wifi link reorders, and dropping those would
        // look like packet loss to everything above.
        ok(wg_handle(&B, p3, l3, plain, sizeof(plain), &plain_len,
                     reply, sizeof(reply), &reply_len) == ib, "newest accepted");
        ok(wg_handle(&B, p1, l1, plain, sizeof(plain), &plain_len,
                     reply, sizeof(reply), &reply_len) == ib, "older still accepted");
        ok(wg_handle(&B, p2, l2, plain, sizeof(plain), &plain_len,
                     reply, sizeof(reply), &reply_len) == ib, "and the one between");
    }

    printf("rekeying\n");
    {
        clock_ms += WG_REKEY_AFTER_MS + 1000;
        ok(wg_needs_handshake(&A, ia), "initiator wants a rekey after two minutes");
        ok(!wg_needs_handshake(&B, ib), "responder does not, so they do not collide");
        clock_ms += WG_REJECT_AFTER_MS;
        ok(!wg_is_established(&A, ia), "an old session stops being usable");
    }

    printf("a rekey does not interrupt the session it replaces\n");
    {
        // Fresh pair: the clock above has already aged A and B out.
        static wg_device P, Q;
        uint8_t p_priv[32], q_priv[32];
        uint8_t pi[WG_INITIATION_SIZE], pr[WG_RESPONSE_SIZE], data[256];
        size_t rl = 0, dl = 0;
        int ip, iq;

        rng_cb(NULL, p_priv, 32); x25519_clamp(p_priv);
        rng_cb(NULL, q_priv, 32); x25519_clamp(q_priv);
        wg_device_init(&P, p_priv); wire(&P);
        wg_device_init(&Q, q_priv); wire(&Q);
        ip = wg_add_peer(&P, Q.static_pub);
        iq = wg_add_peer(&Q, P.static_pub);

        wg_create_initiation(&P, ip, pi);
        wg_handle(&Q, pi, sizeof(pi), plain, sizeof(plain), &plain_len,
                  pr, sizeof(pr), &rl);
        wg_handle(&P, pr, rl, plain, sizeof(plain), &plain_len, NULL, 0, NULL);
        ok(wg_is_established(&P, ip) && wg_is_established(&Q, iq), "session up");

        // Two minutes on, P starts a rekey. Q knows nothing about it and its
        // packet is already on the wire, encrypted with the keys P is about
        // to replace.
        clock_ms += WG_REKEY_AFTER_MS + 1000;
        wg_encrypt(&Q, iq, (const uint8_t *)"in flight", 9, data, sizeof(data), &dl);
        wg_create_initiation(&P, ip, pi);

        ok(wg_handle(&P, data, dl, plain, sizeof(plain), &plain_len,
                     pr, sizeof(pr), &rl) == ip,
           "a packet under the replaced keys still decrypts");
        ok(wg_encrypt(&P, ip, (const uint8_t *)"x", 1, data, sizeof(data), &dl) == 0,
           "and those keys still carry traffic outbound");
        ok(wg_is_established(&P, ip), "so the tunnel is not reported down");

        // Not immortal: the replaced keypair ages out on its own schedule.
        clock_ms += WG_REJECT_AFTER_MS;
        ok(!wg_is_established(&P, ip), "the replaced keypair does age out");
    }

    printf("handshake retries back off\n");
    {
        static wg_device R;
        uint8_t r_priv[32], far_priv[32], far_pub[32];
        uint8_t ri[WG_INITIATION_SIZE];
        uint32_t t0;
        int ir, i;

        rng_cb(NULL, r_priv, 32); x25519_clamp(r_priv);
        rng_cb(NULL, far_priv, 32); x25519_clamp(far_priv);
        x25519_base(far_pub, far_priv);
        wg_device_init(&R, r_priv); wire(&R);
        ir = wg_add_peer(&R, far_pub);        // switched off; never answers

        wg_create_initiation(&R, ir, ri);
        t0 = clock_ms;
        clock_ms = t0 + WG_REKEY_TIMEOUT_MS + 1;
        ok(wg_needs_handshake(&R, ir), "the first retry comes after five seconds");

        wg_create_initiation(&R, ir, ri);
        t0 = clock_ms;
        clock_ms = t0 + WG_REKEY_TIMEOUT_MS + 1;
        ok(!wg_needs_handshake(&R, ir), "the second does not come that fast");
        clock_ms = t0 + 2 * WG_REKEY_TIMEOUT_MS + 1;
        ok(wg_needs_handshake(&R, ir), "it comes at twice the wait");

        for (i = 0; i < 8; i++) {
            wg_create_initiation(&R, ir, ri);
            clock_ms += WG_HANDSHAKE_MAX_MS + 1;
        }
        wg_create_initiation(&R, ir, ri);
        t0 = clock_ms;
        clock_ms = t0 + WG_HANDSHAKE_MAX_MS - 1000;
        ok(!wg_needs_handshake(&R, ir), "a peer off for a long time waits a minute");
        clock_ms = t0 + WG_HANDSHAKE_MAX_MS + 1000;
        ok(wg_needs_handshake(&R, ir), "and never longer than that");
    }

    printf("strangers\n");
    {
        static wg_device C;
        uint8_t c_priv[32], c_init[WG_INITIATION_SIZE];
        rng_cb(NULL, c_priv, 32); x25519_clamp(c_priv);
        wg_device_init(&C, c_priv); wire(&C);
        wg_add_peer(&C, B.static_pub);
        wg_create_initiation(&C, 0, c_init);
        rc = wg_handle(&B, c_init, sizeof(c_init), plain, sizeof(plain), &plain_len,
                       reply, sizeof(reply), &reply_len);
        ok(rc == -3, "a handshake from a node we were never told about is refused");
    }

    printf("\n%s\n", fails ? "WIREGUARD TESTS FAILED" : "all WireGuard tests passed");
    return fails ? 1 : 0;
}
