#include <string.h>
#include "wireguard.h"
#include "tscrypto.h"

static const char kConstruction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char kIdentifier[]   = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char kLabelMac1[]    = "mac1----";

// TAI64 puts the epoch at 2^62, and adds 10 leap seconds for the Unix epoch.
#define TAI64_BASE 4611686018427387914ULL

static const uint8_t kZeroNonce[12] = {0};

static void put32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void put64le(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get64le(const uint8_t *p) {
    uint64_t v = 0;
    int i;
    for (i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

// ------------------------------------------------------- noise helpers

static void mix_hash(uint8_t h[32], const uint8_t *data, size_t len) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, 32);
    blake2s_update(&ctx, h, 32);
    blake2s_update(&ctx, data, len);
    blake2s_final(&ctx, h);
}

// KDF1: chaining key only.
static void mix_key(uint8_t ck[32], const uint8_t *input, size_t len) {
    uint8_t out[32];
    hkdf_blake2s(out, 32, input, len, ck, 32);
    memcpy(ck, out, 32);
}

// KDF2: advances the chaining key and produces one cipher key.
static void kdf2(uint8_t ck[32], uint8_t key[32], const uint8_t *input, size_t len) {
    uint8_t out[64];
    hkdf_blake2s(out, 64, input, len, ck, 32);
    memcpy(ck, out, 32);
    memcpy(key, out + 32, 32);
    memset(out, 0, sizeof(out));
}

// KDF3: as above plus the tau value the response mixes into the hash.
static void kdf3(uint8_t ck[32], uint8_t tau[32], uint8_t key[32],
                 const uint8_t *input, size_t len) {
    uint8_t out[96];
    hkdf_blake2s(out, 96, input, len, ck, 32);
    memcpy(ck, out, 32);
    memcpy(tau, out + 32, 32);
    memcpy(key, out + 64, 32);
    memset(out, 0, sizeof(out));
}

// mac1 proves the sender knows the recipient's public key, which lets a
// server discard floods cheaply. mac2 is only demanded under load; an empty
// one is correct until a cookie reply says otherwise.
static void compute_mac1(const uint8_t mac1_key[32],
                         const uint8_t *msg, size_t len, uint8_t out[16]) {
    blake2s_keyed(out, 16, mac1_key, 32, msg, len);
}

static void mac1_key_for(const uint8_t static_pub[32], uint8_t out[32]) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, 32);
    blake2s_update(&ctx, kLabelMac1, sizeof(kLabelMac1) - 1);
    blake2s_update(&ctx, static_pub, 32);
    blake2s_final(&ctx, out);
}

static void initial_state(uint8_t ck[32], uint8_t h[32]) {
    blake2s(ck, 32, kConstruction, sizeof(kConstruction) - 1);
    memcpy(h, ck, 32);
    mix_hash(h, (const uint8_t *)kIdentifier, sizeof(kIdentifier) - 1);
}

// ------------------------------------------------------------- device

void wg_device_init(wg_device *d, const uint8_t static_priv[32]) {
    uint8_t (*saved_ctx)[0];
    (void)saved_ctx;
    memset(d->peers, 0, sizeof(d->peers));
    memcpy(d->static_priv, static_priv, 32);
    x25519_base(d->static_pub, d->static_priv);
    mac1_key_for(d->static_pub, d->mac1_key);
}

int wg_find_peer(const wg_device *d, const uint8_t remote_static[32]) {
    int i;
    for (i = 0; i < WG_MAX_PEERS; i++)
        if (d->peers[i].in_use && memcmp(d->peers[i].remote_static, remote_static, 32) == 0)
            return i;
    return -1;
}

int wg_add_peer(wg_device *d, const uint8_t remote_static[32]) {
    int idx = wg_find_peer(d, remote_static), i;
    wg_peer *p;

    if (idx >= 0) return idx;
    for (i = 0; i < WG_MAX_PEERS; i++) if (!d->peers[i].in_use) { idx = i; break; }
    if (idx < 0) return -1;

    p = &d->peers[idx];
    memset(p, 0, sizeof(*p));
    memcpy(p->remote_static, remote_static, 32);
    // Precomputed because every handshake needs it and X25519 is the most
    // expensive thing this chip does.
    if (x25519(p->precomputed_ss, d->static_priv, remote_static) != 0) return -1;
    p->in_use = 1;
    return idx;
}

void wg_remove_peer(wg_device *d, int idx) {
    if (idx >= 0 && idx < WG_MAX_PEERS) memset(&d->peers[idx], 0, sizeof(d->peers[idx]));
}

static uint32_t now(wg_device *d) { return d->now_ms ? d->now_ms(d->ctx) : 0; }

int wg_is_established(wg_device *d, int idx) {
    wg_peer *p;
    if (idx < 0 || idx >= WG_MAX_PEERS) return 0;
    p = &d->peers[idx];
    if (!p->in_use || p->state != WG_HS_ESTABLISHED) return 0;
    return (uint32_t)(now(d) - p->established_ms) < WG_REJECT_AFTER_MS;
}

int wg_needs_handshake(wg_device *d, int idx) {
    wg_peer *p;
    uint32_t t;
    if (idx < 0 || idx >= WG_MAX_PEERS) return 0;
    p = &d->peers[idx];
    if (!p->in_use) return 0;
    t = now(d);

    if (p->state == WG_HS_INITIATION_SENT)
        return (uint32_t)(t - p->handshake_started_ms) > WG_REKEY_TIMEOUT_MS;
    if (p->state != WG_HS_ESTABLISHED) return 1;
    // Only the side that started the last handshake rekeys, so both do not
    // fire at once.
    if (!p->initiator) return (uint32_t)(t - p->established_ms) > WG_REJECT_AFTER_MS;
    return (uint32_t)(t - p->established_ms) > WG_REKEY_AFTER_MS;
}

// ---------------------------------------------------------- initiator

int wg_create_initiation(wg_device *d, int idx, uint8_t *out) {
    wg_peer *p;
    uint8_t eph_pub[32], dh[32], key[32], ts[12];
    uint64_t secs;

    if (idx < 0 || idx >= WG_MAX_PEERS) return -1;
    p = &d->peers[idx];
    if (!p->in_use) return -1;

    initial_state(p->ck, p->h);
    mix_hash(p->h, p->remote_static, 32);

    d->random(d->ctx, p->eph_priv, 32);
    x25519_clamp(p->eph_priv);
    x25519_base(eph_pub, p->eph_priv);

    d->random(d->ctx, (uint8_t *)&p->local_index, 4);

    out[0] = WG_MSG_INITIATION;
    out[1] = out[2] = out[3] = 0;
    put32le(out + 4, p->local_index);
    memcpy(out + 8, eph_pub, 32);

    mix_key(p->ck, eph_pub, 32);
    mix_hash(p->h, eph_pub, 32);

    // es
    if (x25519(dh, p->eph_priv, p->remote_static) != 0) return -1;
    kdf2(p->ck, key, dh, 32);
    chacha20poly1305_seal(out + 40, key, kZeroNonce, d->static_pub, 32, p->h, 32);
    mix_hash(p->h, out + 40, 48);

    // ss, then the timestamp that stops replays
    kdf2(p->ck, key, p->precomputed_ss, 32);
    secs = (d->unix_time ? d->unix_time(d->ctx) : 0) + TAI64_BASE;
    {
        int i;
        for (i = 0; i < 8; i++) ts[i] = (uint8_t)(secs >> (56 - 8 * i));
        memset(ts + 8, 0, 4);       // nanoseconds; whole seconds are enough
    }
    chacha20poly1305_seal(out + 88, key, kZeroNonce, ts, 12, p->h, 32);
    mix_hash(p->h, out + 88, 28);

    // mac1 over everything so far; mac2 stays zero until a cookie says no.
    {
        uint8_t peer_mac1_key[32];
        mac1_key_for(p->remote_static, peer_mac1_key);
        compute_mac1(peer_mac1_key, out, 116, out + 116);
    }
    memset(out + 132, 0, 16);

    p->state = WG_HS_INITIATION_SENT;
    p->handshake_started_ms = now(d);
    memset(dh, 0, sizeof(dh));
    memset(key, 0, sizeof(key));
    return 0;
}

// Turns the finished handshake into session keys.
static void begin_session(wg_device *d, wg_peer *p, int initiator) {
    uint8_t out[64];
    hkdf_blake2s(out, 64, NULL, 0, p->ck, 32);
    if (initiator) {
        memcpy(p->send_key, out, 32);
        memcpy(p->recv_key, out + 32, 32);
    } else {
        memcpy(p->recv_key, out, 32);
        memcpy(p->send_key, out + 32, 32);
    }
    p->send_counter = 0;
    p->recv_highest = 0;
    p->recv_window = 0;
    p->initiator = initiator;
    p->state = WG_HS_ESTABLISHED;
    p->established_ms = now(d);
    memset(out, 0, sizeof(out));
    memset(p->ck, 0, 32);
    memset(p->eph_priv, 0, 32);
}

static int consume_response(wg_device *d, const uint8_t *msg, size_t len) {
    int i;
    uint8_t ck[32], h[32], tau[32], key[32], dh[32], nothing[1];
    uint32_t receiver;

    if (len != WG_RESPONSE_SIZE) return -1;
    receiver = get32le(msg + 8);

    for (i = 0; i < WG_MAX_PEERS; i++) {
        wg_peer *p = &d->peers[i];
        if (!p->in_use || p->state != WG_HS_INITIATION_SENT) continue;
        if (p->local_index != receiver) continue;

        memcpy(ck, p->ck, 32);
        memcpy(h, p->h, 32);

        mix_hash(h, msg + 12, 32);          // their ephemeral
        mix_key(ck, msg + 12, 32);

        // ee
        if (x25519(dh, p->eph_priv, msg + 12) != 0) return -1;
        mix_key(ck, dh, 32);
        // se
        if (x25519(dh, d->static_priv, msg + 12) != 0) return -1;
        mix_key(ck, dh, 32);

        // psk is all zeros for Tailscale
        {
            uint8_t psk[32];
            memset(psk, 0, sizeof(psk));
            kdf3(ck, tau, key, psk, 32);
        }
        mix_hash(h, tau, 32);

        if (chacha20poly1305_open(nothing, key, kZeroNonce, msg + 44, 16, h, 32) != 0)
            return -2;

        p->remote_index = get32le(msg + 4);
        memcpy(p->ck, ck, 32);
        begin_session(d, p, 1);
        memset(ck, 0, 32); memset(key, 0, 32); memset(dh, 0, 32);
        return i;
    }
    return -1;
}

// ---------------------------------------------------------- responder

static int consume_initiation(wg_device *d, const uint8_t *msg, size_t len,
                              uint8_t *reply, size_t reply_cap, size_t *reply_len) {
    uint8_t ck[32], h[32], key[32], dh[32], remote_static[32], ts[12];
    uint8_t eph_pub[32], eph_priv[32], tau[32];
    int idx;
    wg_peer *p;

    if (len != WG_INITIATION_SIZE || reply_cap < WG_RESPONSE_SIZE) return -1;

    // mac1 first: it is cheap and rejects anything not meant for us.
    {
        uint8_t mac[16];
        compute_mac1(d->mac1_key, msg, 116, mac);
        if (ts_memcmp_ct(mac, msg + 116, 16) != 0) return -1;
    }

    initial_state(ck, h);
    mix_hash(h, d->static_pub, 32);
    mix_key(ck, msg + 8, 32);
    mix_hash(h, msg + 8, 32);

    // es
    if (x25519(dh, d->static_priv, msg + 8) != 0) return -1;
    kdf2(ck, key, dh, 32);
    if (chacha20poly1305_open(remote_static, key, kZeroNonce, msg + 40, 48, h, 32) != 0)
        return -2;
    mix_hash(h, msg + 40, 48);

    idx = wg_find_peer(d, remote_static);
    if (idx < 0) return -3;            // a stranger; the netmap has not named them
    p = &d->peers[idx];

    // ss
    kdf2(ck, key, p->precomputed_ss, 32);
    if (chacha20poly1305_open(ts, key, kZeroNonce, msg + 88, 28, h, 32) != 0) return -2;
    mix_hash(h, msg + 88, 28);

    // Now the response.
    d->random(d->ctx, eph_priv, 32);
    x25519_clamp(eph_priv);
    x25519_base(eph_pub, eph_priv);
    d->random(d->ctx, (uint8_t *)&p->local_index, 4);
    p->remote_index = get32le(msg + 4);

    reply[0] = WG_MSG_RESPONSE;
    reply[1] = reply[2] = reply[3] = 0;
    put32le(reply + 4, p->local_index);
    put32le(reply + 8, p->remote_index);
    memcpy(reply + 12, eph_pub, 32);

    mix_hash(h, eph_pub, 32);
    mix_key(ck, eph_pub, 32);

    // ee, then se from their static
    if (x25519(dh, eph_priv, msg + 8) != 0) return -1;
    mix_key(ck, dh, 32);
    if (x25519(dh, eph_priv, remote_static) != 0) return -1;
    mix_key(ck, dh, 32);

    {
        uint8_t psk[32];
        memset(psk, 0, sizeof(psk));
        kdf3(ck, tau, key, psk, 32);
    }
    mix_hash(h, tau, 32);
    chacha20poly1305_seal(reply + 44, key, kZeroNonce, NULL, 0, h, 32);
    mix_hash(h, reply + 44, 16);

    {
        uint8_t peer_mac1_key[32];
        mac1_key_for(p->remote_static, peer_mac1_key);
        compute_mac1(peer_mac1_key, reply, 60, reply + 60);
    }
    memset(reply + 76, 0, 16);
    *reply_len = WG_RESPONSE_SIZE;

    memcpy(p->ck, ck, 32);
    begin_session(d, p, 0);
    memset(ck, 0, 32); memset(key, 0, 32); memset(dh, 0, 32);
    memset(eph_priv, 0, 32);
    return idx;
}

// --------------------------------------------------------- transport

static void counter_nonce(uint8_t nonce[12], uint64_t counter) {
    memset(nonce, 0, 4);
    put64le(nonce + 4, counter);
}

// A 64-packet sliding window: enough for the reordering a WiFi link causes,
// and it is what stops a replayed packet from being accepted twice.
static int window_check_and_set(wg_peer *p, uint64_t counter) {
    if (counter > p->recv_highest) {
        uint64_t shift = counter - p->recv_highest;
        p->recv_window = shift >= 64 ? 0 : (p->recv_window << shift);
        p->recv_window |= 1;
        p->recv_highest = counter;
        return 0;
    }
    {
        uint64_t back = p->recv_highest - counter;
        if (back >= 64) return -1;                 // too old
        if (p->recv_window & (1ULL << back)) return -1;   // already seen
        p->recv_window |= (1ULL << back);
        return 0;
    }
}

int wg_encrypt(wg_device *d, int idx, const uint8_t *plain, size_t len,
               uint8_t *out, size_t out_cap, size_t *out_len) {
    wg_peer *p;
    uint8_t nonce[12];

    if (!wg_is_established(d, idx)) return -1;
    p = &d->peers[idx];
    if (len > WG_MAX_PACKET) return -1;
    if (out_cap < WG_TRANSPORT_HEADER + len + WG_TAG_LEN) return -1;

    out[0] = WG_MSG_TRANSPORT;
    out[1] = out[2] = out[3] = 0;
    put32le(out + 4, p->remote_index);
    put64le(out + 8, p->send_counter);

    counter_nonce(nonce, p->send_counter);
    chacha20poly1305_seal(out + WG_TRANSPORT_HEADER, p->send_key, nonce,
                          plain, len, NULL, 0);
    p->send_counter++;
    p->tx_packets++;
    p->last_send_ms = now(d);
    *out_len = WG_TRANSPORT_HEADER + len + WG_TAG_LEN;
    return 0;
}

int wg_keepalive(wg_device *d, int idx, uint8_t *out, size_t out_cap, size_t *out_len) {
    return wg_encrypt(d, idx, NULL, 0, out, out_cap, out_len);
}

static int consume_transport(wg_device *d, const uint8_t *msg, size_t len,
                             uint8_t *plain, size_t plain_cap, size_t *plain_len) {
    uint32_t receiver;
    uint64_t counter;
    uint8_t nonce[12];
    int i;

    if (len < WG_TRANSPORT_HEADER + WG_TAG_LEN) return -1;
    receiver = get32le(msg + 4);
    counter = get64le(msg + 8);

    for (i = 0; i < WG_MAX_PEERS; i++) {
        wg_peer *p = &d->peers[i];
        size_t ctlen = len - WG_TRANSPORT_HEADER;
        if (!p->in_use || p->state != WG_HS_ESTABLISHED) continue;
        if (p->local_index != receiver) continue;
        if ((uint32_t)(now(d) - p->established_ms) > WG_REJECT_AFTER_MS) return -1;
        if (ctlen - WG_TAG_LEN > plain_cap) return -1;

        counter_nonce(nonce, counter);
        if (chacha20poly1305_open(plain, p->recv_key, nonce,
                                  msg + WG_TRANSPORT_HEADER, ctlen, NULL, 0) != 0)
            return -2;
        // Only after the tag verifies: an attacker must not be able to poke
        // holes in the replay window with forged packets.
        if (window_check_and_set(p, counter) != 0) return -4;

        *plain_len = ctlen - WG_TAG_LEN;
        p->rx_packets++;
        p->last_recv_ms = now(d);
        return i;
    }
    return -1;
}

int wg_handle(wg_device *d, const uint8_t *msg, size_t len,
              uint8_t *plain, size_t plain_cap, size_t *plain_len,
              uint8_t *reply, size_t reply_cap, size_t *reply_len) {
    if (len < 4) return -1;
    if (plain_len) *plain_len = 0;
    if (reply_len) *reply_len = 0;

    switch (msg[0]) {
    case WG_MSG_INITIATION:
        return consume_initiation(d, msg, len, reply, reply_cap, reply_len);
    case WG_MSG_RESPONSE:
        return consume_response(d, msg, len);
    case WG_MSG_TRANSPORT:
        return consume_transport(d, msg, len, plain, plain_cap, plain_len);
    case WG_MSG_COOKIE:
        // Only sent when a peer is under load. Ignoring it costs a retry.
        return -1;
    default:
        return -1;
    }
}
