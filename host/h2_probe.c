// Diagnostic: complete the Noise handshake, then dump the raw plaintext the
// server sends inside the tunnel, before and after we send the h2 preface.
#include <stdio.h>
#include <string.h>
#include "posix_io.h"
#include "ts_control.h"
#include "tscrypto.h"

#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

static void dump(const char *label, const uint8_t *b, size_t n) {
    size_t i;
    printf("%s (%zu bytes)\n", label, n);
    for (i = 0; i < n; i++) {
        if (i % 16 == 0) printf("  %04zx  ", i);
        printf("%02x ", b[i]);
        if (i % 16 == 15 || i + 1 == n) {
            size_t j, start = i - (i % 16);
            for (j = i % 16; j < 15; j++) printf("   ");
            printf(" |");
            for (j = start; j <= i; j++)
                putchar(b[j] >= 32 && b[j] < 127 ? b[j] : '.');
            printf("|\n");
        }
    }
}

static void decode_frames(const uint8_t *b, size_t n) {
    static const char *names[] = { "DATA", "HEADERS", "PRIORITY", "RST_STREAM",
                                   "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY",
                                   "WINDOW_UPDATE", "CONTINUATION" };
    size_t i = 0;
    printf("frames:\n");
    while (i + 9 <= n) {
        uint32_t len = ((uint32_t)b[i] << 16) | ((uint32_t)b[i+1] << 8) | b[i+2];
        uint8_t type = b[i+3], flags = b[i+4];
        uint32_t sid = ((uint32_t)b[i+5] << 24) | ((uint32_t)b[i+6] << 16) |
                       ((uint32_t)b[i+7] << 8) | b[i+8];
        printf("  %-14s len=%u flags=0x%02x stream=%u\n",
               type < 10 ? names[type] : "UNKNOWN", len, flags, sid & 0x7fffffff);
        if (type == 7 && len >= 8) {   // GOAWAY carries a readable reason
            printf("      last_stream=%u code=%u debug=%.*s\n",
                   ((uint32_t)b[i+9] << 24) | ((uint32_t)b[i+10] << 16) |
                   ((uint32_t)b[i+11] << 8) | b[i+12],
                   ((uint32_t)b[i+13] << 24) | ((uint32_t)b[i+14] << 16) |
                   ((uint32_t)b[i+15] << 8) | b[i+16],
                   (int)(len - 8), (const char *)b + i + 17);
        }
        i += 9 + len;
    }
    if (i != n) printf("  (%zu trailing bytes)\n", n - i);
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "controlplane.tailscale.com";
    const char *port = argc > 2 ? argv[2] : "80";
    uint8_t machine_priv[32], eph_priv[32], control_pub[32], init[TS2021_INIT_LEN],
            resp[TS2021_RESP_LEN], buf[2048];
    char b64[256], req[1024], head[512];
    posix_io pio;
    ts2021_handshake hs;
    ts2021_conn conn;
    ts_noise_stream ns;
    ts_io stream;
    int n, got;
    size_t hl = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    posix_random(machine_priv, 32);
    posix_random(eph_priv, 32);
    x25519_clamp(machine_priv);
    ts2021_parse_hex32(control_pub, TS2021_TAILSCALE_CONTROL_KEY);

    if (posix_io_connect(&pio, host, port) != 0) { printf("connect failed\n"); return 1; }
    ts2021_handshake_start(&hs, machine_priv, control_pub,
                           TS2021_PROTOCOL_VERSION, eph_priv, init);
    ts2021_base64(b64, sizeof(b64), init, sizeof(init));
    n = snprintf(req, sizeof(req),
                 "POST /ts2021 HTTP/1.1\r\nHost: %s\r\n"
                 "Upgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n"
                 "X-Tailscale-Handshake: %s\r\nContent-Length: 0\r\n\r\n", host, b64);
    pio.io.write(pio.io.ctx, (const uint8_t *)req, (size_t)n);

    // Read the response head one byte at a time.
    {
        int state = 0;
        while (hl + 1 < sizeof(head)) {
            uint8_t c;
            if (ts_io_read_full(&pio.io, &c, 1) != 0) { printf("head eof\n"); return 1; }
            head[hl++] = (char)c;
            if ((state == 0 || state == 2) && c == '\r') state++;
            else if ((state == 1 || state == 3) && c == '\n') state++;
            else state = (c == '\r') ? 1 : 0;
            if (state == 4) break;
        }
        head[hl] = 0;
    }
    printf("HTTP head:\n%s", head);

    if (ts_io_read_full(&pio.io, resp, sizeof(resp)) != 0) { printf("noise eof\n"); return 1; }
    if (ts2021_handshake_finish(&hs, resp, &conn) != 0) { printf("handshake failed\n"); return 1; }
    printf("noise handshake OK\n\n");

    ts_noise_stream_init(&ns, &pio.io, &conn, &stream);

    printf(">> sending h2 preface + empty SETTINGS\n");
    stream.write(stream.ctx, (const uint8_t *)H2_PREFACE, sizeof(H2_PREFACE) - 1);
    {
        uint8_t settings[9] = { 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
        stream.write(stream.ctx, settings, sizeof(settings));
    }

    got = stream.read(stream.ctx, buf, sizeof(buf));
    if (got <= 0) { printf("<< read returned %d\n", got); return 1; }
    printf("\n");
    dump("<< server plaintext", buf, (size_t)got);
    decode_frames(buf, (size_t)got);
    posix_io_close(&pio);
    return 0;
}
