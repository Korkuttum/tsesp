// HPACK decoder against every example in RFC 7541 Appendix C, plus an
// encoder round-trip through our own decoder.
#include <stdio.h>
#include <string.h>
#include "hpack.h"
#include "hpack_vectors.h"

static int fails = 0;

// Roomier than any RFC example so the round-trip test isn't capped by it.
#define MAX_COLLECT 16

typedef struct {
    char names[MAX_COLLECT][64];
    char values[MAX_COLLECT][128];
    int  count;
    int  overflow;
} collector;

static void collect(void *ctx, const char *n, size_t nl, const char *v, size_t vl) {
    collector *c = (collector *)ctx;
    if (c->count >= MAX_COLLECT || nl >= 64 || vl >= 128) {
        c->overflow = 1;
        return;
    }
    memcpy(c->names[c->count], n, nl);  c->names[c->count][nl] = 0;
    memcpy(c->values[c->count], v, vl); c->values[c->count][vl] = 0;
    c->count++;
}

static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex) / 2, i;
    if (n > cap) return 0;
    for (i = 0; i < n; i++) {
        unsigned b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t)b;
    }
    return n;
}

static void run_sequence(const hpack_vector_seq *seq) {
    hpack_decoder dec;
    int s;

    printf("%s (table %u)\n", seq->label, seq->table_size);
    hpack_decoder_init(&dec, seq->table_size);

    for (s = 0; s < seq->step_count; s++) {
        const hpack_vector_step *st = &seq->steps[s];
        uint8_t buf[512];
        collector c;
        size_t n;
        int rc, i, ok = 1;

        memset(&c, 0, sizeof(c));
        n = unhex(st->hex, buf, sizeof(buf));
        if (n == 0) { printf("  FAIL %s: hex too long\n", st->label); fails++; continue; }

        rc = hpack_decode(&dec, buf, n, collect, &c);
        if (rc != 0) {
            printf("  FAIL %s: decode error %d\n", st->label, rc);
            fails++;
            continue;
        }
        if (c.overflow || c.count != st->header_count) {
            printf("  FAIL %s: got %d headers, want %d\n",
                   st->label, c.count, st->header_count);
            fails++;
            continue;
        }
        for (i = 0; i < c.count; i++) {
            if (strcmp(c.names[i], st->headers[i].name) != 0 ||
                strcmp(c.values[i], st->headers[i].value) != 0) {
                printf("  FAIL %s: header %d is \"%s: %s\", want \"%s: %s\"\n",
                       st->label, i, c.names[i], c.values[i],
                       st->headers[i].name, st->headers[i].value);
                ok = 0;
                fails++;
                break;
            }
        }
        if (ok) printf("  ok   %s (%d headers)\n", st->label, c.count);
    }
}

// Our encoder never indexes, so a decoder starting cold must reproduce the
// exact header list we fed in.
static void test_roundtrip(void) {
    static const char *pairs[][2] = {
        { ":method",        "POST" },
        { ":scheme",        "https" },
        { ":authority",     "controlplane.tailscale.com" },
        { ":path",          "/machine/register" },
        { "content-type",   "application/json" },
        { "content-length", "1234" },
        { "user-agent",     "tsesp/0.1 esp32" },
    };
    const int n = (int)(sizeof(pairs) / sizeof(pairs[0]));
    uint8_t buf[512];
    hpack_encoder enc;
    hpack_decoder dec;
    collector c;
    size_t len;
    int i;

    printf("encoder round-trip\n");
    hpack_encoder_init(&enc, buf, sizeof(buf));
    for (i = 0; i < n; i++) hpack_encode_header(&enc, pairs[i][0], pairs[i][1]);
    if (hpack_encoder_finish(&enc, &len) != 0) {
        printf("  FAIL encoder overflowed\n"); fails++; return;
    }

    memset(&c, 0, sizeof(c));
    hpack_decoder_init(&dec, 4096);
    if (hpack_decode(&dec, buf, len, collect, &c) != 0) {
        printf("  FAIL could not decode our own block\n"); fails++; return;
    }
    if (c.count != n) {
        printf("  FAIL round-trip header count %d != %d\n", c.count, n); fails++; return;
    }
    for (i = 0; i < n; i++) {
        if (strcmp(c.names[i], pairs[i][0]) != 0 ||
            strcmp(c.values[i], pairs[i][1]) != 0) {
            printf("  FAIL round-trip header %d\n", i); fails++; return;
        }
    }
    if (dec.count != 0) {
        printf("  FAIL our block grew the peer's dynamic table (%d entries)\n", dec.count);
        fails++;
        return;
    }
    printf("  ok   %d headers in %zu bytes, peer table untouched\n", n, len);
}

static void test_malformed(void) {
    hpack_decoder dec;
    collector c;
    struct { const char *label, *hex; } bad[] = {
        { "index 0",          "80" },
        { "index past table", "ff00" },
        { "truncated string", "40" },
        { "huffman EOS",      "418cffffffffffffffffffffff" },
    };
    size_t i;

    printf("malformed input\n");
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        uint8_t buf[64];
        size_t n = unhex(bad[i].hex, buf, sizeof(buf));
        memset(&c, 0, sizeof(c));
        hpack_decoder_init(&dec, 4096);
        if (hpack_decode(&dec, buf, n, collect, &c) == 0) {
            printf("  FAIL %s was accepted\n", bad[i].label);
            fails++;
        } else {
            printf("  ok   %s rejected\n", bad[i].label);
        }
    }
}

int main(void) {
    int i;
    for (i = 0; i < hpack_vectors_count; i++) run_sequence(&hpack_vectors[i]);
    test_roundtrip();
    test_malformed();
    printf("\n%s\n", fails ? "HPACK TESTS FAILED" : "all HPACK tests passed");
    return fails ? 1 : 0;
}
