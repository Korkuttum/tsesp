// The property that matters: parsing must not depend on how the bytes were
// chopped up by the network. Every document here is parsed whole, then again
// split at every possible offset, and the callback traces must be identical.
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "json_stream.h"

static int fails = 0;

#define TRACE_CAP 16384
typedef struct { char buf[TRACE_CAP]; size_t len; } trace;

static void trace_add(trace *t, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void trace_add(trace *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (t->len < TRACE_CAP - 1)
        t->len += (size_t)vsnprintf(t->buf + t->len, TRACE_CAP - t->len, fmt, ap);
    va_end(ap);
}

static void on_value(void *ctx, const char *path, const char *v, size_t len,
                     json_type type, int trunc) {
    static const char *names[] = { "str", "num", "true", "false", "null" };
    trace_add((trace *)ctx, "V %s = [%.*s] %s%s\n", path, (int)len, v,
              names[type], trunc ? " TRUNC" : "");
}
static void on_enter(void *ctx, const char *path, int arr) {
    trace_add((trace *)ctx, "{ %s %s\n", path, arr ? "array" : "object");
}
static void on_leave(void *ctx, const char *path, int arr) {
    trace_add((trace *)ctx, "} %s %s\n", path, arr ? "array" : "object");
}

static int parse(const char *doc, size_t chunk, trace *t) {
    json_stream js;
    json_stream_cbs cbs = { on_value, on_enter, on_leave, t };
    size_t i, n = strlen(doc);

    memset(t, 0, sizeof(*t));
    json_stream_init(&js, &cbs);
    for (i = 0; i < n; i += chunk) {
        size_t take = n - i < chunk ? n - i : chunk;
        if (json_stream_feed(&js, (const uint8_t *)doc + i, take) != 0) return -1;
    }
    return json_stream_finish(&js);
}

// Feeds the document as two pieces, split at `at`.
static int parse_split(const char *doc, size_t at, trace *t) {
    json_stream js;
    json_stream_cbs cbs = { on_value, on_enter, on_leave, t };
    size_t n = strlen(doc);

    memset(t, 0, sizeof(*t));
    json_stream_init(&js, &cbs);
    if (json_stream_feed(&js, (const uint8_t *)doc, at) != 0) return -1;
    if (json_stream_feed(&js, (const uint8_t *)doc + at, n - at) != 0) return -1;
    return json_stream_finish(&js);
}

static void check_doc(const char *label, const char *doc, const char *want_tail) {
    trace whole, other;
    size_t n = strlen(doc), at;

    if (parse(doc, n, &whole) != 0) {
        printf("  FAIL %s: rejected a valid document\n", label);
        fails++;
        return;
    }
    if (want_tail && !strstr(whole.buf, want_tail)) {
        printf("  FAIL %s: trace missing %s\n       got:\n%s", label, want_tail, whole.buf);
        fails++;
        return;
    }
    // Byte-at-a-time.
    if (parse(doc, 1, &other) != 0 || strcmp(whole.buf, other.buf) != 0) {
        printf("  FAIL %s: byte-at-a-time differs\n", label);
        fails++;
        return;
    }
    // Every two-way split.
    for (at = 0; at <= n; at++) {
        if (parse_split(doc, at, &other) != 0 || strcmp(whole.buf, other.buf) != 0) {
            printf("  FAIL %s: split at %zu differs\n", label, at);
            fails++;
            return;
        }
    }
    printf("  ok   %s (%zu splits identical)\n", label, n + 1);
}

static void check_bad(const char *label, const char *doc) {
    trace t;
    if (parse(doc, strlen(doc), &t) == 0) {
        printf("  FAIL %s was accepted\n", label);
        fails++;
    } else {
        printf("  ok   %s rejected\n", label);
    }
}

int main(void) {
    printf("well-formed documents\n");
    check_doc("scalars", "{\"a\":1,\"b\":-2.5e3,\"c\":true,\"d\":false,\"e\":null,\"f\":\"x\"}",
              "V e = [] null\n");
    check_doc("nesting", "{\"o\":{\"p\":{\"q\":[1,2]}}}", "V o.p.q[] = [2] num\n");
    check_doc("empty containers", "{\"a\":{},\"b\":[],\"c\":[[],{}]}", "} b array\n");
    check_doc("escapes", "{\"s\":\"a\\\"b\\\\c\\nd\\u0041e\"}", "V s = [a\"b\\c\ndAe] str\n");
    check_doc("array of objects",
              "{\"Peers\":[{\"Key\":\"nodekey:aa\",\"DERP\":1},"
              "{\"Key\":\"nodekey:bb\",\"DERP\":2}]}",
              "V Peers[].Key = [nodekey:bb] str\n");
    // Shaped like the real thing: the netmap fields we will actually read.
    check_doc("netmap shape",
              "{\"Node\":{\"Addresses\":[\"100.64.0.1/32\"]},"
              "\"Peers\":[{\"ID\":7,\"Key\":\"nodekey:aa\",\"DiscoKey\":\"discokey:bb\","
              "\"Addresses\":[\"100.64.0.2/32\"],\"Endpoints\":[\"1.2.3.4:41641\"],"
              "\"DERP\":\"127.3.3.40:9\",\"Online\":true}],"
              "\"DNSConfig\":{\"Domains\":[\"example.ts.net\"]}}",
              "V Peers[].Endpoints[] = [1.2.3.4:41641] str\n");
    check_doc("top-level array", "[{\"a\":1},{\"a\":2}]", "V [].a = [2] num\n");

    printf("malformed documents\n");
    check_bad("trailing comma",  "{\"a\":1,}");
    check_bad("trailing comma array", "[1,]");
    check_bad("empty after comma", "{\"a\":1,,\"b\":2}");
    check_bad("unclosed object", "{\"a\":1");
    check_bad("bad literal",     "{\"a\":tru}");
    check_bad("bare colon",      "{\"a\"::1}");
    check_bad("mismatched",      "{\"a\":[1}");
    check_bad("junk after end",  "{} x");
    check_bad("bad escape",      "{\"a\":\"\\q\"}");

    printf("\n%s\n", fails ? "JSON TESTS FAILED" : "all JSON stream tests passed");
    return fails ? 1 : 0;
}
