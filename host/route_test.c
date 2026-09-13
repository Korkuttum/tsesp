// What the control plane says about our advertised subnet route, read off a
// synthetic netmap so it can be checked without a board or a tailnet.
//
// Advertising a route and having one are different things: the route only
// works once somebody approves it in the admin console, and the approval
// comes back in our own node's AllowedIPs. Everything there that is not one
// of our own host addresses is an approved network. The distinction that
// matters most here is the third case - a record with no AllowedIPs at all
// means "we were not told", which must not be reported as "not approved".
#include <stdio.h>
#include <string.h>
#include "ts_netmap.h"

static int fails = 0;

static void ok(int cond, const char *what) {
    printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond) fails++;
}

static int on_message(void *ctx, const ts_netmap_info *info) {
    (void)ctx; (void)info;
    return 0;
}

// The netmap arrives as 4-byte little-endian lengths followed by JSON.
static void feed(ts_netmap_parser *p, const char *json) {
    uint8_t hdr[4];
    size_t n = strlen(json);
    hdr[0] = (uint8_t)n; hdr[1] = (uint8_t)(n >> 8);
    hdr[2] = (uint8_t)(n >> 16); hdr[3] = (uint8_t)(n >> 24);
    if (ts_netmap_feed(p, hdr, 4) != 0 ||
        ts_netmap_feed(p, (const uint8_t *)json, n) != 0)
        printf("  FAIL parser rejected the message\n"), fails++;
}

static void reset(ts_netmap_parser *p) {
    ts_netmap_parser_init(p, NULL, NULL);
    ts_netmap_parser_on_message(p, on_message);
}

int main(void) {
    ts_netmap_parser p;

    printf("onaylanmış rota\n");
    reset(&p);
    feed(&p, "{\"Node\":{\"ID\":7,"
             "\"Addresses\":[\"100.115.225.84/32\",\"fd7a:1::1/128\"],"
             "\"AllowedIPs\":[\"100.115.225.84/32\",\"fd7a:1::1/128\","
             "\"192.168.1.0/24\"]},\"Peers\":[]}");
    ok(p.info.self_has_allowed_ips == 1, "AllowedIPs geldi");
    ok(p.info.self_nroutes == 1, "bir rota bulundu");
    ok(p.info.self_nroutes == 1 &&
       strcmp(p.info.self_routes[0], "192.168.1.0/24") == 0, "rota doğru");

    printf("ilan edilmiş ama onaylanmamış\n");
    reset(&p);
    feed(&p, "{\"Node\":{\"ID\":7,\"Addresses\":[\"100.115.225.84/32\"],"
             "\"AllowedIPs\":[\"100.115.225.84/32\",\"fd7a:1::1/128\"]},"
             "\"Peers\":[]}");
    ok(p.info.self_has_allowed_ips == 1, "AllowedIPs geldi");
    ok(p.info.self_nroutes == 0, "kendi adreslerimiz rota sayılmadı");

    printf("AllowedIPs hiç yok: bilinmiyor, 'onaylanmamış' değil\n");
    reset(&p);
    feed(&p, "{\"Node\":{\"ID\":7,\"Addresses\":[\"100.115.225.84/32\"]},"
             "\"Peers\":[]}");
    ok(p.info.self_has_allowed_ips == 0, "alan yoktu diye işaretlendi");
    ok(p.info.self_nroutes == 0, "rota yok");

    printf("onay geri alınınca sonraki mesajda düşüyor\n");
    reset(&p);
    feed(&p, "{\"Node\":{\"ID\":7,\"Addresses\":[\"100.115.225.84/32\"],"
             "\"AllowedIPs\":[\"100.115.225.84/32\",\"192.168.1.0/24\"]},"
             "\"Peers\":[]}");
    ok(p.info.self_nroutes == 1, "önce onaylıydı");
    feed(&p, "{\"Node\":{\"ID\":7,\"Addresses\":[\"100.115.225.84/32\"],"
             "\"AllowedIPs\":[\"100.115.225.84/32\"]},\"Peers\":[]}");
    ok(p.info.self_nroutes == 0, "her mesaj kendi kaydını yeniden söylüyor");

    // A peer's own routes must not land in our record: the fields are
    // per-node and the path decides which node a value belongs to.
    printf("peer'in rotası bizim kaydımıza yazılmıyor\n");
    reset(&p);
    feed(&p, "{\"Node\":{\"ID\":7,\"Addresses\":[\"100.115.225.84/32\"],"
             "\"AllowedIPs\":[\"100.115.225.84/32\"]},"
             "\"Peers\":[{\"ID\":9,\"Addresses\":[\"100.90.1.2/32\"],"
             "\"AllowedIPs\":[\"100.90.1.2/32\",\"10.0.0.0/8\"]}]}");
    ok(p.info.self_nroutes == 0, "10.0.0.0/8 bize yazılmadı");

    printf(fails ? "\n%d check failed\n" : "\nall route approval tests passed\n",
           fails);
    return fails ? 1 : 0;
}
