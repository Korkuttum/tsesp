// Path discovery against simulated home routers.
//
// The scenarios are the ones that decide whether this project works in a
// house: a plain restricted-cone router (most of them), a full cone, and a
// symmetric NAT. The symmetric case is expected to FAIL to find a direct
// path - reporting success there would be worse than failing, because the
// device would sit on a path that carries nothing.
#include <stdio.h>
#include <string.h>
#include "sim_net.h"

static int fails = 0;

static void ok(int cond, const char *what) {
    printf("    %s %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond) fails++;
}

static const char *nat_name(nat_type t) {
    switch (t) {
    case NAT_NONE:       return "açık internet";
    case NAT_FULL_CONE:  return "full cone";
    case NAT_RESTRICTED: return "restricted cone";
    default:             return "simetrik";
    }
}

static void addr_str(char *out, size_t cap, const ts_path *p) {
    uint8_t v4[4];
    if (p && disco_is_ipv4_mapped(p->ip, v4))
        snprintf(out, cap, "%u.%u.%u.%u:%u", v4[0], v4[1], v4[2], v4[3], p->port);
    else
        snprintf(out, cap, "%s", p ? "ipv6" : "(yok)");
}

// Runs A and B behind the given NATs and reports whether a direct path formed.
static int scenario(const char *label, nat_type ta, nat_type tb,
                    int expect_direct, uint32_t loss_permille) {
    sim_net net;
    sim_nat *na = NULL, *nb = NULL;
    int a, b;
    const ts_path *pa, *pb;
    char sa[48], sb[48];

    printf("  %s: A=%s, B=%s%s\n", label, nat_name(ta), nat_name(tb),
           loss_permille ? ", %10 paket kaybı" : "");

    sim_net_init(&net, 15);
    net.loss_permille = loss_permille;
    if (ta != NAT_NONE) na = sim_add_nat(&net, ta, "78.190.240.153");
    if (tb != NAT_NONE) nb = sim_add_nat(&net, tb, "85.106.118.217");
    a = sim_add_host(&net, "A", ta != NAT_NONE ? "192.168.1.73" : "78.190.240.153",
                     41641, na);
    b = sim_add_host(&net, "B", tb != NAT_NONE ? "192.168.2.50" : "85.106.118.217",
                     41641, nb);
    sim_start(&net);
    sim_host_learn_public(&net, a);
    sim_host_learn_public(&net, b);

    // Control tells each side about the other's public address.
    sim_introduce(&net, a, b, 3);
    sim_introduce(&net, b, a, 3);

    sim_run(&net, 20000);

    pa = ts_path_best(&net.hosts[a].eng, 0);
    pb = ts_path_best(&net.hosts[b].eng, 0);
    addr_str(sa, sizeof(sa), pa);
    addr_str(sb, sizeof(sb), pb);
    printf("    A -> %s   B -> %s   (ping %u, pong %u, NAT'ta düşen %u)\n",
           sa, sb, net.hosts[a].eng.pings_sent, net.hosts[a].eng.pongs_received,
           net.dropped_nat);

    if (expect_direct) {
        ok(pa != NULL && pb != NULL, "iki taraf da doğrudan yol buldu");
        if (pa) ok(pa->latency_ms > 0 && pa->latency_ms < 500, "gecikme makul ölçüldü");
    } else {
        ok(pa == NULL && pb == NULL,
           "doğrudan yol bulunamadı ve motor bulduğunu iddia etmiyor");
    }
    return pa != NULL;
}

int main(void) {
    printf("NAT senaryoları\n");
    scenario("1", NAT_NONE,       NAT_NONE,       1, 0);
    scenario("2", NAT_RESTRICTED, NAT_NONE,       1, 0);
    scenario("3", NAT_RESTRICTED, NAT_RESTRICTED, 1, 0);
    scenario("4", NAT_FULL_CONE,  NAT_RESTRICTED, 1, 0);
    scenario("5", NAT_SYMMETRIC,  NAT_SYMMETRIC,  0, 0);
    scenario("6", NAT_RESTRICTED, NAT_RESTRICTED, 1, 100);

    printf("ölü aday eleniyor mu\n");
    {
        sim_net net;
        sim_nat *na;
        int a, b, pi;
        uint8_t dead[16];
        const ts_path *best;

        sim_net_init(&net, 15);
        na = sim_add_nat(&net, NAT_RESTRICTED, "78.190.240.153");
        a = sim_add_host(&net, "A", "192.168.1.73", 41641, na);
        b = sim_add_host(&net, "B", "85.106.118.217", 41641, NULL);
        sim_start(&net);
        sim_host_learn_public(&net, a);
        sim_host_learn_public(&net, b);

        // Two candidates: one real, one pointing nowhere - exactly what a
        // netmap full of stale LAN addresses looks like.
        sim_introduce(&net, a, b, 3);
        sim_introduce(&net, b, a, 3);
        pi = ts_path_find_peer(&net.hosts[a].eng, (uint64_t)(b + 1));
        sim_v4(dead, "10.99.99.99");
        ts_path_add_candidate(&net.hosts[a].eng, pi, dead, 41641, 3);

        sim_run(&net, 20000);
        best = ts_path_best(&net.hosts[a].eng, pi);
        ok(best != NULL, "çalışan yol bulundu");
        if (best) {
            uint8_t v4[4];
            disco_is_ipv4_mapped(best->ip, v4);
            ok(v4[0] != 10, "ölü aday seçilmedi");
        }
    }

    printf("kurulan yol canlı tutuluyor mu\n");
    {
        sim_net net;
        sim_nat *na, *nb;
        int a, b;
        uint32_t pings_after_setup;
        const ts_path *best;

        sim_net_init(&net, 15);
        na = sim_add_nat(&net, NAT_RESTRICTED, "78.190.240.153");
        nb = sim_add_nat(&net, NAT_RESTRICTED, "85.106.118.217");
        a = sim_add_host(&net, "A", "192.168.1.73", 41641, na);
        b = sim_add_host(&net, "B", "192.168.2.50", 41641, nb);
        sim_start(&net);
        sim_host_learn_public(&net, a);
        sim_host_learn_public(&net, b);
        sim_introduce(&net, a, b, 3);
        sim_introduce(&net, b, a, 3);

        sim_run(&net, 20000);
        ok(ts_path_best(&net.hosts[a].eng, 0) != NULL, "yol kuruldu");
        pings_after_setup = net.hosts[a].eng.pings_sent;

        // NAT mappings expire around 30 s of silence, so the keepalive has to
        // fire well inside that window.
        sim_run(&net, 60000);
        ok(net.hosts[a].eng.pings_sent > pings_after_setup,
           "60 saniyede keepalive ping'leri gitti");
        ok(ts_path_best(&net.hosts[a].eng, 0) != NULL, "yol hâlâ ayakta");

        // Now cut the wire and confirm the engine admits the path is gone
        // instead of pointing at a dead address.
        net.partitioned = 1;
        sim_run(&net, 60000);
        best = ts_path_best(&net.hosts[a].eng, 0);
        ok(best == NULL, "bağlantı kesilince yol düştü, ısrar etmedi");
    }

    printf("\n%s\n", fails ? "PATH TESTS FAILED" : "all path discovery tests passed");
    return fails ? 1 : 0;
}
