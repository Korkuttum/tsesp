// The device lifecycle, driven against a fake clock: first boot, interactive
// login, reconnects, backoff, and the promise that a device with a dead
// uplink does not hammer someone else's control plane.
#include <stdio.h>
#include <string.h>
#include "ts_client.h"

static int fails = 0;

static void ok(int cond, const char *what) {
    printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond) fails++;
}

int main(void) {
    printf("ilk açılış: kayıtsız cihaz\n");
    {
        ts_client c;
        uint32_t t = 0;
        ts_action a;
        int saw_show_login = 0, polls = 0, reached_map = 0;
        int steps;

        ts_client_init(&c, 0, 0xC0FFEE);

        for (steps = 0; steps < 200 && !reached_map; steps++) {
            a = ts_client_next(&c, t);
            switch (a.kind) {
            case TS_ACT_WAIT:
                t += a.wait_ms ? a.wait_ms : 100;
                break;
            case TS_ACT_CONNECT:
                ts_client_report(&c, a.kind, TS_OK, NULL, t);
                break;
            case TS_ACT_REGISTER:
                ts_client_report(&c, a.kind, TS_ERR_NEEDS_LOGIN,
                                 "https://login.tailscale.com/a/abc123", t);
                break;
            case TS_ACT_SHOW_LOGIN:
                saw_show_login++;
                ok(a.login_url && strstr(a.login_url, "login.tailscale.com") != NULL,
                   "login URL'i kullanıcıya gösterilecek şekilde verildi");
                break;
            case TS_ACT_POLL_LOGIN:
                polls++;
                // The human clicks the link on the third poll.
                ts_client_report(&c, a.kind, polls < 3 ? TS_ERR_NEEDS_LOGIN : TS_OK,
                                 "https://login.tailscale.com/a/abc123", t);
                break;
            case TS_ACT_MAP:
                reached_map = 1;
                break;
            default:
                break;
            }
        }
        ok(saw_show_login == 1, "login URL'i tam bir kez gösterildi, tekrar tekrar değil");
        ok(polls >= 3, "onay beklenirken düzenli yoklandı");
        ok(reached_map, "onaydan sonra netmap'e geçildi");
        ok(c.registered, "kayıtlı olarak işaretlendi");
        printf("    (%u ms sürdü, %d yoklama)\n", t, polls);
    }

    printf("yeniden açılış: zaten kayıtlı\n");
    {
        ts_client c;
        ts_action a;
        ts_client_init(&c, 1, 1);
        a = ts_client_next(&c, 0);
        ok(a.kind == TS_ACT_CONNECT, "önce bağlan");
        ts_client_report(&c, a.kind, TS_OK, NULL, 0);
        a = ts_client_next(&c, 0);
        ok(a.kind == TS_ACT_MAP, "kayıt atlanıp doğrudan netmap'e gidildi");
    }

    printf("geri çekilme\n");
    {
        ts_client c;
        uint32_t t = 0, waits[10];
        int n = 0, steps;
        ts_client_init(&c, 1, 42);

        for (steps = 0; steps < 400 && n < 8; steps++) {
            ts_action a = ts_client_next(&c, t);
            if (a.kind == TS_ACT_WAIT) {
                if (n < 10) waits[n++] = a.wait_ms;
                t += a.wait_ms;
            } else if (a.kind == TS_ACT_CONNECT) {
                ts_client_report(&c, a.kind, TS_ERR_TRANSPORT, NULL, t);
            } else {
                t += 100;
            }
        }
        printf("    beklemeler:");
        for (steps = 0; steps < n; steps++) printf(" %ums", waits[steps]);
        printf("\n");
        ok(n >= 6, "arka arkaya hatalarda bekleniyor");
        ok(waits[0] >= 750 && waits[0] <= 1250, "ilk bekleme ~1 sn (jitter dahil)");
        ok(waits[3] > waits[0], "bekleme süresi büyüyor");
        {
            int capped = 1, i;
            for (i = 0; i < n; i++) if (waits[i] > TS_BACKOFF_MAX_MS * 5 / 4) capped = 0;
            ok(capped, "bekleme 60 sn tavanını aşmıyor");
        }
        {
            // Jitter must actually vary, or a fleet retries in lockstep.
            int varied = 0, i;
            for (i = 1; i < n; i++) if (waits[i] != waits[i - 1] * 2) varied = 1;
            ok(varied, "jitter uygulanıyor, sabit ikiye katlama değil");
        }
    }

    printf("bir saatlik kesintide sunucuya kaç kez gidiliyor\n");
    {
        ts_client c;
        uint32_t t = 0;
        int connects = 0, steps;
        ts_client_init(&c, 1, 7);

        for (steps = 0; steps < 100000 && t < 3600000u; steps++) {
            ts_action a = ts_client_next(&c, t);
            if (a.kind == TS_ACT_WAIT) t += a.wait_ms ? a.wait_ms : 1;
            else if (a.kind == TS_ACT_CONNECT) {
                connects++;
                ts_client_report(&c, a.kind, TS_ERR_TRANSPORT, NULL, t);
            } else t += 1;
        }
        printf("    1 saatte %d bağlantı denemesi\n", connects);
        ok(connects < 120, "saatte 120'den az deneme: kontrol sunucusu yorulmuyor");
        ok(connects > 10, "yine de düzenli deniyor, pes etmiyor");
    }

    printf("429 gelirse\n");
    {
        ts_client c;
        ts_action a;
        uint32_t t = 1000;
        ts_client_init(&c, 1, 3);
        a = ts_client_next(&c, t);
        ts_client_report(&c, a.kind, TS_ERR_RATE_LIMITED, NULL, t);
        a = ts_client_next(&c, t);
        ok(a.kind == TS_ACT_WAIT && a.wait_ms > 200000u,
           "hız sınırına takılınca dakikalarca bekleniyor, ısrar edilmiyor");
        printf("    bekleme: %u ms\n", a.wait_ms);
    }

    printf("netmap oturumu normal bitince\n");
    {
        ts_client c;
        ts_action a;
        uint32_t t = 5000;
        ts_client_init(&c, 1, 9);
        ts_client_report(&c, TS_ACT_CONNECT, TS_OK, NULL, t);
        c.state = TS_STATE_RUNNING;
        ts_client_report(&c, TS_ACT_MAP, TS_OK, NULL, t);
        a = ts_client_next(&c, t);
        ok(a.kind == TS_ACT_WAIT && a.wait_ms <= 1300,
           "uzun bağlantı bitince hemen yeniden bağlanılıyor, cezalı beklenmiyor");
    }

    printf("node key reddedilirse\n");
    {
        ts_client c;
        ts_action a;
        uint32_t t = 0;
        int steps;
        ts_client_init(&c, 1, 11);
        ts_client_report(&c, TS_ACT_CONNECT, TS_OK, NULL, t);
        c.state = TS_STATE_RUNNING;
        ts_client_report(&c, TS_ACT_MAP, TS_ERR_AUTH, NULL, t);
        ok(!c.registered, "kayıt geçersiz sayıldı");
        for (steps = 0; steps < 20; steps++) {
            a = ts_client_next(&c, t);
            if (a.kind == TS_ACT_WAIT) { t += a.wait_ms; continue; }
            if (a.kind == TS_ACT_CONNECT) { ts_client_report(&c, a.kind, TS_OK, NULL, t); continue; }
            break;
        }
        ok(a.kind == TS_ACT_REGISTER, "baştan kaydolmaya gidildi");
    }

    printf("kalıcı hata\n");
    {
        ts_client c;
        ts_action a;
        ts_client_init(&c, 1, 13);
        ts_client_report(&c, TS_ACT_CONNECT, TS_ERR_FATAL, NULL, 0);
        a = ts_client_next(&c, 0);
        ok(a.kind == TS_ACT_STOP, "düzelmeyecek hatada duruluyor");
        a = ts_client_next(&c, 3600000u);
        ok(a.kind == TS_ACT_STOP, "bir saat sonra da duruluyor");
    }

    printf("49 günde saat başa sarınca\n");
    {
        ts_client c;
        ts_action a;
        uint32_t t = 0xFFFFF000u;      // just before the wrap
        ts_client_init(&c, 1, 17);
        ts_client_report(&c, TS_ACT_CONNECT, TS_ERR_TRANSPORT, NULL, t);
        t += 5000;                      // wraps past zero
        a = ts_client_next(&c, t);
        ok(a.kind == TS_ACT_CONNECT,
           "milisaniye sayacı başa sarınca cihaz 49 gün donup kalmıyor");
    }

    printf("\n%s\n", fails ? "CLIENT TESTS FAILED" : "all client state machine tests passed");
    return fails ? 1 : 0;
}
