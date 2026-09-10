// The device's state machine: what to do next, and when.
//
// This module makes decisions and nothing else. It performs no I/O and reads
// no clock of its own, so the whole lifecycle - first boot, interactive
// login, reconnects, backoff - can be tested in microseconds against a fake
// clock instead of by unplugging a router for an afternoon.
//
// The device loop is:
//
//     for (;;) {
//         act = ts_client_next(&c, now_ms());
//         switch (act.kind) { ... do the work ... }
//         ts_client_report(&c, act.kind, result);
//     }
#ifndef TS_CLIENT_H
#define TS_CLIENT_H

#include <stdint.h>

typedef enum {
    TS_ACT_WAIT = 0,       // nothing to do for act.wait_ms
    TS_ACT_CONNECT,        // open a control connection
    TS_ACT_REGISTER,       // POST /machine/register
    TS_ACT_SHOW_LOGIN,     // put act.login_url in front of the user
    TS_ACT_POLL_LOGIN,     // re-register with Followup set, waits for approval
    TS_ACT_MAP,            // POST /machine/map and stream it
    TS_ACT_STOP            // give up until something external changes
} ts_action_kind;

typedef enum {
    TS_OK = 0,
    TS_ERR_TRANSPORT,      // could not reach the control plane
    TS_ERR_AUTH,           // registration rejected; our node key is no good
    TS_ERR_NEEDS_LOGIN,    // server handed back an AuthURL
    TS_ERR_RATE_LIMITED,   // 429: back off hard and do not argue
    TS_ERR_FATAL           // misconfiguration; retrying will not help
} ts_result;

typedef enum {
    TS_STATE_START = 0,
    TS_STATE_CONNECTING,
    TS_STATE_REGISTERING,
    TS_STATE_AWAITING_LOGIN,
    TS_STATE_RUNNING,
    TS_STATE_BACKOFF,
    TS_STATE_STOPPED
} ts_client_state;

#define TS_LOGIN_URL_MAX 256

// Backoff: quick enough that a flapping Wi-Fi link recovers in seconds, slow
// enough that a device left in a cupboard with a dead uplink is not hammering
// anyone's servers.
#define TS_BACKOFF_MIN_MS   1000u
#define TS_BACKOFF_MAX_MS   60000u
#define TS_BACKOFF_RATE_MS  300000u   // after a 429, wait five minutes
// A login URL is not useful forever; ask for a fresh one rather than showing
// a stale one indefinitely.
#define TS_LOGIN_URL_TTL_MS 600000u
// How often to re-poll while waiting for a human to click the link.
#define TS_LOGIN_POLL_MS    5000u

typedef struct {
    ts_action_kind kind;
    uint32_t       wait_ms;       // for TS_ACT_WAIT
    const char    *login_url;     // for TS_ACT_SHOW_LOGIN / TS_ACT_POLL_LOGIN
} ts_action;

typedef struct {
    ts_client_state state;
    uint32_t next_at_ms;          // when the current wait ends
    uint32_t backoff_ms;
    uint32_t attempt;             // consecutive failures
    uint32_t login_url_at_ms;
    char     login_url[TS_LOGIN_URL_MAX];
    int      have_login_url;
    int      registered;          // survives reboots, via NVS
    int      connected;           // a control connection is open right now
    int      login_shown;

    // Jitter keeps a roomful of these devices from retrying in lockstep after
    // a shared outage. Seeded from the node key so each device differs.
    uint32_t rng;

    // Counters for the status page.
    uint32_t connects, registrations, map_sessions, failures;
} ts_client;

void ts_client_init(ts_client *c, int already_registered, uint32_t seed);

// Decides what to do at now_ms.
ts_action ts_client_next(ts_client *c, uint32_t now_ms);

// Reports how the action turned out. `login_url` is only read when the
// result is TS_ERR_NEEDS_LOGIN.
void ts_client_report(ts_client *c, ts_action_kind kind, ts_result result,
                      const char *login_url, uint32_t now_ms);

// Tells the machine the control connection dropped, from anywhere.
void ts_client_connection_lost(ts_client *c, uint32_t now_ms);

const char *ts_client_state_name(ts_client_state s);

#endif
