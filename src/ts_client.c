#include <string.h>
#include <stdio.h>
#include "ts_client.h"

static uint32_t rng_next(ts_client *c) {
    c->rng = c->rng * 1664525u + 1013904223u;
    return c->rng >> 8;
}

// +/- 25%, so devices that fail together do not retry together.
static uint32_t jitter(ts_client *c, uint32_t ms) {
    uint32_t spread = ms / 2;
    if (spread == 0) return ms;
    return ms - spread / 2 + (rng_next(c) % spread);
}

void ts_client_init(ts_client *c, int already_registered, uint32_t seed) {
    memset(c, 0, sizeof(*c));
    c->state = TS_STATE_START;
    c->backoff_ms = TS_BACKOFF_MIN_MS;
    c->registered = already_registered;
    c->rng = seed ? seed : 1u;
}

static void enter_backoff(ts_client *c, uint32_t now_ms, uint32_t base) {
    c->state = TS_STATE_BACKOFF;
    c->connected = 0;
    c->attempt++;
    c->failures++;
    c->next_at_ms = now_ms + jitter(c, base);
    // Double for next time, capped.
    if (c->backoff_ms < TS_BACKOFF_MAX_MS) {
        c->backoff_ms *= 2;
        if (c->backoff_ms > TS_BACKOFF_MAX_MS) c->backoff_ms = TS_BACKOFF_MAX_MS;
    }
}

static void reset_backoff(ts_client *c) {
    c->backoff_ms = TS_BACKOFF_MIN_MS;
    c->attempt = 0;
}

void ts_client_connection_lost(ts_client *c, uint32_t now_ms) {
    if (c->state == TS_STATE_STOPPED) return;
    c->connected = 0;
    // A drop after a healthy session is usually a blip, so do not punish it
    // with the accumulated backoff of an earlier bad patch.
    if (c->state == TS_STATE_RUNNING) reset_backoff(c);
    enter_backoff(c, now_ms, c->backoff_ms);
}

ts_action ts_client_next(ts_client *c, uint32_t now_ms) {
    ts_action a;
    memset(&a, 0, sizeof(a));

    switch (c->state) {
    case TS_STATE_STOPPED:
        a.kind = TS_ACT_STOP;
        return a;

    case TS_STATE_BACKOFF:
        // Signed comparison handles the 49-day wrap of a millisecond clock.
        if ((int32_t)(now_ms - c->next_at_ms) < 0) {
            a.kind = TS_ACT_WAIT;
            a.wait_ms = c->next_at_ms - now_ms;
            return a;
        }
        c->state = TS_STATE_START;
        /* fall through */

    case TS_STATE_START:
        c->state = TS_STATE_CONNECTING;
        a.kind = TS_ACT_CONNECT;
        return a;

    case TS_STATE_CONNECTING:
        // The connection is open; what comes next depends on whether this
        // device has ever been registered.
        c->state = TS_STATE_REGISTERING;
        a.kind = c->registered ? TS_ACT_MAP : TS_ACT_REGISTER;
        if (c->registered) c->state = TS_STATE_RUNNING;
        return a;

    case TS_STATE_REGISTERING:
        a.kind = TS_ACT_REGISTER;
        return a;

    case TS_STATE_AWAITING_LOGIN:
        if (!c->have_login_url) {          // expired, ask for a new one
            c->state = TS_STATE_REGISTERING;
            a.kind = TS_ACT_REGISTER;
            return a;
        }
        if (!c->login_shown) {
            c->login_shown = 1;
            a.kind = TS_ACT_SHOW_LOGIN;
            a.login_url = c->login_url;
            return a;
        }
        if ((uint32_t)(now_ms - c->login_url_at_ms) > TS_LOGIN_URL_TTL_MS) {
            c->have_login_url = 0;
            c->login_shown = 0;
            c->state = TS_STATE_REGISTERING;
            a.kind = TS_ACT_REGISTER;
            return a;
        }
        if ((int32_t)(now_ms - c->next_at_ms) < 0) {
            a.kind = TS_ACT_WAIT;
            a.wait_ms = c->next_at_ms - now_ms;
            return a;
        }
        a.kind = TS_ACT_POLL_LOGIN;
        a.login_url = c->login_url;
        return a;

    case TS_STATE_RUNNING:
        a.kind = TS_ACT_MAP;
        return a;
    }

    a.kind = TS_ACT_WAIT;
    a.wait_ms = TS_BACKOFF_MIN_MS;
    return a;
}

void ts_client_report(ts_client *c, ts_action_kind kind, ts_result result,
                      const char *login_url, uint32_t now_ms) {
    if (c->state == TS_STATE_STOPPED) return;

    if (result == TS_ERR_FATAL) {
        c->state = TS_STATE_STOPPED;
        c->failures++;
        return;
    }
    if (result == TS_ERR_RATE_LIMITED) {
        // Never argue with a 429: this is someone else's infrastructure.
        enter_backoff(c, now_ms, TS_BACKOFF_RATE_MS);
        c->backoff_ms = TS_BACKOFF_MAX_MS;
        return;
    }
    if (result == TS_ERR_TRANSPORT) {
        enter_backoff(c, now_ms, c->backoff_ms);
        return;
    }

    switch (kind) {
    case TS_ACT_CONNECT:
        if (result == TS_OK) {
            c->connected = 1;
            c->connects++;
            reset_backoff(c);
        } else {
            enter_backoff(c, now_ms, c->backoff_ms);
        }
        return;

    case TS_ACT_REGISTER:
    case TS_ACT_POLL_LOGIN:
        if (result == TS_OK) {
            c->registered = 1;
            c->have_login_url = 0;
            c->login_shown = 0;
            c->registrations++;
            reset_backoff(c);
            c->state = TS_STATE_RUNNING;
        } else if (result == TS_ERR_NEEDS_LOGIN) {
            if (login_url && login_url[0] &&
                strcmp(login_url, c->login_url) != 0) {
                snprintf(c->login_url, sizeof(c->login_url), "%s", login_url);
                c->login_url_at_ms = now_ms;
                c->have_login_url = 1;
                c->login_shown = 0;      // a new URL must be shown again
            }
            c->state = TS_STATE_AWAITING_LOGIN;
            c->next_at_ms = now_ms + TS_LOGIN_POLL_MS;
        } else if (result == TS_ERR_AUTH) {
            // Our node key is no longer accepted: start over as a new device.
            c->registered = 0;
            c->have_login_url = 0;
            c->login_shown = 0;
            enter_backoff(c, now_ms, c->backoff_ms);
        }
        return;

    case TS_ACT_MAP:
        if (result == TS_OK) {
            c->map_sessions++;
            reset_backoff(c);
            // A streaming map session ending is normal; reconnect promptly.
            c->state = TS_STATE_BACKOFF;
            c->next_at_ms = now_ms + jitter(c, TS_BACKOFF_MIN_MS);
            c->connected = 0;
        } else if (result == TS_ERR_AUTH) {
            c->registered = 0;
            enter_backoff(c, now_ms, c->backoff_ms);
        } else {
            enter_backoff(c, now_ms, c->backoff_ms);
        }
        return;

    default:
        return;
    }
}

const char *ts_client_state_name(ts_client_state s) {
    switch (s) {
    case TS_STATE_START:          return "start";
    case TS_STATE_CONNECTING:     return "connecting";
    case TS_STATE_REGISTERING:    return "registering";
    case TS_STATE_AWAITING_LOGIN: return "awaiting-login";
    case TS_STATE_RUNNING:        return "running";
    case TS_STATE_BACKOFF:        return "backoff";
    case TS_STATE_STOPPED:        return "stopped";
    }
    return "?";
}
