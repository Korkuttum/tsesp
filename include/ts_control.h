// The Tailscale control client: HTTP upgrade, ts2021 Noise handshake, HTTP/2,
// and the /machine/* requests, all on top of a plain byte stream.
#ifndef TS_CONTROL_H
#define TS_CONTROL_H

#include "ts_io.h"
#include "ts2021.h"
#include "ts_noise_stream.h"
#include "h2.h"
#include "ts_netmap.h"

#define TS_AUTH_URL_MAX 256
#define TS_ERROR_MAX    192
#define TS_NAME_MAX     64

typedef struct {
    ts_io           *raw;
    ts_noise_stream  ns;
    ts_io            stream;
    h2_conn          h2;
    char             host[80];
    // From the server's optional early payload. Empty when it sent none.
    char             node_key_challenge[80];
} ts_control;

// Runs the whole bring-up on an already-connected TCP stream:
//   POST /ts2021 upgrade  ->  Noise IK  ->  HTTP/2 preface + SETTINGS
// `eph_priv` must be 32 fresh random bytes.
int ts_control_connect(ts_control *tc, ts_io *raw, const char *host,
                       const uint8_t machine_priv[32],
                       const uint8_t control_pub[32],
                       const uint8_t eph_priv[32]);

typedef struct {
    const uint8_t *node_pub;      // 32 bytes
    const char    *hostname;
    const char    *auth_key;      // NULL asks for an interactive login URL
    const char    *followup;      // set to the previous AuthURL when re-polling
    int            ephemeral;
} ts_register_req;

typedef struct {
    char auth_url[TS_AUTH_URL_MAX];
    char error[TS_ERROR_MAX];
    char login_name[TS_NAME_MAX];
    char user_display[TS_NAME_MAX];
    int  machine_authorized;
    int  node_key_expired;
    int  http_status;
} ts_register_resp;

// POSTs /machine/register. Without an auth key the server answers with an
// AuthURL and creates nothing until a human visits it; call again with
// `followup` set to that URL to block until they do.
int ts_control_register(ts_control *tc, const ts_register_req *req,
                        ts_register_resp *resp);

#define TS_MAX_SELF_ENDPOINTS 4

typedef struct {
    const uint8_t *node_pub;    // 32 bytes
    const uint8_t *disco_pub;   // 32 bytes
    const char    *hostname;
    // Capability version claimed in the request body. Modern control stops
    // distributing endpoints to clients new enough to trade them over DERP
    // instead, so a client without DERP may need to claim less.
    int            capver;
    int            stream;      // long-poll for updates instead of one shot
    int            omit_peers;
    // Where peers should try to reach us, as "1.2.3.4:41641". Without these
    // the control plane has no address to hand out and nobody can start a
    // conversation with this device.
    const char    *endpoints[TS_MAX_SELF_ENDPOINTS];
    int            nendpoints;
    // A node's home DERP region, reported through Hostinfo.NetInfo. The
    // control plane appears to withhold a node's disco key and endpoints
    // from its peers until it has one, so without this nobody can reach us
    // even on the same LAN.
    int            preferred_derp;
    int            working_udp;
    // Networks this device offers to route for, as "192.168.1.0/24". A peer
    // can only use them once they are approved in the admin console.
    const char    *routes[2];
    int            nroutes;
} ts_map_req;

// POSTs /machine/map and streams the response through `parser`. With
// stream = 0 the server sends one netmap and closes; with stream = 1 it holds
// the request open and keeps sending updates, so this call will not return.
int ts_control_map(ts_control *tc, const ts_map_req *req,
                   ts_netmap_parser *parser, int *out_status);

// Pushes our endpoints, disco key and Hostinfo without asking for peers.
//
// This is the shape tailcfg documents for the purpose: OmitPeers true,
// Stream false, ReadOnly false, which lets a client update itself without
// disturbing a long-poll session it already has open. Putting the same
// fields in the streaming request is apparently not how the server expects
// to receive them.
int ts_control_update_endpoints(ts_control *tc, const ts_map_req *req,
                                int *out_status);

// Set to log the request bodies we send. Off by default.
extern void (*ts_control_debug_body)(const char *body, size_t len);

#endif
