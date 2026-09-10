// Minimal HTTP/2 client — exactly what the Tailscale control server needs
// inside the ts2021 Noise tunnel, and nothing more.
//
// Deliberate limits, all of them safe for this one server:
//   * one request in flight at a time
//   * response bodies are streamed to a callback, never buffered, so a
//     300-peer netmap costs no more RAM than a 3-peer one
//   * response header blocks must fit H2_MAX_HEADER_BLOCK
//   * we never send Huffman or grow the peer's dynamic table
#ifndef H2_H
#define H2_H

#include "ts_io.h"
#include "hpack.h"

#ifndef H2_MAX_HEADER_BLOCK
#define H2_MAX_HEADER_BLOCK 2048
#endif

#define H2_ERR_IO        -1
#define H2_ERR_PROTOCOL  -2
#define H2_ERR_TOOBIG    -3
#define H2_ERR_GOAWAY    -4
#define H2_ERR_RST       -5
#define H2_ERR_ABORTED   -6   // a callback asked us to stop

typedef void (*h2_header_cb)(void *ctx, const char *name, size_t name_len,
                             const char *value, size_t value_len);
// Return 0 to keep going, non-zero to abort the request.
typedef int  (*h2_data_cb)(void *ctx, const uint8_t *data, size_t len);

typedef struct {
    ts_io        *io;
    hpack_decoder hpack;

    uint32_t next_stream_id;
    int32_t  conn_send_window;
    uint32_t peer_max_frame;
    uint32_t peer_initial_window;
    int      goaway;

    // Live request state.
    uint32_t     cur_stream;
    int32_t      stream_send_window;
    int          stream_done;
    int          status;
    int          abort;
    h2_header_cb hcb;
    h2_data_cb   dcb;
    void        *cbctx;

    uint8_t  hdrbuf[H2_MAX_HEADER_BLOCK];
    size_t   hdrlen;
    int      in_headers;      // a CONTINUATION sequence is open
} h2_conn;

// Sends the client preface and our SETTINGS, then waits for the server's
// SETTINGS and acknowledges it.
int h2_connect(h2_conn *c, ts_io *io);

// Performs one request and pumps frames until the response ends.
// `body` may be NULL. `hcb`/`dcb` may be NULL. On success returns 0 and
// stores the HTTP status in *out_status.
int h2_request(h2_conn *c,
               const char *method, const char *scheme,
               const char *authority, const char *path,
               const char *content_type,
               const uint8_t *body, size_t body_len,
               h2_header_cb hcb, h2_data_cb dcb, void *cbctx,
               int *out_status);

#endif
