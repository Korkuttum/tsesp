// Turns the ts2021 record layer into a plain byte stream, so the HTTP/2 code
// above never has to think about Noise framing. Decryption happens in place,
// so this costs one 4 KB receive buffer and one 4 KB send buffer.
#ifndef TS_NOISE_STREAM_H
#define TS_NOISE_STREAM_H

#include "ts_io.h"
#include "ts2021.h"

typedef struct {
    ts_io       *inner;      // the raw TCP stream
    ts2021_conn  conn;
    uint8_t      rx[TS2021_MAX_CIPHER];
    size_t       rx_len;     // decrypted bytes available
    size_t       rx_pos;     // how many already handed out
    uint8_t      tx[TS2021_MAX_FRAME];
    // Lets a caller peek at the first bytes of the tunnel and put them back
    // if they turn out to belong to the layer above (see the early payload).
    uint8_t      pushback[16];
    uint8_t      pushback_len;
    uint8_t      pushback_pos;
    int          failed;
} ts_noise_stream;

// Wraps `inner`, taking ownership of the already-completed handshake state.
// Fills in `out` as a ts_io that speaks plaintext.
void ts_noise_stream_init(ts_noise_stream *s, ts_io *inner,
                          const ts2021_conn *conn, ts_io *out);

// Puts up to sizeof(s->pushback) bytes back at the head of the stream.
// Returns 0 on success, -1 if they would not fit.
int ts_noise_stream_unread(ts_noise_stream *s, const uint8_t *buf, size_t len);

#endif
