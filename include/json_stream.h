// Push-mode JSON parser. Bytes go in as they arrive off the wire, values come
// out through callbacks, and nothing is ever buffered whole.
//
// This is the piece that lets a 300-peer netmap cost the same RAM as a
// 3-peer one. Paths are normalised with empty array brackets, so every peer
// in a list reports as "Peers[].Key" and the caller accumulates one peer at a
// time between the matching enter/leave callbacks.
#ifndef JSON_STREAM_H
#define JSON_STREAM_H

#include <stddef.h>
#include <stdint.h>

#ifndef JSON_MAX_DEPTH
#define JSON_MAX_DEPTH 24
#endif
#ifndef JSON_MAX_PATH
#define JSON_MAX_PATH 192
#endif
#ifndef JSON_MAX_KEY
#define JSON_MAX_KEY 48
#endif
// Values longer than this are delivered truncated, with `truncated` set.
#ifndef JSON_MAX_VALUE
#define JSON_MAX_VALUE 256
#endif

typedef enum {
    JSON_STRING,
    JSON_NUMBER,
    JSON_TRUE,
    JSON_FALSE,
    JSON_NULL
} json_type;

typedef struct json_stream json_stream;

typedef struct {
    // A scalar was parsed. `path` is NUL-terminated, `value` is not.
    void (*on_value)(void *ctx, const char *path,
                     const char *value, size_t len, json_type type, int truncated);
    // An object or array started / ended. `path` names the container.
    void (*on_enter)(void *ctx, const char *path, int is_array);
    void (*on_leave)(void *ctx, const char *path, int is_array);
    void *ctx;
} json_stream_cbs;

struct json_stream {
    json_stream_cbs cb;

    uint8_t  state;
    uint8_t  depth;
    uint8_t  is_array[JSON_MAX_DEPTH];
    uint16_t path_len_at[JSON_MAX_DEPTH];   // path length when the frame opened
    uint32_t index[JSON_MAX_DEPTH];         // current array index

    char     path[JSON_MAX_PATH];
    uint16_t path_len;

    char     key[JSON_MAX_KEY];
    uint16_t key_len;
    uint8_t  key_truncated;

    char     value[JSON_MAX_VALUE];
    uint16_t value_len;
    uint8_t  value_truncated;

    uint8_t  in_key;          // the string being read is an object key
    uint8_t  unicode_left;    // remaining \uXXXX hex digits
    uint16_t unicode_acc;
    uint8_t  literal_len;
    char     literal[6];

    int      error;
};

void json_stream_init(json_stream *js, const json_stream_cbs *cbs);

// Feeds a chunk. Returns 0 while the document is still well-formed, -1 once
// it is not (after which further feeding is a no-op).
int json_stream_feed(json_stream *js, const uint8_t *data, size_t len);

// Returns 0 if the document ended cleanly at depth 0.
int json_stream_finish(json_stream *js);

#endif
