#include <string.h>
#include "json_stream.h"

enum {
    ST_VALUE,        // expecting a value (after a comma: no closing bracket)
    ST_VALUE_OR_END, // expecting a value or ']' (right after '[')
    ST_STRING,
    ST_STRING_ESC,
    ST_STRING_UNI,
    ST_NUMBER,
    ST_LITERAL,
    ST_KEY,          // expecting "key" (after a comma: no closing brace)
    ST_KEY_OR_END,   // expecting "key" or '}' (right after '{')
    ST_COLON,
    ST_NEXT,         // expecting , or closing bracket
    ST_DONE
};

static void fail(json_stream *js) { js->error = -1; js->state = ST_DONE; }

// ---------------------------------------------------------------- path

static void path_append(json_stream *js, const char *s, size_t n) {
    if (js->path_len + n >= JSON_MAX_PATH) { fail(js); return; }
    memcpy(js->path + js->path_len, s, n);
    js->path_len += (uint16_t)n;
    js->path[js->path_len] = '\0';
}

// Rebuilds the trailing path component for the value about to be reported.
static void path_push_current(json_stream *js) {
    if (js->depth == 0) return;
    if (js->is_array[js->depth - 1]) {
        path_append(js, "[]", 2);
    } else {
        if (js->path_len > 0) path_append(js, ".", 1);
        path_append(js, js->key, js->key_len);
    }
}

static void path_pop_to(json_stream *js, uint16_t len) {
    js->path_len = len;
    js->path[len] = '\0';
}

// ---------------------------------------------------------------- values

static void value_reset(json_stream *js) {
    js->value_len = 0;
    js->value_truncated = 0;
}

static void value_push(json_stream *js, char c) {
    if (js->value_len < JSON_MAX_VALUE) js->value[js->value_len++] = c;
    else js->value_truncated = 1;
}

static void key_reset(json_stream *js) {
    js->key_len = 0;
    js->key_truncated = 0;
}

static void key_push(json_stream *js, char c) {
    if (js->key_len < JSON_MAX_KEY - 1) js->key[js->key_len++] = c;
    else js->key_truncated = 1;
}

static void str_push(json_stream *js, char c) {
    if (js->in_key) key_push(js, c);
    else value_push(js, c);
}

// Emits a completed scalar, then restores the path.
static void emit_value(json_stream *js, json_type type) {
    uint16_t saved = js->path_len;
    path_push_current(js);
    if (js->error) return;
    if (js->cb.on_value) {
        js->key[js->key_len] = '\0';
        js->cb.on_value(js->cb.ctx, js->path, js->value, js->value_len,
                        type, js->value_truncated);
    }
    path_pop_to(js, saved);
    if (js->depth && js->is_array[js->depth - 1]) js->index[js->depth - 1]++;
    js->state = js->depth ? ST_NEXT : ST_DONE;
}

static void open_container(json_stream *js, int is_array) {
    uint16_t saved;

    if (js->depth >= JSON_MAX_DEPTH) { fail(js); return; }
    saved = js->path_len;
    path_push_current(js);
    if (js->error) return;

    js->path_len_at[js->depth] = saved;
    js->is_array[js->depth] = (uint8_t)is_array;
    js->index[js->depth] = 0;
    js->depth++;

    if (js->cb.on_enter) js->cb.on_enter(js->cb.ctx, js->path, is_array);
    js->state = is_array ? ST_VALUE_OR_END : ST_KEY_OR_END;
    key_reset(js);
}

static void close_container(json_stream *js) {
    int is_array;
    uint16_t restore;

    if (js->depth == 0) { fail(js); return; }
    js->depth--;
    is_array = js->is_array[js->depth];
    restore = js->path_len_at[js->depth];

    if (js->cb.on_leave) js->cb.on_leave(js->cb.ctx, js->path, is_array);
    path_pop_to(js, restore);

    if (js->depth && js->is_array[js->depth - 1]) js->index[js->depth - 1]++;
    js->state = js->depth ? ST_NEXT : ST_DONE;
}

// ---------------------------------------------------------------- driver

void json_stream_init(json_stream *js, const json_stream_cbs *cbs) {
    memset(js, 0, sizeof(*js));
    js->cb = *cbs;
    js->state = ST_VALUE;
    js->path[0] = '\0';
}

static int is_ws(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Encodes one code point as UTF-8 into the current string.
static void push_utf8(json_stream *js, uint32_t cp) {
    if (cp < 0x80) {
        str_push(js, (char)cp);
    } else if (cp < 0x800) {
        str_push(js, (char)(0xc0 | (cp >> 6)));
        str_push(js, (char)(0x80 | (cp & 0x3f)));
    } else {
        str_push(js, (char)(0xe0 | (cp >> 12)));
        str_push(js, (char)(0x80 | ((cp >> 6) & 0x3f)));
        str_push(js, (char)(0x80 | (cp & 0x3f)));
    }
}

int json_stream_feed(json_stream *js, const uint8_t *data, size_t len) {
    size_t i;

    if (js->error) return -1;

    for (i = 0; i < len; i++) {
        char c = (char)data[i];

    again:
        switch (js->state) {

        case ST_VALUE_OR_END:
            if (is_ws(c)) break;
            if (c == ']') {
                if (js->depth == 0 || !js->is_array[js->depth - 1]) { fail(js); break; }
                close_container(js);
                break;
            }
            js->state = ST_VALUE;
            goto again;

        case ST_VALUE:
            if (is_ws(c)) break;
            if (c == '{') { open_container(js, 0); break; }
            if (c == '[') { open_container(js, 1); break; }
            if (c == '"') {
                value_reset(js);
                js->in_key = 0;
                js->state = ST_STRING;
                break;
            }
            if (c == '-' || (c >= '0' && c <= '9')) {
                value_reset(js);
                value_push(js, c);
                js->state = ST_NUMBER;
                break;
            }
            if (c == 't' || c == 'f' || c == 'n') {
                js->literal_len = 0;
                js->literal[js->literal_len++] = c;
                js->state = ST_LITERAL;
                break;
            }
            fail(js);
            break;

        case ST_STRING:
            if (c == '"') {
                if (js->in_key) {
                    js->key[js->key_len] = '\0';
                    js->state = ST_COLON;
                } else {
                    emit_value(js, JSON_STRING);
                }
                break;
            }
            if (c == '\\') { js->state = ST_STRING_ESC; break; }
            str_push(js, c);
            break;

        case ST_STRING_ESC:
            switch (c) {
            case '"':  str_push(js, '"');  js->state = ST_STRING; break;
            case '\\': str_push(js, '\\'); js->state = ST_STRING; break;
            case '/':  str_push(js, '/');  js->state = ST_STRING; break;
            case 'b':  str_push(js, '\b'); js->state = ST_STRING; break;
            case 'f':  str_push(js, '\f'); js->state = ST_STRING; break;
            case 'n':  str_push(js, '\n'); js->state = ST_STRING; break;
            case 'r':  str_push(js, '\r'); js->state = ST_STRING; break;
            case 't':  str_push(js, '\t'); js->state = ST_STRING; break;
            case 'u':  js->unicode_left = 4; js->unicode_acc = 0;
                       js->state = ST_STRING_UNI; break;
            default:   fail(js); break;
            }
            break;

        case ST_STRING_UNI: {
            int h = hexval(c);
            if (h < 0) { fail(js); break; }
            js->unicode_acc = (uint16_t)((js->unicode_acc << 4) | (uint16_t)h);
            if (--js->unicode_left == 0) {
                // Surrogate halves are passed through as-is; the control
                // protocol never puts astral characters in the fields we read.
                push_utf8(js, js->unicode_acc);
                js->state = ST_STRING;
            }
            break;
        }

        case ST_NUMBER:
            if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' ||
                c == '+' || c == '-') {
                value_push(js, c);
                break;
            }
            emit_value(js, JSON_NUMBER);
            if (js->error) break;
            goto again;      // re-handle the delimiter we just consumed

        case ST_LITERAL: {
            static const char *lits[] = { "true", "false", "null" };
            static const json_type types[] = { JSON_TRUE, JSON_FALSE, JSON_NULL };
            size_t k;
            if (js->literal_len >= sizeof(js->literal)) { fail(js); break; }
            js->literal[js->literal_len++] = c;
            for (k = 0; k < 3; k++) {
                size_t n = strlen(lits[k]);
                if (js->literal_len == n && memcmp(js->literal, lits[k], n) == 0) {
                    value_reset(js);
                    emit_value(js, types[k]);
                    break;
                }
            }
            if (k == 3 && js->literal_len >= 5) {
                // "false" is the longest; anything else this long is bad.
                if (js->literal_len > 5) fail(js);
            }
            break;
        }

        case ST_KEY_OR_END:
            if (is_ws(c)) break;
            if (c == '}') { close_container(js); break; }
            js->state = ST_KEY;
            goto again;

        case ST_KEY:
            if (is_ws(c)) break;
            if (c == '"') { key_reset(js); js->in_key = 1; js->state = ST_STRING; break; }
            fail(js);
            break;

        case ST_COLON:
            if (is_ws(c)) break;
            if (c != ':') { fail(js); break; }
            js->in_key = 0;
            js->state = ST_VALUE;
            break;

        case ST_NEXT:
            if (is_ws(c)) break;
            if (c == ',') {
                // Not the *_OR_END variants: a comma must be followed by a
                // real element, so "[1,]" and "{\"a\":1,}" are rejected.
                js->state = js->is_array[js->depth - 1] ? ST_VALUE : ST_KEY;
                break;
            }
            if (c == '}' && !js->is_array[js->depth - 1]) { close_container(js); break; }
            if (c == ']' && js->is_array[js->depth - 1]) { close_container(js); break; }
            fail(js);
            break;

        case ST_DONE:
            if (is_ws(c)) break;
            fail(js);
            break;
        }

        if (js->error) return -1;
    }
    return 0;
}

int json_stream_finish(json_stream *js) {
    if (js->error) return -1;
    // A bare number at the top level only ends at EOF.
    if (js->state == ST_NUMBER) emit_value(js, JSON_NUMBER);
    if (js->error) return -1;
    return (js->state == ST_DONE && js->depth == 0) ? 0 : -1;
}
