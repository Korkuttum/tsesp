// HPACK (RFC 7541) for the ts2021 control channel.
//
// Sized for a device with no PSRAM: the decoder owns a small dynamic table
// with a byte arena, and hands headers to a callback instead of building a
// list. The encoder never uses a dynamic table at all — it emits static-table
// indices where it can and literals otherwise, which keeps our side stateless.
#ifndef HPACK_H
#define HPACK_H

#include <stddef.h>
#include <stdint.h>

#define HPACK_STATIC_COUNT 61
#define HPACK_HUFF_MAX_BITS 30

// Dynamic table budget. We advertise this as SETTINGS_HEADER_TABLE_SIZE so the
// server's encoder never indexes more than we can hold.
#ifndef HPACK_DYN_ARENA
#define HPACK_DYN_ARENA 2048
#endif
#ifndef HPACK_DYN_MAX_ENTRIES
#define HPACK_DYN_MAX_ENTRIES 32
#endif
// Longest single header name or value we will materialize.
#ifndef HPACK_SCRATCH
#define HPACK_SCRATCH 512
#endif

typedef struct {
    const char *name;
    const char *value;
} hpack_static_entry;

extern const hpack_static_entry hpack_static_table[HPACK_STATIC_COUNT];
extern const uint8_t  hpack_huff_bits[257];
extern const uint32_t hpack_huff_code[257];
extern const uint32_t hpack_huff_first_code[HPACK_HUFF_MAX_BITS + 1];
extern const uint16_t hpack_huff_first_index[HPACK_HUFF_MAX_BITS + 1];
extern const uint16_t hpack_huff_count[HPACK_HUFF_MAX_BITS + 1];
extern const uint16_t hpack_huff_symbol[257];

typedef struct {
    uint16_t name_off, name_len;
    uint16_t value_off, value_len;
} hpack_dyn_entry;

typedef struct {
    // Entries are newest-first: index 0 is HPACK index 62. Their strings sit
    // in the arena in insertion order, so the oldest occupies the lowest
    // offsets and eviction is a memmove down.
    hpack_dyn_entry ents[HPACK_DYN_MAX_ENTRIES];
    uint8_t  arena[HPACK_DYN_ARENA];
    int      count;
    size_t   arena_used;
    size_t   size;       // RFC 7541 4.1 accounting: sum of len+len+32
    size_t   max_size;   // current limit, changeable by a size update
    size_t   limit;      // hard ceiling we advertised in SETTINGS
    uint8_t  scratch[HPACK_SCRATCH];
} hpack_decoder;

// Called once per decoded header. `name` and `value` are NOT NUL-terminated
// and are only valid for the duration of the call.
typedef void (*hpack_header_cb)(void *ctx,
                                const char *name, size_t name_len,
                                const char *value, size_t value_len);

void hpack_decoder_init(hpack_decoder *d, size_t max_size);

// Decodes one header block. Returns 0 on success, negative on a malformed
// block (bad index, oversized string, bad Huffman padding, truncated input).
int hpack_decode(hpack_decoder *d, const uint8_t *in, size_t inlen,
                 hpack_header_cb cb, void *ctx);

// ---- Encoder (stateless) ----

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   len;
    int      overflow;
} hpack_encoder;

void hpack_encoder_init(hpack_encoder *e, uint8_t *buf, size_t cap);

// Appends one header, preferring a static-table index for the name (and for
// the whole field when name+value both match). Never indexes into a dynamic
// table, so the peer's decoder state stays empty.
void hpack_encode_header(hpack_encoder *e,
                         const char *name, const char *value);

// Emits a dynamic table size update (RFC 7541 6.3). Send 0 first if you want
// to tell the peer you keep no dynamic table.
void hpack_encode_table_size_update(hpack_encoder *e, size_t size);

// Returns 0 if everything fit, -1 if the buffer overflowed at any point.
int hpack_encoder_finish(hpack_encoder *e, size_t *out_len);

#endif
