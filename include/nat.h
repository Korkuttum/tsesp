// Address translation for a subnet router, done here rather than by the stack.
//
// esp-lwip has NAPT, and the forward half of it works: a packet from the
// tailnet leaves with this device's LAN address. The reverse half does not -
// the answer comes back, is not recognised as belonging to a mapping, keeps
// this device's address, looks like it was addressed here, and is dropped.
// Measured on the board: target answered 3, went back into the tunnel 0.
//
// So the table lives here instead, where both directions are already in hand,
// and where it can be tested on a host rather than by asking someone to open
// a page on their phone.
//
// Deliberately plain C over a byte buffer: no lwIP, no sockets, no ESP.
#ifndef NAT_H
#define NAT_H

#include <stddef.h>
#include <stdint.h>

#ifndef NAT_MAX
#define NAT_MAX 32
#endif
// A mapping with nothing on it for this long is free for reuse. WireGuard
// keeps a tunnel alive far longer than a TCP connection idles, so this is
// about table space, not about correctness.
#define NAT_IDLE_MS 120000
// Source ports handed out. Above the ephemeral range this device uses for
// itself, so a translated flow can never collide with a local socket.
#define NAT_PORT_FIRST 40000
#define NAT_PORT_LAST  49999

typedef struct {
    uint32_t peer_ip;      // the tailnet address that started this
    uint32_t lan_ip;       // the machine on the LAN it is talking to
    uint16_t peer_port;    // its source port, or ICMP echo id
    uint16_t lan_port;     // the port on the LAN machine, or the same id
    uint16_t mport;        // what its source port became on the way out
    uint8_t  proto;
    uint8_t  in_use;
    uint32_t last_ms;
} nat_entry;

typedef struct {
    nat_entry e[NAT_MAX];
    uint16_t  next_port;
    uint32_t  rewrites_out, rewrites_in, misses_in, full;
} nat_table;

void nat_init(nat_table *t);

// A packet from the tunnel, addressed to the LAN. Rewrites its source to
// `lan_ip` and its source port to one of ours, in place, fixing every
// checksum. Returns 1 when it rewrote, 0 when it left the packet alone (not
// IPv4, a protocol without ports, or the table is full).
int nat_out(nat_table *t, uint8_t *pkt, size_t len, uint32_t lan_ip, uint32_t now_ms);

// A packet arriving from the LAN addressed to this device. If it belongs to
// a mapping, rewrites the destination back to the peer that started the flow
// and returns 1, with *peer_ip set; the caller should then put it into the
// tunnel instead of handing it to the stack. Returns 0 when it is not ours.
int nat_in(nat_table *t, uint8_t *pkt, size_t len, uint32_t our_lan_ip,
           uint32_t now_ms, uint32_t *peer_ip);

// How many live mappings there are, for the status page.
int nat_live(const nat_table *t, uint32_t now_ms);

// True when every checksum in the packet verifies, recomputed in full rather
// than adjusted. A rewrite that gets this wrong produces a packet the far end
// drops without a word, which looks exactly like a machine that will not
// answer.
int nat_csum_ok(const uint8_t *pkt, size_t len);

#endif
