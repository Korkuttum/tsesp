// The tunnel as a network interface.
//
// Until now WireGuard packets went in and out but nothing above cared. This
// registers an lwIP netif for the tailnet range, so the device answers on its
// 100.x address like any other host: ping, the status page, anything bound to
// that interface.
#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Called by lwIP when it wants a packet sent to `dst` inside the tailnet.
// Returns 0 if it went out.
typedef int (*tun_send_fn)(const uint8_t *ip_packet, size_t len, uint32_t dst_be);

// Brings the interface up with our tailnet address. The netmask covers the
// whole 100.64.0.0/10 range so every peer routes here.
int  tun_start(uint32_t our_ip_be, tun_send_fn send);

// Hands a decrypted packet to the stack.
void tun_input(const uint8_t *ip_packet, size_t len);

bool tun_is_up(void);
void tun_stats(uint32_t *in, uint32_t *out);

// The subnet routing half of the same traffic, kept apart because it is the
// part that breaks on its own: `fwd_in` counts packets a peer sent us for
// some other address (nothing here means the route never reached the peer),
// `fwd_out` the answers that came back off the LAN, and `too_big` packets
// dropped for being longer than the tunnel MTU.
void tun_route_stats(uint32_t *fwd_in, uint32_t *fwd_out, uint32_t *too_big);

// lwIP's own view, which is the half our counters cannot see: `fw` counts
// packets the stack actually forwarded out of an interface, `rterr` those it
// had no route for, `drop` those it discarded.
void tun_ip_stats(uint32_t *fw, uint32_t *rterr, uint32_t *drop);

// What the Wi-Fi interface itself saw. `hooked` says the watch is installed
// at all - without it the other two are silence, not evidence. `untranslated`
// counts forwarded packets that left still carrying a tailnet source, and
// `replies` answers from a LAN web server on their way back.
void tun_trace_stats(bool *hooked, uint32_t *untranslated, uint32_t *replies);

// Everything the Wi-Fi interface was asked to send, and the part of it aimed
// at another machine on this LAN. The second is what a forwarded packet looks
// like from here, and zero means it never reached the interface at all.
void tun_wifi_out(uint32_t *total, uint32_t *to_lan);

// Packets that left the Wi-Fi interface for the same address and port the
// last forwarded packet was aimed at. This is the forwarded flow itself,
// separated from this device's own traffic to the same machine.
uint32_t tun_fwd_reached_wifi(void);

// Packets that came back from that same machine. Zero against a non-zero
// tun_fwd_reached_wifi() means the target never answered; both non-zero moves
// the fault to what happens to the answer here.
uint32_t tun_fwd_answered(void);

#endif
