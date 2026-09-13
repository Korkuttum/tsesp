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

#endif
