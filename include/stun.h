// STUN binding requests (RFC 8489), enough to learn our public ip:port.
//
// Pure message building and parsing — no sockets — so the same code runs on
// lwIP. Tailscale's DERP servers answer STUN on port 3478, and the same UDP
// socket carries WireGuard and DISCO traffic, so responses must be told apart
// from those by their first byte (STUN's top two bits are always zero).
#ifndef STUN_H
#define STUN_H

#include <stddef.h>
#include <stdint.h>

#define STUN_HEADER_LEN 20
#define STUN_TXID_LEN   12

// Fills a 20-byte binding request. `txid` must be 12 random bytes; keep it to
// match the response.
void stun_build_request(uint8_t out[STUN_HEADER_LEN], const uint8_t txid[STUN_TXID_LEN]);

// True if the datagram looks like STUN rather than WireGuard or DISCO.
int stun_looks_like_stun(const uint8_t *buf, size_t len);

// Parses a binding success response. On success writes the reflexive address
// (4 bytes for IPv4, 16 for IPv6) and port, and sets *is_ipv6.
// Returns 0 on success, -1 if malformed, -2 if the transaction id does not
// match, -3 if the server returned an error response.
int stun_parse_response(const uint8_t *buf, size_t len,
                        const uint8_t txid[STUN_TXID_LEN],
                        uint8_t addr[16], int *is_ipv6, uint16_t *port);

// Formats an address as "1.2.3.4:41641" or "[::1]:41641".
void stun_format_addr(char *out, size_t cap,
                      const uint8_t addr[16], int is_ipv6, uint16_t port);

#endif
