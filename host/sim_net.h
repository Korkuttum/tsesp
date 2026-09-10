// A simulated UDP network with simulated NATs, so path discovery can be
// tested against the behaviours real home routers actually have.
#ifndef SIM_NET_H
#define SIM_NET_H

#include <stdint.h>
#include <stddef.h>
#include "ts_path.h"

typedef enum {
    NAT_NONE = 0,     // on the open internet
    NAT_FULL_CONE,    // endpoint-independent mapping and filtering
    NAT_RESTRICTED,   // mapping is shared, but only hosts we wrote to may reply
    NAT_SYMMETRIC     // a different external port per destination: the case
                      // that defeats hole punching and forces a relay
} nat_type;

#define SIM_MAX_HOSTS   4
#define SIM_MAX_MAPS    16
#define SIM_MAX_SEEN    8
#define SIM_MAX_QUEUE   256
#define SIM_MAX_PACKET  512

typedef struct {
    uint8_t  lan_ip[16];
    uint16_t lan_port;
    uint8_t  dst_ip[16];      // only meaningful for symmetric NAT
    uint16_t dst_port;
    uint16_t pub_port;
    uint8_t  seen_ip[SIM_MAX_SEEN][16];
    uint16_t seen_port[SIM_MAX_SEEN];
    int      nseen;
    int      used;
} sim_map;

typedef struct {
    nat_type type;
    uint8_t  pub_ip[16];
    uint16_t next_port;
    sim_map  maps[SIM_MAX_MAPS];
} sim_nat;

typedef struct sim_net sim_net;

typedef struct {
    sim_net *net;
    int      index;
    char     name[16];

    ts_path_engine eng;
    uint8_t  disco_priv[32], disco_pub[32], node_pub[32];

    uint8_t  lan_ip[16];
    uint16_t lan_port;
    sim_nat *nat;             // NULL when on the open internet

    // What control would have learned about this host, i.e. the mapping it
    // created towards the STUN server.
    uint8_t  pub_ip[16];
    uint16_t pub_port;

    uint32_t rx_count, tx_count, dropped;
} sim_host;

typedef struct {
    uint32_t due_ms;
    int      dst_host;
    uint8_t  src_ip[16];
    uint16_t src_port;
    uint8_t  data[SIM_MAX_PACKET];
    size_t   len;
    int      used;
} sim_packet;

struct sim_net {
    uint32_t   now_ms;
    sim_host   hosts[SIM_MAX_HOSTS];
    int        nhosts;
    sim_nat    nats[SIM_MAX_HOSTS];
    int        nnats;
    sim_packet queue[SIM_MAX_QUEUE];
    uint32_t   latency_ms;
    uint32_t   loss_permille;   // deterministic pseudo-random loss
    uint32_t   rng;
    uint32_t   delivered, dropped_loss, dropped_nat;
    int        partitioned;     // drop everything, to simulate a path dying
};

void sim_net_init(sim_net *n, uint32_t latency_ms);
sim_nat *sim_add_nat(sim_net *n, nat_type type, const char *pub_ipv4);
int  sim_add_host(sim_net *n, const char *name, const char *lan_ipv4,
                  uint16_t port, sim_nat *nat);
// Runs the mapping a STUN lookup would create, filling in pub_ip/pub_port.
void sim_host_learn_public(sim_net *n, int host);
// Tells `a` about `b`'s public address, the way the control plane would.
void sim_introduce(sim_net *n, int a, int b, uint8_t score);
void sim_run(sim_net *n, uint32_t ms);
void sim_start(sim_net *n);
void sim_v4(uint8_t out[16], const char *dotted);

#endif
