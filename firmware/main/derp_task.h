#ifndef DERP_TASK_H
#define DERP_TASK_H
#include <stdint.h>
#include <stdbool.h>
// Starts the relay connection. It waits until a netmap has told us which
// relays exist, then keeps one connection alive.
void derp_task_start(const uint8_t node_priv[32], const uint8_t node_pub[32]);
// Called when a netmap arrives, with the first relay in the map.
void derp_task_set_region(uint16_t region_id, const char *host, const char *code);
// The region we are actually connected to, or 0. This is what gets reported
// to the control plane as our home relay.
uint16_t derp_task_region(void);
bool     derp_task_connected(void);
void     derp_task_stats(uint32_t *sent, uint32_t *received);
// True once the relay region changed since the last map request, so the
// control loop knows to reconnect and report it.
bool     derp_task_take_changed(void);
#endif
