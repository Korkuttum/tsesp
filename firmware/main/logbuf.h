// The log, kept in RAM so it can be read without a cable.
#ifndef LOGBUF_H
#define LOGBUF_H

#include <stddef.h>
#include <stdbool.h>

// Tees every ESP_LOG line into a ring buffer. Call once, as early as
// possible: what goes wrong at boot is what a cable is usually needed for.
void logbuf_start(void);

// Copies up to `cap` bytes of the ring, oldest first, into `out`. Returns
// how many. Not NUL-terminated.
size_t logbuf_read(char *out, size_t cap);

#endif
