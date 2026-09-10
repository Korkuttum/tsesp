#ifndef ESP_IO_H
#define ESP_IO_H
#include "ts_io.h"
typedef struct { ts_io io; int fd; } esp_io;
// Connects a TCP socket and wraps it as a ts_io. Returns 0 on success.
int  esp_io_connect(esp_io *eio, const char *host, const char *port, int timeout_s);
void esp_io_close(esp_io *eio);
#endif
