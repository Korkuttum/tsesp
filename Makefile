CFLAGS ?= -O2 -Wall -Wextra -Iinclude
SRC := src/blake2s.c src/x25519.c src/chacha20poly1305.c src/ts2021.c

all: build/selftest build/ts2021_handshake

build:
	@mkdir -p build

build/selftest: build $(SRC) host/selftest.c
	$(CC) $(CFLAGS) -o $@ host/selftest.c $(SRC)

build/ts2021_handshake: build $(SRC) host/handshake_test.c
	$(CC) $(CFLAGS) -o $@ host/handshake_test.c $(SRC)

test: build/selftest
	./build/selftest

clean:
	rm -rf build

.PHONY: all test clean

build/hpack_test: build src/hpack.c src/hpack_tables.c host/hpack_test.c host/hpack_vectors.c
	$(CC) $(CFLAGS) -Ihost -o $@ host/hpack_test.c host/hpack_vectors.c src/hpack.c src/hpack_tables.c

build/json_test: build src/json_stream.c host/json_test.c
	$(CC) $(CFLAGS) -o $@ host/json_test.c src/json_stream.c

CORE := src/blake2s.c src/x25519.c src/chacha20poly1305.c src/ts2021.c \
        src/ts_io.c src/ts_noise_stream.c src/hpack.c src/hpack_tables.c \
        src/h2.c src/json_stream.c src/ts_netmap.c src/ts_control.c src/stun.c

build/register_test: build $(CORE) host/register_test.c host/posix_io.c
	$(CC) $(CFLAGS) -Ihost -o $@ host/register_test.c host/posix_io.c $(CORE)

build/h2_probe: build $(CORE) host/h2_probe.c host/posix_io.c
	$(CC) $(CFLAGS) -Ihost -o $@ host/h2_probe.c host/posix_io.c $(CORE)

build/stun_test: build src/stun.c host/stun_test.c host/posix_io.c
	$(CC) $(CFLAGS) -Ihost -o $@ host/stun_test.c host/posix_io.c src/stun.c src/ts_io.c

build/netmap_test: build $(CORE) host/netmap_test.c host/posix_io.c
	$(CC) $(CFLAGS) -Ihost -o $@ host/netmap_test.c host/posix_io.c $(CORE)
