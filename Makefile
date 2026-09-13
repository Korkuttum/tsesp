# Host build. The protocol sources under src/ are the same translation units
# that go into the ESP-IDF component; only host/posix_io.c is platform code.

# -Wformat-truncation and friends match what the ESP-IDF build enforces;
# without them a snprintf that silently truncates only fails at cross-compile.
CFLAGS ?= -O2 -Wall -Wextra -Wformat=2 -Wshadow -Wvla -Iinclude -Ihost

CORE := src/blake2s.c src/x25519.c src/poly1305.c src/chacha20poly1305.c src/ts2021.c \
        src/ts_io.c src/ts_noise_stream.c src/hpack.c src/hpack_tables.c \
        src/h2.c src/json_stream.c src/ts_netmap.c src/ts_control.c src/stun.c \
        src/nacl_box.c src/disco.c src/ts_path.c src/ts_client.c \
        src/tsesp_selftest.c src/derp.c src/wireguard.c

# Offline known-answer tests. These are what `make test` runs.
TESTS := build/selftest build/hpack_test build/json_test build/stun_test \
         build/nacl_test build/disco_test build/path_test build/client_test \
         build/wireguard_test build/route_test

# Programs that talk to a real control server.
LIVE  := build/ts2021_handshake build/register_test build/netmap_test build/h2_probe

all: $(TESTS) $(LIVE)

build:
	@mkdir -p build

build/selftest: | build
build/selftest: host/selftest.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/selftest.c $(CORE)

build/hpack_test: | build
build/hpack_test: host/hpack_test.c host/hpack_vectors.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/hpack_test.c host/hpack_vectors.c $(CORE)

build/json_test: | build
build/json_test: host/json_test.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/json_test.c $(CORE)

build/stun_test: | build
build/stun_test: host/stun_test.c host/posix_io.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/stun_test.c host/posix_io.c $(CORE)

build/nacl_test: | build
build/nacl_test: host/nacl_test.c host/nacl_vectors.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/nacl_test.c host/nacl_vectors.c $(CORE)

build/disco_test: | build
build/disco_test: host/disco_test.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/disco_test.c $(CORE)

build/path_test: | build
build/path_test: host/path_test.c host/sim_net.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/path_test.c host/sim_net.c $(CORE)

build/client_test: | build
build/client_test: host/client_test.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/client_test.c $(CORE)

build/wireguard_test: | build
build/wireguard_test: host/wireguard_test.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/wireguard_test.c $(CORE)

build/route_test: | build
build/route_test: host/route_test.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/route_test.c $(CORE)

build/ts2021_handshake: | build
build/ts2021_handshake: host/handshake_test.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/handshake_test.c $(CORE)

build/register_test: | build
build/register_test: host/register_test.c host/posix_io.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/register_test.c host/posix_io.c $(CORE)

build/netmap_test: | build
build/netmap_test: host/netmap_test.c host/posix_io.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/netmap_test.c host/posix_io.c $(CORE)

build/h2_probe: | build
build/h2_probe: host/h2_probe.c host/posix_io.c $(CORE)
	$(CC) $(CFLAGS) -o $@ host/h2_probe.c host/posix_io.c $(CORE)

# Runs every offline test and fails the build if any of them fails.
test: $(TESTS)
	@rc=0; for t in $(TESTS); do \
	  printf '\n=== %s ===\n' "$$t"; ./$$t || rc=1; \
	done; exit $$rc

# Regenerates the HPACK tables and test vectors from RFC 7541 (needs network).
tables:
	python3 tools/gen_hpack.py
	python3 tools/gen_hpack_vectors.py

# NaCl vectors come from libsodium via PyNaCl, in a throwaway venv:
#   python3 -m venv /tmp/tsesp-venv && /tmp/tsesp-venv/bin/pip install pynacl
nacl-vectors:
	/tmp/tsesp-venv/bin/python tools/gen_nacl_vectors.py

clean:
	rm -rf build

.PHONY: all test tables nacl-vectors clean

# Live DERP test needs TLS on the host; the device uses mbedTLS instead.
OPENSSL_PREFIX ?= /opt/homebrew/opt/openssl@3
build/derp_test: | build
build/derp_test: host/derp_test.c host/openssl_io.c host/posix_io.c $(CORE)
	$(CC) $(CFLAGS) -I$(OPENSSL_PREFIX)/include -o $@ host/derp_test.c \
	  host/openssl_io.c host/posix_io.c $(CORE) \
	  -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
