# Wraps the portable protocol code at the repository root. Nothing here is
# ESP-specific: if a file in ../../../src stops compiling for xtensa, it has
# picked up a host dependency it should not have.
set(TSESP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../..")

idf_component_register(
    SRCS
        "${TSESP_ROOT}/src/blake2s.c"
        "${TSESP_ROOT}/src/x25519.c"
        "${TSESP_ROOT}/src/poly1305.c"
        "${TSESP_ROOT}/src/chacha20poly1305.c"
        "${TSESP_ROOT}/src/nacl_box.c"
        "${TSESP_ROOT}/src/ts2021.c"
        "${TSESP_ROOT}/src/ts_io.c"
        "${TSESP_ROOT}/src/ts_noise_stream.c"
        "${TSESP_ROOT}/src/hpack.c"
        "${TSESP_ROOT}/src/hpack_tables.c"
        "${TSESP_ROOT}/src/h2.c"
        "${TSESP_ROOT}/src/json_stream.c"
        "${TSESP_ROOT}/src/ts_netmap.c"
        "${TSESP_ROOT}/src/ts_control.c"
        "${TSESP_ROOT}/src/stun.c"
        "${TSESP_ROOT}/src/disco.c"
        "${TSESP_ROOT}/src/ts_path.c"
        "${TSESP_ROOT}/src/ts_client.c"
        "${TSESP_ROOT}/src/derp.c"
        "${TSESP_ROOT}/src/wireguard.c"
        "${TSESP_ROOT}/src/nat.c"
        "${TSESP_ROOT}/src/tsesp_selftest.c"
    INCLUDE_DIRS
        "${TSESP_ROOT}/include"
)
