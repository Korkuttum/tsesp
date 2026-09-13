# tsesp

A Tailscale client written from scratch for a classic ESP32 (520 KB SRAM, no
PSRAM). `src/` and `include/` are portable C compiled for both the POSIX test
harness and the ESP-IDF firmware; `firmware/main/` is the only ESP-specific
code. README.md is in Turkish and is the project's record of what was measured
and what was only assumed - keep that distinction when adding to it.

## Building

Host, no board needed:

```
make            # every test and probe
make test       # the offline suite; must stay green
```

Firmware (ESP-IDF v5.3.1, esp32 target):

```
rm -f firmware/sdkconfig      # see the trap below
cd firmware && idf.py set-target esp32 && idf.py build
idf.py -p <port> flash monitor
```

**The sdkconfig trap.** `firmware/sdkconfig` is gitignored, and ESP-IDF reads
`sdkconfig.defaults` only when creating it - so a build tree from before an
option was added silently drops it. Deleting `firmware/sdkconfig` is the fix,
and `ota.c` and `tun.c` carry `#error`s that say so if the options they need
are missing. Never work around those by hand-editing sdkconfig.

Never run `erase-flash`: `nvs` holds the Wi-Fi credentials and the tailnet
identity, and `idf.py flash` leaves it alone.

## Things that are easy to get wrong

- **NAPT lives on the tunnel interface** (`tun_start`), not the Wi-Fi one.
  esp-lwip translates a forwarded packet only when the interface it arrived on
  has the flag and the one it leaves by does not. Moving it to the Wi-Fi side
  looks more natural and silently kills subnet routing; that bug is written up
  in README.md.
- **Protocol code never touches a socket.** Everything in `src/` goes through
  `ts_io`; `host/posix_io.c` and `firmware/main/esp_io.c` are the only
  implementations. A new dependency on a platform header in `src/` is a bug.
- **The netmap is never held whole in memory.** Peers are streamed to a
  callback and forgotten. Buffering the response would undo the reason this
  fits on the chip at all.
- The status page is built into one heap buffer in `portal.c`; panels render in
  order, so overflowing it truncates the last tab. Count the format specifiers
  against the arguments - they are long lists.

## Testing

`make test` is the offline suite and is expected to pass before any commit.
The `build/*_test` binaries that talk to the live control plane need
`tsesp-keys.bin` from `register_test` and are not part of it. Firmware changes
cannot be tested without a board: say so plainly rather than implying they were
verified.

## Commits

Subject is a sentence about what changed, no `type:` prefix, e.g. "Retry the
stored network instead of sitting in the setup portal forever". The body
explains why, names what was measured, and says outright what went untested.
