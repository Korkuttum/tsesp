# tsesp — a Tailscale client written from scratch for the ESP32-WROOM-32U

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Portable C, written to fit a classic PSRAM-less ESP32 (520 KB SRAM). The
protocol code never touches a socket; the same `.c` files compile both in the
POSIX test harness and in the ESP-IDF firmware.

## Status

| Stage | Work | Status |
|---|---|---|
| 1 | Crypto: BLAKE2s (keyed included), HKDF, X25519, ChaCha20-Poly1305 | ✅ RFC test vectors |
| 2 | ts2021 Noise IK handshake + record framing | ✅ against the live server |
| 3 | HPACK + HTTP/2 + streaming JSON | ✅ RFC 7541 Appendix C; every split point |
| 4 | `/machine/register` → registering on the tailnet | ✅ on the board |
| 5 | `/machine/map` → netmap, peers, DERP map | ✅ on the board, long-lived connection |
| 6 | NaCl box + DISCO + STUN | ✅ verified against libsodium/RFC 5769 |
| 7 | Path discovery (ping/measure/pick/keep alive) | ✅ fake NATs + real peers |
| 8 | DERP relay (TLS) — both presence **and** data | ✅ tested with the direct path down |
| 9 | WireGuard (Noise IKpsk2) | ✅ tunneled with real Tailscale nodes |
| 10 | lwIP interface — the device shows up at its own 100.x address | ✅ 0% ping loss, the status page over the tunnel |
| 11 | NAPT subnet routing | ✅ NAPT fix confirmed on the board; in daily use routing to the home network |
| 12 | ESP-IDF firmware: AP mode, setup page, NVS | ✅ |
| 13 | OTA: firmware updates over the tunnel + rollback | ✅ the device's only update path since the first wired flash - dozens of updates, no lost device |

The whole chain runs on the board:

```
Wi-Fi setup (AP + setup page)
  -> TCP :80 -> /ts2021 upgrade -> Noise IK -> HTTP/2 -> register -> netmap
  -> DERP relay (TLS 443)          <- presence and the fallback data path
  -> DISCO ping/pong               -> direct path (NAT hole punching)
  -> WireGuard (Noise IKpsk2)      -> the tunnel
  -> lwIP interface 100.64.0.0/10  -> the device is visible on the tailnet
  -> IP forward + NAPT             -> reaching devices on the home network
```

Measured (ESP32-D0WD-V3, 240 MHz):

```
ping to the tailnet address    0% loss, 20 ms average    (direct path)
                                0% loss, 480 ms average   (relay only)
status page over the tunnel    http 200, 0.36 s
X25519                         180 ms      <- the slowest single operation
ChaCha20-Poly1305              1.35 MB/s   <- the data plane's ceiling
free heap (everything up)      ~97 KB
```

## Where this stands

The device has been running since the bring-up checklist below was completed:
subnet routing to the home network works day to day, and every change since —
including everything in this document past this point — has shipped to it as
an OTA update over the tunnel, never a second trip with a cable.

Unverified still: stability measured continuously over hours or days rather
than pieced together across many separate boots, and behavior under real
load (this is a low-traffic device: SSH, sensors, a status page someone
checks occasionally).

<details>
<summary>First bring-up checklist (completed - kept as a reference for
setting up a new device)</summary>

The last two changes at the time — moving NAPT to the right interface, and
OTA — had never been compiled; there was no ESP-IDF in the environment they
were written in, and the partition table had just changed, so that first
flash had to be wired. Everything after it went over the tunnel:

```
rm -f firmware/sdkconfig                       # skip this and the build stops with an #error
cd firmware && idf.py set-target esp32 && idf.py build
idf.py -p /dev/cu.usbserial-XXXX flash monitor # NOT erase-flash: keep nvs
```

What followed, in order, and **all of it doable from home** — no need to wait
for the village house:

1. **The boot log.** Four lines: `ota: running ota_0`,
   `tun: interface up: 100.x.x.x/10`, `tun: NAPT on the tunnel side`,
   `offering 192.168.x.0/24 as a route`.
2. **Approve the route** — admin console → Machines → the device → Subnet
   routes. The log should print `route ... approved`, and the status page
   should say "approved".
3. **Reach the home network.** Turn the phone's Wi-Fi off, ping a home-network
   address from mobile data. `tun: routing for the tailnet: ... -> ...` should
   print once and the ping should return. This is where the NAPT fix is either
   confirmed or disproved; the counters (Network → Remote access to the home
   network) say which half it got stuck on.
4. **OTA.** Bump the version, build a second image, upload it over the tunnel,
   watch the log go `ON TRIAL` → `confirmed`.
5. **Try the rollback too**, because an untested seatbelt is not a seatbelt:
   point it at a `CONTROL_HOST` that doesn't exist and flash it. No netmap
   ever arrives, the image never confirms itself; a manual restart should send
   the bootloader back to the old slot and the page should say "the most
   recently uploaded firmware could not confirm itself".
6. **At the village house.** If the network there is a different range, the
   device advertises the new route itself, but it still needs **approving
   again** in the console.

</details>

**Speed, actually measured.** The Network tab's "Speed test" button
(`/api/speedtest`) downloads 1 MB from the browser to the device and times it
in JS. Pulling the same 1 MB twice, remotely from home: 63 KB/s over the relay
(DERP fra) (0.50 Mbps, 16.6 s), then 52 KB/s (0.42 Mbps, 20 s) on a direct path
that came up a few seconds later. Both are below the "1-3 Mbps" guess this
document used to carry — that number was never measured, it was an assumption;
these two are a single real measurement. Not repeated, and what a different
signal strength or a different home network would give is unknown.

### NAPT was on the wrong interface

The first attempt in the field: the device answers pings to its own `100.x`
address, nothing on the home network does, and the log has not one line about
it. Found without the board in hand, purely by reading the code and the
esp-lwip source.

`ip_napt_enable(addr, 1)` doesn't flag an address, it flags an **interface**,
and in esp-lwip the flag doesn't mean "translate traffic to this address," it
means "translate traffic *arriving from* this interface":

```c
/* ip4_forward() - the netif is the OUTGOING interface */
if (!netif->napt) {
    if (ip_napt_forward(p, iphdr, inp, netif) != ERR_OK) return;
}

/* ip_napt_forward() */
if (!inp->napt) return ERR_OK;
...
ip_napt_modify_addr(iphdr, &iphdr->src, ip_2_ip4(&outp->ip_addr)->addr);
```

So translation only happens when the flag is set on the interface the packet
**came in on**, and clear on the one it **leaves by**; the new source address
is also read from the outgoing interface. The flag had been set on the Wi-Fi
interface — and for a packet arriving from the tailnet and leaving onto the
LAN, that Wi-Fi interface is exactly the outgoing one, so `if (!netif->napt)`
was **suppressing** the translation. The packet left for the home network with
its `100.x` source address intact, the target device sent its reply to the
modem, and since the modem has no route to 100.64/10, the reply died there.
Silent on both ends.

Worse, the wrong flag was enabling the opposite direction: traffic from the
LAN toward the tailnet was being masqueraded — the one direction nobody
wanted. The flag belongs on the tunnel interface, and one flag can't cover
both directions at once: in esp-lwip's model, the NAPT'd interface is the
"inside." For a subnet router, the inside is the tailnet.

The flag moved into `tun_start()`. A side benefit: the address NAPT writes is
no longer configured anywhere, it's read from the outgoing interface, so
there's nothing left to refresh when the modem hands out a new DHCP address.

Ruled-out hypothesis: "the sdkconfig on flash is stale, `CONFIG_LWIP_IP_FORWARD`
might never have been turned on" (`sdkconfig` is gitignored, and ESP-IDF
doesn't read `sdkconfig.defaults` if the file already exists). Can't be it:
`ip_napt_enable`'s declaration in `lwip_napt.h` is wrapped in
`#if ESP_LWIP / #if IP_FORWARD / #if IP_NAPT`. If either were off, the firmware
couldn't have compiled and linked, so both are on in the image that's on the
board.

**Confirmed since.** The fix was worked out by reading the source with no
board in hand at the time; it has since been flashed and is what subnet
routing to the home network runs on day to day.

### The device answers pings on its own 100.x address but not on the home network

This is the classic subnet-routing failure and it has exactly one meaning:
the tunnel works (the device's own address answers), but somewhere the path
to the LAN is broken. The break has two halves and from the outside they look
identical — either the request never gets here at all, or it gets here and
the reply never comes back. The status page's **Network → Remote access to
the home network** section tells them apart:

| Route approval | Incoming requests | Replies sent back | Problem |
|---|---|---|---|
| awaiting approval | 0 | 0 | The route isn't approved in the admin console |
| approved | 0 | 0 | The remote device isn't using the route, or there's an address collision |
| approved | rising | 0 | The target device isn't replying — or the NAPT fix hasn't been flashed |
| approved | rising | rising | The path works; the problem is on the application/port side |

"Route approval" comes from the device's own netmap: an approved route comes
back in the node's `AllowedIPs`, an unapproved one shows up nowhere. So
"advertised" and "in use" are two separate things, and the device now says
which one it's in. It shows up as a single log line too:

```
route 192.168.1.0/24 approved; peers can reach that network through this device
route 192.168.1.0/24 advertised but NOT approved; approve it in the admin console
tun: routing for the tailnet: 100.101.7.3 -> 192.168.1.50 (subnet route is in use)
```

The third line prints once, on the first packet actually routed — it's there
if the request reached the device, absent if it didn't.

If incoming requests stay at zero, in order:

1. **Approval.** Admin console → Machines → the device → Subnet routes →
   approve the route.
2. **Does the remote device accept the route.** Off by default on Linux:
   `tailscale up --accept-routes`. Mac/Windows/iOS/Android accept it.
   `tailscale status` should show the route next to the device.
3. **Address collision.** The most common cause, and it never shows up in any
   log: if the local network you're standing on is also `192.168.1.0/24` (the
   default on most modems in Turkey), a packet bound for `192.168.1.50` goes
   to its own network and never enters the tunnel at all. Test:
   `tailscale ping 192.168.1.50` — "no matching route" means 1 or 2, an answer
   from your own network means a collision. The fix is putting the village
   house modem's LAN on a different range (e.g. `192.168.37.0/24`); the device
   updates the route itself once it sees the new address, but **the new route
   still needs approving again in the console**.
4. **Try it from mobile data.** Turning off Wi-Fi rules out point 3 in one
   move.

If incoming requests rise but no reply comes back, the problem isn't this
device: the target is off, its address changed under DHCP, or its firewall
doesn't answer ICMP (the Windows default). Thanks to NAPT, packets arrive on
the home network looking like they came from this device's own address, so
the target doesn't need to know about the tailnet at all — it just sees an
ordinary neighbor on the same subnet. Pinging from another device on the same
home network is the fastest way to confirm the target is actually up.

The third counter in the same section ("Dropped (too large)") counts packets
dropped for being longer than the tunnel's MTU (1280 bytes). Unrelated to
ping; if it's nonzero the symptom is "connects fine but large transfers stall."

### Modem restart: two bugs

"Recovering after Wi-Fi drops" was on the list, and it broke in the field —
once the modem restarted, the device never reconnected. Two separate bugs
turned up underneath, and the second one only became visible once the first
was fixed.

**1. The reconnect budget.** The five-try counter was only ever reset by
`GOT_IP`, and once it ran out it set `BIT_FAILED` — but the only place waiting
on that bit was `net_start()`, which had already returned at boot. The bit
fell into a void, and `esp_wifi_connect()` was never called again. Five tries
burned through in a few seconds, well before the modem had even finished
booting. The budget now applies only to the *first* join; after that it's
unlimited, with a wait that climbs from 2 s to 30 s, running in its own task.

**2. `WIFI_FAST_SCAN`.** Writing `wifi_config_t cfg = {0}` leaves `scan_method`
at zero, which means fast scan: stop scanning at the **first** AP with a
matching SSID and connect to it, regardless of signal. With a mesh at home
this is a coin flip — and it lands wrong exactly when the modem is restarting,
because the upstairs node that never lost power is the first to answer. The
device locks onto it at -80 dBm, can't finish DHCP, times out on `bcn_timeout`
and lands right back in the same spot. `WIFI_ALL_CHANNEL_SCAN` +
`WIFI_CONNECT_AP_BY_SIGNAL` scans every channel and picks the strongest.

A third thing got fixed too, though it hadn't broken in the field: everything
tied to the LAN (the advertised route, the address NAPT writes, the "is this
peer on my network" test) was derived once, at boot. If the modem handed out a
different IP, all of it went stale and subnet routing died without leaving a
single line in the log. It's now re-derived whenever the address changes.

Measured in the field (the modem was unplugged twice, left off for ~2 min):

```
drop detected              2 s after the beacon timeout
retry interval              2, 4, 8, 16, 30, 30 s ...  (no ceiling)
while the modem was off    latched onto the upstairs node 3 times, -71..-78, no address
once the modem came back   the scan in that round picked the -48 modem
full recovery               97 s after the drop: ip, control plane,
                            netmap, DERP, 4 WireGuard tunnels
```

Most of the 97 seconds is the modem's own boot time; the device connected on
the first scan after the modem came back. The status page's "Reconnect count"
makes this visible.

One scenario is still unverified: if the device **can** get a DHCP address
from the weak node, it declares itself "connected" and stays there — it
doesn't rescan while connected, so it would stay stuck on -80 even once the
modem is back. Neither test hit this (the weak node never handed out an
address), so no "signal is bad, look for something better" behavior was
written.

### The setup portal used to be a dead end

If the device couldn't join its saved network at boot, it opened the setup
portal and stayed there in a `while (1)` — never trying the saved network
again. This is the boot-time twin of the modem-restart bug: after a power cut,
the board is up in two seconds, the modem takes a minute; the board gives up
after ~15 seconds and opens the portal, then sits there even once its own
network comes back. Nobody can press reset at the village house either.

The give-up threshold at boot changed too. "Five tries" was the wrong unit —
five tries burn through in seconds, far shorter than the modem's own boot
time. The measure is now time: **90 seconds**. But a flat 90 seconds still
treats two different situations as one, and ESP-IDF already tells them apart
— `WIFI_REASON_NO_AP_FOUND` (the network simply isn't there yet, worth
waiting, the modem might be booting) versus `AUTH_FAIL` / `HANDSHAKE_TIMEOUT`
(the password doesn't work, waiting changes nothing). Two authentication
rejections in a row opens the portal immediately; every other reason gets the
full 90 seconds of patience. The reason code now prints to the log too, so
"why won't it connect" gets a single line next time instead of a guess.

While the portal is open, the saved network is now retried every two minutes:
since the boot path itself is already well-tested, the retry is just an
`esp_restart()`. Two guards on it — the first five minutes never retry (so
whoever just carried the device in has time to join the setup network and
open the page), and a retry is postponed if the setup page was opened in the
last five minutes (restarting would erase a half-typed password). If there's
no saved network at all, it never retries.

If the device gets moved somewhere its saved network can't reach, the retry
simply never catches, and its only cost is one join attempt every two
minutes.

The setup network's name is now logged on every boot (`tsesp-xxxx`), not only
when the portal opens: knowing the name before you need it saves a trip.

**None of these paths ran in the field** — the device has connected on every
boot so far, so neither the 90-second wait, nor the reason-based split, nor
the retry-from-the-portal path has fired even once. What was confirmed is
that normal boot still works. Two bugs turned up while writing this, and both
were caught just by looking at the output (a log line was printing the AP
name before it was computed; the idle-time measurement was wrong for a portal
that had never opened, disabling the feature for the first five minutes).
Easy to verify: turn the modem off, restart the board, wait for the portal to
open, turn the modem back on — it should come back on its own within five
minutes.

### Subnet routing: the packet never left the wire

The route was approved, the NAPT flag was on the right interface, the
translation checksum was correct — and still not one request that made it
through the tunnel reached a device on the home network. The measurement
chain ("Incoming requests" → "Forwarded onto the network" → "Reached the
target") looked positive at every stage for hours, but not a single byte ever
came back from a real target.

The root cause wasn't in esp-lwip, it was in `tun_input()`'s own pbuf
allocation call: `pbuf_alloc(PBUF_RAW, ...)` leaves no room at the front of the
pbuf for an Ethernet header. A packet addressed to the device's own tailnet
address never hit the problem, because that one is delivered locally inside
`ip4_input` and `netif->output` is never called. But **every routed packet**
goes through `ip4_forward → netif->output → ethernet_output`, which tries to
add a 14-byte Ethernet header there (`pbuf_add_header`), fails for lack of
room, returns `ERR_BUF` — and since nothing that called it checked the return
value, the packet vanished silently. It never reached the Wi-Fi chip at all.

This was hiding in the same corner both in the morning's esp-lwip NAPT
attempt and in the afternoon's own NAT layer (`src/nat.c`) — both worked
correctly, and neither had anywhere to deliver to. That's also why the
"Forwarded onto the network" counter kept coming back positive: nothing ever
read `netif->output`'s return code, so the packet was assumed "sent."

The fix is one line: `PBUF_RAW` → `PBUF_LINK`. Confirmed on the board — a
request over the tunnel reached three separate LAN targets (an extender, an
IoT device), the reply came back, the page loaded.

### WireGuard: rekeys were cutting the tunnel

Lines like `wireguard type 4 ... rejected (-1)` stood out in the board's log.
Some of it is harmless — after every restart, peers spend a while sending
packets to a session that no longer exists, and every implementation drops
those. But the rejections were clustering in exactly the seconds a peer
started a handshake.

The cause: there was a **single key slot** per peer. Both
`wg_create_initiation` and `consume_initiation` were overwriting the
`local_index` and `state` fields of the session that was still actively
carrying traffic. The result was the tunnel closing in both directions from
the moment a rekey started until the reply arrived — an incoming packet no
longer matched, and `wg_encrypt` rejected outgoing traffic too. If the rekey
went unanswered, the session died completely, even though the spec gives the
old keys another 60 seconds (`REKEY_AFTER` is 120 s, `REJECT_AFTER` 180 s;
that gap exists for exactly this).

Real WireGuard keeps one generation back. There's now a `wg_keypair prev`
here too: `consume_transport` checks the current key first, falling back to
the previous one if that fails; `wg_encrypt` keeps sending with the old key
while a rekey is in flight. The cost is +896 bytes for `wg_device`.

Second finding: a handshake attempt to a peer that's down repeated forever,
every 5 seconds. Each attempt is two X25519 operations, ~360 ms on this board.
There's now a wait that doubles, capped at 60 seconds.

Tests fail on the old code and pass on the new one (`./build/wireguard_test`).
Measured on the board: after the first 40 seconds, 5 peer handshakes, zero
rejections; attempts against a down peer spread out to 5.6 → 11.3 → 20.8 s
intervals.

## Remote updates (OTA)

The device lives at the village house; the nearest person who could press
reset is an hour's drive away and maybe a week out. So an update isn't
"flash it and hope" — the bootloader keeps the running image around, the new
image comes up **on trial**, and it only becomes permanent once it proves
itself.

### One wired flash

The old partition table had a single `factory` partition — OTA can't work
without a second app slot and its own `otadata`, and the partition table
can't be changed from application level. So **this one flash has to be
wired**, everything after it goes over the tunnel.

The room came from a 1.9 MB spiffs partition that nothing was mounting:

```
nvs       data  nvs     0x009000 ..0x00F000      24 KB
phy_init  data  phy     0x00F000 ..0x010000       4 KB
otadata   data  ota     0x010000 ..0x012000       8 KB
ota_0     app   ota_0   0x020000 ..0x200000    1920 KB
ota_1     app   ota_1   0x200000 ..0x3E0000    1920 KB
```

`nvs` stayed where it was and the same size, and `idf.py flash` doesn't touch
it either: switching to the new table erases neither the Wi-Fi credentials
nor the tailnet identity. `erase-flash` would — there's no need to run it.

```
rm -f firmware/sdkconfig        # let sdkconfig.defaults be read again
cd firmware && idf.py set-target esp32 && idf.py build
idf.py -p /dev/cu.usbserial-0001 flash monitor
```

The first line matters: `sdkconfig` is gitignored, and ESP-IDF does **not**
read `sdkconfig.defaults` if the file already exists. Forget it, and the new
partition table and the rollback setting silently don't apply — which is why
`ota.c` and `tun.c` each carry an `#error`: building with a missing option
stops, naming the cause and the fix.

There's 1920 KB per slot, and the most recently measured firmware is 1.06 MB:
~860 KB of headroom. If it doesn't fit, the build fails loudly, which is fine
since that happens with the cable in hand anyway.

### Every update after that, over the tunnel

```
curl -H 'Expect:' --data-binary @firmware/build/tsesp.bin \
     http://100.115.225.84/ota
```

Or the status page → Settings → Firmware update: pick the file, upload, watch
the percentage. The image goes up as the raw body; no multipart, so there's no
wrapper to parse on a chip with 97 KB of heap either.

Before writing, the device checks the image's first 288 bytes: the ESP32 image
magic byte, the app descriptor, and the **project name**. Writing an unrelated
`.bin` to a board you can't reach is the one mistake with no way back, and
both checks are already right there in the header.

### Trial period and rollback

The new image comes up as `PENDING_VERIFY`. Becoming permanent depends on two
conditions:

1. **the netmap arrived** — meaning Wi-Fi, the control plane and registration
   all work, and the device is reachable remotely again,
2. **120 seconds since boot have passed** — without this, an image that panics
   right after booting and registering could confirm itself and leave the
   device in an endless restart loop.

Once both are true, `esp_ota_mark_app_valid_cancel_rollback()` is called and a
single line goes to the log. If not: the image keeps running, but **on the
next boot** the bootloader falls back to the old slot. A broken update costs
one restart, not a trip out to fix it.

This has a cost too, and it was accepted on purpose: if the power cuts before
the trial period completes (it happens at the village house), a perfectly
healthy image gets rolled back as well. As a direction, that's the safe side
to fail on. The rollback isn't silent either — the status page shows a note
saying the most recently uploaded firmware couldn't confirm itself, otherwise
a reverted update would look like it was never uploaded at all.

`/ota` is open in setup mode too (the `tsesp-xxxx` network): a device that
can't join any network can still be reflashed by joining its own — one fewer
reason to need a cable.

**Confirmed since.** This was written and reasoned about with no ESP-IDF in
the environment at the time - the page's JavaScript was only checked with
`node --check`, and the partition table only worked out by hand. Since then
it has become the device's only update mechanism: dozens of ordinary OTA
cycles, all confirming within the trial window. None of them has ever
actually needed the rollback path - it hasn't failed to confirm even once in
practice, which says the trial period is working, not that rollback itself
has been exercised for real.

## Why it works without PSRAM

Two decisions make the whole difference:

1. **The control plane runs over plain HTTP on port 80.** `/ts2021` doesn't
   need TLS — Noise already encrypts end to end. The control server's public
   key is pinned in `ts2021.h`, so a `/key` call isn't needed either.
   **mbedTLS is never linked in at all: that recovers ~45 KB of heap.**
2. **The netmap is never held whole in memory** (Stage 5). It's parsed while
   streaming out of HTTP/2 DATA frames and reduced to roughly a 100-byte
   record per peer. That's the step reference implementations skip, which is
   why they ask for a 512 KB buffer.

Measured cost (the whole control plane, `-Os` host build):

```
code + rodata      32.0 KB      (expect ~40 KB on xtensa)
RAM                15.1 KB      ts_control        13.5 KB
                                  noise rx+tx      8.2 KB
                                  HPACK            2.9 KB
                                  h2 header block  2.0 KB
                                netmap parser      1.6 KB
                                  one peer         0.6 KB  <- independent of peer count
```

The netmap was pulled from a real tailnet with 6 peers; RAM stays the same at
300 peers, because peers are handed to a callback one at a time and forgotten.

For comparison: reference implementations ask for a 512 KB buffer for the same
job. The difference isn't cleverness, it comes from two decisions — no TLS,
and the netmap is never held whole in memory.

## Build and run (Mac/Linux, no board needed)

```
make                       # build everything
./build/selftest           # crypto known-answer tests
./build/hpack_test         # RFC 7541 Appendix C
./build/json_test          # streaming parser, every split point
./build/route_test         # route approval: AllowedIPs read from the netmap
./build/ts2021_handshake   # Noise handshake against the live server
./build/register_test      # the full stack: register request -> login URL
./build/stun_test          # STUN parser + a live query
./build/netmap_test        # fetch a registered node's netmap
./build/h2_probe           # dump the raw bytes inside the tunnel (diagnostic)
```

Run `register_test` without an auth key and the server only hands back a
login URL — **nothing gets added to any tailnet**. To actually join a device:

```
TSESP_AUTHKEY=tskey-auth-...  ./build/register_test     # with a key, one step
TSESP_FOLLOWUP=<login-url>    ./build/register_test     # wait until the URL is approved
```

Against Headscale: `./build/register_test <host> <port>` — and swap your own
server's key in for `TS2021_TAILSCALE_CONTROL_KEY`.

## Files

```
include/tscrypto.h        src/blake2s.c          BLAKE2s + HMAC + HKDF
                          src/x25519.c           X25519 (TweetNaCl ladder, public domain)
                          src/chacha20poly1305.c
include/ts2021.h          src/ts2021.c           Noise IK handshake + record framing
include/ts_io.h           src/ts_io.c            byte-stream abstraction
include/ts_noise_stream.h src/ts_noise_stream.c  Noise records -> byte stream
include/hpack.h           src/hpack.c            HPACK codec
                          src/hpack_tables.c     GENERATED - tools/gen_hpack.py
include/h2.h              src/h2.c               minimal HTTP/2 client
include/json_stream.h     src/json_stream.c      push-mode JSON parser
include/ts_netmap.h       src/ts_netmap.c        netmap framing + peer extraction
include/stun.h            src/stun.c             STUN binding
include/poly1305.h        src/poly1305.c         Poly1305 (shared by AEAD and NaCl)
include/nacl_box.h        src/nacl_box.c         Salsa20/HSalsa20 + NaCl secretbox
include/disco.h           src/disco.c            DISCO message framing
include/ts_path.h         src/ts_path.c          path discovery and selection
include/ts_client.h       src/ts_client.c        the device's state machine
include/ts_control.h      src/ts_control.c       upgrade + handshake + /machine/*

firmware/main/main.c                             boot sequence + control task
firmware/main/net.c, portal.c                    Wi-Fi, setup portal, status page
firmware/main/magic.c                            UDP socket, DISCO, WireGuard driver
firmware/main/derp_task.c, tls_io.c              relay connection
firmware/main/tun.c                              lwIP interface + NAPT (subnet routing)
firmware/main/ota.c                              updates over the tunnel + rollback
firmware/main/peers.c, device_nvs.c              peer table, persistent identity
firmware/partitions.csv                          two app slots + otadata

host/sim_net.c                                   fake UDP network + fake NATs
host/posix_io.c                                  the ONE platform-specific file
host/*_test.c, host/h2_probe.c                   tests and diagnostics
tools/gen_hpack.py, tools/gen_hpack_vectors.py   table/vector generation from the RFC
tools/gen_nacl_vectors.py                        NaCl vectors from libsodium
```

The NaCl vectors weren't hand-written either — `make nacl-vectors` generates
them from libsodium (via PyNaCl). Message lengths are chosen to land on both
sides of 32 bytes, because NaCl's keystream reserves its first 32 bytes for
the Poly1305 key, and that's the most likely place for a hand-written
implementation to get it wrong.

Not a single table was hand-written: HPACK's static table, its Huffman code,
and the test vectors are all generated from the text of RFC 7541, and the
generator verifies the Huffman code it produces is canonical (the decoder
depends on that).

## Protocol notes (worked out from the Tailscale source)

```
Noise_IK_25519_ChaChaPoly_BLAKE2s
prologue    "Tailscale Control Protocol v" + capver   (currently 146)
initiation  [2b ver][1b type=1][2b len=96][32b eph pub][48b enc machine pub][16b tag]
response    [1b type=2][2b len=48][32b eph pub][16b tag]
transport   [1b type=4][2b len][ct||16b tag]   max frame 4096, header is NOT authenticated
nonce       4 zero bytes + a big-endian uint64 counter, no AAD
HTTP upgrade  POST /ts2021, Upgrade: tailscale-control-protocol,
              X-Tailscale-Handshake: base64(initiation) → 101 Switching Protocols
```

## License

MIT — see [LICENSE](LICENSE). Third-party code and attribution in
[NOTICE.md](NOTICE.md).

Not affiliated with, or endorsed by, Tailscale Inc.

## Requirements

### Hardware

**Tested on:** ESP32-D0WD-V3 (WROOM-32U), 4 MB flash, no PSRAM, 240 MHz. Every
measurement here was taken on this chip, and everything below ran on this
board.

**Minimum requirements:**

| | |
|---|---|
| Flash | **4 MB** — `partitions.csv` gives OTA two app slots of 1920 KB each; the built firmware is 1.06 MB. Two slots don't fit on a 2 MB module: you'd have to go back to a single-slot table and give up OTA. |
| RAM | No PSRAM needed. ~97 KB of heap stays free with everything up. |
| Wi-Fi | 2.4 GHz. The setup portal uses AP+STA mode. |
| ESP-IDF | Built and tested with v5.3.1. |

### Other ESP32 variants

There's no assembly in the code, no chip-specific registers, no endianness
assumptions — the crypto reads byte by byte. So it's **expected** to be
portable, but expecting isn't testing:

| Chip | Status |
|---|---|
| ESP32 (WROOM-32/32D/32U, WROVER) | ✅ **run** (WROOM-32U), the others share the same core |
| ESP32-S3 | ⚠️ **builds clean**, never flashed to a board |
| ESP32-C3 / C6 / H2 (RISC-V) | ❓ **untried** — this machine has no RISC-V compiler installed (needs `install.sh esp32c3`) |
| ESP32-S2 | ❓ untried |
| ESP8266 | ❌ won't work — not supported by ESP-IDF v5, and not enough RAM either |

Nothing known blocks the single-core variants (S2, C3, SOLO-1); the code
doesn't depend on two cores. Still untried, though.

### On the network side

- A Tailscale account. Headscale should work too — `TS2021_TAILSCALE_CONTROL_KEY`
  and the server address change — but it's **untried**.
- Outgoing **TCP 80** for the control plane, outgoing **TCP 443** for the
  relay.
- Outgoing UDP 41641 — if it's blocked, no direct path can form and everything
  goes over the relay.
- For subnet routing: the route needs **approving** in the admin console, and
  the connecting device needs **"use subnet routes"** turned on.

### Known limits

- End-to-end measured speed is 0.4-0.5 Mbps (with the panel's "Speed test"
  button, see above) — well under the 1.35 MB/s AEAD ceiling measured on the
  host; Wi-Fi, lwIP, and `httpd` sending everything in 4 KB chunks each cost
  more than assumed. Enough for SSH, sensors, a device's own interface; not
  enough for video.
- A ~100 ms latency spike during handshakes: X25519 takes 180 ms on this chip,
  and the receiving task does nothing else while it runs.
- At most 8 WireGuard peers and 16 path-discovery peers at a time (build-time
  constants).
- An IPv6 tailnet address is assigned but never used; everything runs over
  IPv4.

## The reality of NAT

The `build/path_test` engine runs against how real home modems actually
behave. The result is what decides whether this project works at your house:

| Your modem | The other side | Direct path |
|---|---|---|
| open / full cone / restricted cone | the same | ✅ forms |
| restricted cone | restricted cone | ✅ a hole gets punched |
| **symmetric** | anything | ❌ **can't form — DERP is required** |

The last line matters: a symmetric NAT can't have a hole punched through it —
that's a consequence of the math, not the protocol. In that case traffic has
to go through Tailscale's relay servers, which means TLS, which means ~45 KB
of RAM. Which class your modem falls into is something we'll only learn once
STUN runs on the board.

The engine deliberately never claims "found a path" in the symmetric case,
and that's tested on purpose: showing a path that doesn't exist is worse than
admitting none was found.

## Not hammering anyone else's servers

This is someone else's infrastructure. `build/client_test` simulates a full
hour-long outage and counts how many times it tried to reconnect: **66.**
Backoff starts at 1 second and caps at 60, with ±25% jitter on top — so a pile
of devices that get power back at the same second don't all hit the server in
the same one. A 429 gets five minutes of silence, no arguing with it.
