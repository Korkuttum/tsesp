# Üçüncü taraf kod

Proje MIT lisanslı. İçindeki tek türetilmiş kod parçası:

**`src/x25519.c`** — Curve25519 Montgomery merdiveni TweetNaCl'den türetilmiştir
(Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen, Tanja Lange,
Peter Schwabe, Sjaak Smetsers). TweetNaCl **public domain**'dir, yani MIT ile
birleştirilmesinde kısıtlama yoktur.

Geri kalan her şey bu proje için yazılmıştır. BLAKE2s (RFC 7693),
ChaCha20-Poly1305 (RFC 8439), HPACK (RFC 7541), HTTP/2 (RFC 7540) ve
STUN (RFC 8489) ilgili RFC'lerden uygulanmıştır — RFC metinleri
telif kısıtı getirmez.

`src/hpack_tables.c` ve `host/hpack_vectors.c` dosyaları `tools/` altındaki
betiklerle RFC 7541'in metninden **üretilmiştir**, elle yazılmamıştır.

Tailscale'in wire protokolü (ts2021) kendi açık kaynak istemcisinin
(BSD-3-Clause) davranışı incelenerek uygulanmıştır; bu projeye Tailscale'den
kod kopyalanmamıştır. Proje Tailscale Inc. ile ilişkili değildir ve onun
tarafından onaylanmamıştır.
