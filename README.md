# tsesp — ESP32-WROOM-32U için sıfırdan Tailscale istemcisi

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

PSRAM'siz klasik ESP32'ye (520 KB SRAM) sığacak şekilde yazılmış, taşınabilir C.
Protokol kodu socket'e hiç dokunmaz; aynı `.c` dosyaları hem POSIX test
harness'ında hem ESP-IDF firmware'inde derlenir.

## Durum

| Aşama | İş | Durum |
|---|---|---|
| 1 | Kripto: BLAKE2s, HKDF, X25519, ChaCha20-Poly1305 | ✅ RFC 7693/7748/8439 vektörleri |
| 2 | ts2021 Noise IK handshake + record framing | ✅ canlı sunucuya karşı |
| 3a | HPACK codec | ✅ RFC 7541 Ek C'nin 16 örneği |
| 3b | Noise içinde minimal HTTP/2 istemcisi | ✅ canlı sunucuya karşı |
| 3c | Streaming JSON parser | ✅ her bölünme noktasında aynı sonuç |
| 4 | `/machine/register` → gerçek login URL'i | ✅ HTTP 200, URL alındı |
| 5 | `/machine/map` → peer listesi + 100.x IP | ✅ gerçek tailnet'ten çekildi |
| 6a | STUN istemcisi | ✅ RFC 5769 vektörü |
| 6b | NaCl box (Curve25519 + XSalsa20-Poly1305) | ✅ libsodium'la bayt bayt aynı |
| 6c | DISCO ping/pong/call-me-maybe mesajları | ✅ wire format testleri |
| 7 | Yol keşfi motoru (ping/ölç/seç/canlı tut) | ✅ sahte NAT'larla test edildi |
| 8 | WireGuard veri düzlemi (esp_wireguard) | ⬜ kart gerektiriyor |
| 9 | NAPT subnet routing — ev ağındaki cihazlara erişim | ⬜ |
| 10 | ESP-IDF firmware: AP modu, kurulum sayfası, NVS | ⬜ |
| 11 | DERP relay (TLS gerektirir, bellek baskısı) | ⬜ simetrik NAT'ta şart |

Kontrol düzlemi çalışıyor. Uçtan uca doğrulanmış zincir:

```
TCP :80 -> POST /ts2021 upgrade -> Noise IK -> early payload
        -> HTTP/2 + HPACK -> POST /machine/register -> AuthURL -> kayıt
                          -> POST /machine/map      -> netmap -> 100.x adres
```

Kontrol düzlemi bitti. Cihaz gerçek bir tailnet'te kayıtlı, kendi adresini ve
peer'larının anahtar/endpoint'lerini çekebiliyor. Kalan iş veri düzlemi:
paketleri gerçekten taşımak.

## Neden PSRAM'siz çalışabiliyor

İki karar bütün farkı yaratıyor:

1. **Kontrol düzlemi düz HTTP port 80 üzerinden.** `/ts2021` TLS istemiyor — Noise
   zaten uçtan uca şifreliyor. Kontrol sunucusunun public key'i `ts2021.h`'de
   pinli, yani `/key` çağrısı da gerekmiyor. **mbedTLS hiç linklenmiyor: ~45 KB heap kurtuldu.**
2. **Netmap asla tamamen bellekte tutulmayacak** (Aşama 5). HTTP/2 DATA
   frame'lerinden akarken parse edilip peer başına ~100 baytlık kayda indirgenecek.
   Referans implementasyonların 512 KB buffer istemesinin sebebi bu adımı atlamaları.

Ölçülen maliyet (tüm kontrol düzlemi, -Os host derlemesi):

```
kod + sabit veri   32.0 KB      (xtensa'da ~40 KB bekle)
RAM                15.1 KB      ts_control        13.5 KB
                                  noise rx+tx      8.2 KB
                                  HPACK            2.9 KB
                                  h2 başlık bloğu  2.0 KB
                                netmap parser      1.6 KB
                                  tek peer         0.6 KB  <- peer sayısından bağımsız
```

6 peer'lı gerçek bir tailnet'ten netmap çekildi; 300 peer'da RAM aynı kalır,
çünkü peer'lar tek tek callback'e verilip unutuluyor.

Karşılaştırma: referans implementasyonlar aynı iş için 512 KB buffer istiyor.
Fark akıllılıktan değil, iki karardan geliyor — TLS yok, ve netmap hiçbir zaman
bütün olarak bellekte tutulmuyor.

## Derle ve çalıştır (Mac/Linux, kart gerekmez)

```
make                       # her şeyi derle
./build/selftest           # kripto known-answer testleri
./build/hpack_test         # RFC 7541 Ek C
./build/json_test          # streaming parser, her bölünme noktası
./build/ts2021_handshake   # canlı sunucuyla Noise handshake
./build/register_test      # tam yığın: kayıt isteği -> login URL
./build/stun_test          # STUN parser + canlı sorgu
./build/netmap_test        # kayıtlı node'un netmap'ini çek
./build/h2_probe           # tünel içindeki ham baytları dök (teşhis)
```

`register_test` auth key olmadan çalıştırıldığında sunucu sadece bir login URL'i
döner ve **hiçbir tailnet'e hiçbir şey eklenmez**. Cihazı gerçekten katmak için:

```
TSESP_AUTHKEY=tskey-auth-...  ./build/register_test     # anahtarla, tek adımda
TSESP_FOLLOWUP=<login-url>    ./build/register_test     # URL onaylanana kadar bekle
```

Headscale'e karşı: `./build/register_test <host> <port>` — ayrıca kendi
sunucunun key'ini `TS2021_TAILSCALE_CONTROL_KEY` yerine koy.

## Dosyalar

```
include/tscrypto.h        src/blake2s.c          BLAKE2s + HMAC + HKDF
                          src/x25519.c           X25519 (TweetNaCl ladder, public domain)
                          src/chacha20poly1305.c
include/ts2021.h          src/ts2021.c           Noise IK handshake + record framing
include/ts_io.h           src/ts_io.c            bayt akışı soyutlaması
include/ts_noise_stream.h src/ts_noise_stream.c  Noise record'ları -> bayt akışı
include/hpack.h           src/hpack.c            HPACK codec
                          src/hpack_tables.c     ÜRETİLMİŞ - tools/gen_hpack.py
include/h2.h              src/h2.c               minimal HTTP/2 istemcisi
include/json_stream.h     src/json_stream.c      push-mode JSON parser
include/ts_netmap.h       src/ts_netmap.c        netmap çerçeveleme + peer çıkarma
include/stun.h            src/stun.c             STUN binding
include/poly1305.h        src/poly1305.c         Poly1305 (AEAD ve NaCl ortak kullanır)
include/nacl_box.h        src/nacl_box.c         Salsa20/HSalsa20 + NaCl secretbox
include/disco.h           src/disco.c            DISCO mesaj çerçeveleme
include/ts_path.h         src/ts_path.c          yol keşfi ve seçimi
include/ts_control.h      src/ts_control.c       upgrade + handshake + /machine/*

host/sim_net.c                                   sahte UDP ağı + sahte NAT'lar
host/posix_io.c                                  TEK platforma özgü dosya
host/*_test.c, host/h2_probe.c                   test ve teşhis
tools/gen_hpack.py, tools/gen_hpack_vectors.py   RFC'den tablo/vektör üretimi
tools/gen_nacl_vectors.py                        libsodium'dan NaCl vektörleri
```

NaCl vektörleri de elle yazılmadı — `make nacl-vectors` onları libsodium'dan
(PyNaCl üzerinden) üretir. Mesaj uzunlukları 32 baytın iki yanına düşecek
şekilde seçilmiştir, çünkü NaCl anahtar akışının ilk 32 baytını Poly1305
anahtarına ayırır ve elle yazılmış bir uygulamanın yanılması en olası yer
orasıdır.

Elle yazılmış tek bir tablo yok: HPACK'in statik tablosu, Huffman kodu ve test
vektörleri RFC 7541'in metninden üretiliyor, ve üretici Huffman kodunun kanonik
olduğunu doğruluyor (decoder buna dayanıyor).

## Protokol notları (Tailscale kaynağından çıkarıldı)

```
Noise_IK_25519_ChaChaPoly_BLAKE2s
prologue    "Tailscale Control Protocol v" + capver   (şu an 146)
initiation  [2b ver][1b type=1][2b len=96][32b eph pub][48b enc machine pub][16b tag]
response    [1b type=2][2b len=48][32b eph pub][16b tag]
transport   [1b type=4][2b len][ct||16b tag]   max frame 4096, header authenticate EDİLMEZ
nonce       4 sıfır bayt + big-endian uint64 sayaç, AAD yok
HTTP upgrade  POST /ts2021, Upgrade: tailscale-control-protocol,
              X-Tailscale-Handshake: base64(initiation) → 101 Switching Protocols
```

## Lisans

MIT — bkz. [LICENSE](LICENSE). Üçüncü taraf kod ve atıflar için [NOTICE.md](NOTICE.md).

Tailscale Inc. ile ilişkili değildir, onun tarafından onaylanmamıştır.

## NAT gerçeği

`build/path_test` motoru gerçek ev modemlerinin davranışlarına karşı çalıştırır.
Sonuç, projenin senin evinde çalışıp çalışmayacağını belirleyen şey:

| Senin modemin | Karşı taraf | Doğrudan yol |
|---|---|---|
| açık / full cone / restricted cone | aynısı | ✅ kuruluyor |
| restricted cone | restricted cone | ✅ delik açılıyor |
| **simetrik** | herhangi | ❌ **kurulamıyor — DERP şart** |

Son satır önemli: simetrik NAT'ta delik açılamaz, bu protokolün değil
matematiğin sonucu. O durumda trafiğin Tailscale'in relay sunucularından
geçmesi gerekir, o da TLS demek, o da ~45 KB RAM demek. Modeminin hangi
sınıfta olduğunu ancak kartta STUN çalıştırınca öğreneceğiz.

Motorun simetrik senaryoda "yol buldum" dememesi bilerek test ediliyor:
olmayan bir yolu varmış gibi göstermek, hiç bulamamaktan daha kötüdür.
