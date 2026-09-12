# tsesp — ESP32-WROOM-32U için sıfırdan Tailscale istemcisi

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

PSRAM'siz klasik ESP32'ye (520 KB SRAM) sığacak şekilde yazılmış, taşınabilir C.
Protokol kodu socket'e hiç dokunmaz; aynı `.c` dosyaları hem POSIX test
harness'ında hem ESP-IDF firmware'inde derlenir.

## Durum

| Aşama | İş | Durum |
|---|---|---|
| 1 | Kripto: BLAKE2s (anahtarlı dahil), HKDF, X25519, ChaCha20-Poly1305 | ✅ RFC vektörleri |
| 2 | ts2021 Noise IK handshake + record framing | ✅ canlı sunucuya karşı |
| 3 | HPACK + HTTP/2 + streaming JSON | ✅ RFC 7541 Ek C; her bölünme noktası |
| 4 | `/machine/register` → tailnet'e kayıt | ✅ kartta |
| 5 | `/machine/map` → netmap, peer'lar, DERP haritası | ✅ kartta, uzun bağlantı |
| 6 | NaCl box + DISCO + STUN | ✅ libsodium/RFC 5769 ile doğrulandı |
| 7 | Yol keşfi (ping/ölç/seç/canlı tut) | ✅ sahte NAT'lar + gerçek peer'lar |
| 8 | DERP rölesi (TLS) — varlık **ve** veri | ✅ doğrudan yol kapalıyken test edildi |
| 9 | WireGuard (Noise IKpsk2) | ✅ gerçek Tailscale düğümleriyle tünel |
| 10 | lwIP arayüzü — cihaz kendi 100.x adresinde | ✅ ping %0 kayıp, sayfa tünelden |
| 11 | NAPT subnet routing | ✅ kod hazır, **rota onayı + saha testi bekliyor** |
| 12 | ESP-IDF firmware: AP modu, kurulum sayfası, NVS | ✅ |

Zincirin tamamı kartta çalışıyor:

```
WiFi kurulumu (AP + kurulum sayfası)
  -> TCP :80 -> /ts2021 upgrade -> Noise IK -> HTTP/2 -> kayıt -> netmap
  -> DERP rölesi (TLS 443)         <- varlık ve yedek veri yolu
  -> DISCO ping/pong               -> doğrudan yol (NAT delme)
  -> WireGuard (Noise IKpsk2)      -> tünel
  -> lwIP arayüzü 100.64.0.0/10    -> cihaz ağda görünür
  -> IP forward + NAPT             -> ev ağındaki cihazlara erişim
```

Ölçülenler (ESP32-D0WD-V3, 240 MHz):

```
tailnet adresine ping     %0 kayıp, ortalama 20 ms   (doğrudan yol)
                          %0 kayıp, ortalama 480 ms  (sadece röle)
durum sayfası tünelden    http 200, 0.36 s
X25519                    180 ms      <- en yavaş işlem
ChaCha20-Poly1305         1.35 MB/s   <- veri düzleminin tavanı
boş heap (her şey açık)   ~97 KB
```

## Kaldığı yer

Kod tarafında bitmemiş bir şey yok; eksik olan **saha testi**:

1. Admin panelde ilan edilen rotayı onayla
2. Bağlanacağın cihazda "subnet route'ları kullan"ı aç
3. **Mobil veriden** (WiFi kapalı) ev ağındaki bir adrese eriş

Doğrulanmamışlar: saatler/günler süren kararlılık, yük altında davranış.
Hız beklentisi 1-3 Mbps.

### Modem yeniden başlatma: iki hata

"WiFi koptuğunda toparlanma" bu listedeydi ve sahada patladı — modem yeniden
başlatılınca cihaz bir daha bağlanmıyordu. Altından iki ayrı hata çıktı, ve
ikincisi ancak birincisi düzeltildikten sonra görünür oldu.

**1. Yeniden bağlanma bütçesi.** 5 denemelik sayaç sadece `GOT_IP` ile
sıfırlanıyordu ve tükenince `BIT_FAILED` set ediliyordu — ama o biti bekleyen
tek yer `net_start()`, o da açılışta çoktan dönmüştü. Bit boşluğa düşüyor,
`esp_wifi_connect()` bir daha hiç çağrılmıyordu. Beş deneme, modem daha
açılmadan birkaç saniyede bitiyordu. Artık bütçe yalnızca *ilk* katılım için;
sonrası sınırsız, 2 sn'den 30 sn'ye çıkan beklemeyle, kendi task'ında.

**2. `WIFI_FAST_SCAN`.** `wifi_config_t cfg = {0}` yazınca `scan_method` sıfır
kalıyor, o da fast scan demek: SSID eşleşen **ilk** AP'yi bulunca taramayı
bırakıp ona bağlanıyor, sinyaline bakmadan. Evde mesh varsa bu yazı tura — ve
tam modem yeniden başlarken tura geliyor, çünkü elektriği hiç kesilmeyen üst
kat node'u ilk cevap veren oluyor. Cihaz -80 dBm'de ona kilitlenip DHCP'yi
tamamlayamıyor, `bcn_timeout` yiyip aynı yere geri dönüyordu.
`WIFI_ALL_CHANNEL_SCAN` + `WIFI_CONNECT_AP_BY_SIGNAL` ile bütün kanallar
taranıp en güçlüsü seçiliyor.

Üçüncü bir şey de düzeltildi ama sahada patlamamıştı: LAN'a bağlı her şey
(ilan edilen rota, NAPT'ın yazdığı adres, "bu peer benim ağımda mı" testi)
açılışta bir kez türetiliyordu. Modem farklı bir IP verirse hepsi bayatlıyor
ve subnet routing log'da tek satır iz bırakmadan ölüyordu. Artık adres
değişince yeniden türetiliyor.

Sahada ölçülen (iki kez modem fişten çekildi, ~2 dk bekletildi):

```
kopma algılandı            beacon timeout'tan 2 sn sonra
deneme aralığı             2, 4, 8, 16, 30, 30 sn ...  (sınır yok)
modem kapalıyken           üst kat node'una 3 kez tutundu, -71..-78, adres yok
modem dönünce              o turdaki taramada -48'lik modemi seçti
tam toparlanma             kopmadan 97 sn sonra: ip, kontrol düzlemi,
                           netmap, DERP, 4 WireGuard tüneli
```

97 saniyenin çoğu modemin kendi açılış süresi; cihaz modem geri geldikten
sonraki ilk taramada bağlandı. Durum sayfasındaki "Kopma sayısı" bunu
görünür kılıyor.

Hâlâ doğrulanmamış bir senaryo var: zayıf node'dan DHCP adresi **alınabilirse**
cihaz "bağlandım" deyip orada kalır ve modem dönse bile -80'lik hatta takılı
kalır, çünkü bağlıyken yeniden tarama yapmıyor. İki testte de olmadı (zayıf
node adres vermedi), o yüzden "sinyal kötüyse daha iyisini ara" davranışı
yazılmadı.

### Kurulum portalı artık bir çıkmaz sokak değil

Açılışta kayıtlı ağa bağlanamayınca cihaz kurulum portalını açıyor ve
`while (1)` ile orada kalıyordu — kayıtlı ağı bir daha hiç denemeden. Bu,
modem yeniden başlatma hatasının açılış anındaki ikizi: elektrik kesintisinden
sonra kart iki saniyede, modem bir dakikada açılır; kart ~15 saniyede pes edip
portalı açar ve kendi ağı gelmesine rağmen orada oturur. Köy evinde kimse de
reset atamaz.

Açılıştaki bırakma ölçüsü de değişti. "Beş deneme" yanlış birimdi — beş deneme
saniyeler içinde tükeniyor, modemin açılma süresinden çok kısa. Artık ölçü
zaman: **90 saniye**. Ama düz 90 saniye de iki ayrı durumu aynı sayıyor, ve
ESP-IDF bunları zaten ayırt ediyor — `WIFI_REASON_NO_AP_FOUND` (ağ ortada yok,
beklemeye değer, modem açılıyor olabilir) ile `AUTH_FAIL` / `HANDSHAKE_TIMEOUT`
(parola tutmuyor, beklemek hiçbir şeyi değiştirmez). Kimlik doğrulama üst üste
iki kez reddedilirse portal hemen açılıyor; başka her sebepte 90 saniye
sabrediliyor. Sebep kodu artık log'a da basılıyor, ki "neden bağlanamıyor"
sorusu bir dahakine tahminle değil tek satırla cevaplansın.

Artık portal açıkken kayıtlı ağ iki dakikada bir yeniden deneniyor: açılış
yolunun kendisi zaten test edilmiş olduğu için deneme `esp_restart()` ile
yapılıyor. İki koruma var — ilk beş dakika hiç denenmiyor (cihazı yeni
taşımış biri kurulum ağına katılıp sayfayı açacak kadar süre bulsun), ve
kurulum sayfası son beş dakikada açıldıysa erteleniyor (yeniden başlatmak,
yarısı yazılmış parolayı siler). Kayıtlı ağ yoksa hiç denenmiyor.

Cihazı kayıtlı ağın erişemeyeceği bir yere taşıdıysan deneme hiç tutmaz, ve
maliyeti iki dakikada bir katılma denemesinden ibarettir.

Kurulum ağının adı artık her açılışta log'a yazılıyor (`tsesp-xxxx`), sadece
portal açıldığında değil: adı ihtiyaç duymadan önce bilmek bir yolculuk
kurtarıyor.

**Bu yolların hiçbiri sahada çalıştırılmadı** — bugün cihaz her açılışta
bağlanabildi, yani ne 90 saniyelik bekleme, ne sebep koduna göre ayrım, ne de
portaldan geri dönüş bir kez olsun tetiklendi. Normal açılışın bozulmadığı
doğrulandı, o kadar. Kod yazılırken iki hatası çıktı ve ikisi de
çıktıya bakılarak yakalandı (log satırı AP adı hesaplanmadan basılıyordu;
boşta kalma süresi hiç açılmamış portal için yanlış hesaplanıyor, özelliği
ilk beş dakika devre dışı bırakıyordu). Doğrulaması kolay: modemi kapat,
kartı yeniden başlat, portalın açılmasını bekle, modemi aç — beş dakika
içinde kendiliğinden dönmeli.

### WireGuard: rekey tüneli kesiyordu

Kart günlüğünde `wireguard type 4 ... rejected (-1)` satırları göze çarptı.
Bir kısmı zararsız — her yeniden başlatmadan sonra peer'lar bir süre artık var
olmayan bir oturuma paket yollar, bunu her implementasyon düşürür. Ama
reddetmeler tam peer'ların handshake başlattığı saniyelerde kümeleniyordu.

Sebep: peer başına **tek anahtar yuvası** vardı. Hem `wg_create_initiation`
hem `consume_initiation`, hâlâ trafik taşıyan oturumun `local_index` ve
`state` alanlarının üstüne yazıyordu. Sonuç, rekey başladığı andan cevap
gelene kadar tünelin çift yönlü kapanması — gelen paket eşleşmiyor, giden
`wg_encrypt` de reddediyor. Rekey cevapsız kalırsa oturum tamamen ölüyordu,
oysa spec eski anahtarlara 60 saniye daha tanıyor (`REKEY_AFTER` 120 sn,
`REJECT_AFTER` 180 sn; o aralık tam bunun için var).

Gerçek WireGuard bir kuşak geriyi saklar. Artık burada da `wg_keypair prev`
var: `consume_transport` önce güncel anahtara, tutmazsa öncekine bakıyor;
`wg_encrypt` rekey uçuştayken eski anahtarla göndermeye devam ediyor.
Maliyet `wg_device` için +896 bayt.

İkinci bulgu: kapalı bir peer'a handshake denemesi 5 saniyede bir, sonsuza
kadar tekrarlıyordu. Her deneme iki X25519, bu kartta ~360 ms. Artık ikiye
katlanan, 60 saniyede sınırlanan bir bekleme var.

Testler eski kodda düşüyor, yenisinde geçiyor (`./build/wireguard_test`).
Kartta ölçülen: ilk 40 saniyeden sonra 5 peer-handshake, sıfır reddetme;
kapalı peer'a denemeler 5.6 → 11.3 → 20.8 sn aralıklarla seyreldi.

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
include/ts_client.h       src/ts_client.c        cihaz durum makinesi
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

## Gereksinimler

### Donanım

**Test edilen:** ESP32-D0WD-V3 (WROOM-32U), 4 MB flash, PSRAM yok, 240 MHz.
Bütün ölçümler bu çipte alındı ve aşağıdaki her şey bu kartta çalıştırıldı.

**Asgari gereksinimler:**

| | |
|---|---|
| Flash | **4 MB** — `partitions.csv` uygulamaya 2 MB veriyor, derlenen firmware 1.06 MB. 2 MB'lık bir modülde bölüm tablosunu küçültmen gerekir. |
| RAM | PSRAM gerekmiyor. Her şey ayaktayken ~97 KB heap boş kalıyor. |
| WiFi | 2.4 GHz. Kurulum portalı için AP+STA modu kullanılıyor. |
| ESP-IDF | v5.3.1 ile geliştirildi ve test edildi. |

### Diğer ESP32 çeşitleri

Kodda assembly yok, çipe özel register yok, endian varsayımı yok — kripto
bayt bayt okuyor. Yani taşınabilir olması **bekleniyor**, ama beklemek test
değil:

| Çip | Durum |
|---|---|
| ESP32 (WROOM-32/32D/32U, WROVER) | ✅ **çalıştırıldı** (WROOM-32U), diğerleri aynı çekirdek |
| ESP32-S3 | ⚠️ **temiz derleniyor**, karta atılmadı |
| ESP32-C3 / C6 / H2 (RISC-V) | ❓ **denenmedi** — bu makinede RISC-V derleyicisi kurulu değil (`install.sh esp32c3` gerekir) |
| ESP32-S2 | ❓ denenmedi |
| ESP8266 | ❌ olmaz — ESP-IDF v5 desteklemiyor, RAM de yetmez |

Tek çekirdekli çeşitler (S2, C3, SOLO-1) için bilinen bir engel yok; kod iki
çekirdeğe bağımlı değil. Ama yine de denenmedi.

### Ağ tarafı

- Bir Tailscale hesabı. Headscale de çalışmalı — `TS2021_TAILSCALE_CONTROL_KEY`
  ve sunucu adresi değişir — ama **denenmedi**.
- Kontrol düzlemi için giden **TCP 80**, röle için giden **TCP 443**.
- UDP 41641 giden — kapalıysa doğrudan yol kurulamaz, her şey röleden gider.
- Subnet routing için: rotanın admin panelde **onaylanması**, ve bağlanan
  cihazda **"use subnet routes"** açık olması.

### Bilinen sınırlar

- Hız 1-3 Mbps civarı. Ölçülen AEAD tavanı 1.35 MB/s, üstüne WiFi ve lwIP payı
  biniyor. SSH, sensör, cihaz arayüzü için yeter; video için yetmez.
- El sıkışma anlarında ~100 ms gecikme sıçraması: X25519 bu çipte 180 ms
  sürüyor ve o sırada alıcı görev başka iş yapmıyor.
- Aynı anda en fazla 8 WireGuard peer'ı, 16 yol keşfi peer'ı (derleme sabiti).
- IPv6 tailnet adresi atanıyor ama kullanılmıyor; her şey IPv4 üzerinden.

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

## Sunucuları yormama

Bu, başkasının altyapısı. `build/client_test` bir saatlik tam kesinti
simüle edip kaç kez bağlanmaya çalışıldığını sayıyor: **66.** Geri çekilme
1 saniyeden başlayıp 60 saniyede tavan yapıyor, üstüne ±%25 jitter var —
aynı anda elektrik gelen bir sürü cihaz aynı saniyede saldırmasın diye.
429 gelirse beş dakika susuluyor, ısrar edilmiyor.
