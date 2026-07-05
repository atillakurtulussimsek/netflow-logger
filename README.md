# netflow-logger

Bu proje, OPNsense üzerinden UDP `9995` portuna gönderilen NetFlow v9 kayıtlarını dinleyen, kayıtları saatlik düz metin log dosyalarına yazan, her saat kapanışında ilgili log dosyası için SHA-256 özeti ile FreeTSA üzerinden zaman damgası alan ve canlı izleme için tek kullanıcılı bir kontrol paneli sunan Go uygulamasıdır.

## Özellikler

- UDP `9995` üzerinde NetFlow v9 dinleme
- `Europe/Istanbul` zaman dilimi ile saatlik log döndürme
- `./logs/YYYY/MM/DD/HH.log` dizin ve dosya yapısı
- Pipe ayrılmış düz metin log satırları
- Her saatlik dosya için `HH.log.sha256` ve `HH.log.tsr` üretimi
- SHA-256 özet alma
- FreeTSA `https://freetsa.org/tsr` entegrasyonu
- HTTP Basic Auth ile korunan kontrol paneli
- SSE ile canlı güncellenen son 200 log kaydı görünümü
- Aktif log dosyası, son SHA-256 ve son TSA durumunu panelde izleme
- Arka planda tehdit analizi (brute-force, dikey/yatay tarama) ve açılır güvenlik paneli
- Tehdit analizinde görmezden gelinecek kaynak IP/CIDR whitelist'i (`config.json` içinde kalıcı)
- Zararlı IP kara listesi (`blocklist.json` içinde kalıcı, 72 saat saklama) ve OPNsense için düz metin `/blocklist` endpoint'i
- Ubuntu için otomatik kurulum ve `systemd` servisleştirme desteği

## Log Satır Formatı

Her kayıt aşağıdaki sabit sırada pipe ayrılmış olarak yazılır:

`timestamp|src_ip|dst_ip|src_port|dst_port|protocol|packets|bytes|input_if|output_if|flow_start|flow_end`

Örnek:

`2026-05-19T20:00:01+03:00|192.0.2.10|198.51.100.20|443|51514|TCP|12|8400|1|2|2026-05-19T19:59:58+03:00|2026-05-19T20:00:01+03:00`

## Üretilen Dosyalar

Bir saatlik log için aynı dizinde üç artefakt bulunur:

- `HH.log`: saatlik düz metin kayıt dosyası
- `HH.log.sha256`: yalnızca SHA-256 hex özeti ve satır sonu
- `HH.log.tsr`: FreeTSA tarafından dönen zaman damgası yanıtı

## Yapılandırma

Uygulama gerçek çalıştırmada [`.env`](.env) dosyası bekler. Örnek yapı [`.env.example`](.env.example) içinde sağlanmıştır.

Örnek:

`cp .env.example .env`

Sonrasında [`.env`](.env) içindeki kullanıcı adı ve parolayı değiştirmen gerekir.

Desteklenen değişkenler:

- `NETFLOW_LISTEN_ADDRESS`: NetFlow UDP dinleme adresi, varsayılan `:9995`
- `DASHBOARD_ADDRESS`: kontrol paneli HTTP adresi, varsayılan `:8080`
- `DASHBOARD_USERNAME`: kontrol paneli kullanıcı adı
- `DASHBOARD_PASSWORD`: kontrol paneli parolası
- `LOG_ROOT`: log kök dizini, varsayılan `./logs`
- `TSA_URL`: TSA servisi, varsayılan `https://freetsa.org/tsr`
- `TIMEZONE`: zaman dilimi, varsayılan `Europe/Istanbul`
- `BLOCKLIST_TOKEN`: `/blocklist` düz metin endpoint erişim token'ı; boşsa endpoint devre dışı
- `BLOCKLIST_ALLOW_IPS`: (opsiyonel) `/blocklist` için izin verilen IP/CIDR listesi (virgülle ayrılır)

## Geliştirme Ortamında Çalıştırma

Go yüklü bir ortamda aşağıdaki komutları kullan:

`cp .env.example .env`

[`.env`](.env) içeriğini düzenle.

`go mod tidy`

`go build ./...`

`go run .`

Uygulama varsayılan olarak UDP `9995` portunu ve HTTP `8080` portunu kullanır.

## Ubuntu Kurulum ve Servisleştirme

Ubuntu üzerinde otomatik kurulum için [`install.sh`](install.sh) scripti eklendi. Bu script aşağıdaki akışı yürütür:

- temel paketleri kurar
- Go yüklü değilse önce `apt` ile kurmayı dener, olmazsa `go.dev` üzerinden güncel stable sürümü dinamik olarak indirir
- sistem kullanıcısı ve grubu oluşturur
- projeyi GitHub deposundan [`/srv/netflow-logger`](install.sh:5) altına çeker veya mevcut kurulum varsa GitHub'dan günceller
- Git güvenlik denetimindeki `dubious ownership` durumuna karşı hedef dizini `safe.directory` olarak ekler
- etkileşimli olarak dashboard kullanıcı adı, parola, portlar ve zaman dilimi bilgilerini doğrudan terminalden ister
- mevcut [`.env`](.env) varsa üzerine yazmadan korur; istenirse yeniden oluşturur
- parola girişi ve diğer değerler `/dev/tty` üzerinden alındığı için here-doc veya stdin karışmasından kaynaklı `.env` bozulmalarını önler
- uygulamayı `-buildvcs=false` ile derler; böylece VCS stamping kaynaklı kurulum hatalarını önler
- [`deploy/netflow-logger.service`](deploy/netflow-logger.service) içeriğine denk gelen `systemd` servis dosyasını yazar
- `daemon-reload`, `enable` ve `restart` işlemlerini yapar

Kurulum komutu:

`sudo bash install.sh`

Kurulum veya güncelleme sonunda şu yollar kullanılır:

- kurulum dizini: `/srv/netflow-logger`
- servis adı: `netflow-logger`
- servis dosyası: `/etc/systemd/system/netflow-logger.service`
- çevre dosyası: `/srv/netflow-logger/.env`
- log dizini: `/srv/netflow-logger/logs`
- binary: `/srv/netflow-logger/netflow-logger`

Servis yönetimi komutları:

`sudo systemctl status netflow-logger`

`sudo systemctl restart netflow-logger`

`sudo systemctl stop netflow-logger`

`sudo journalctl -u netflow-logger -f`

Aynı [`install.sh`](install.sh) scripti daha sonra tekrar çalıştırıldığında mevcut kurulum tespit edilir, repo güncellenir, binary yeniden derlenir ve servis yeniden başlatılır. Bu sayede ayrı bir güncelleme scriptine ihtiyaç olmadan kurulum ve upgrade aynı akıştan yönetilebilir.

## Kontrol Paneli

Kontrol paneli varsayılan olarak `http://127.0.0.1:8080` adresinde çalışır. Tarayıcı erişiminde HTTP Basic Auth sorulur. Başarılı giriş sonrası panel aşağıdaki bilgileri canlı olarak gösterir:

- aktif saatlik log dosyası
- son üretilen SHA-256 özeti
- son TSA işlemi durumu
- son 200 log kaydı

Canlı veri akışı SSE ile sağlanır.

## Güvenlik İzleme ve Whitelist

Akış trafiği arka planda sürekli analiz edilir; kayan zaman penceresi içinde tek kaynak IP'nin davranışına bakılarak brute-force, dikey port tarama ve yatay host tarama denemeleri tespit edilir. Uyarılar, üstteki "Canlı SSE akışı" butonunun yanındaki **Güvenlik uyarıları** butonu ile açılan modal içinde gösterilir; aktif uyarı varken buton kırmızı yanıp söner.

Aynı modal içinde bir **whitelist** bölümü bulunur. Buraya eklenen kaynak IP adresleri veya CIDR blokları (ör. `10.0.0.0/24`) tehdit analizinde tamamen yok sayılır; bu kaynaklar için hiç uyarı üretilmez ve whitelist'e eklenen bir kaynağın mevcut uyarısı da anında düşer.

Whitelist girişleri çalışma dizinindeki `config.json` dosyasında kalıcı olarak saklanır ve süreç yeniden başlatıldığında geri yüklenir:

```json
{
  "source_ip_whitelist": [
    "192.168.1.10",
    "10.0.0.0/24"
  ]
}
```

Whitelist ayrıca HTTP API ile de yönetilebilir (tümü HTTP Basic Auth ile korunur):

- `GET /api/whitelist` — mevcut girişleri listeler
- `POST /api/whitelist` — gövde `{"entry":"10.0.0.0/24"}` ile giriş ekler
- `DELETE /api/whitelist?entry=10.0.0.0%2F24` — girişi kaldırır

Girişler eklenirken doğrulanır ve kanonik biçime indirgenir (ör. `10.0.0.5/24` → `10.0.0.0/24`); geçersiz IP/CIDR değerleri `400` ile reddedilir.

## Zararlı IP Kara Listesi (OPNsense Otomatik Ban)

Tehdit analizi bir kaynak IP'yi zararlı olarak işaretlediğinde (brute-force, port/host tarama), bu IP çalışma dizinindeki `blocklist.json` dosyasında **kalıcı** olarak saklanır. Uyarıların aksine kara liste süreç yeniden başlatıldığında kaybolmaz.

- Her IP, **son tespitten itibaren 72 saat** boyunca listede kalır (`blocklistRetention`). Aktif bir saldırganın her yeni tespiti bu süreyi tazeler; saldırı durduktan sonra IP en az 72 saat listede kalır ve süresi dolunca otomatik temizlenir.
- Whitelist'e alınan bir IP kara listeye asla girmez; sonradan whitelist'e eklenirse kara listeden de anında düşürülür.

`blocklist.json` biçimi:

```json
{
  "entries": [
    {
      "ip": "185.234.12.34",
      "rule": "bruteforce",
      "hits": 7,
      "first_seen": "2026-07-06T10:00:00+03:00",
      "last_seen": "2026-07-06T10:12:30+03:00",
      "expires_at": "2026-07-09T10:12:30+03:00"
    }
  ]
}
```

### Manuel IP Ekleme

Kara listeye elle IP eklemek istersen, kaydın içine **`"manual": true`** alanını yazman gerekir. Sistem `blocklist.json` dosyasını bellekten yeniden yazdığı için, bu işaret olmadan elle eklenen kayıtlar bir sonraki yazımda ezilir. Manuel kayıtlar:

- Süre aşımıyla **temizlenmez** (72 saat kuralı yalnızca sistem kayıtları içindir); kalıcıdır.
- Sistem dosyayı yeniden yazarken **korunur** (yazımdan önce dosyadaki manuel kayıtlar geri okunur).
- Çalışma zamanında yapılan ekleme/çıkarmalar endpoint'e **anında** yansır: her `/blocklist` (ve `/api/blocklist`) isteği dosyadaki manuel kayıtları önce belleğe senkronlar. Ayrıca 5 sn'lik bakım döngüsü de senkronu tekrarlar. Süreç yeniden başlatmak gerekmez.
- Dosyadan silinince bellekten de düşer.

```json
{
  "entries": [
    { "ip": "203.0.113.66", "manual": true, "rule": "manual-ban" }
  ]
}
```

> Not: Manuel bir kayıt whitelist ile çakışırsa dosyada kalır ama `/blocklist` çıktısında whitelist filtresi nedeniyle görünmez.

### Düz Metin Endpoint (`/blocklist`)

OPNsense'in **Firewall → Aliases** ekranında **URL Table (IPs)** tipiyle çekebileceği, satır başına bir IP içeren temiz düz metin çıktısı sağlanır (HTML / JSON / boş satır yok):

```
185.234.12.34
45.155.204.15
```

Bu endpoint HTTP Basic Auth yerine token ile korunur (firewall'lar Basic Auth göndermez). `.env` içinde:

```env
BLOCKLIST_TOKEN=uzun-rastgele-bir-token
# (opsiyonel) yalnızca OPNsense WAN IP'sinden erişime izin ver
BLOCKLIST_ALLOW_IPS=203.0.113.10
```

OPNsense alias URL'si:

```
https://<host>:<port>/blocklist?token=uzun-rastgele-bir-token
```

- `BLOCKLIST_TOKEN` boş bırakılırsa endpoint tamamen **devre dışıdır** (her istek `403`).
- Token `?token=` sorgu parametresi veya `Authorization: Bearer <token>` başlığı ile gönderilebilir; karşılaştırma sabit zamanlıdır.
- `BLOCKLIST_ALLOW_IPS` tanımlıysa (virgülle ayrılmış IP/CIDR), yalnızca bu ağlardan gelen istekler kabul edilir.

Ayrıca panel/görüntüleme için Basic Auth arkasında ayrıntılı JSON döndüren `GET /api/blocklist` bulunur.

## OPNsense Tarafı

OPNsense üzerinde NetFlow dışa aktarımı NetFlow v9 olarak etkinleştirilmeli ve hedef sistem olarak bu uygulamanın çalıştığı sunucunun IP adresi ile UDP `9995` portu tanımlanmalıdır.

## Uygulama Akışı

Uygulama gelen NetFlow v9 paketlerini alır, template tabanlı alanları çözer, zorunlu alanları çıkarır ve ilgili saatlik dosyaya yazar. Saat değiştiğinde kapanan dosya önce senkronize edilir, ardından SHA-256 özeti alınır, `.sha256` dosyası yazılır ve aynı özet için TSA isteği gönderilerek `.tsr` çıktısı saklanır. Panel tarafında aynı anda son kayıtlar ve mühürleme durumu yayınlanır.

## 5651 Açısından Notlar

Bu uygulama 5651 uyum hedefini destekleyen dosya bütünlüğü, zaman damgalama ve denetlenebilir log akışı üretir; ancak tek başına tam mevzuat uyumluluğu garantisi vermez. İşletim sistemi sertleştirmesi, erişim yetkileri, saat senkronizasyonu, yedekleme, saklama politikası, denetim izi ve operasyonel prosedürlerin ayrıca tasarlanması gerekir.

## Mevcut Teknik Sınırlar

- Sadece NetFlow v9 hedeflenmiştir.
- Kayıt yazımı için veritabanı kullanılmaz.
- Kütüphane tarafından çözümlenemeyen ya da zorunlu alanları eksik gelen kayıtlar loglanmaz.
- TSA yanıtı temel bütünlük kontrolü ile doğrulanır; tam CMS imza zinciri doğrulaması yapılmaz.
- Dashboard tek kullanıcı mantığıyla çalışır; gelişmiş oturum yönetimi yoktur.
