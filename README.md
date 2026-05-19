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
- Go yüklü değilse otomatik kurar
- sistem kullanıcısı ve grubu oluşturur
- projeyi GitHub deposundan [`/srv/netflow-logger`](install.sh:5) altına çeker veya mevcut kurulum varsa GitHub'dan günceller
- etkileşimli olarak dashboard kullanıcı adı, parola, portlar ve zaman dilimi bilgilerini ister
- mevcut [`.env`](.env) varsa üzerine yazmadan korur; istenirse yeniden oluşturur
- uygulamayı derler
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
