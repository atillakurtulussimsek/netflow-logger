package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
)

const (
	defaultFTPPort            = 21
	defaultLocalRetentionDays = 7
	ftpDialTimeout            = 30 * time.Second
	ftpScanInterval           = 5 * time.Minute
	// ftpMarkerSuffix: FTP'ye başarıyla yüklenen saatin yanına yazılan işaret
	// dosyası. İçinde yüklenen sürümün SHA-256 değeri tutulur; saat yeniden
	// mühürlenirse (geç gelen kayıtlar) değer uyuşmaz ve paket yeniden yüklenir.
	ftpMarkerSuffix = ".ftp"
	// ftpSinceFile: geriye dönük yükleme kapalıyken, FTP'nin ilk açıldığı anı
	// tutar. Bu andan önceki saatler yüklenmez.
	ftpSinceFile = "ftp_since"
)

// FTPConfig, saatlik log paketlerinin yükleneceği FTP sunucusu ayarlarıdır.
type FTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	// Prefix, FTP üzerindeki kök klasördür (boş olabilir). Paketler
	// [Prefix/]YYYY/MM/DD/HH.tar.gz yoluna yazılır.
	Prefix string
	// Backfill true ise FTP açılmadan önce oluşmuş loglar da yüklenir.
	Backfill bool
}

func (c FTPConfig) address() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// loadFTPConfig, .env içindeki FTP_* değişkenlerini okur. FTP_ENABLED true
// değilse nil döner.
func loadFTPConfig(env map[string]string) (*FTPConfig, error) {
	if !parseBool(env["FTP_ENABLED"]) {
		return nil, nil
	}

	port := defaultFTPPort
	if raw := strings.TrimSpace(env["FTP_PORT"]); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("FTP_PORT geçersiz: %s", raw)
		}
		port = value
	}

	cfg := &FTPConfig{
		Host:     strings.TrimSpace(env["FTP_HOST"]),
		Port:     port,
		User:     strings.TrimSpace(env["FTP_USER"]),
		Password: env["FTP_PASSWORD"],
		Prefix:   normalizeFTPPrefix(env["FTP_PREFIX"]),
		Backfill: parseBool(env["FTP_BACKFILL"]),
	}
	if cfg.Host == "" || cfg.User == "" {
		return nil, errors.New("FTP_ENABLED=true iken FTP_HOST ve FTP_USER zorunludur")
	}
	return cfg, nil
}

// loadLocalRetentionDays, LOCAL_RETENTION_DAYS değerini okur. 0 yerel
// silmeyi kapatır.
func loadLocalRetentionDays(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultLocalRetentionDays, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("LOCAL_RETENTION_DAYS geçersiz: %s", raw)
	}
	return value, nil
}

func normalizeFTPPrefix(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	cleaned := path.Clean(raw)
	if cleaned == "." {
		return ""
	}
	return cleaned
}

func parseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on", "evet":
		return true
	}
	return false
}

// dialFTP, FTP sunucusuna bağlanıp oturum açar.
func dialFTP(ctx context.Context, cfg FTPConfig) (*ftp.ServerConn, error) {
	conn, err := ftp.Dial(cfg.address(),
		ftp.DialWithTimeout(ftpDialTimeout),
		ftp.DialWithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("ftp bağlantısı kurulamadı (%s): %w", cfg.address(), err)
	}
	if err := conn.Login(cfg.User, cfg.Password); err != nil {
		_ = conn.Quit()
		return nil, fmt.Errorf("ftp oturumu açılamadı: %w", err)
	}
	return conn, nil
}

// ensureFTPDir, uzak klasörü (ara klasörlerle birlikte) oluşturur. Var olan
// klasörler için sunucunun döndürdüğü hata yok sayılır.
func ensureFTPDir(conn *ftp.ServerConn, dir string) {
	if dir == "" || dir == "." || dir == "/" {
		return
	}
	current := ""
	if strings.HasPrefix(dir, "/") {
		current = "/"
	}
	for _, part := range strings.Split(strings.Trim(dir, "/"), "/") {
		current = path.Join(current, part)
		_ = conn.MakeDir(current)
	}
}

// uploadVerified, r içeriğini önce geçici adla yükler, sunucudaki boyutu
// doğrular, sonra nihai ada taşır. Yarım kalan yüklemeler nihai adı bozmaz.
//
// verify nil değilse, geçici dosya nihai ada taşınmadan önce çağrılır (geri
// okuma doğrulaması); hata dönerse geçici dosya silinir.
func uploadVerified(conn *ftp.ServerConn, remotePath string, write func(io.Writer) error, verify func(tmpPath string) error) error {
	ensureFTPDir(conn, path.Dir(remotePath))

	tmpPath := remotePath + ".part"
	pr, pw := io.Pipe()
	counter := &countingWriter{w: pw}
	go func() {
		pw.CloseWithError(write(counter))
	}()

	err := conn.Stor(tmpPath, pr)
	_ = pr.CloseWithError(errors.New("upload aborted"))
	if err != nil {
		return fmt.Errorf("ftp yükleme başarısız (%s): %w", tmpPath, err)
	}

	size, err := conn.FileSize(tmpPath)
	if err != nil {
		return fmt.Errorf("ftp boyut doğrulaması yapılamadı (%s): %w", tmpPath, err)
	}
	if size != counter.n {
		return fmt.Errorf("ftp boyut uyuşmazlığı (%s): gönderilen %d, sunucuda %d", tmpPath, counter.n, size)
	}

	if verify != nil {
		if err := verify(tmpPath); err != nil {
			_ = conn.Delete(tmpPath)
			return err
		}
	}

	_ = conn.Delete(remotePath)
	if err := conn.Rename(tmpPath, remotePath); err != nil {
		return fmt.Errorf("ftp yeniden adlandırma başarısız (%s): %w", remotePath, err)
	}
	return nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// writeHourArchive, bir saate ait .log, .sha256 ve .tsr dosyalarını tek bir
// tar.gz akışına yazar. Mühür dosyaları (.sha256, .tsr) yoksa paket yalnız
// mevcut dosyalarla oluşturulur.
//
// Pakete yazılan .log içeriğinin SHA-256 değeri ve boyutu döndürülür; geri
// okuma doğrulaması bununla karşılaştırır.
func writeHourArchive(w io.Writer, logPath string) (string, int64, error) {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	hasher := sha256.New()
	var logBytes int64
	for i, filePath := range []string{logPath, logPath + ".sha256", logPath + ".tsr"} {
		if i > 0 && !fileExists(filePath) {
			continue
		}
		var tee io.Writer
		if i == 0 {
			tee = hasher
		}
		n, err := addFileToTar(tw, filePath, tee)
		if err != nil {
			return "", 0, err
		}
		if i == 0 {
			logBytes = n
		}
	}
	if err := tw.Close(); err != nil {
		return "", 0, fmt.Errorf("tar kapatılamadı: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", 0, fmt.Errorf("gzip kapatılamadı: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), logBytes, nil
}

// addFileToTar, dosyayı tar'a ekler; tee nil değilse içerik oraya da yazılır.
func addFileToTar(tw *tar.Writer, filePath string, tee io.Writer) (int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("paketlenecek dosya açılamadı: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("paketlenecek dosya okunamadı: %w", err)
	}
	header := &tar.Header{
		Name:    filepath.Base(filePath),
		Mode:    0o644,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return 0, fmt.Errorf("tar başlığı yazılamadı: %w", err)
	}
	var dst io.Writer = tw
	if tee != nil {
		dst = io.MultiWriter(tw, tee)
	}
	// Dosya bu sırada büyüse bile başlıktaki boyut kadar okunur.
	if _, err := io.CopyN(dst, file, header.Size); err != nil {
		return 0, fmt.Errorf("tar içeriği yazılamadı: %w", err)
	}
	return header.Size, nil
}

// remoteArchivePath, bir saatin FTP üzerindeki paket yolunu döndürür.
func remoteArchivePath(prefix string, hour time.Time) string {
	return path.Join(prefix, hour.Format("2006"), hour.Format("01"), hour.Format("02"), hour.Format("15")+".tar.gz")
}

// runFTPTest, FTP ayarlarını uçtan uca dener: bağlanır, oturum açar, prefix
// klasörüne küçük bir dosya yükleyip boyutunu doğrular ve siler.
func runFTPTest(ctx context.Context, cfg FTPConfig, out io.Writer) error {
	fmt.Fprintf(out, "FTP bağlantısı test ediliyor: %s (kullanıcı: %s)\n", cfg.address(), cfg.User)
	conn, err := dialFTP(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Quit()
	fmt.Fprintln(out, "  bağlantı ve oturum: OK")

	payload := []byte("netflow-logger ftp test " + time.Now().Format(time.RFC3339) + "\n")
	testPath := path.Join(cfg.Prefix, fmt.Sprintf(".netflow-logger-test-%d.txt", time.Now().UnixNano()))
	err = uploadVerified(conn, testPath, func(w io.Writer) error {
		_, err := w.Write(payload)
		return err
	}, func(tmpPath string) error {
		resp, err := conn.Retr(tmpPath)
		if err != nil {
			return fmt.Errorf("test dosyası geri okunamadı: %w", err)
		}
		data, readErr := io.ReadAll(resp)
		closeErr := resp.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(data, payload) {
			return fmt.Errorf("test dosyası geri okuma uyuşmuyor")
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "  yazma, boyut ve geri okuma doğrulama: OK (%s)\n", testPath)

	if err := conn.Delete(testPath); err != nil {
		return fmt.Errorf("test dosyası silinemedi (%s): %w", testPath, err)
	}
	fmt.Fprintln(out, "  silme: OK")
	fmt.Fprintln(out, "FTP testi başarılı.")
	return nil
}

// FTPArchiver, mühürlenmiş saatlik logları paketleyip FTP'ye yükler ve
// yüklenmiş saatleri yerel saklama süresi dolunca yerelden siler.
type FTPArchiver struct {
	cfg           FTPConfig
	logRoot       string
	location      *time.Location
	retentionDays int
	// activePath, şu an yazılan log dosyasını döndürür; bu dosya atlanır.
	activePath func() string
	now        func() time.Time

	trigger chan struct{}
	runMu   sync.Mutex

	statusMu sync.Mutex
	status   FTPStatus
}

// FTPStatus, dashboard'da gösterilen FTP arşivleme durumudur.
type FTPStatus struct {
	Enabled       bool   `json:"enabled"`
	Server        string `json:"server,omitempty"`
	Prefix        string `json:"prefix,omitempty"`
	Backfill      bool   `json:"backfill"`
	RetentionDays int    `json:"retention_days"`

	// State: "ok", "error" veya "pending" (henüz tarama yapılmadı).
	State          string `json:"state"`
	LastScan       string `json:"last_scan,omitempty"`
	LastUpload     string `json:"last_upload,omitempty"`
	LastUploadFile string `json:"last_upload_file,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	LastErrorAt    string `json:"last_error_at,omitempty"`

	// Son taramadaki yerel saat sayıları ve boyutları.
	UploadedLocal      int    `json:"uploaded_local"`
	UploadedLocalBytes int64  `json:"uploaded_local_bytes"`
	Pending            int    `json:"pending"`
	PendingBytes       int64  `json:"pending_bytes"`
	Skipped            int    `json:"skipped"`
	SkippedBytes       int64  `json:"skipped_bytes"`
	OldestLocal        string `json:"oldest_local,omitempty"`
	// Tarama ilerlemesi: Scanning true iken ScanDone/ScanTotal saat işlendi.
	Scanning     bool   `json:"scanning"`
	ScanDone     int    `json:"scan_done"`
	ScanTotal    int    `json:"scan_total"`
	NextDeletion string `json:"next_deletion,omitempty"`

	// Servis açıldığından beri toplamlar.
	UploadedTotal int `json:"uploaded_total"`
	// ReadbackTotal, geri okunarak doğrulanan yükleme sayısıdır.
	ReadbackTotal int   `json:"readback_total"`
	DeletedTotal  int   `json:"deleted_total"`
	DeletedBytes  int64 `json:"deleted_bytes"`
}

// Status, son FTP durumunun kopyasını döndürür.
func (a *FTPArchiver) Status() FTPStatus {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	return a.status
}

func (a *FTPArchiver) updateStatus(fn func(*FTPStatus)) {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	fn(&a.status)
}

func (a *FTPArchiver) recordError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("ftp: %s", msg)
	a.updateStatus(func(st *FTPStatus) {
		st.State = "error"
		st.LastError = msg
		st.LastErrorAt = a.now().In(a.location).Format(time.RFC3339)
	})
}

func NewFTPArchiver(cfg FTPConfig, logRoot string, location *time.Location, retentionDays int, activePath func() string) *FTPArchiver {
	return &FTPArchiver{
		cfg:           cfg,
		logRoot:       logRoot,
		location:      location,
		retentionDays: retentionDays,
		activePath:    activePath,
		now:           time.Now,
		trigger:       make(chan struct{}, 1),
		status: FTPStatus{
			Enabled:       true,
			Server:        cfg.address(),
			Prefix:        cfg.Prefix,
			Backfill:      cfg.Backfill,
			RetentionDays: retentionDays,
			State:         "pending",
		},
	}
}

// Notify, yeni bir saat mühürlendiğinde taramayı hemen tetikler.
func (a *FTPArchiver) Notify() {
	select {
	case a.trigger <- struct{}{}:
	default:
	}
}

func (a *FTPArchiver) Run(ctx context.Context) {
	since, err := a.loadOrInitSince()
	if err != nil {
		log.Printf("ftp: başlangıç zamanı okunamadı: %v", err)
	}

	if conn, err := dialFTP(ctx, a.cfg); err != nil {
		a.recordError("başlangıç bağlantı testi başarısız: %v", err)
	} else {
		_ = conn.Quit()
		log.Printf("ftp: %s bağlantısı doğrulandı", a.cfg.address())
	}

	ticker := time.NewTicker(ftpScanInterval)
	defer ticker.Stop()
	for {
		a.RunOnce(ctx, since)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-a.trigger:
		}
	}
}

type hourLog struct {
	path string
	hour time.Time
}

// RunOnce, bekleyen saatleri yükler ve süresi dolanları yerelden siler.
// FTP'ye ulaşılamasa bile daha önce yüklenmiş saatlerin silinmesi sürer.
func (a *FTPArchiver) RunOnce(ctx context.Context, since time.Time) {
	a.runMu.Lock()
	defer a.runMu.Unlock()

	hours, err := a.scanHourLogs()
	if err != nil {
		a.recordError("log taraması başarısız: %v", err)
		return
	}

	currentHour := a.now().In(a.location).Truncate(time.Hour)
	active := ""
	if a.activePath != nil {
		active = a.activePath()
	}

	var conn *ftp.ServerConn
	dialFailed := false
	defer func() {
		if conn != nil {
			_ = conn.Quit()
		}
	}()

	var (
		scanErr                  string
		uploadedLocal, pending   int
		skipped                  int
		uploadedBytes, pendBytes int64
		skippedBytes             int64
		oldest, nextDeletion     time.Time
	)
	fail := func(format string, args ...any) {
		scanErr = fmt.Sprintf(format, args...)
		a.recordError("%s", scanErr)
	}

	// publish, sayaçları dashboard'a yansıtır; uzun taramalarda (ör. geriye
	// dönük yükleme) tarama sürerken de periyodik çağrılır.
	publish := func(done int, finished bool) {
		a.updateStatus(func(st *FTPStatus) {
			st.ScanDone, st.ScanTotal, st.Scanning = done, len(hours), !finished
			if finished {
				st.LastScan = a.now().In(a.location).Format(time.RFC3339)
				if scanErr == "" {
					st.State = "ok"
				}
			}
			st.UploadedLocal, st.UploadedLocalBytes = uploadedLocal, uploadedBytes
			st.Pending, st.PendingBytes = pending, pendBytes
			st.Skipped, st.SkippedBytes = skipped, skippedBytes
			st.OldestLocal, st.NextDeletion = "", ""
			if !oldest.IsZero() {
				st.OldestLocal = oldest.In(a.location).Format(time.RFC3339)
			}
			if !nextDeletion.IsZero() {
				st.NextDeletion = nextDeletion.In(a.location).Format(time.RFC3339)
			}
		})
	}
	defer func() {
		// İptal edilen taramada da "sürüyor" durumunda kalmasın.
		a.updateStatus(func(st *FTPStatus) { st.Scanning = false })
	}()
	lastPublish := time.Now()

	for i, h := range hours {
		if time.Since(lastPublish) >= 2*time.Second {
			publish(i, false)
			lastPublish = time.Now()
		}
		if ctx.Err() != nil {
			return
		}
		if !h.hour.Before(currentHour) || h.path == active {
			continue
		}
		info, err := os.Stat(h.path)
		if err != nil {
			continue
		}
		size := info.Size() + fileSize(h.path+".sha256") + fileSize(h.path+".tsr")

		digest, err := hourUploadKey(h.path)
		if err != nil {
			fail("%s okunamadı: %v", h.path, err)
			continue
		}
		uploaded := readMarker(h.path) == digest

		if !uploaded {
			if !a.cfg.Backfill && h.hour.Before(since) {
				skipped++
				skippedBytes += size
				if oldest.IsZero() {
					oldest = h.hour
				}
				continue
			}
			if conn == nil && !dialFailed {
				conn, err = dialFTP(ctx, a.cfg)
				if err != nil {
					dialFailed = true
					fail("%v (sonraki taramada yeniden denenecek)", err)
				}
			}
			if conn != nil {
				remotePath := remoteArchivePath(a.cfg.Prefix, h.hour)
				var logSHA string
				var logBytes int64
				uploadConn := conn
				err := uploadVerified(conn, remotePath, func(w io.Writer) error {
					var err error
					logSHA, logBytes, err = writeHourArchive(w, h.path)
					return err
				}, func(tmpPath string) error {
					// Geri okuma: paketi indirip içindeki log'un gönderilenle
					// birebir aynı olduğunu doğrula.
					check, _, err := checkRemoteArchive(uploadConn, tmpPath)
					if err != nil {
						return fmt.Errorf("geri okuma başarısız: %w", err)
					}
					if check.LogSHA != logSHA || check.LogBytes != logBytes {
						return fmt.Errorf("geri okuma uyuşmuyor: %s", check.Detail)
					}
					return nil
				})
				if err != nil {
					fail("%s yüklenemedi: %v (sonraki taramada yeniden denenecek)", h.path, err)
					_ = conn.Quit()
					conn = nil
				} else {
					log.Printf("ftp: %s -> %s yüklendi", h.path, remotePath)
					uploaded = true
					a.updateStatus(func(st *FTPStatus) {
						st.UploadedTotal++
						st.ReadbackTotal++
						st.LastUpload = a.now().In(a.location).Format(time.RFC3339)
						st.LastUploadFile = remotePath
					})
					// Saklama süresi dolmuşsa işaret dosyasına gerek yok; hemen
					// silinir. Disk tamamen doluyken işaret yazılamaz ama silme
					// boş alan gerektirmez.
					if !a.expired(h.hour) {
						if err := os.WriteFile(h.path+ftpMarkerSuffix, []byte(digest+"\n"), 0o644); err != nil {
							fail("işaret dosyası yazılamadı (%s): %v", h.path, err)
						}
					}
				}
			}
		}

		if uploaded && a.expired(h.hour) {
			if err := a.removeLocal(h.path); err != nil {
				fail("%v", err)
			} else {
				a.updateStatus(func(st *FTPStatus) {
					st.DeletedTotal++
					st.DeletedBytes += size
				})
				continue
			}
		}

		if oldest.IsZero() {
			oldest = h.hour
		}
		if uploaded {
			uploadedLocal++
			uploadedBytes += size
			if a.retentionDays > 0 && nextDeletion.IsZero() {
				nextDeletion = h.hour.Add(time.Hour + time.Duration(a.retentionDays)*24*time.Hour)
			}
		} else {
			pending++
			pendBytes += size
		}
	}

	// Bu taramada yükleme yapılmadıysa da sunucuya ulaşılabildiğini doğrula;
	// böylece bağlantı kopması yüklenecek dosya beklenmeden fark edilir.
	if conn == nil && !dialFailed && ctx.Err() == nil {
		if c, err := dialFTP(ctx, a.cfg); err != nil {
			fail("%v (sonraki taramada yeniden denenecek)", err)
		} else {
			_ = c.Quit()
		}
	}

	publish(len(hours), true)
}

func fileSize(p string) int64 {
	info, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (a *FTPArchiver) expired(hour time.Time) bool {
	if a.retentionDays <= 0 {
		return false
	}
	cutoff := a.now().Add(-time.Duration(a.retentionDays) * 24 * time.Hour)
	return hour.Add(time.Hour).Before(cutoff)
}

func (a *FTPArchiver) removeLocal(logPath string) error {
	for _, p := range []string{logPath, logPath + ".sha256", logPath + ".tsr", logPath + ftpMarkerSuffix} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("yerel dosya silinemedi (%s): %w", p, err)
		}
	}
	log.Printf("ftp: saklama süresi dolan %s yerelden silindi", logPath)

	// Boşalan gün/ay/yıl klasörlerini temizle.
	root := filepath.Clean(a.logRoot)
	for dir := filepath.Dir(logPath); dir != root && strings.HasPrefix(dir, root); dir = filepath.Dir(dir) {
		if os.Remove(dir) != nil {
			break
		}
	}
	return nil
}

// scanHourLogs, LogRoot/YYYY/MM/DD/HH.log düzenindeki dosyaları eskiden yeniye
// sıralı döndürür.
func (a *FTPArchiver) scanHourLogs() ([]hourLog, error) {
	var result []hourLog
	years, err := os.ReadDir(a.logRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	for _, y := range years {
		if !y.IsDir() || len(y.Name()) != 4 {
			continue
		}
		months, _ := os.ReadDir(filepath.Join(a.logRoot, y.Name()))
		for _, m := range months {
			if !m.IsDir() {
				continue
			}
			days, _ := os.ReadDir(filepath.Join(a.logRoot, y.Name(), m.Name()))
			for _, d := range days {
				if !d.IsDir() {
					continue
				}
				dayDir := filepath.Join(a.logRoot, y.Name(), m.Name(), d.Name())
				files, _ := os.ReadDir(dayDir)
				for _, f := range files {
					name := f.Name()
					if f.IsDir() || !strings.HasSuffix(name, ".log") || len(name) != len("15.log") {
						continue
					}
					stamp := fmt.Sprintf("%s-%s-%s %s", y.Name(), m.Name(), d.Name(), strings.TrimSuffix(name, ".log"))
					hour, err := time.ParseInLocation("2006-01-02 15", stamp, a.location)
					if err != nil {
						continue
					}
					result = append(result, hourLog{path: filepath.Join(dayDir, name), hour: hour})
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].hour.Before(result[j].hour) })
	return result, nil
}

// hourUploadKey, saatin yüklenecek içeriğini temsil eden anahtarı döndürür.
// İşaret dosyasındaki anahtar bununla uyuşmuyorsa paket (yeniden) yüklenir:
//   - mühür tamsa (.sha256 + .tsr): SHA-256 değeri
//   - yalnız .sha256 varsa: SHA-256 + "+notsr" (TSR sonradan gelirse yeniden yüklenir)
//   - mühür yoksa: dosya boyutu ve değişiklik zamanı (her taramada hash
//     hesaplamamak için)
func hourUploadKey(logPath string) (string, error) {
	info, err := os.Stat(logPath)
	if err != nil {
		return "", err
	}
	if data, err := os.ReadFile(logPath + ".sha256"); err == nil {
		if digest := strings.TrimSpace(string(data)); digest != "" {
			if fileExists(logPath + ".tsr") {
				return digest, nil
			}
			return digest + "+notsr", nil
		}
	}
	return fmt.Sprintf("nosha:%d:%d", info.Size(), info.ModTime().UnixNano()), nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readMarker(logPath string) string {
	data, err := os.ReadFile(logPath + ftpMarkerSuffix)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// loadOrInitSince, FTP'nin ilk açıldığı anı okur; yoksa şimdiki zamanı yazar.
func (a *FTPArchiver) loadOrInitSince() (time.Time, error) {
	sincePath := filepath.Join(a.logRoot, ftpSinceFile)
	if data, err := os.ReadFile(sincePath); err == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data))); err == nil {
			return t.Truncate(time.Hour), nil
		}
	}
	now := a.now()
	if err := os.MkdirAll(a.logRoot, 0o755); err != nil {
		return now.Truncate(time.Hour), err
	}
	if err := os.WriteFile(sincePath, []byte(now.Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return now.Truncate(time.Hour), err
	}
	return now.Truncate(time.Hour), nil
}
