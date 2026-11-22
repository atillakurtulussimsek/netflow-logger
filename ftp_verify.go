package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
)

// Doğrulama sonuç durumları.
const (
	verifyOK      = "ok"      // paket sağlam, SHA-256 ve TSR geçerli
	verifyWarn    = "warn"    // paket sağlam ama mühür dosyası eksik
	verifyError   = "error"   // paket bozuk, SHA-256/TSR uyuşmuyor veya yerelde olup FTP'de yok
	verifyMissing = "missing" // FTP'de yok (yerelde de yok: trafik yok ya da silinmiş)
)

// ArchiveCheck, bir tar.gz paketinin iç tutarlılık kontrolünün sonucudur.
type ArchiveCheck struct {
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	LogBytes int64  `json:"log_bytes"`
	LogSHA   string `json:"log_sha256,omitempty"`
	HasSHA   bool   `json:"has_sha256"`
	HasTSR   bool   `json:"has_tsr"`
}

// checkArchive, paketi akış halinde açar: .log dosyasının SHA-256 değerini
// hesaplar, .sha256 dosyasıyla karşılaştırır ve .tsr zaman damgasının bu
// özeti içerdiğini doğrular.
func checkArchive(r io.Reader) ArchiveCheck {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return ArchiveCheck{Status: verifyError, Detail: "gzip açılamadı: " + err.Error()}
	}
	defer gz.Close()

	var (
		res       ArchiveCheck
		logDigest []byte
		hasLog    bool
		shaText   string
		tsrBytes  []byte
	)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ArchiveCheck{Status: verifyError, Detail: "tar okunamadı: " + err.Error()}
		}
		switch {
		case strings.HasSuffix(hdr.Name, ".log"):
			h := sha256.New()
			n, err := io.Copy(h, tr)
			if err != nil {
				return ArchiveCheck{Status: verifyError, Detail: "log okunamadı: " + err.Error()}
			}
			hasLog, logDigest, res.LogBytes = true, h.Sum(nil), n
		case strings.HasSuffix(hdr.Name, ".log.sha256"):
			data, err := io.ReadAll(io.LimitReader(tr, 1024))
			if err != nil {
				return ArchiveCheck{Status: verifyError, Detail: "sha256 okunamadı: " + err.Error()}
			}
			res.HasSHA, shaText = true, strings.TrimSpace(string(data))
		case strings.HasSuffix(hdr.Name, ".log.tsr"):
			data, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return ArchiveCheck{Status: verifyError, Detail: "tsr okunamadı: " + err.Error()}
			}
			res.HasTSR, tsrBytes = true, data
		}
	}
	// gzip sağlama toplamı (CRC) yalnız akış sonuna kadar okununca denetlenir.
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return ArchiveCheck{Status: verifyError, Detail: "gzip bozuk: " + err.Error()}
	}

	if !hasLog {
		return ArchiveCheck{Status: verifyError, Detail: "pakette .log dosyası yok"}
	}
	res.LogSHA = hex.EncodeToString(logDigest)

	var notes []string
	if res.HasSHA {
		if !strings.EqualFold(shaText, res.LogSHA) {
			res.Status, res.Detail = verifyError, "SHA-256 uyuşmuyor: dosyada "+shaText+", hesaplanan "+res.LogSHA
			return res
		}
	} else {
		notes = append(notes, ".sha256 yok")
	}
	if res.HasTSR {
		if err := validateTSR(tsrBytes, logDigest); err != nil {
			res.Status, res.Detail = verifyError, "TSR geçersiz: "+err.Error()
			return res
		}
	} else {
		notes = append(notes, ".tsr yok")
	}

	if len(notes) > 0 {
		res.Status, res.Detail = verifyWarn, "paket sağlam; "+strings.Join(notes, ", ")
		return res
	}
	res.Status, res.Detail = verifyOK, "SHA-256 ve TSR doğrulandı"
	return res
}

// checkRemoteArchive, paketi FTP'den indirip checkArchive ile doğrular.
func checkRemoteArchive(conn *ftp.ServerConn, remotePath string) (ArchiveCheck, int64, error) {
	resp, err := conn.Retr(remotePath)
	if err != nil {
		return ArchiveCheck{}, 0, fmt.Errorf("indirilemedi (%s): %w", remotePath, err)
	}
	counter := &countingReader{r: resp}
	check := checkArchive(counter)
	// Kalan baytları tüket ki bağlantı bir sonraki komut için temiz kalsın.
	_, _ = io.Copy(io.Discard, counter)
	if err := resp.Close(); err != nil && check.Status != verifyError {
		return ArchiveCheck{}, counter.n, fmt.Errorf("indirme tamamlanamadı (%s): %w", remotePath, err)
	}
	return check, counter.n, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// VerifyResult, bir saatin FTP doğrulama sonucudur.
type VerifyResult struct {
	Hour         string `json:"hour"` // YYYY-MM-DD HH
	RemotePath   string `json:"remote_path"`
	Status       string `json:"status"`
	Detail       string `json:"detail"`
	ArchiveBytes int64  `json:"archive_bytes"`
	LogBytes     int64  `json:"log_bytes"`
}

// VerifySummary, bir doğrulama çalışmasının özetidir.
type VerifySummary struct {
	OK           int   `json:"ok"`
	Warn         int   `json:"warn"`
	Error        int   `json:"error"`
	Missing      int   `json:"missing"`
	ArchiveBytes int64 `json:"archive_bytes"`
	LogBytes     int64 `json:"log_bytes"`
}

func (s *VerifySummary) add(r VerifyResult) {
	switch r.Status {
	case verifyOK:
		s.OK++
	case verifyWarn:
		s.Warn++
	case verifyError:
		s.Error++
	case verifyMissing:
		s.Missing++
	}
	s.ArchiveBytes += r.ArchiveBytes
	s.LogBytes += r.LogBytes
}

// verifyRange, from..to (dahil) günlerindeki saatleri FTP'de doğrular. Her
// sonuç onResult ile bildirilir; total, kontrol edilecek saat sayısıdır.
func verifyRange(ctx context.Context, cfg FTPConfig, logRoot string, loc *time.Location, from, to, now time.Time,
	onTotal func(total int), onResult func(VerifyResult)) error {
	from = time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, loc)
	to = time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, loc)
	if to.Before(from) {
		return errors.New("bitiş tarihi başlangıçtan önce olamaz")
	}
	currentHour := now.In(loc).Truncate(time.Hour)

	var hours []time.Time
	for day := from; !day.After(to); day = day.AddDate(0, 0, 1) {
		for h := 0; h < 24; h++ {
			hour := time.Date(day.Year(), day.Month(), day.Day(), h, 0, 0, 0, loc)
			if hour.Before(currentHour) {
				hours = append(hours, hour)
			}
		}
	}
	if onTotal != nil {
		onTotal(len(hours))
	}

	conn, err := dialFTP(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if conn != nil {
			_ = conn.Quit()
		}
	}()

	listed := map[string]map[string]bool{}
	for _, hour := range hours {
		if err := ctx.Err(); err != nil {
			return err
		}
		remotePath := remoteArchivePath(cfg.Prefix, hour)
		dir := path.Dir(remotePath)
		if _, ok := listed[dir]; !ok {
			names := map[string]bool{}
			entries, _ := conn.NameList(dir)
			for _, e := range entries {
				names[path.Base(e)] = true
			}
			listed[dir] = names
		}

		res := VerifyResult{Hour: hour.Format("2006-01-02 15"), RemotePath: remotePath}
		if !listed[dir][path.Base(remotePath)] {
			if _, err := os.Stat(buildLogPath(logRoot, hour)); err == nil {
				res.Status, res.Detail = verifyError, "FTP'de yok, yerelde var (henüz yüklenmemiş olabilir)"
			} else {
				res.Status, res.Detail = verifyMissing, "FTP'de yok (bu saatte kayıt oluşmamış ya da hiç yüklenmemiş)"
			}
			onResult(res)
			continue
		}

		check, n, err := checkRemoteArchive(conn, remotePath)
		res.ArchiveBytes = n
		if err != nil {
			res.Status, res.Detail = verifyError, err.Error()
			onResult(res)
			// Bağlantı bozulmuş olabilir; yeniden bağlan.
			_ = conn.Quit()
			conn, err = dialFTP(ctx, cfg)
			if err != nil {
				conn = nil
				return err
			}
			continue
		}
		res.Status, res.Detail, res.LogBytes = check.Status, check.Detail, check.LogBytes
		onResult(res)
	}
	return nil
}

// VerifyJob, dashboard'dan başlatılan doğrulama işinin durumudur.
type VerifyJob struct {
	Running    bool           `json:"running"`
	From       string         `json:"from"`
	To         string         `json:"to"`
	StartedAt  string         `json:"started_at,omitempty"`
	FinishedAt string         `json:"finished_at,omitempty"`
	Total      int            `json:"total"`
	Done       int            `json:"done"`
	Summary    VerifySummary  `json:"summary"`
	Results    []VerifyResult `json:"results"`
	Error      string         `json:"error,omitempty"`
}

// FTPVerifier, aynı anda tek bir doğrulama işi çalıştırır.
type FTPVerifier struct {
	cfg     FTPConfig
	logRoot string
	loc     *time.Location

	mu     sync.Mutex
	job    VerifyJob
	cancel context.CancelFunc
}

func NewFTPVerifier(cfg FTPConfig, logRoot string, loc *time.Location) *FTPVerifier {
	return &FTPVerifier{cfg: cfg, logRoot: logRoot, loc: loc}
}

func (v *FTPVerifier) Snapshot() VerifyJob {
	v.mu.Lock()
	defer v.mu.Unlock()
	job := v.job
	job.Results = append([]VerifyResult(nil), v.job.Results...)
	return job
}

// Start, from..to aralığı için arka planda doğrulama başlatır.
func (v *FTPVerifier) Start(parent context.Context, from, to time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.job.Running {
		return errors.New("bir doğrulama zaten sürüyor")
	}
	ctx, cancel := context.WithCancel(parent)
	v.cancel = cancel
	v.job = VerifyJob{
		Running:   true,
		From:      from.Format("2006-01-02"),
		To:        to.Format("2006-01-02"),
		StartedAt: time.Now().In(v.loc).Format(time.RFC3339),
	}
	go func() {
		defer cancel()
		err := verifyRange(ctx, v.cfg, v.logRoot, v.loc, from, to, time.Now(),
			func(total int) {
				v.mu.Lock()
				v.job.Total = total
				v.mu.Unlock()
			},
			func(r VerifyResult) {
				v.mu.Lock()
				v.job.Done++
				v.job.Summary.add(r)
				v.job.Results = append(v.job.Results, r)
				v.mu.Unlock()
			})
		v.mu.Lock()
		v.job.Running = false
		v.job.FinishedAt = time.Now().In(v.loc).Format(time.RFC3339)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				v.job.Error = "doğrulama durduruldu"
			} else {
				v.job.Error = err.Error()
			}
		}
		v.mu.Unlock()
	}()
	return nil
}

// Stop, süren doğrulamayı durdurur.
func (v *FTPVerifier) Stop() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cancel != nil {
		v.cancel()
	}
}

// runFTPVerifyCommand, `netflow-logger ftp-verify` komutudur.
func runFTPVerifyCommand(ctx context.Context, cfg Config, args []string, out io.Writer) error {
	if cfg.FTP == nil {
		return errors.New("FTP kapalı: .env içinde FTP_ENABLED=true değil")
	}
	now := time.Now().In(cfg.Location)
	fromStr, toStr := now.AddDate(0, 0, -1).Format("2006-01-02"), ""
	showAll := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--from", "--to":
			if i+1 >= len(args) {
				return fmt.Errorf("%s bir tarih bekler (YYYY-AA-GG)", args[i])
			}
			if args[i] == "--from" {
				fromStr = args[i+1]
			} else {
				toStr = args[i+1]
			}
			i++
		case "--all":
			showAll = true
		default:
			return fmt.Errorf("bilinmeyen argüman: %s\nkullanım: netflow-logger ftp-verify [--from YYYY-AA-GG] [--to YYYY-AA-GG] [--all]", args[i])
		}
	}
	if toStr == "" {
		toStr = fromStr
	}
	from, err := time.ParseInLocation("2006-01-02", fromStr, cfg.Location)
	if err != nil {
		return fmt.Errorf("--from geçersiz: %s", fromStr)
	}
	to, err := time.ParseInLocation("2006-01-02", toStr, cfg.Location)
	if err != nil {
		return fmt.Errorf("--to geçersiz: %s", toStr)
	}

	fmt.Fprintf(out, "FTP doğrulaması: %s → %s (%s)\n", fromStr, toStr, cfg.FTP.address())
	var sum VerifySummary
	err = verifyRange(ctx, *cfg.FTP, cfg.LogRoot, cfg.Location, from, to, now, nil, func(r VerifyResult) {
		sum.add(r)
		if showAll || (r.Status != verifyOK && r.Status != verifyMissing) {
			fmt.Fprintf(out, "  %-7s %s  %s  %s\n", strings.ToUpper(r.Status), r.Hour, r.RemotePath, r.Detail)
		}
	})
	fmt.Fprintf(out, "Özet: %d sağlam, %d uyarı, %d hata, %d FTP'de yok · paket %s, log %s\n",
		sum.OK, sum.Warn, sum.Error, sum.Missing, humanBytes(sum.ArchiveBytes), humanBytes(sum.LogBytes))
	if err != nil {
		return err
	}
	if sum.Error > 0 {
		return fmt.Errorf("%d saatte hata bulundu", sum.Error)
	}
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
