package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFTPServer, testler için bellekte çalışan asgari bir FTP sunucusudur.
type fakeFTPServer struct {
	t        *testing.T
	ln       net.Listener
	user     string
	password string

	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
}

func newFakeFTPServer(t *testing.T) *fakeFTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeFTPServer{
		t: t, ln: ln, user: "u", password: "p",
		files: map[string][]byte{},
		dirs:  map[string]bool{"": true, "/": true},
	}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeFTPServer) config() FTPConfig {
	host, portStr, _ := net.SplitHostPort(s.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return FTPConfig{Host: host, Port: port, User: s.user, Password: s.password}
}

func (s *fakeFTPServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func cleanRemote(p string) string {
	p = path.Clean(p)
	if p == "." {
		return ""
	}
	return p
}

func (s *fakeFTPServer) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	reply := func(format string, args ...any) { fmt.Fprintf(conn, format+"\r\n", args...) }
	reply("220 fake")

	var dataLn net.Listener
	var renameFrom string
	loggedIn := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)

		if !loggedIn && cmd != "USER" && cmd != "PASS" && cmd != "QUIT" {
			reply("530 not logged in")
			continue
		}

		s.mu.Lock()
		switch cmd {
		case "USER":
			if arg == s.user {
				reply("331 password")
			} else {
				reply("530 bad user")
			}
		case "PASS":
			if arg == s.password {
				loggedIn = true
				reply("230 ok")
			} else {
				reply("530 bad password")
			}
		case "FEAT":
			reply("211-Features:\r\n SIZE\r\n211 End")
		case "TYPE":
			reply("200 ok")
		case "EPSV":
			dataLn, _ = net.Listen("tcp", "127.0.0.1:0")
			_, port, _ := net.SplitHostPort(dataLn.Addr().String())
			reply("229 Entering Extended Passive Mode (|||%s|)", port)
		case "MKD":
			p := cleanRemote(arg)
			if s.dirs[p] {
				reply("550 exists")
			} else if !s.dirs[cleanRemote(path.Dir(p))] {
				reply("550 parent missing")
			} else {
				s.dirs[p] = true
				reply("257 created")
			}
		case "STOR":
			p := cleanRemote(arg)
			if !s.dirs[cleanRemote(path.Dir(p))] || dataLn == nil {
				reply("550 no dir")
				break
			}
			ln := dataLn
			dataLn = nil
			s.mu.Unlock()
			reply("150 ok")
			dc, err := ln.Accept()
			_ = ln.Close()
			var data []byte
			if err == nil {
				data, _ = io.ReadAll(dc)
				_ = dc.Close()
			}
			s.mu.Lock()
			s.files[p] = data
			reply("226 done")
		case "RETR", "NLST":
			var payload []byte
			if cmd == "RETR" {
				data, ok := s.files[cleanRemote(arg)]
				if !ok || dataLn == nil {
					reply("550 not found")
					break
				}
				payload = data
			} else {
				if dataLn == nil {
					reply("425 no data conn")
					break
				}
				dir := cleanRemote(arg)
				for name := range s.files {
					if cleanRemote(path.Dir(name)) == dir {
						payload = append(payload, []byte(name+"\r\n")...)
					}
				}
			}
			ln := dataLn
			dataLn = nil
			s.mu.Unlock()
			reply("150 ok")
			if dc, err := ln.Accept(); err == nil {
				_, _ = dc.Write(payload)
				_ = dc.Close()
			}
			_ = ln.Close()
			s.mu.Lock()
			reply("226 done")
		case "SIZE":
			if data, ok := s.files[cleanRemote(arg)]; ok {
				reply("213 %d", len(data))
			} else {
				reply("550 not found")
			}
		case "DELE":
			p := cleanRemote(arg)
			if _, ok := s.files[p]; ok {
				delete(s.files, p)
				reply("250 deleted")
			} else {
				reply("550 not found")
			}
		case "RNFR":
			renameFrom = cleanRemote(arg)
			reply("350 ready")
		case "RNTO":
			data, ok := s.files[renameFrom]
			if !ok {
				reply("550 not found")
				break
			}
			delete(s.files, renameFrom)
			s.files[cleanRemote(arg)] = data
			reply("250 renamed")
		case "QUIT":
			reply("221 bye")
			s.mu.Unlock()
			return
		default:
			reply("502 not implemented")
		}
		s.mu.Unlock()
	}
}

func (s *fakeFTPServer) fileNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for name := range s.files {
		names = append(names, name)
	}
	return names
}

func (s *fakeFTPServer) file(name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.files[name]
	return data, ok
}

func writeSealedHour(t *testing.T, root string, hour time.Time, content, digest string) string {
	t.Helper()
	logPath := buildLogPath(root, hour)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatal(err)
	}
	for p, data := range map[string]string{
		logPath:             content,
		logPath + ".sha256": digest + "\n",
		logPath + ".tsr":    "tsr-" + digest,
	} {
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return logPath
}

func readTarGz(t *testing.T, data []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		body, _ := io.ReadAll(tr)
		out[h.Name] = string(body)
	}
	return out
}

func TestRunFTPTest(t *testing.T) {
	srv := newFakeFTPServer(t)
	cfg := srv.config()
	cfg.Prefix = "musteri1"
	var out bytes.Buffer
	if err := runFTPTest(context.Background(), cfg, &out); err != nil {
		t.Fatalf("ftp test failed: %v\n%s", err, out.String())
	}
	if names := srv.fileNames(); len(names) != 0 {
		t.Fatalf("test dosyası silinmemiş: %v", names)
	}

	cfg.Password = "yanlis"
	if err := runFTPTest(context.Background(), cfg, io.Discard); err == nil {
		t.Fatal("yanlış parola ile test başarılı olmamalı")
	}

	cfg = srv.config()
	cfg.Port = 1
	if err := runFTPTest(context.Background(), cfg, io.Discard); err == nil {
		t.Fatal("erişilemeyen sunucu ile test başarılı olmamalı")
	}
}

func TestFTPArchiverUploadsPackagesAndRetention(t *testing.T) {
	srv := newFakeFTPServer(t)
	root := t.TempDir()
	loc := time.UTC
	now := time.Date(2026, 11, 22, 14, 30, 0, 0, loc)

	oldHour := now.Add(-10 * 24 * time.Hour).Truncate(time.Hour) // saklama süresi dolmuş
	recentHour := now.Add(-2 * time.Hour).Truncate(time.Hour)
	unsealedHour := now.Add(-1 * time.Hour).Truncate(time.Hour)
	currentHour := now.Truncate(time.Hour)

	oldPath := writeSealedHour(t, root, oldHour, "old-data\n", "aaa")
	recentPath := writeSealedHour(t, root, recentHour, "recent-data\n", "bbb")
	unsealedPath := buildLogPath(root, unsealedHour)
	_ = os.WriteFile(unsealedPath, []byte("x\n"), 0o644)
	currentPath := writeSealedHour(t, root, currentHour, "current\n", "ccc")

	cfg := srv.config()
	cfg.Prefix = "netflow/site1"
	archiver := NewFTPArchiver(cfg, root, loc, 7, func() string { return currentPath })
	archiver.now = func() time.Time { return now }

	// Geriye dönük yükleme kapalı: FTP'nin açıldığı andan önceki saatler atlanır.
	since := shaOnlyHourStart(now)
	archiver.RunOnce(context.Background(), since)

	if _, ok := srv.file(remoteArchivePath(cfg.Prefix, oldHour)); ok {
		t.Fatal("backfill kapalıyken eski saat yüklenmemeli")
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatal("yüklenmemiş saat yerelden silinmemeli")
	}
	data, ok := srv.file("netflow/site1/2026/11/22/12.tar.gz")
	if !ok {
		t.Fatalf("son saat yüklenmeli; sunucudaki dosyalar: %v", srv.fileNames())
	}
	files := readTarGz(t, data)
	if files["12.log"] != "recent-data\n" || files["12.log.sha256"] != "bbb\n" || files["12.log.tsr"] != "tsr-bbb" || len(files) != 3 {
		t.Fatalf("paket içeriği hatalı: %v", files)
	}
	if readMarker(recentPath) != "bbb" {
		t.Fatal("yükleme işareti yazılmalı")
	}
	if _, err := os.Stat(recentPath); err != nil {
		t.Fatal("saklama süresi dolmamış saat yerelde kalmalı")
	}
	// Mühürsüz saat de (yalnız .log ile) yüklenir; aktif saat yüklenmez.
	data, ok = srv.file("netflow/site1/2026/11/22/13.tar.gz")
	if !ok {
		t.Fatalf("mühürsüz saat yüklenmeli; sunucudaki dosyalar: %v", srv.fileNames())
	}
	if files := readTarGz(t, data); len(files) != 1 || files["13.log"] != "x\n" {
		t.Fatalf("mühürsüz paket içeriği hatalı: %v", files)
	}
	if len(srv.fileNames()) != 2 {
		t.Fatalf("aktif saat yüklenmemeli: %v", srv.fileNames())
	}

	// Mühür sonradan tamamlanırsa paket mühür dosyalarıyla yeniden yüklenir.
	writeSealedHour(t, root, unsealedHour, "x\n", "eee")
	archiver.RunOnce(context.Background(), since)
	data, _ = srv.file("netflow/site1/2026/11/22/13.tar.gz")
	if files := readTarGz(t, data); len(files) != 3 || files["13.log.tsr"] != "tsr-eee" {
		t.Fatalf("mühürlenen saat yeniden yüklenmeli: %v", files)
	}

	// Yalnız .sha256 olan (TSA başarısız) saat de yüklenir.
	shaOnlyHour := now.Add(-3 * time.Hour).Truncate(time.Hour)
	shaOnlyPath := writeSealedHour(t, root, shaOnlyHour, "sha-only\n", "fff")
	_ = os.Remove(shaOnlyPath + ".tsr")
	archiver.RunOnce(context.Background(), since)
	data, ok = srv.file("netflow/site1/2026/11/22/11.tar.gz")
	if !ok {
		t.Fatal(".tsr olmayan saat yüklenmeli")
	}
	if files := readTarGz(t, data); len(files) != 2 || files["11.log.sha256"] != "fff\n" {
		t.Fatalf(".tsr olmayan paket içeriği hatalı: %v", files)
	}

	// Geriye dönük yükleme açık: eski saat yüklenir ve süresi dolduğu için silinir.
	archiver.cfg.Backfill = true
	archiver.RunOnce(context.Background(), since)
	if _, ok := srv.file(remoteArchivePath(cfg.Prefix, oldHour)); !ok {
		t.Fatal("backfill açıkken eski saat yüklenmeli")
	}
	for _, p := range []string{oldPath, oldPath + ".sha256", oldPath + ".tsr", oldPath + ftpMarkerSuffix} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s silinmeliydi", p)
		}
	}
	if _, err := os.Stat(filepath.Dir(oldPath)); !os.IsNotExist(err) {
		t.Fatal("boşalan gün klasörü silinmeli")
	}

	// Saat yeniden mühürlenirse (SHA değişir) paket yeniden yüklenir.
	writeSealedHour(t, root, recentHour, "recent-data\nlate\n", "ddd")
	archiver.RunOnce(context.Background(), since)
	data, _ = srv.file("netflow/site1/2026/11/22/12.tar.gz")
	if readTarGz(t, data)["12.log"] != "recent-data\nlate\n" || readMarker(recentPath) != "ddd" {
		t.Fatal("yeniden mühürlenen saat yeniden yüklenmeli")
	}
}

func shaOnlyHourStart(now time.Time) time.Time {
	return now.Add(-3 * time.Hour).Truncate(time.Hour)
}

func TestFTPArchiverKeepsLocalWhenServerDown(t *testing.T) {
	srv := newFakeFTPServer(t)
	root := t.TempDir()
	now := time.Date(2026, 11, 22, 14, 30, 0, 0, time.UTC)
	oldHour := now.Add(-30 * 24 * time.Hour).Truncate(time.Hour)
	logPath := writeSealedHour(t, root, oldHour, "data\n", "aaa")

	cfg := srv.config()
	cfg.Password = "yanlis"
	cfg.Backfill = true
	archiver := NewFTPArchiver(cfg, root, time.UTC, 7, nil)
	archiver.now = func() time.Time { return now }
	archiver.RunOnce(context.Background(), now)

	if _, err := os.Stat(logPath); err != nil {
		t.Fatal("yüklenemeyen saat yerelden silinmemeli")
	}
	if readMarker(logPath) != "" {
		t.Fatal("başarısız yüklemede işaret yazılmamalı")
	}
}

func TestFTPArchiverRetentionZeroNeverDeletes(t *testing.T) {
	srv := newFakeFTPServer(t)
	root := t.TempDir()
	now := time.Date(2026, 11, 22, 14, 30, 0, 0, time.UTC)
	logPath := writeSealedHour(t, root, now.Add(-365*24*time.Hour).Truncate(time.Hour), "data\n", "aaa")

	cfg := srv.config()
	cfg.Backfill = true
	archiver := NewFTPArchiver(cfg, root, time.UTC, 0, nil)
	archiver.now = func() time.Time { return now }
	archiver.RunOnce(context.Background(), now)

	if readMarker(logPath) != "aaa" {
		t.Fatal("saat yüklenmeli")
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Fatal("LOCAL_RETENTION_DAYS=0 iken yerel dosya silinmemeli")
	}
}

func TestLoadFTPConfig(t *testing.T) {
	cfg, err := loadFTPConfig(map[string]string{})
	if err != nil || cfg != nil {
		t.Fatalf("FTP_ENABLED yokken nil beklenir: %v %v", cfg, err)
	}
	if _, err := loadFTPConfig(map[string]string{"FTP_ENABLED": "true"}); err == nil {
		t.Fatal("host/kullanıcı eksikken hata beklenir")
	}
	if _, err := loadFTPConfig(map[string]string{"FTP_ENABLED": "true", "FTP_HOST": "h", "FTP_USER": "u", "FTP_PORT": "abc"}); err == nil {
		t.Fatal("geçersiz port hata vermeli")
	}
	cfg, err = loadFTPConfig(map[string]string{
		"FTP_ENABLED": "true", "FTP_HOST": "ftp.example.com", "FTP_USER": "u",
		"FTP_PASSWORD": "p", "FTP_PREFIX": " /yedek/netflow/ ", "FTP_BACKFILL": "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 21 || cfg.Prefix != "/yedek/netflow" || !cfg.Backfill {
		t.Fatalf("beklenmeyen config: %+v", cfg)
	}
	if got := remoteArchivePath("", time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)); got != "2026/01/02/03.tar.gz" {
		t.Fatalf("prefix'siz yol hatalı: %s", got)
	}

	if d, err := loadLocalRetentionDays(""); err != nil || d != 7 {
		t.Fatalf("varsayılan 7 gün olmalı: %d %v", d, err)
	}
	if _, err := loadLocalRetentionDays("-1"); err == nil {
		t.Fatal("negatif süre hata vermeli")
	}
}

func TestFTPArchiverStatusAndDeletesWhenServerDown(t *testing.T) {
	srv := newFakeFTPServer(t)
	root := t.TempDir()
	now := time.Date(2026, 11, 22, 14, 30, 0, 0, time.UTC)

	// Daha önce yüklenmiş ve süresi dolmuş saat: FTP'ye ulaşılamasa da silinmeli.
	expiredHour := now.Add(-20 * 24 * time.Hour).Truncate(time.Hour)
	expiredPath := writeSealedHour(t, root, expiredHour, "old\n", "aaa")
	if err := os.WriteFile(expiredPath+ftpMarkerSuffix, []byte("aaa\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Yüklenmemiş saat: bekliyor olarak sayılmalı.
	pendingHour := now.Add(-2 * time.Hour).Truncate(time.Hour)
	writeSealedHour(t, root, pendingHour, "pending\n", "bbb")
	// Geriye dönük kapalıyken başlangıçtan önceki saat: atlanan.
	skippedHour := now.Add(-3 * 24 * time.Hour).Truncate(time.Hour)
	writeSealedHour(t, root, skippedHour, "skip\n", "ccc")

	cfg := srv.config()
	cfg.Password = "yanlis"
	archiver := NewFTPArchiver(cfg, root, time.UTC, 7, nil)
	archiver.now = func() time.Time { return now }
	archiver.RunOnce(context.Background(), now.Add(-24*time.Hour).Truncate(time.Hour))

	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Fatal("FTP kapalıyken de yüklenmiş ve süresi dolmuş saat silinmeli")
	}
	st := archiver.Status()
	if st.State != "error" || st.LastError == "" {
		t.Fatalf("hata durumu beklenir: %+v", st)
	}
	if st.Pending != 1 || st.Skipped != 1 || st.UploadedLocal != 0 || st.DeletedTotal != 1 {
		t.Fatalf("beklenmeyen sayılar: %+v", st)
	}
	if st.PendingBytes != int64(len("pending\n")+len("bbb\n")+len("tsr-bbb")) {
		t.Fatalf("bekleyen boyut hatalı: %d", st.PendingBytes)
	}

	// Sunucu düzelince bekleyen yüklenir, durum güncellenir.
	archiver.cfg.Password = srv.password
	archiver.RunOnce(context.Background(), now.Add(-24*time.Hour).Truncate(time.Hour))
	st = archiver.Status()
	if st.State != "ok" || st.Pending != 0 || st.UploadedLocal != 1 || st.UploadedTotal != 1 || st.LastUpload == "" {
		t.Fatalf("başarılı tarama sonrası durum hatalı: %+v", st)
	}
	wantNext := pendingHour.Add(time.Hour + 7*24*time.Hour).Format(time.RFC3339)
	if st.NextDeletion != wantNext {
		t.Fatalf("sonraki silme %s, beklenen %s", st.NextDeletion, wantNext)
	}
}

func TestBuildDiskStatus(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "a.log"), make([]byte, 1000), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "x"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "x", "b.tsr"), make([]byte, 24), 0o644)
	st := buildDiskStatus(root)
	if st.LogRootBytes != 1024 {
		t.Fatalf("log dizini boyutu 1024 olmalı: %d", st.LogRootBytes)
	}
	if st.Total == 0 || st.Free > st.Total {
		t.Fatalf("disk bilgisi hatalı: %+v", st)
	}
}

// Disk doluyken işaret dosyası yazılamaz; süresi dolmuş saat yine de
// yüklendikten sonra silinmeli (silme boş alan gerektirmez).
func TestFTPArchiverDeletesExpiredWhenMarkerUnwritable(t *testing.T) {
	srv := newFakeFTPServer(t)
	root := t.TempDir()
	now := time.Date(2026, 11, 22, 14, 30, 0, 0, time.UTC)

	expiredHour := now.Add(-50 * 24 * time.Hour).Truncate(time.Hour)
	expiredPath := writeSealedHour(t, root, expiredHour, "old\n", "aaa")
	recentHour := now.Add(-2 * time.Hour).Truncate(time.Hour)
	recentPath := writeSealedHour(t, root, recentHour, "new\n", "bbb")
	// İşaret yolunu klasör yaparak yazmayı başarısız kıl (ENOSPC benzetimi).
	for _, p := range []string{expiredPath, recentPath} {
		if err := os.Mkdir(p+ftpMarkerSuffix, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cfg := srv.config()
	cfg.Backfill = true
	archiver := NewFTPArchiver(cfg, root, time.UTC, 3, nil)
	archiver.now = func() time.Time { return now }
	archiver.RunOnce(context.Background(), now)

	if _, ok := srv.file(remoteArchivePath("", expiredHour)); !ok {
		t.Fatal("süresi dolmuş saat yüklenmeli")
	}
	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Fatal("işaret yazılamasa da süresi dolmuş saat silinmeli")
	}
	if _, err := os.Stat(recentPath); err != nil {
		t.Fatal("süresi dolmamış saat yerelde kalmalı")
	}
	st := archiver.Status()
	if st.DeletedTotal != 1 || st.UploadedTotal != 2 || st.State != "error" || st.Scanning {
		t.Fatalf("beklenmeyen durum: %+v", st)
	}
	if st.ScanDone != st.ScanTotal || st.ScanTotal != 2 {
		t.Fatalf("tarama ilerlemesi hatalı: %+v", st)
	}
}
