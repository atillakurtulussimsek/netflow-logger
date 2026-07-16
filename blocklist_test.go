package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBlocklistAddAndIPs, ekleme, whitelist filtrelemesi ve düz metin çıktısını doğrular.
func TestBlocklistAddAndIPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	if err := w.Add("10.0.0.5"); err != nil {
		t.Fatalf("whitelist Add: %v", err)
	}
	b := NewBlocklist(path, blocklistRetention, w)

	b.Add("185.234.12.34", "bruteforce")
	b.Add("45.155.204.15", "portscan")
	b.Add("185.234.12.34", "hostsweep") // aynı IP tekrar → tekilleştirilmeli, hits artmalı
	b.Add("10.0.0.5", "bruteforce")     // whitelist'te → eklenmemeli

	ips := b.IPs()
	if len(ips) != 2 {
		t.Fatalf("2 IP bekleniyordu, alınan %d: %v", len(ips), ips)
	}
	joined := strings.Join(ips, ",")
	if !strings.Contains(joined, "185.234.12.34") || !strings.Contains(joined, "45.155.204.15") {
		t.Errorf("beklenen IP'ler yok: %v", ips)
	}
	if strings.Contains(joined, "10.0.0.5") {
		t.Errorf("whitelist'teki IP kara listeye girmemeliydi: %v", ips)
	}

	snap := b.Snapshot()
	for _, e := range snap {
		if e.IP == "185.234.12.34" && e.Hits != 2 {
			t.Errorf("185.234.12.34 için hits=2 bekleniyordu, alınan %d", e.Hits)
		}
	}
}

// TestBlocklistPersistAndReload, diske yazma ve süresi dolmuş kayıtların yeniden
// yüklemede atlanmasını doğrular.
func TestBlocklistPersistAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))

	b := NewBlocklist(path, blocklistRetention, w)
	b.Add("185.234.12.34", "bruteforce")

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("blocklist.json yazılmadı: %v", err)
	}

	// Yeni örnek diskten yüklemeli.
	b2 := NewBlocklist(path, blocklistRetention, w)
	if got := b2.IPs(); len(got) != 1 || got[0] != "185.234.12.34" {
		t.Fatalf("yeniden yükleme başarısız, alınan: %v", got)
	}

	// Süresi dolmuş bir kayıt içeren dosya yazıp yüklemenin onu atlamasını doğrula.
	expired := blocklistFileFormat{Entries: []blocklistEntry{{
		IP:        "1.2.3.4",
		Rule:      "bruteforce",
		Hits:      1,
		FirstSeen: time.Now().Add(-100 * time.Hour),
		LastSeen:  time.Now().Add(-100 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // geçmişte → atlanmalı
	}}}
	data, _ := json.MarshalIndent(expired, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("dosya yazımı: %v", err)
	}
	b3 := NewBlocklist(path, blocklistRetention, w)
	if got := b3.IPs(); len(got) != 0 {
		t.Fatalf("süresi dolmuş kayıt atlanmalıydı, alınan: %v", got)
	}
}

// TestBlocklistPurgeExpired, negatif retention ile süresi anında dolan kayıtların
// PurgeExpired ile temizlenmesini doğrular.
func TestBlocklistPurgeExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	b := NewBlocklist(path, -1*time.Minute, w) // ExpiresAt geçmişte olur

	b.Add("185.234.12.34", "bruteforce")
	if got := b.IPs(); len(got) != 0 {
		t.Fatalf("süresi geçmiş kayıt IPs() içinde görünmemeli: %v", got)
	}
	b.PurgeExpired()
	if got := b.Snapshot(); len(got) != 0 {
		t.Fatalf("PurgeExpired sonrası boş bekleniyordu: %v", got)
	}
}

// TestBlocklistEndpointToken, düz metin endpoint'in token doğrulamasını ve
// çıktısını doğrular.
func TestBlocklistEndpointToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	b := NewBlocklist(path, blocklistRetention, w)
	b.Add("185.234.12.34", "bruteforce")

	app := &App{
		cfg:       Config{BlocklistToken: "gizli-token"},
		blocklist: b,
	}

	// Token yok → 403.
	req := httptest.NewRequest(http.MethodGet, "/blocklist", nil)
	rec := httptest.NewRecorder()
	app.handleBlocklist(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token'sız istek 403 bekleniyordu, alınan %d", rec.Code)
	}

	// Yanlış token → 403.
	req = httptest.NewRequest(http.MethodGet, "/blocklist?token=yanlis", nil)
	rec = httptest.NewRecorder()
	app.handleBlocklist(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("yanlış token 403 bekleniyordu, alınan %d", rec.Code)
	}

	// Doğru token → 200 ve düz metin IP.
	req = httptest.NewRequest(http.MethodGet, "/blocklist?token=gizli-token", nil)
	rec = httptest.NewRecorder()
	app.handleBlocklist(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("doğru token 200 bekleniyordu, alınan %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("text/plain bekleniyordu, alınan %q", ct)
	}
	body := strings.TrimSpace(rec.Body.String())
	if body != "185.234.12.34" {
		t.Errorf("beklenen çıktı '185.234.12.34', alınan %q", body)
	}
}

// TestBlocklistEndpointDisabledWithoutToken, BLOCKLIST_TOKEN boşken endpoint'in
// devre dışı olduğunu doğrular.
func TestBlocklistEndpointDisabledWithoutToken(t *testing.T) {
	b := NewBlocklist(filepath.Join(t.TempDir(), "blocklist.json"), blocklistRetention,
		NewWhitelist(filepath.Join(t.TempDir(), "config.json")))
	app := &App{cfg: Config{BlocklistToken: ""}, blocklist: b}

	req := httptest.NewRequest(http.MethodGet, "/blocklist?token=any", nil)
	rec := httptest.NewRecorder()
	app.handleBlocklist(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token yapılandırılmamışken 403 bekleniyordu, alınan %d", rec.Code)
	}
}

// TestBlocklistEndpointReflectsManualImmediately, dosyaya elle eklenen manuel
// kaydın (SyncManual elle çağrılmadan) endpoint isteğinde anında görünmesini doğrular.
func TestBlocklistEndpointReflectsManualImmediately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	b := NewBlocklist(path, blocklistRetention, w)
	app := &App{cfg: Config{BlocklistToken: "tok"}, blocklist: b}

	// Süreç çalışırken kullanıcı dosyaya elle manuel IP ekler.
	writeBlocklistFile(t, path, blocklistEntry{IP: "185.234.12.34", Manual: true})

	// Endpoint isteği SyncManual'ı elle çağırmadan yansıtmalı.
	req := httptest.NewRequest(http.MethodGet, "/blocklist?token=tok", nil)
	rec := httptest.NewRecorder()
	app.handleBlocklist(rec, req)
	if body := strings.TrimSpace(rec.Body.String()); body != "185.234.12.34" {
		t.Fatalf("manuel IP endpoint'te anında görünmeliydi, alınan: %q", body)
	}
}

// writeBlocklistFile, testte dosyaya doğrudan (elle düzenleme simülasyonu) yazar.
func writeBlocklistFile(t *testing.T, path string, entries ...blocklistEntry) {
	t.Helper()
	data, err := json.MarshalIndent(blocklistFileFormat{Entries: entries}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readBlocklistFile(t *testing.T, path string) blocklistFileFormat {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var f blocklistFileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return f
}

// TestBlocklistManualPreservedOnSystemRewrite, sistem yeni IP yazarken dosyaya elle
// eklenmiş manuel kaydın ezilmediğini doğrular (kullanıcının bildirdiği hata).
func TestBlocklistManualPreservedOnSystemRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	b := NewBlocklist(path, blocklistRetention, w)

	// Sistem bir IP tespit eder → dosya oluşur.
	b.Add("45.155.204.15", "portscan")

	// Kullanıcı çalışma zamanında dosyaya elle manuel bir IP ekler.
	f := readBlocklistFile(t, path)
	f.Entries = append(f.Entries, blocklistEntry{
		IP:        "185.234.12.34",
		Rule:      "manual-ban",
		Manual:    true,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	writeBlocklistFile(t, path, f.Entries...)

	// Sistem başka bir IP tespit eder → dosyayı yeniden yazar.
	b.Add("203.0.113.7", "bruteforce")

	// Manuel kayıt hem dosyada hem endpoint çıktısında olmalı.
	got := b.IPs()
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "185.234.12.34") {
		t.Fatalf("manuel IP ezilmiş, alınan: %v", got)
	}
	if !strings.Contains(joined, "45.155.204.15") || !strings.Contains(joined, "203.0.113.7") {
		t.Errorf("sistem IP'leri kaybolmuş, alınan: %v", got)
	}
	onDisk := readBlocklistFile(t, path)
	foundManual := false
	for _, e := range onDisk.Entries {
		if e.IP == "185.234.12.34" && e.Manual {
			foundManual = true
		}
	}
	if !foundManual {
		t.Errorf("manuel kayıt diskte manual=true olarak korunmadı: %+v", onDisk.Entries)
	}
}

// TestBlocklistManualNotPurged, manuel kaydın süresi geçmiş olsa bile PurgeExpired
// tarafından silinmediğini doğrular.
func TestBlocklistManualNotPurged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	// Süresi geçmiş bir manuel kayıt yaz.
	writeBlocklistFile(t, path, blocklistEntry{
		IP:        "185.234.12.34",
		Rule:      "manual-ban",
		Manual:    true,
		FirstSeen: time.Now().Add(-100 * time.Hour),
		LastSeen:  time.Now().Add(-100 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // geçmişte ama manuel → kalmalı
	})

	b := NewBlocklist(path, blocklistRetention, w)
	if got := b.IPs(); len(got) != 1 || got[0] != "185.234.12.34" {
		t.Fatalf("süresi geçmiş manuel kayıt yüklenmeliydi, alınan: %v", got)
	}
	b.PurgeExpired()
	if got := b.IPs(); len(got) != 1 {
		t.Fatalf("manuel kayıt PurgeExpired ile silinmemeliydi, alınan: %v", got)
	}
}

// TestBlocklistSyncManualAddRemove, çalışma zamanında dosyaya eklenen manuel kaydın
// belleğe alınmasını ve dosyadan silinince bellekten düşmesini doğrular.
func TestBlocklistSyncManualAddRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	b := NewBlocklist(path, blocklistRetention, w)

	// Süreç çalışırken dosyaya elle manuel IP ekle.
	writeBlocklistFile(t, path, blocklistEntry{
		IP:        "185.234.12.34",
		Manual:    true,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	b.SyncManual()
	if got := b.IPs(); len(got) != 1 || got[0] != "185.234.12.34" {
		t.Fatalf("SyncManual manuel IP'yi almadı, alınan: %v", got)
	}

	// Kullanıcı manuel kaydı dosyadan siler → SyncManual bellekten düşürmeli.
	writeBlocklistFile(t, path)
	b.SyncManual()
	if got := b.IPs(); len(got) != 0 {
		t.Fatalf("dosyadan silinen manuel kayıt bellekte kaldı, alınan: %v", got)
	}
}

// TestBlocklistAddManual, web arayüzünden gelen manuel engellemenin diske kalıcı
// yazıldığını ve yeniden yüklemede korunduğunu doğrular. Ayrıca whitelist'teki IP'nin
// ve geçersiz girdinin reddedildiğini kontrol eder.
func TestBlocklistAddManual(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	if err := w.Add("10.0.0.5"); err != nil {
		t.Fatalf("whitelist Add: %v", err)
	}
	b := NewBlocklist(path, blocklistRetention, w)

	if err := b.AddManual("203.0.113.7", "Panelden elle engellendi"); err != nil {
		t.Fatalf("AddManual: %v", err)
	}
	// Whitelist'teki IP engellenememeli.
	if err := b.AddManual("10.0.0.5", ""); err == nil {
		t.Error("whitelist'teki IP için AddManual hata vermeliydi")
	}
	// Geçersiz IP reddedilmeli.
	if err := b.AddManual("değil-ip", ""); err == nil {
		t.Error("geçersiz IP için AddManual hata vermeliydi")
	}

	// Diskten yeniden yükle: manuel kayıt korunmalı ve manual=true olmalı.
	b2 := NewBlocklist(path, blocklistRetention, w)
	snap := b2.Snapshot()
	if len(snap) != 1 || snap[0].IP != "203.0.113.7" || !snap[0].Manual {
		t.Fatalf("manuel kayıt yeniden yüklemede korunmadı, alınan: %+v", snap)
	}
}

// TestBlocklistRemoveManual, manuel engelin kaldırılabildiğini; sistem (manuel olmayan)
// kayıtların ise RemoveManual ile silinemediğini doğrular.
func TestBlocklistRemoveManual(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	b := NewBlocklist(path, blocklistRetention, w)

	if err := b.AddManual("203.0.113.7", ""); err != nil {
		t.Fatalf("AddManual: %v", err)
	}
	b.Add("185.234.12.34", "bruteforce") // sistem kaydı

	// Sistem kaydı RemoveManual ile silinememeli.
	if err := b.RemoveManual("185.234.12.34"); err == nil {
		t.Error("sistem kaydı için RemoveManual hata vermeliydi")
	}
	// Manuel kayıt kaldırılabilmeli.
	if err := b.RemoveManual("203.0.113.7"); err != nil {
		t.Fatalf("RemoveManual: %v", err)
	}

	// Diskten yeniden yükle: manuel kayıt gitmiş, sistem kaydı durmalı.
	b2 := NewBlocklist(path, blocklistRetention, w)
	ips := b2.IPs()
	if len(ips) != 1 || ips[0] != "185.234.12.34" {
		t.Fatalf("beklenen yalnız sistem kaydı, alınan: %v", ips)
	}
}

// TestBlocklistAPIManualLifecycle, /api/blocklist POST/GET/DELETE akışını uçtan uca doğrular.
func TestBlocklistAPIManualLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.json")
	w := NewWhitelist(filepath.Join(t.TempDir(), "config.json"))
	b := NewBlocklist(path, blocklistRetention, w)
	app := &App{cfg: Config{}, blocklist: b}

	// POST: IP engelle.
	req := httptest.NewRequest(http.MethodPost, "/api/blocklist", strings.NewReader(`{"ip":"203.0.113.7"}`))
	rec := httptest.NewRecorder()
	app.handleBlocklistAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST 200 bekleniyordu, alınan %d: %s", rec.Code, rec.Body.String())
	}

	// GET: kayıt görünmeli ve manual=true olmalı.
	req = httptest.NewRequest(http.MethodGet, "/api/blocklist", nil)
	rec = httptest.NewRecorder()
	app.handleBlocklistAPI(rec, req)
	var resp struct {
		Entries []blocklistEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET yanıtı çözümlenemedi: %v", err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].IP != "203.0.113.7" || !resp.Entries[0].Manual {
		t.Fatalf("GET beklenen manuel kaydı döndürmedi: %+v", resp.Entries)
	}

	// POST geçersiz IP → 400.
	req = httptest.NewRequest(http.MethodPost, "/api/blocklist", strings.NewReader(`{"ip":"bozuk"}`))
	rec = httptest.NewRecorder()
	app.handleBlocklistAPI(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("geçersiz IP POST 400 bekleniyordu, alınan %d", rec.Code)
	}

	// DELETE: engeli kaldır.
	req = httptest.NewRequest(http.MethodDelete, "/api/blocklist?ip=203.0.113.7", nil)
	rec = httptest.NewRecorder()
	app.handleBlocklistAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE 200 bekleniyordu, alınan %d: %s", rec.Code, rec.Body.String())
	}
	if got := b.IPs(); len(got) != 0 {
		t.Fatalf("DELETE sonrası liste boş olmalıydı, alınan: %v", got)
	}
}
