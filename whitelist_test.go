package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeWhitelistEntry(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{" 192.168.1.10 ", "192.168.1.10", false},
		{"10.0.0.0/24", "10.0.0.0/24", false},
		{"10.0.0.5/24", "10.0.0.0/24", false}, // CIDR kanonik ağ adresine indirgenir
		{"2001:db8::1", "2001:db8::1", false},
		{"", "", true},
		{"not-an-ip", "", true},
		{"10.0.0.0/33", "", true},
	}
	for _, c := range cases {
		got, err := normalizeWhitelistEntry(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: hata bekleniyordu, alınmadı (got=%q)", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: beklenmeyen hata: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: beklenen %q, alınan %q", c.in, c.want, got)
		}
	}
}

func TestWhitelistContainsAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	w := NewWhitelist(path)

	if err := w.Add("192.168.1.10"); err != nil {
		t.Fatalf("Add tekil IP: %v", err)
	}
	if err := w.Add("10.0.0.0/24"); err != nil {
		t.Fatalf("Add CIDR: %v", err)
	}
	// Yinelenen ekleme sessizce başarılı olmalı ve listeyi büyütmemeli.
	if err := w.Add("192.168.1.10"); err != nil {
		t.Fatalf("Add yinelenen: %v", err)
	}
	if got := len(w.Entries()); got != 2 {
		t.Fatalf("beklenen 2 giriş, alınan %d", got)
	}

	if !w.Contains("192.168.1.10") {
		t.Error("tekil IP whitelist'te bulunmalı")
	}
	if !w.Contains("10.0.0.55") {
		t.Error("CIDR blok içindeki IP whitelist'te sayılmalı")
	}
	if w.Contains("172.16.0.1") {
		t.Error("listede olmayan IP whitelist'te sayılmamalı")
	}

	// config.json diske yazılmış olmalı ve yeni bir örnek onu geri yüklemeli.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config.json yazılmadı: %v", err)
	}
	w2 := NewWhitelist(path)
	if !w2.Contains("10.0.0.99") {
		t.Error("yeniden yükleme sonrası CIDR blok korunmalı")
	}

	// Kaldırma.
	if err := w.Remove("10.0.0.0/24"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if w.Contains("10.0.0.55") {
		t.Error("kaldırılan CIDR artık eşleşmemeli")
	}
}

func TestWhitelistIgnoredByAnalyzer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	w := NewWhitelist(path)
	if err := w.Add("203.0.113.0/24"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	hub := NewDashboardHub(10)
	a := NewThreatAnalyzer(hub, w)
	// Whitelist'teki kaynaktan dikey port tarama denemesi — hiç uyarı olmamalı.
	for p := 0; p < threatPortScanMin+5; p++ {
		a.Observe(FlowRecord{SrcIP: "203.0.113.7", DstIP: "10.0.0.5", DstPort: uint16(1000 + p), Protocol: "TCP"})
	}
	state := hub.Snapshot()
	if len(state.Threats) != 0 {
		t.Errorf("whitelist'teki kaynak için uyarı üretilmemeli, alınan %d", len(state.Threats))
	}
}

func TestHandleWhitelistFlow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	w := NewWhitelist(path)
	hub := NewDashboardHub(10)
	app := &App{whitelist: w, analyzer: NewThreatAnalyzer(hub, w)}

	// POST — geçerli giriş ekle.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/whitelist", strings.NewReader(`{"entry":"198.51.100.0/24"}`))
	app.handleWhitelist(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST beklenen 200, alınan %d (%s)", rec.Code, rec.Body.String())
	}

	// GET — eklenen giriş listede olmalı.
	rec = httptest.NewRecorder()
	app.handleWhitelist(rec, httptest.NewRequest(http.MethodGet, "/api/whitelist", nil))
	var resp struct {
		Entries []string `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET yanıtı çözülemedi: %v", err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0] != "198.51.100.0/24" {
		t.Fatalf("beklenen [198.51.100.0/24], alınan %v", resp.Entries)
	}

	// POST — geçersiz giriş 400 dönmeli.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/whitelist", strings.NewReader(`{"entry":"bozuk"}`))
	app.handleWhitelist(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("geçersiz giriş için 400 bekleniyordu, alınan %d", rec.Code)
	}

	// DELETE — girişi kaldır.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/whitelist?entry="+strings.NewReplacer("/", "%2F").Replace("198.51.100.0/24"), nil)
	app.handleWhitelist(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE beklenen 200, alınan %d", rec.Code)
	}
	if len(w.Entries()) != 0 {
		t.Errorf("silme sonrası liste boş olmalı, alınan %v", w.Entries())
	}
}
