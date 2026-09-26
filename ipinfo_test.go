package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func flowLine(ts, src, dst, sp, dp, proto, pkts, bytes string) string {
	return strings.Join([]string{ts, src, dst, sp, dp, proto, pkts, bytes, "1", "2", ts, ts}, "|")
}

// IP'nin kaynak veya hedef olduğu akışların süzüldüğünü, en yenisinin üstte
// olduğunu ve özetin doğru hesaplandığını doğrular.
func TestSummarizeIPTraffic(t *testing.T) {
	records := []string{
		flowLine("2026-09-25T10:00:00Z", "10.0.0.5", "8.8.8.8", "51000", "53", "UDP", "1", "80"),
		flowLine("2026-09-25T10:00:01Z", "1.2.3.4", "10.0.0.9", "40000", "22", "TCP", "5", "500"),
		flowLine("2026-09-25T10:00:02Z", "8.8.8.8", "10.0.0.5", "53", "51000", "UDP", "1", "120"),
		flowLine("2026-09-25T10:00:03Z", "10.0.0.5", "1.1.1.1", "51001", "443", "TCP", "10", "1000"),
	}

	matched, sum := summarizeIPTraffic(records, "10.0.0.5")

	if len(matched) != 3 {
		t.Fatalf("eşleşen kayıt sayısı = %d, beklenen 3", len(matched))
	}
	if matched[0] != records[3] {
		t.Errorf("en yeni kayıt ilk sırada değil: %q", matched[0])
	}
	if sum.Flows != 3 || sum.Outbound != 2 || sum.Inbound != 1 {
		t.Errorf("akış sayıları hatalı: %+v", sum)
	}
	if sum.Bytes != 1200 || sum.BytesOut != 1080 || sum.BytesIn != 120 || sum.Packets != 12 {
		t.Errorf("bayt/paket toplamları hatalı: %+v", sum)
	}
	if sum.FirstSeen != "2026-09-25T10:00:00Z" || sum.LastSeen != "2026-09-25T10:00:03Z" {
		t.Errorf("ilk/son görülme hatalı: %s / %s", sum.FirstSeen, sum.LastSeen)
	}
	if len(sum.TopPeers) != 2 || sum.TopPeers[0].IP != "8.8.8.8" || sum.TopPeers[0].Flows != 2 {
		t.Errorf("en çok konuşulan eş hatalı: %+v", sum.TopPeers)
	}
	if len(sum.TopPorts) != 2 || sum.TopPorts[0].Port != 53 || sum.TopPorts[0].Protocol != "UDP" {
		t.Errorf("servis portu özeti hatalı: %+v", sum.TopPorts)
	}
}

func TestIPScope(t *testing.T) {
	cases := map[string]struct {
		scope  string
		public bool
	}{
		"10.1.2.3":    {"Özel ağ", false},
		"127.0.0.1":   {"Loopback", false},
		"100.64.1.1":  {"CGNAT", false},
		"169.254.1.1": {"Link-local", false},
		"8.8.8.8":     {"Genel", true},
		"2001:4860::": {"Genel", true},
	}
	for in, want := range cases {
		scope, public := ipScope(net.ParseIP(in))
		if scope != want.scope || public != want.public {
			t.Errorf("%s: (%s, %v), beklenen (%s, %v)", in, scope, public, want.scope, want.public)
		}
	}
}

// Konum yanıtının önbelleğe alındığını ve ikinci sorguda servise gidilmediğini doğrular.
func TestGeoResolverCaches(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"status":"success","country":"Almanya","countryCode":"DE","city":"Frankfurt","isp":"Örnek ISP","as":"AS64500 Örnek"}`))
	}))
	defer srv.Close()

	g := NewGeoResolver()
	g.baseURL = srv.URL + "/"

	for i := 0; i < 2; i++ {
		geo, errMsg := g.Lookup(context.Background(), "8.8.8.8")
		if errMsg != "" || geo == nil || geo.CountryCode != "DE" || geo.AS != "AS64500 Örnek" {
			t.Fatalf("beklenmeyen konum yanıtı: %+v, %q", geo, errMsg)
		}
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("servis %d kez çağrıldı, önbellek çalışmıyor", hits)
	}
}

func TestHandleIPInfo(t *testing.T) {
	hub := NewDashboardHub(dashboardMaxRecords)
	hub.records = []string{
		flowLine("2026-09-25T10:00:00Z", "10.0.0.5", "10.0.0.1", "51000", "53", "UDP", "1", "80"),
		flowLine("2026-09-25T10:00:01Z", "10.0.0.7", "10.0.0.1", "51000", "53", "UDP", "1", "80"),
	}
	app := &App{dashboard: hub}

	rec := httptest.NewRecorder()
	app.handleIPInfo(rec, httptest.NewRequest(http.MethodGet, "/api/ip?ip=10.0.0.5&lite=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("durum kodu = %d, gövde: %s", rec.Code, rec.Body.String())
	}
	var resp IPInfoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Scope != "Özel ağ" || resp.Public || resp.Version != 4 {
		t.Errorf("ağ sınıfı hatalı: %+v", resp)
	}
	if len(resp.Records) != 1 || resp.Summary.Outbound != 1 || resp.Scanned != 2 {
		t.Errorf("trafik süzme hatalı: %d kayıt, özet %+v", len(resp.Records), resp.Summary)
	}

	rec = httptest.NewRecorder()
	app.handleIPInfo(rec, httptest.NewRequest(http.MethodGet, "/api/ip?ip=abc", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("geçersiz IP için durum kodu = %d", rec.Code)
	}
}
