package main

import (
	"strconv"
	"testing"
	"time"
)

func feed(a *ThreatAnalyzer, r FlowRecord, n int) {
	for i := 0; i < n; i++ {
		a.Observe(r)
	}
}

func alertsByRule(hub *DashboardHub) map[string]ThreatAlert {
	out := make(map[string]ThreatAlert)
	for _, al := range hub.Snapshot().Threats {
		out[al.Rule] = al
	}
	return out
}

func TestBruteforceDetection(t *testing.T) {
	hub := NewDashboardHub(10)
	a := NewThreatAnalyzer(hub, nil, nil)

	feed(a, FlowRecord{SrcIP: "203.0.113.9", DstIP: "10.0.0.5", DstPort: 22, Protocol: "TCP"}, threatBruteforceMin+5)

	got := alertsByRule(hub)
	al, ok := got["bruteforce"]
	if !ok {
		t.Fatalf("brute-force uyarısı bekleniyordu, üretilmedi: %+v", hub.Snapshot().Threats)
	}
	if al.Severity != "high" {
		t.Errorf("brute-force yüksek önem beklenir, alınan: %q", al.Severity)
	}
	if al.Port != 22 || al.Service != "SSH" {
		t.Errorf("port/servis 22/SSH beklenir, alınan: %d/%s", al.Port, al.Service)
	}
	if al.Count < threatBruteforceMin {
		t.Errorf("sayaç en az %d beklenir, alınan: %d", threatBruteforceMin, al.Count)
	}
}

func TestVerticalPortScanDetection(t *testing.T) {
	hub := NewDashboardHub(10)
	a := NewThreatAnalyzer(hub, nil, nil)

	for p := 0; p < threatPortScanMin; p++ {
		a.Observe(FlowRecord{SrcIP: "198.51.100.7", DstIP: "10.0.0.5", DstPort: uint16(1000 + p), Protocol: "TCP"})
	}

	if _, ok := alertsByRule(hub)["portscan"]; !ok {
		t.Fatalf("dikey port tarama uyarısı bekleniyordu: %+v", hub.Snapshot().Threats)
	}
}

func TestHorizontalHostSweepDetection(t *testing.T) {
	hub := NewDashboardHub(10)
	a := NewThreatAnalyzer(hub, nil, nil)

	for i := 0; i < threatHostSweepMin; i++ {
		a.Observe(FlowRecord{SrcIP: "198.51.100.8", DstIP: "10.0.0." + strconv.Itoa(i), DstPort: 445, Protocol: "TCP"})
	}

	al, ok := alertsByRule(hub)["hostsweep"]
	if !ok {
		t.Fatalf("yatay host tarama uyarısı bekleniyordu: %+v", hub.Snapshot().Threats)
	}
	if al.Port != 445 {
		t.Errorf("port 445 beklenir, alınan: %d", al.Port)
	}
}

// TestAlertExpiresWhenIdle, tespit edilip banlanan bir kaynağın uyarısının,
// threatAlertTTL (3 dk) boyunca yeni akış gelmezse Maintain ile panelden
// kaldırıldığını doğrular. Böylece hareketsiz IP'ler ekranda takılı kalmaz.
func TestAlertExpiresWhenIdle(t *testing.T) {
	hub := NewDashboardHub(10)
	a := NewThreatAnalyzer(hub, nil, nil)

	feed(a, FlowRecord{SrcIP: "203.0.113.9", DstIP: "10.0.0.5", DstPort: 22, Protocol: "TCP"}, threatBruteforceMin+5)
	if len(hub.Snapshot().Threats) == 0 {
		t.Fatalf("önce bir uyarı üretilmeliydi")
	}

	// Kaynağı hareketsiz say: tüm uyarıların son görülme zamanını TTL'in ötesine çek.
	a.mu.Lock()
	for _, al := range a.alerts {
		al.lastSeen = time.Now().Add(-threatAlertTTL - time.Second)
	}
	a.mu.Unlock()

	a.Maintain()

	if n := len(hub.Snapshot().Threats); n != 0 {
		t.Fatalf("TTL sonrası hareketsiz uyarı kaldırılmalıydı, kalan: %d — %+v", n, hub.Snapshot().Threats)
	}
}

// TestAlertPersistsWhileActive, TTL dolmadan önce uyarının panelde kaldığını doğrular.
func TestAlertPersistsWhileActive(t *testing.T) {
	hub := NewDashboardHub(10)
	a := NewThreatAnalyzer(hub, nil, nil)

	feed(a, FlowRecord{SrcIP: "203.0.113.9", DstIP: "10.0.0.5", DstPort: 22, Protocol: "TCP"}, threatBruteforceMin+5)

	// TTL'in yarısı kadar hareketsizlik: uyarı hâlâ görünmeli.
	a.mu.Lock()
	for _, al := range a.alerts {
		al.lastSeen = time.Now().Add(-threatAlertTTL / 2)
	}
	a.mu.Unlock()

	a.Maintain()

	if n := len(hub.Snapshot().Threats); n != 1 {
		t.Fatalf("TTL dolmadan uyarı panelde kalmalıydı, alınan: %d", n)
	}
}

func TestBenignTrafficNoAlert(t *testing.T) {
	hub := NewDashboardHub(10)
	a := NewThreatAnalyzer(hub, nil, nil)

	// Eşik altında normal trafik: birkaç farklı hedefe azar akış.
	a.Observe(FlowRecord{SrcIP: "10.0.0.20", DstIP: "93.184.216.34", DstPort: 443, Protocol: "TCP"})
	a.Observe(FlowRecord{SrcIP: "10.0.0.20", DstIP: "8.8.8.8", DstPort: 53, Protocol: "UDP"})
	a.Observe(FlowRecord{SrcIP: "10.0.0.20", DstIP: "10.0.0.5", DstPort: 22, Protocol: "TCP"})

	if n := len(hub.Snapshot().Threats); n != 0 {
		t.Fatalf("normal trafikte uyarı beklenmez, alınan: %d — %+v", n, hub.Snapshot().Threats)
	}
}
