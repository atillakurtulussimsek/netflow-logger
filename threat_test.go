package main

import (
	"strconv"
	"testing"
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
	a := NewThreatAnalyzer(hub)

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
	a := NewThreatAnalyzer(hub)

	for p := 0; p < threatPortScanMin; p++ {
		a.Observe(FlowRecord{SrcIP: "198.51.100.7", DstIP: "10.0.0.5", DstPort: uint16(1000 + p), Protocol: "TCP"})
	}

	if _, ok := alertsByRule(hub)["portscan"]; !ok {
		t.Fatalf("dikey port tarama uyarısı bekleniyordu: %+v", hub.Snapshot().Threats)
	}
}

func TestHorizontalHostSweepDetection(t *testing.T) {
	hub := NewDashboardHub(10)
	a := NewThreatAnalyzer(hub)

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

func TestBenignTrafficNoAlert(t *testing.T) {
	hub := NewDashboardHub(10)
	a := NewThreatAnalyzer(hub)

	// Eşik altında normal trafik: birkaç farklı hedefe azar akış.
	a.Observe(FlowRecord{SrcIP: "10.0.0.20", DstIP: "93.184.216.34", DstPort: 443, Protocol: "TCP"})
	a.Observe(FlowRecord{SrcIP: "10.0.0.20", DstIP: "8.8.8.8", DstPort: 53, Protocol: "UDP"})
	a.Observe(FlowRecord{SrcIP: "10.0.0.20", DstIP: "10.0.0.5", DstPort: 22, Protocol: "TCP"})

	if n := len(hub.Snapshot().Threats); n != 0 {
		t.Fatalf("normal trafikte uyarı beklenmez, alınan: %d — %+v", n, hub.Snapshot().Threats)
	}
}
