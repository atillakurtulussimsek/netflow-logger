package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// makeTestTSR, validateTSR'nin kabul ettiği asgari bir zaman damgası yanıtı
// üretir (imza içermez; yalnız yapı ve özet denetlenir).
func makeTestTSR(t *testing.T, digest []byte) []byte {
	t.Helper()
	sd, err := asn1.Marshal(signedData{
		Version:          3,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: encapContentInfo{
			EContentType: oidTSTInfo,
			EContent:     asn1.RawValue{FullBytes: explicitTag0(octetString(digest))},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := asn1.Marshal(contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{FullBytes: explicitTag0(sd)},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _ := asn1.Marshal(struct{ Status int }{0})
	resp, err := asn1.Marshal(timeStampResp{
		Status:         asn1.RawValue{FullBytes: status},
		TimeStampToken: asn1.RawValue{FullBytes: token},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateTSR(resp, digest); err != nil {
		t.Fatalf("test TSR geçersiz: %v", err)
	}
	return resp
}

func octetString(b []byte) []byte {
	out, _ := asn1.Marshal(b)
	return out
}

// explicitTag0, içeriği [0] EXPLICIT bağlam etiketine sarar.
func explicitTag0(inner []byte) []byte {
	out, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	return out
}

// writeRealSealedHour, gerçek SHA-256 ve geçerli TSR ile mühürlü saat yazar.
func writeRealSealedHour(t *testing.T, root string, hour time.Time, content string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(sum[:])
	logPath := writeSealedHour(t, root, hour, content, digest)
	if err := os.WriteFile(logPath+".tsr", makeTestTSR(t, sum[:]), 0o644); err != nil {
		t.Fatal(err)
	}
	return logPath
}

func archiveOf(t *testing.T, logPath string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, _, err := writeHourArchive(&buf, logPath); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCheckArchive(t *testing.T) {
	root := t.TempDir()
	hour := time.Date(2026, 11, 20, 5, 0, 0, 0, time.UTC)
	logPath := writeRealSealedHour(t, root, hour, "a\nb\n")

	if c := checkArchive(bytes.NewReader(archiveOf(t, logPath))); c.Status != verifyOK || c.LogBytes != 4 {
		t.Fatalf("sağlam paket ok olmalı: %+v", c)
	}

	// .sha256 içeriği log ile uyuşmuyor.
	_ = os.WriteFile(logPath+".sha256", []byte("deadbeef\n"), 0o644)
	if c := checkArchive(bytes.NewReader(archiveOf(t, logPath))); c.Status != verifyError || !strings.Contains(c.Detail, "SHA-256") {
		t.Fatalf("SHA uyuşmazlığı hata olmalı: %+v", c)
	}

	// Mühürsüz paket: uyarı.
	_ = os.Remove(logPath + ".sha256")
	_ = os.Remove(logPath + ".tsr")
	if c := checkArchive(bytes.NewReader(archiveOf(t, logPath))); c.Status != verifyWarn {
		t.Fatalf("mühürsüz paket uyarı olmalı: %+v", c)
	}

	// TSR başka bir özete ait.
	logPath = writeRealSealedHour(t, root, hour, "a\nb\n")
	other := sha256.Sum256([]byte("baska"))
	_ = os.WriteFile(logPath+".tsr", makeTestTSR(t, other[:]), 0o644)
	if c := checkArchive(bytes.NewReader(archiveOf(t, logPath))); c.Status != verifyError || !strings.Contains(c.Detail, "TSR") {
		t.Fatalf("yanlış TSR hata olmalı: %+v", c)
	}

	// Bozuk (kesik) paket.
	logPath = writeRealSealedHour(t, root, hour, strings.Repeat("satir\n", 5000))
	data := archiveOf(t, logPath)
	if c := checkArchive(bytes.NewReader(data[:len(data)/2])); c.Status != verifyError {
		t.Fatalf("kesik paket hata olmalı: %+v", c)
	}
	if c := checkArchive(strings.NewReader("gzip degil")); c.Status != verifyError {
		t.Fatalf("geçersiz veri hata olmalı: %+v", c)
	}
}

func TestVerifyRangeAndReadback(t *testing.T) {
	srv := newFakeFTPServer(t)
	root := t.TempDir()
	loc := time.UTC
	now := time.Date(2026, 11, 22, 3, 30, 0, 0, loc)

	// 22 Kasım 00, 01, 02 saatleri: 00 ve 01 yüklenecek, 02 yalnız yerelde.
	writeRealSealedHour(t, root, time.Date(2026, 11, 22, 0, 0, 0, 0, loc), "h0\n")
	writeRealSealedHour(t, root, time.Date(2026, 11, 22, 1, 0, 0, 0, loc), "h1\n")

	cfg := srv.config()
	cfg.Prefix = "p"
	cfg.Backfill = true
	archiver := NewFTPArchiver(cfg, root, loc, 0, nil)
	archiver.now = func() time.Time { return now }
	archiver.RunOnce(context.Background(), now)
	if st := archiver.Status(); st.ReadbackTotal != 2 || st.State != "ok" {
		t.Fatalf("iki yükleme geri okunarak doğrulanmalı: %+v", st)
	}
	writeRealSealedHour(t, root, time.Date(2026, 11, 22, 2, 0, 0, 0, loc), "h2\n")

	// FTP'deki 01 paketini boz.
	srv.mu.Lock()
	srv.files["p/2026/11/22/01.tar.gz"] = []byte("bozuk")
	srv.mu.Unlock()

	var total int
	results := map[string]VerifyResult{}
	err := verifyRange(context.Background(), cfg, root, loc, now, now, now,
		func(n int) { total = n },
		func(r VerifyResult) { results[r.Hour] = r })
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(results) != 3 {
		t.Fatalf("şimdiki saatten önceki 3 saat kontrol edilmeli: total=%d %v", total, results)
	}
	if r := results["2026-11-22 00"]; r.Status != verifyOK || r.LogBytes != 3 || r.ArchiveBytes == 0 {
		t.Fatalf("00 sağlam olmalı: %+v", r)
	}
	if r := results["2026-11-22 01"]; r.Status != verifyError {
		t.Fatalf("01 bozuk olmalı: %+v", r)
	}
	if r := results["2026-11-22 02"]; r.Status != verifyError || !strings.Contains(r.Detail, "yerelde var") {
		t.Fatalf("02 yerelde olup FTP'de yok olarak raporlanmalı: %+v", r)
	}

	// Komut çıktısı ve çıkış durumu.
	var out bytes.Buffer
	cmdCfg := Config{FTP: &cfg, LogRoot: root, Location: loc}
	err = runFTPVerifyCommand(context.Background(), cmdCfg, []string{"--from", "2026-11-21", "--to", "2026-11-21"}, &out)
	if err != nil || !strings.Contains(out.String(), "0 sağlam") || !strings.Contains(out.String(), "24 FTP'de yok") {
		t.Fatalf("21 Kasım için tüm saatler 'yok' olmalı: %v\n%s", err, out.String())
	}
	if err := runFTPVerifyCommand(context.Background(), cmdCfg, []string{"--from", "2026-11-22"}, io.Discard); err == nil {
		t.Fatal("hatalı saat varken komut hata dönmeli")
	}
}

func TestFTPVerifierJob(t *testing.T) {
	srv := newFakeFTPServer(t)
	root := t.TempDir()
	v := NewFTPVerifier(srv.config(), root, time.UTC)
	day := time.Now().UTC().AddDate(0, 0, -1)
	if err := v.Start(context.Background(), day, day); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for v.Snapshot().Running && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	job := v.Snapshot()
	if job.Running || job.Total != 24 || job.Done != 24 || job.Summary.Missing != 24 || job.FinishedAt == "" {
		t.Fatalf("iş tamamlanmalı: %+v", job)
	}
}
