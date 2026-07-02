package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// Güvenlik uyarılarının ana ekranda değil, üst kontroldeki buton ile açılan
// modal içinde sunulduğunu doğrular.
func TestDashboardThreatModal(t *testing.T) {
	app := &App{}
	rec := httptest.NewRecorder()
	app.handleDashboard(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("beklenmeyen durum kodu: %d", rec.Code)
	}
	body := rec.Body.String()

	// Üst kontrolde güvenlik uyarıları butonu bulunmalı.
	if !strings.Contains(body, `id="threat-toggle"`) {
		t.Error("üst kontrolde güvenlik uyarıları butonu (threat-toggle) yok")
	}

	// Tehdit paneli modal içine sarılmış olmalı ve varsayılan gizli olmalı.
	modalRe := regexp.MustCompile(`(?s)<div class="threat-modal" id="threat-modal"([^>]*)>`)
	m := modalRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("threat-modal sarmalayıcısı bulunamadı")
	}
	if !strings.Contains(m[1], "hidden") {
		t.Errorf("threat-modal varsayılan olarak gizli değil: %q", m[1])
	}

	// Tehdit kartı modal panelinin içinde yer almalı.
	modalIdx := strings.Index(body, `id="threat-modal"`)
	cardIdx := strings.Index(body, `id="threat-card"`)
	if cardIdx < modalIdx {
		t.Error("threat-card, threat-modal içinde değil")
	}

	// Modal ile tablo kartı arasında serbest (modal dışı) bir tehdit bölümü kalmamalı.
	if strings.Contains(body, `<section class="threat-card" id="threat-card">`) {
		t.Error("threat-card hâlâ ana ekranda serbest bir section olarak duruyor")
	}
}
