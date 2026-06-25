package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestDashboardStateReturnsHoursForSelectedDate(t *testing.T) {
	logRoot := t.TempDir()
	dayDir := filepath.Join(logRoot, "2026", "06", "05")
	if err := os.MkdirAll(dayDir, 0o755); err != nil {
		t.Fatalf("create day dir: %v", err)
	}
	for _, name := range []string{"09.log", "10.log", "10.log.sha256", "readme.txt"} {
		if err := os.WriteFile(filepath.Join(dayDir, name), []byte("line\n"), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}

	app := &App{
		cfg: Config{
			LogRoot:  logRoot,
			Location: time.UTC,
		},
		dashboard: NewDashboardHub(dashboardMaxRecords),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/state?date=2026-06-05&limit=50&page=1", nil)
	rec := httptest.NewRecorder()

	app.handleDashboardState(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var state DashboardState
	if err := json.NewDecoder(rec.Body).Decode(&state); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if state.Mode != "historical" {
		t.Fatalf("mode = %q, want historical", state.Mode)
	}
	if state.SelectedDate != "2026-06-05" {
		t.Fatalf("selected date = %q, want 2026-06-05", state.SelectedDate)
	}
	wantHours := []string{"09", "10"}
	if !reflect.DeepEqual(state.AvailableHours, wantHours) {
		t.Fatalf("available hours = %#v, want %#v", state.AvailableHours, wantHours)
	}
}
