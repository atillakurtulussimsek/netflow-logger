package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tehmaze/netflow/netflow9"
	flowsession "github.com/tehmaze/netflow/session"
)

const (
	defaultListenAddress    = ":9995"
	defaultDashboardAddress = ":8080"
	defaultTSAURL           = "https://freetsa.org/tsr"
	defaultLogRoot          = "./logs"
	defaultTimezoneName     = "Europe/Istanbul"
	defaultEnvPath          = ".env"
	maxPacketSize           = 65535
	dashboardMaxRecords     = 1000
	templateCacheFile       = "templates.json"
)

var (
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

type Config struct {
	ListenAddress    string
	DashboardAddress string
	DashboardUser    string
	DashboardPass    string
	TSAURL           string
	LogRoot          string
	Location         *time.Location
	DebugFlowMapping bool
}

type App struct {
	cfg       Config
	session   flowsession.Session
	logger    *HourlyLogger
	dashboard *DashboardHub
}

type FlowRecord struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Packets   uint64
	Bytes     uint64
	InputIf   uint32
	OutputIf  uint32
	FlowStart time.Time
	FlowEnd   time.Time
}

type HourlyLogger struct {
	cfg        Config
	httpClient *http.Client
	dashboard  *DashboardHub

	mu          sync.Mutex
	currentHour time.Time
	currentPath string
	file        *os.File
	sealWG      sync.WaitGroup
}

type DashboardHub struct {
	maxRecords int

	mu             sync.RWMutex
	records        []string
	processedTotal uint64
	activeFile     string
	lastSHA256     string
	lastTSAStatus  string
	updatedAt      time.Time
	clients        map[chan []byte]struct{}
}

type DashboardState struct {
	Mode            string   `json:"mode"`
	Records         []string `json:"records"`
	UpdatedAt       string   `json:"updated_at"`
	SelectedDate    string   `json:"selected_date"`
	SelectedHour    string   `json:"selected_hour"`
	Limit           int      `json:"limit"`
	Page            int      `json:"page"`
	TotalRecords    int      `json:"total_records"`
	TotalPages      int      `json:"total_pages"`
	FileSize        string   `json:"file_size"`
	FileSizeDaily   string   `json:"file_size_daily"`
	FileSizeMonthly string   `json:"file_size_monthly"`
	FileSizeTotal   string   `json:"file_size_total"`
	AvailableDates  []string `json:"available_dates"`
	AvailableHours  []string `json:"available_hours"`
	ActiveFile      string   `json:"active_file,omitempty"`
	LastSHA256      string   `json:"last_sha256,omitempty"`
	LastTSAStatus   string   `json:"last_tsa_status,omitempty"`
	ProcessedTotal  uint64   `json:"processed_total"`
}

type tsRequest struct {
	Version        int
	MessageImprint messageImprint
	CertReq        bool `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type timeStampResp struct {
	Status         asn1.RawValue
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

func main() {
	cfg, err := loadConfig(defaultEnvPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	dashboard := NewDashboardHub(dashboardMaxRecords)
	app := &App{
		cfg:       cfg,
		session:   newPersistentSession(cfg.LogRoot),
		dashboard: dashboard,
		logger: &HourlyLogger{
			cfg:        cfg,
			httpClient: &http.Client{Timeout: 30 * time.Second},
			dashboard:  dashboard,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("application stopped with error: %v", err)
	}
}

// templateSnapshot, diske yazılan/diskten okunan NetFlow v9 şablon kümesidir.
type templateSnapshot struct {
	Regular map[uint16]*netflow9.TemplateRecord       `json:"regular"`
	Options map[uint16]*netflow9.OptionTemplateRecord `json:"options"`
}

// persistentSession, alınan NetFlow v9 şablonlarını diske kaydeden ve açılışta
// geri yükleyen bir oturum sarmalayıcısıdır. NetFlow v9'da veri kayıtları ancak
// ilgili şablon (template) geldikten sonra çözülebilir; router şablonları
// dakikalarca aralıkla gönderdiği için collector ilk açılışta şablon gelene
// kadar gelen veriyi çözemez ("bir süre hiç log gelmiyor" sorunu). Şablonları
// kalıcı tutarak yeniden başlatmalarda veri anında çözülür.
type persistentSession struct {
	flowsession.Session
	mu   sync.Mutex
	path string
	snap templateSnapshot
}

func newPersistentSession(logRoot string) *persistentSession {
	ps := &persistentSession{
		Session: flowsession.New(),
		path:    filepath.Join(logRoot, templateCacheFile),
		snap: templateSnapshot{
			Regular: make(map[uint16]*netflow9.TemplateRecord),
			Options: make(map[uint16]*netflow9.OptionTemplateRecord),
		},
	}
	ps.load()
	return ps
}

// load, daha önce kaydedilmiş şablonları okuyup oturuma ekler.
func (p *persistentSession) load() {
	data, err := os.ReadFile(p.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("template cache read failed: %v", err)
		}
		return
	}

	var snap templateSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		log.Printf("template cache parse failed: %v", err)
		return
	}

	count := 0
	for id, tr := range snap.Regular {
		if tr == nil {
			continue
		}
		tr.TemplateID = id
		p.snap.Regular[id] = tr
		p.Session.AddTemplate(tr)
		count++
	}
	for id, otr := range snap.Options {
		if otr == nil {
			continue
		}
		otr.TemplateID = id
		p.snap.Options[id] = otr
		p.Session.AddTemplate(otr)
		count++
	}
	if count > 0 {
		log.Printf("loaded %d cached NetFlow v9 template(s) from %s", count, p.path)
	}
}

// AddTemplate, oturuma şablon eklerken yeni veya değişmiş şablonları diske de yazar.
func (p *persistentSession) AddTemplate(t flowsession.Template) {
	p.Session.AddTemplate(t)

	p.mu.Lock()
	changed := false
	switch v := t.(type) {
	case *netflow9.TemplateRecord:
		if existing, ok := p.snap.Regular[v.ID()]; !ok || !reflect.DeepEqual(existing, v) {
			p.snap.Regular[v.ID()] = v
			changed = true
		}
	case *netflow9.OptionTemplateRecord:
		if existing, ok := p.snap.Options[v.ID()]; !ok || !reflect.DeepEqual(existing, v) {
			p.snap.Options[v.ID()] = v
			changed = true
		}
	}
	if changed {
		p.persistLocked()
	}
	p.mu.Unlock()
}

// persistLocked, anlık şablon kümesini atomik biçimde diske yazar (p.mu kilitli olmalı).
func (p *persistentSession) persistLocked() {
	data, err := json.MarshalIndent(p.snap, "", "  ")
	if err != nil {
		log.Printf("template cache marshal failed: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o755); err != nil {
		log.Printf("template cache dir create failed: %v", err)
		return
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Printf("template cache write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, p.path); err != nil {
		log.Printf("template cache rename failed: %v", err)
	}
}

func loadConfig(envPath string) (Config, error) {
	env, err := loadEnvFile(envPath)
	if err != nil {
		return Config{}, err
	}

	timezone := defaultTimezoneName
	if value := strings.TrimSpace(env["TIMEZONE"]); value != "" {
		timezone = value
	}

	location, err := time.LoadLocation(timezone)
	if err != nil {
		return Config{}, fmt.Errorf("timezone load failed: %w", err)
	}

	cfg := Config{
		ListenAddress:    firstNonEmpty(env["NETFLOW_LISTEN_ADDRESS"], defaultListenAddress),
		DashboardAddress: firstNonEmpty(env["DASHBOARD_ADDRESS"], defaultDashboardAddress),
		DashboardUser:    strings.TrimSpace(env["DASHBOARD_USERNAME"]),
		DashboardPass:    strings.TrimSpace(env["DASHBOARD_PASSWORD"]),
		TSAURL:           firstNonEmpty(env["TSA_URL"], defaultTSAURL),
		LogRoot:          firstNonEmpty(env["LOG_ROOT"], defaultLogRoot),
		Location:         location,
		DebugFlowMapping: strings.EqualFold(strings.TrimSpace(env["DEBUG_FLOW_MAPPING"]), "true"),
	}

	if cfg.DashboardUser == "" || cfg.DashboardPass == "" {
		return Config{}, errors.New("DASHBOARD_USERNAME and DASHBOARD_PASSWORD must be set in .env")
	}

	return cfg, nil
}

func loadEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open env file failed: %w", err)
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid env line: %s", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"`)
		value = strings.Trim(value, `'`)
		values[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env file failed: %w", err)
	}

	return values, nil
}

func firstNonEmpty(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return fallback
}

func NewDashboardHub(maxRecords int) *DashboardHub {
	return &DashboardHub{
		maxRecords: maxRecords,
		records:    make([]string, 0, maxRecords),
		clients:    make(map[chan []byte]struct{}),
	}
}

func (h *DashboardHub) AddRecord(record string) {
	h.mu.Lock()
	h.records = append(h.records, record)
	if len(h.records) > h.maxRecords {
		h.records = append([]string(nil), h.records[len(h.records)-h.maxRecords:]...)
	}
	h.processedTotal++
	h.updatedAt = time.Now()
	snapshot := h.snapshotLocked()
	h.mu.Unlock()
	h.broadcastSnapshot(snapshot)
}

func (h *DashboardHub) SetActiveFile(path string) {
	h.mu.Lock()
	h.activeFile = path
	h.updatedAt = time.Now()
	snapshot := h.snapshotLocked()
	h.mu.Unlock()
	h.broadcastSnapshot(snapshot)
}

func (h *DashboardHub) SetSealStatus(sha256Hex string, status string) {
	h.mu.Lock()
	h.lastSHA256 = sha256Hex
	h.lastTSAStatus = status
	h.updatedAt = time.Now()
	snapshot := h.snapshotLocked()
	h.mu.Unlock()
	h.broadcastSnapshot(snapshot)
}

func (h *DashboardHub) Snapshot() DashboardState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.snapshotLocked()
}

func (h *DashboardHub) snapshotLocked() DashboardState {
	records := append([]string(nil), h.records...)
	state := DashboardState{
		Mode:           "live",
		Records:        records,
		ActiveFile:     h.activeFile,
		LastSHA256:     h.lastSHA256,
		LastTSAStatus:  h.lastTSAStatus,
		ProcessedTotal: h.processedTotal,
		Limit:          len(records),
		Page:           1,
		TotalRecords:   len(records),
		TotalPages:     1,
	}
	if !h.updatedAt.IsZero() {
		state.UpdatedAt = h.updatedAt.Format(time.RFC3339)
	}
	return state
}

func (h *DashboardHub) Subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 16)

	h.mu.Lock()
	h.clients[ch] = struct{}{}
	snapshot := h.snapshotLocked()
	h.mu.Unlock()

	if payload, err := json.Marshal(snapshot); err == nil {
		ch <- payload
	}

	unsubscribe := func() {
		h.mu.Lock()
		if _, ok := h.clients[ch]; ok {
			delete(h.clients, ch)
			close(ch)
		}
		h.mu.Unlock()
	}

	return ch, unsubscribe
}

func (h *DashboardHub) broadcastSnapshot(state DashboardState) {
	payload, err := json.Marshal(state)
	if err != nil {
		return
	}

	h.mu.RLock()
	clients := make([]chan []byte, 0, len(h.clients))
	for ch := range h.clients {
		clients = append(clients, ch)
	}
	h.mu.RUnlock()

	for _, ch := range clients {
		select {
		case ch <- payload:
		default:
		}
	}
}

func (a *App) Run(ctx context.Context) error {
	httpListener, err := net.Listen("tcp", a.cfg.DashboardAddress)
	if err != nil {
		return fmt.Errorf("dashboard listen failed: %w", err)
	}

	httpServer := &http.Server{Handler: a.dashboardRouter()}
	httpErrCh := make(chan error, 1)
	go func() {
		log.Printf("dashboard listening on %s", a.cfg.DashboardAddress)
		if err := httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErrCh <- err
		}
		close(httpErrCh)
	}()

	pc, err := net.ListenPacket("udp", a.cfg.ListenAddress)
	if err != nil {
		_ = httpServer.Shutdown(context.Background())
		return fmt.Errorf("udp listen failed: %w", err)
	}
	defer pc.Close()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		_ = pc.Close()
	}()

	log.Printf("listening for NetFlow v9 on %s", a.cfg.ListenAddress)

	buffer := make([]byte, maxPacketSize)
	for {
		select {
		case err := <-httpErrCh:
			if err != nil {
				return fmt.Errorf("dashboard server failed: %w", err)
			}
		default:
		}

		n, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				if closeErr := a.logger.CloseCurrent(false); closeErr != nil {
					log.Printf("final log close failed: %v", closeErr)
				}
				return ctx.Err()
			}
			return fmt.Errorf("udp read failed: %w", err)
		}

		packetBytes := append([]byte(nil), buffer[:n]...)
		if err := a.handlePacket(packetBytes, addr); err != nil {
			log.Printf("packet handling failed from %s: %v", addr.String(), err)
		}
	}
}

func (a *App) dashboardRouter() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", a.basicAuth(http.HandlerFunc(a.handleDashboard)))
	mux.Handle("/api/state", a.basicAuth(http.HandlerFunc(a.handleDashboardState)))
	mux.Handle("/events", a.basicAuth(http.HandlerFunc(a.handleDashboardEvents)))
	return mux
}

func (a *App) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(a.cfg.DashboardUser)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(a.cfg.DashboardPass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="netflow-dashboard"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, dashboardHTML)
}

func (a *App) handleDashboardState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	selectedDate := strings.TrimSpace(r.URL.Query().Get("date"))
	selectedHour := strings.TrimSpace(r.URL.Query().Get("hour"))
	limit := normalizeDashboardLimit(r.URL.Query().Get("limit"))
	page := normalizeDashboardPage(r.URL.Query().Get("page"))

	if selectedDate != "" && selectedHour != "" {
		state, err := buildHistoricalDashboardState(a.cfg.LogRoot, selectedDate, selectedHour, limit, page)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	state := a.dashboard.Snapshot()
	state.Limit = limit
	state.Page = page
	state.TotalRecords = len(state.Records)
	state.TotalPages = totalPages(len(state.Records), limit)
	state.AvailableDates = availableLogDates(a.cfg.LogRoot)
	if selectedDate != "" {
		state.Mode = "historical"
		availableHours, err := availableLogHours(a.cfg.LogRoot, selectedDate)
		if err == nil {
			state.SelectedDate = selectedDate
			state.AvailableHours = availableHours
		}
	}
	state.Records = paginateLiveRecords(state.Records, page, limit)
	state.FileSize = formatFileSizeByPath(state.ActiveFile)

	// Use today's date for daily/monthly/total when no specific date is selected
	refDate := selectedDate
	if refDate == "" {
		refDate = time.Now().In(a.cfg.Location).Format("2006-01-02")
	}
	state.FileSizeDaily = calculateLogSizeByDay(a.cfg.LogRoot, refDate)
	state.FileSizeMonthly = calculateLogSizeByMonth(a.cfg.LogRoot, refDate)
	state.FileSizeTotal = calculateTotalLogSize(a.cfg.LogRoot)
	if err := json.NewEncoder(w).Encode(state); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *App) handleDashboardEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	limit := normalizeDashboardLimit(r.URL.Query().Get("limit"))

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	updates, unsubscribe := a.dashboard.Subscribe()
	defer unsubscribe()

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()
	// Ağır dosya/istatistik hesapları boştayken de güncel kalsın diye periyodik
	// tazeleme (dosya büyür, gece yarısı tarih döner). Yeni kayıt akışı bundan
	// bağımsız olarak anında itilir.
	statsRefresh := time.NewTicker(2 * time.Second)
	defer statsRefresh.Stop()

	// Ağır istatistikler (dosya boyutları + tarih listesi) önbelleğe alınır; her
	// pakette dosya sistemi taranmasın diye yalnızca statsRefresh ile yenilenir.
	type heavyStats struct {
		availableDates  []string
		fileSize        string
		fileSizeDaily   string
		fileSizeMonthly string
		fileSizeTotal   string
	}
	var cache heavyStats
	cacheValid := false

	refreshStats := func(activeFile string) {
		refDate := time.Now().In(a.cfg.Location).Format("2006-01-02")
		cache = heavyStats{
			availableDates:  availableLogDates(a.cfg.LogRoot),
			fileSize:        formatFileSizeByPath(activeFile),
			fileSizeDaily:   calculateLogSizeByDay(a.cfg.LogRoot, refDate),
			fileSizeMonthly: calculateLogSizeByMonth(a.cfg.LogRoot, refDate),
			fileSizeTotal:   calculateTotalLogSize(a.cfg.LogRoot),
		}
		cacheValid = true
	}

	send := func(forceStats bool) bool {
		state := a.dashboard.Snapshot()
		if forceStats || !cacheValid {
			refreshStats(state.ActiveFile)
		}
		state.Limit = limit
		state.Page = 1
		state.TotalRecords = len(state.Records)
		state.TotalPages = totalPages(len(state.Records), limit)
		state.Records = paginateLiveRecords(state.Records, 1, limit)
		state.AvailableDates = cache.availableDates
		state.FileSize = cache.fileSize
		state.FileSizeDaily = cache.fileSizeDaily
		state.FileSizeMonthly = cache.fileSizeMonthly
		state.FileSizeTotal = cache.fileSizeTotal

		payload, err := json.Marshal(state)
		if err != nil {
			return true // bu güncellemeyi atla ama bağlantıyı koru
		}
		if _, err := fmt.Fprintf(w, "event: state\ndata: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// İlk durum tam istatistiklerle hemen gönderilir.
	if !send(true) {
		return
	}

	// Yüksek paket hızında her pakette JSON üretmeyi sınırlamak için kısa bir
	// kısıtlama (throttle): ilk güncelleme anında gider, ardışık güncellemeler en
	// fazla minInterval'de bir gönderilir — yine de "anlık" hissiyat korunur.
	const minInterval = 150 * time.Millisecond
	lastSent := time.Now()
	flushTimer := time.NewTimer(time.Hour)
	flushTimer.Stop()
	flushPending := false

	for {
		select {
		case <-r.Context().Done():
			return
		case _, ok := <-updates:
			if !ok {
				return
			}
			if flushPending {
				// Zaten bir gönderim planlandı; en güncel durumu o yollayacak.
				continue
			}
			if since := time.Since(lastSent); since >= minInterval {
				if !send(false) {
					return
				}
				lastSent = time.Now()
			} else {
				flushTimer.Reset(minInterval - since)
				flushPending = true
			}
		case <-flushTimer.C:
			flushPending = false
			if !send(false) {
				return
			}
			lastSent = time.Now()
		case <-statsRefresh.C:
			if !send(true) {
				return
			}
			lastSent = time.Now()
		case <-keepAlive.C:
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func normalizeDashboardLimit(raw string) int {
	if raw == "" {
		return 50
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 50
	}
	switch value {
	case 50, 100, 250, 500:
		return value
	default:
		return 50
	}
}

func normalizeDashboardPage(raw string) int {
	if raw == "" {
		return 1
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 1
	}
	return value
}

func totalPages(total int, limit int) int {
	if limit <= 0 {
		return 1
	}
	pages := (total + limit - 1) / limit
	if pages < 1 {
		return 1
	}
	return pages
}

func paginateRecords(records []string, page int, limit int) []string {
	if limit <= 0 {
		return records
	}
	if page < 1 {
		page = 1
	}
	start := (page - 1) * limit
	if start >= len(records) {
		return []string{}
	}
	end := start + limit
	if end > len(records) {
		end = len(records)
	}
	return records[start:end]
}

func paginateLiveRecords(records []string, page int, limit int) []string {
	if limit <= 0 {
		return records
	}
	if page < 1 {
		page = 1
	}

	total := len(records)
	end := total - ((page - 1) * limit)
	if end <= 0 {
		return []string{}
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	return records[start:end]
}

func buildHistoricalDashboardState(logRoot string, selectedDate string, selectedHour string, limit int, page int) (DashboardState, error) {
	availableDates := availableLogDates(logRoot)
	availableHours, err := availableLogHours(logRoot, selectedDate)
	if err != nil {
		return DashboardState{}, err
	}
	records, updatedAt, total, fileSize, err := readHistoricalLogRecords(logRoot, selectedDate, selectedHour, limit, page)
	if err != nil {
		return DashboardState{}, err
	}

	state := DashboardState{
		Mode:            "historical",
		Records:         records,
		SelectedDate:    selectedDate,
		SelectedHour:    selectedHour,
		Limit:           limit,
		Page:            page,
		TotalRecords:    total,
		TotalPages:      totalPages(total, limit),
		FileSize:        fileSize,
		FileSizeDaily:   calculateLogSizeByDay(logRoot, selectedDate),
		FileSizeMonthly: calculateLogSizeByMonth(logRoot, selectedDate),
		FileSizeTotal:   calculateTotalLogSize(logRoot),
		AvailableDates:  availableDates,
		AvailableHours:  availableHours,
	}
	if !updatedAt.IsZero() {
		state.UpdatedAt = updatedAt.Format(time.RFC3339)
	}
	return state, nil
}

func availableLogDates(logRoot string) []string {
	dates := make([]string, 0)
	years, err := os.ReadDir(logRoot)
	if err != nil {
		return dates
	}

	for _, year := range years {
		if !year.IsDir() {
			continue
		}
		months, err := os.ReadDir(filepath.Join(logRoot, year.Name()))
		if err != nil {
			continue
		}
		for _, month := range months {
			if !month.IsDir() {
				continue
			}
			days, err := os.ReadDir(filepath.Join(logRoot, year.Name(), month.Name()))
			if err != nil {
				continue
			}
			for _, day := range days {
				if !day.IsDir() {
					continue
				}
				dates = append(dates, year.Name()+"-"+month.Name()+"-"+day.Name())
			}
		}
	}

	sort.Sort(sort.Reverse(sort.StringSlice(dates)))
	return dates
}

func availableLogHours(logRoot string, selectedDate string) ([]string, error) {
	parts := strings.Split(selectedDate, "-")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid date format: %s", selectedDate)
	}

	dayPath := filepath.Join(logRoot, parts[0], parts[1], parts[2])
	entries, err := os.ReadDir(dayPath)
	if err != nil {
		return nil, fmt.Errorf("read selected date directory failed: %w", err)
	}

	hours := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".log") || strings.Contains(name, ".log.") {
			continue
		}
		hours = append(hours, strings.TrimSuffix(name, ".log"))
	}
	sort.Strings(hours)
	return hours, nil
}

func readHistoricalLogRecords(logRoot string, selectedDate string, selectedHour string, limit int, page int) ([]string, time.Time, int, string, error) {
	parts := strings.Split(selectedDate, "-")
	if len(parts) != 3 {
		return nil, time.Time{}, 0, "", fmt.Errorf("invalid date format: %s", selectedDate)
	}
	if len(selectedHour) != 2 {
		return nil, time.Time{}, 0, "", fmt.Errorf("invalid hour format: %s", selectedHour)
	}

	logPath := filepath.Join(logRoot, parts[0], parts[1], parts[2], selectedHour+".log")
	file, err := os.Open(logPath)
	if err != nil {
		return nil, time.Time{}, 0, "", fmt.Errorf("open selected log file failed: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, time.Time{}, 0, "", fmt.Errorf("stat selected log file failed: %w", err)
	}

	allRecords := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		allRecords = append(allRecords, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, time.Time{}, 0, "", fmt.Errorf("read selected log file failed: %w", err)
	}

	paged := paginateRecords(allRecords, page, limit)
	return paged, info.ModTime(), len(allRecords), formatByteSize(info.Size()), nil
}

func formatFileSizeByPath(path string) string {
	if path == "" {
		return "-"
	}
	info, err := os.Stat(path)
	if err != nil {
		return "-"
	}
	return formatByteSize(info.Size())
}

func formatByteSize(size int64) string {
	if size >= 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", float64(size)/(1024*1024*1024))
	}
	if size >= 1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
	}
	if size >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%d B", size)
}

func sumLogFilesRecursive(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".log") {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func calculateLogSizeByDay(logRoot string, date string) string {
	parts := strings.Split(date, "-")
	if len(parts) != 3 {
		return "-"
	}
	dayPath := filepath.Join(logRoot, parts[0], parts[1], parts[2])
	total, err := sumLogFilesRecursive(dayPath)
	if err != nil {
		return "-"
	}
	return formatByteSize(total)
}

func calculateLogSizeByMonth(logRoot string, date string) string {
	parts := strings.Split(date, "-")
	if len(parts) < 2 {
		return "-"
	}
	monthPath := filepath.Join(logRoot, parts[0], parts[1])
	total, err := sumLogFilesRecursive(monthPath)
	if err != nil {
		return "-"
	}
	return formatByteSize(total)
}

func calculateTotalLogSize(logRoot string) string {
	total, err := sumLogFilesRecursive(logRoot)
	if err != nil {
		return "-"
	}
	return formatByteSize(total)
}

func (a *App) handlePacket(packetBytes []byte, addr net.Addr) error {
	packet, err := decodeNetFlowV9Packet(packetBytes, a.session)
	if err != nil {
		return fmt.Errorf("netflow decode failed: %w (len=%d version=%d count=%d)", err, len(packetBytes), packetVersion(packetBytes), packetCount(packetBytes))
	}

	records := extractFlowRecords(packet, a.cfg.Location, a.cfg.DebugFlowMapping)
	if len(records) == 0 {
		log.Printf("no eligible flow records in packet from %s", addr.String())
		return nil
	}

	for _, record := range records {
		if err := a.logger.Write(record); err != nil {
			return fmt.Errorf("log write failed: %w", err)
		}
	}

	return nil
}

func decodeNetFlowV9Packet(packetBytes []byte, sess flowsession.Session) (*netflow9.Packet, error) {
	if len(packetBytes) < 20 {
		return nil, fmt.Errorf("packet too short for NetFlow v9 header: %d bytes", len(packetBytes))
	}
	if version := packetVersion(packetBytes); version != netflow9.Version {
		return nil, fmt.Errorf("unexpected netflow version: %d", version)
	}

	reader := bytes.NewReader(packetBytes)
	packet := &netflow9.Packet{}
	if err := packet.Header.Unmarshal(reader); err != nil {
		return nil, fmt.Errorf("header unmarshal failed: %w", err)
	}

	translator := netflow9.NewTranslate(sess)
	for reader.Len() > 0 {
		if reader.Len() < 4 {
			break
		}

		var header netflow9.FlowSetHeader
		if err := header.Unmarshal(reader); err != nil {
			return nil, fmt.Errorf("flowset header unmarshal failed: %w", err)
		}
		if header.Length < 4 {
			return nil, fmt.Errorf("invalid flowset length: %d", header.Length)
		}

		payloadLen := int(header.Length) - header.Len()
		if payloadLen > reader.Len() {
			return nil, fmt.Errorf("short flowset payload: need=%d remaining=%d id=%d", payloadLen, reader.Len(), header.ID)
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, fmt.Errorf("flowset payload read failed: %w", err)
		}

		switch header.ID {
		case 0:
			flowSet := netflow9.TemplateFlowSet{Header: header}
			if err := flowSet.UnmarshalRecords(bytes.NewReader(payload)); err != nil {
				return nil, fmt.Errorf("template flowset unmarshal failed: %w", err)
			}
			if sess != nil {
				for i := range flowSet.Records {
					record := flowSet.Records[i]
					sess.AddTemplate(&record)
				}
			}
			packet.TemplateFlowSets = append(packet.TemplateFlowSets, flowSet)
		case 1:
			flowSet := netflow9.OptionsTemplateFlowSet{Header: header}
			if err := flowSet.UnmarshalRecords(bytes.NewReader(payload)); err != nil {
				return nil, fmt.Errorf("options template flowset unmarshal failed: %w", err)
			}
			if sess != nil {
				for i := range flowSet.Records {
					record := flowSet.Records[i]
					sess.AddTemplate(&record)
				}
			}
			packet.OptionsTemplateFlowSets = append(packet.OptionsTemplateFlowSets, flowSet)
		default:
			flowSet := netflow9.DataFlowSet{Header: header}
			if sess == nil {
				flowSet.Bytes = payload
				packet.DataFlowSets = append(packet.DataFlowSets, flowSet)
				continue
			}

			template, ok := sess.GetTemplate(header.ID)
			if !ok {
				flowSet.Bytes = payload
				packet.DataFlowSets = append(packet.DataFlowSets, flowSet)
				continue
			}

			if err := flowSet.Unmarshal(bytes.NewReader(payload), template, translator); err != nil {
				return nil, fmt.Errorf("data flowset unmarshal failed for template=%d: %w", header.ID, err)
			}

			switch template.(type) {
			case *netflow9.OptionTemplateRecord:
				packet.OptionsDataFlowSets = append(packet.OptionsDataFlowSets, flowSet)
			default:
				packet.DataFlowSets = append(packet.DataFlowSets, flowSet)
			}
		}
	}

	return packet, nil
}

func packetVersion(packetBytes []byte) uint16 {
	if len(packetBytes) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(packetBytes[0:2])
}

func packetCount(packetBytes []byte) uint16 {
	if len(packetBytes) < 4 {
		return 0
	}
	return binary.BigEndian.Uint16(packetBytes[2:4])
}

func extractFlowRecords(packet *netflow9.Packet, location *time.Location, debugFlowMapping bool) []FlowRecord {
	result := make([]FlowRecord, 0)
	for _, flowSet := range packet.DataFlowSets {
		for _, dataRecord := range flowSet.Records {
			record, ok := mapFlowRecord(packet.Header, dataRecord, location, debugFlowMapping)
			if ok {
				result = append(result, record)
			}
		}
	}
	return result
}

func mapFlowRecord(header netflow9.PacketHeader, dataRecord netflow9.DataRecord, location *time.Location, debugFlowMapping bool) (FlowRecord, bool) {
	values := make(map[string]interface{})
	for _, field := range dataRecord.Fields {
		if field.Translated == nil || field.Translated.Name == "" {
			continue
		}
		values[field.Translated.Name] = field.Translated.Value
	}

	packetTime := time.Unix(int64(header.UnixSecs), 0).In(location)

	srcIP := firstString(values, "sourceIPv4Address", "sourceIPv6Address")
	dstIP := firstString(values, "destinationIPv4Address", "destinationIPv6Address")
	if strings.Contains(srcIP, ":") || strings.Contains(dstIP, ":") {
		return FlowRecord{}, false
	}
	srcPort, okSrcPort := firstUint16(values, "sourceTransportPort")
	dstPort, okDstPort := firstUint16(values, "destinationTransportPort")
	protocolNumber, okProtocol := firstUint8(values, "protocolIdentifier")
	bytesCount, okBytes := firstUint64(values, "octetDeltaCount", "postOctetDeltaCount")
	inputIf, okInputIf := firstUint32(values, "ingressInterface")
	outputIf, okOutputIf := firstUint32(values, "egressInterface")
	flowStart, okFlowStart := resolveFlowStart(values, header, location)
	flowEnd, okFlowEnd := resolveFlowEnd(values, header, location)

	missing := make([]string, 0)
	if srcIP == "" {
		missing = append(missing, "src_ip")
	}
	if dstIP == "" {
		missing = append(missing, "dst_ip")
	}
	if !okSrcPort {
		missing = append(missing, "src_port")
	}
	if !okDstPort {
		missing = append(missing, "dst_port")
	}
	if !okProtocol {
		missing = append(missing, "protocol")
	}
	if !okBytes {
		missing = append(missing, "bytes")
	}
	if len(missing) > 0 {
		if debugFlowMapping {
			log.Printf("flow record skipped, missing required fields: %s | available=%s | values=%s", strings.Join(missing, ", "), strings.Join(sortedKeys(values), ", "), formatFieldMap(values))
		} else {
			log.Printf("flow record skipped, missing required fields: %s | available=%s", strings.Join(missing, ", "), strings.Join(sortedKeys(values), ", "))
		}
		return FlowRecord{}, false
	}

	packets, okPackets := firstUint64(values, "packetDeltaCount", "postPacketDeltaCount")
	if !okPackets {
		packets = 0
	}
	if !okInputIf {
		inputIf = 0
	}
	if !okOutputIf {
		outputIf = 0
	}
	if !okFlowStart {
		flowStart = packetTime
	}
	if !okFlowEnd {
		flowEnd = packetTime
	}

	return FlowRecord{
		Timestamp: packetTime,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocolName(protocolNumber),
		Packets:   packets,
		Bytes:     bytesCount,
		InputIf:   inputIf,
		OutputIf:  outputIf,
		FlowStart: flowStart,
		FlowEnd:   flowEnd,
	}, true
}

func sortedKeys(values map[string]interface{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func formatFieldMap(values map[string]interface{}) string {
	keys := sortedKeys(values)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+fmt.Sprint(values[key]))
	}
	return strings.Join(parts, "; ")
}

func firstString(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case net.IP:
			return v.String()
		case string:
			return v
		case fmt.Stringer:
			return v.String()
		default:
			return fmt.Sprint(v)
		}
	}
	return ""
}

func firstUint8(values map[string]interface{}, keys ...string) (uint8, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			if number, ok := asUint64(value); ok && number <= 255 {
				return uint8(number), true
			}
		}
	}
	return 0, false
}

func firstUint16(values map[string]interface{}, keys ...string) (uint16, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			if number, ok := asUint64(value); ok && number <= 65535 {
				return uint16(number), true
			}
		}
	}
	return 0, false
}

func firstUint32(values map[string]interface{}, keys ...string) (uint32, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			if number, ok := asUint64(value); ok && number <= 4294967295 {
				return uint32(number), true
			}
		}
	}
	return 0, false
}

func firstUint64(values map[string]interface{}, keys ...string) (uint64, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			if number, ok := asUint64(value); ok {
				return number, true
			}
		}
	}
	return 0, false
}

func resolveFlowStart(values map[string]interface{}, header netflow9.PacketHeader, location *time.Location) (time.Time, bool) {
	if ts, ok := firstTime(values, location, "flowStartSeconds", "flowStartMilliseconds", "flowStartMicroseconds", "flowStartNanoseconds"); ok {
		return ts, true
	}
	if uptime, ok := firstUint64(values, "flowStartSysUpTime"); ok {
		return sysUpTimeToTime(header, uptime, location), true
	}
	return time.Time{}, false
}

func resolveFlowEnd(values map[string]interface{}, header netflow9.PacketHeader, location *time.Location) (time.Time, bool) {
	if ts, ok := firstTime(values, location, "flowEndSeconds", "flowEndMilliseconds", "flowEndMicroseconds", "flowEndNanoseconds"); ok {
		return ts, true
	}
	if uptime, ok := firstUint64(values, "flowEndSysUpTime"); ok {
		return sysUpTimeToTime(header, uptime, location), true
	}
	return time.Time{}, false
}

func firstTime(values map[string]interface{}, location *time.Location, keys ...string) (time.Time, bool) {
	for _, key := range keys {
		value, ok := values[key]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case time.Time:
			return v.In(location), true
		case *time.Time:
			return v.In(location), true
		}

		number, ok := asUint64(value)
		if !ok {
			continue
		}

		switch key {
		case "flowStartSeconds", "flowEndSeconds":
			return time.Unix(int64(number), 0).In(location), true
		case "flowStartMilliseconds", "flowEndMilliseconds":
			return time.Unix(0, int64(number)*int64(time.Millisecond)).In(location), true
		case "flowStartMicroseconds", "flowEndMicroseconds":
			return time.Unix(0, int64(number)*int64(time.Microsecond)).In(location), true
		case "flowStartNanoseconds", "flowEndNanoseconds":
			return time.Unix(0, int64(number)).In(location), true
		}
	}
	return time.Time{}, false
}

func asUint64(value interface{}) (uint64, bool) {
	switch v := value.(type) {
	case uint8:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case int8:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int16:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int32:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case uint:
		return uint64(v), true
	case string:
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func sysUpTimeToTime(header netflow9.PacketHeader, uptimeMillis uint64, location *time.Location) time.Time {
	exportTime := time.Unix(int64(header.UnixSecs), 0)
	deltaMillis := int64(header.SysUpTime) - int64(uptimeMillis)
	return exportTime.Add(-time.Duration(deltaMillis) * time.Millisecond).In(location)
}

func protocolName(number uint8) string {
	switch number {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	default:
		return strconv.FormatUint(uint64(number), 10)
	}
}

func (h *HourlyLogger) Write(record FlowRecord) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	targetHour := record.Timestamp.In(h.cfg.Location).Truncate(time.Hour)
	if err := h.rotateLocked(targetHour); err != nil {
		return err
	}

	line := formatFlowRecord(record)
	if _, err := h.file.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("write log line failed: %w", err)
	}
	if err := h.file.Sync(); err != nil {
		return fmt.Errorf("sync log file failed: %w", err)
	}

	h.dashboard.AddRecord(line)
	return nil
}

func (h *HourlyLogger) CloseCurrent(seal bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closeCurrentLocked(seal)
}

func (h *HourlyLogger) rotateLocked(targetHour time.Time) error {
	if h.file == nil {
		return h.openLocked(targetHour)
	}
	if h.currentHour.Equal(targetHour) {
		return nil
	}
	if err := h.closeCurrentLocked(true); err != nil {
		return err
	}
	return h.openLocked(targetHour)
}

func (h *HourlyLogger) openLocked(targetHour time.Time) error {
	logPath := buildLogPath(h.cfg.LogRoot, targetHour)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("create log directory failed: %w", err)
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file failed: %w", err)
	}

	h.file = file
	h.currentHour = targetHour
	h.currentPath = logPath
	h.dashboard.SetActiveFile(logPath)
	return nil
}

func (h *HourlyLogger) closeCurrentLocked(seal bool) error {
	if h.file == nil {
		return nil
	}

	currentFile := h.file
	currentPath := h.currentPath
	h.file = nil
	h.currentPath = ""
	h.currentHour = time.Time{}
	h.dashboard.SetActiveFile("")

	if err := currentFile.Sync(); err != nil {
		_ = currentFile.Close()
		return fmt.Errorf("sync current log failed: %w", err)
	}
	if err := currentFile.Close(); err != nil {
		return fmt.Errorf("close current log failed: %w", err)
	}
	if seal {
		// Seal asynchronously: SHA-256 + TSA round-trip can take seconds and
		// must not block the packet-receive loop while h.mu is held.
		// sealHourlyLog operates only on the closed file path, so it is safe
		// to run without the lock.
		h.sealWG.Add(1)
		go func(path string) {
			defer h.sealWG.Done()
			if err := h.sealHourlyLog(path); err != nil {
				log.Printf("seal hourly log failed for %s: %v", path, err)
			}
		}(currentPath)
	}

	return nil
}

// WaitForSeals blocks until all in-flight asynchronous seal operations finish.
func (h *HourlyLogger) WaitForSeals() {
	h.sealWG.Wait()
}

func (h *HourlyLogger) sealHourlyLog(logPath string) error {
	digestHex, digestBytes, err := computeSHA256(logPath)
	if err != nil {
		h.dashboard.SetSealStatus("", "SHA-256 failed: "+err.Error())
		return err
	}

	shaPath := logPath + ".sha256"
	if err := os.WriteFile(shaPath, []byte(digestHex+"\n"), 0o644); err != nil {
		h.dashboard.SetSealStatus(digestHex, "SHA-256 file write failed: "+err.Error())
		return fmt.Errorf("write sha256 file failed: %w", err)
	}

	tsrBytes, err := h.requestTimestamp(digestBytes)
	if err != nil {
		h.dashboard.SetSealStatus(digestHex, "TSA failed: "+err.Error())
		return err
	}

	tsrPath := logPath + ".tsr"
	if err := os.WriteFile(tsrPath, tsrBytes, 0o644); err != nil {
		h.dashboard.SetSealStatus(digestHex, "TSR file write failed: "+err.Error())
		return fmt.Errorf("write tsr file failed: %w", err)
	}

	h.dashboard.SetSealStatus(digestHex, "OK: "+tsrPath)
	return nil
}

func computeSHA256(path string) (string, []byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("open file for sha256 failed: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", nil, fmt.Errorf("hash file failed: %w", err)
	}

	digestBytes := hasher.Sum(nil)
	return hex.EncodeToString(digestBytes), digestBytes, nil
}

func (h *HourlyLogger) requestTimestamp(digest []byte) ([]byte, error) {
	requestBytes, err := buildTSQ(digest)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Post(h.cfg.TSAURL, "application/timestamp-query", bytes.NewReader(requestBytes))
	if err != nil {
		return nil, fmt.Errorf("tsa request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read tsa response failed: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("tsa returned status %s", resp.Status)
	}
	if err := validateTSR(responseBytes, digest); err != nil {
		return nil, err
	}

	return responseBytes, nil
}

func buildTSQ(digest []byte) ([]byte, error) {
	request := tsRequest{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1.RawValue{Class: 0, Tag: 5},
			},
			HashedMessage: digest,
		},
		CertReq: true,
	}

	encoded, err := asn1.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal tsq failed: %w", err)
	}
	return encoded, nil
}

func validateTSR(response []byte, digest []byte) error {
	if len(response) == 0 {
		return errors.New("empty tsr response")
	}

	var tsr timeStampResp
	if _, err := asn1.Unmarshal(response, &tsr); err != nil {
		return fmt.Errorf("unmarshal time-stamp response failed: %w", err)
	}
	if len(tsr.TimeStampToken.FullBytes) == 0 {
		return errors.New("tsr does not contain time-stamp token")
	}

	var outer contentInfo
	if _, err := asn1.Unmarshal(tsr.TimeStampToken.FullBytes, &outer); err != nil {
		return fmt.Errorf("unmarshal tsr token content info failed: %w", err)
	}
	if !outer.ContentType.Equal(oidSignedData) {
		return fmt.Errorf("unexpected tsr token content type: %s", outer.ContentType.String())
	}

	var signed signedData
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &signed); err != nil {
		return fmt.Errorf("unmarshal signed data failed: %w", err)
	}
	if !signed.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return fmt.Errorf("unexpected tsr encapsulated content type: %s", signed.EncapContentInfo.EContentType.String())
	}

	content := signed.EncapContentInfo.EContent.Bytes
	if len(content) == 0 {
		return errors.New("tsr tstinfo content is empty")
	}
	if !bytes.Contains(content, digest) {
		return errors.New("tsr does not contain expected message imprint")
	}

	return nil
}

func buildLogPath(root string, hour time.Time) string {
	return filepath.Join(
		root,
		hour.Format("2006"),
		hour.Format("01"),
		hour.Format("02"),
		hour.Format("15")+".log",
	)
}

func formatFlowRecord(record FlowRecord) string {
	parts := []string{
		record.Timestamp.Format(time.RFC3339),
		record.SrcIP,
		record.DstIP,
		strconv.FormatUint(uint64(record.SrcPort), 10),
		strconv.FormatUint(uint64(record.DstPort), 10),
		record.Protocol,
		strconv.FormatUint(record.Packets, 10),
		strconv.FormatUint(record.Bytes, 10),
		strconv.FormatUint(uint64(record.InputIf), 10),
		strconv.FormatUint(uint64(record.OutputIf), 10),
		record.FlowStart.Format(time.RFC3339),
		record.FlowEnd.Format(time.RFC3339),
	}
	return strings.Join(parts, "|")
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>netflow logger panel</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #04050a;
      --panel: rgba(13, 18, 32, 0.72);
      --panel-2: rgba(9, 13, 24, 0.78);
      --border: rgba(34, 211, 238, 0.20);
      --border-soft: rgba(56, 189, 248, 0.12);
      --text: #e9f1ff;
      --muted: #93a7cc;
      --muted-2: #5f76a0;
      --accent: #22d3ee;
      --accent-soft: rgba(34, 211, 238, 0.14);
      --accent-2: #2bff88;
      --neon-cyan: #22d3ee;
      --neon-blue: #38bdf8;
      --neon-pink: #ff3d9a;
      --neon-purple: #b06bff;
      --neon-green: #2bff88;
      --neon-amber: #ffb020;
      --warn: #ffb020;
      --danger: #ff5d7a;
      --shadow: 0 24px 70px rgba(0, 0, 0, 0.6);
      --glow-cyan: 0 0 10px rgba(34,211,238,0.55), 0 0 26px rgba(34,211,238,0.28);
      --glow-pink: 0 0 10px rgba(255,61,154,0.55), 0 0 26px rgba(255,61,154,0.28);
      --glow-green: 0 0 10px rgba(43,255,136,0.55), 0 0 26px rgba(43,255,136,0.26);
      --radius: 22px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(900px circle at 0% -5%, rgba(34,211,238,0.16), transparent 42%),
        radial-gradient(900px circle at 100% 0%, rgba(255,61,154,0.14), transparent 40%),
        radial-gradient(1200px circle at 50% 120%, rgba(176,107,255,0.14), transparent 45%),
        linear-gradient(180deg, #06070f 0%, #04050a 100%);
      background-attachment: fixed;
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      padding: 32px;
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(34,211,238,0.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(34,211,238,0.045) 1px, transparent 1px);
      background-size: 44px 44px;
      mask-image: radial-gradient(circle at 50% 0%, #000 0%, transparent 75%);
      -webkit-mask-image: radial-gradient(circle at 50% 0%, #000 0%, transparent 75%);
      z-index: 0;
    }

    .layout { position: relative; z-index: 1; }

    .layout {
      width: min(1440px, 100%);
      margin: 0 auto;
      display: grid;
      gap: 22px;
    }

    .hero {
      position: relative;
      background: linear-gradient(180deg, rgba(13,18,32,0.78), rgba(8,11,22,0.82));
      border: 1px solid var(--border);
      border-radius: 28px;
      box-shadow: var(--shadow), 0 0 36px rgba(34,211,238,0.10), inset 0 1px 0 rgba(255,255,255,0.04);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      padding: 18px 24px 20px 24px;
      display: grid;
      gap: 16px;
      overflow: hidden;
    }

    .hero::before {
      content: "";
      position: absolute;
      top: -1px; left: 24px; right: 24px;
      height: 1px;
      background: linear-gradient(90deg, transparent, var(--neon-cyan), var(--neon-pink), transparent);
      opacity: 0.7;
    }

    .hero-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 13px;
      min-width: 0;
    }

    .brand-mark {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 42px;
      height: 42px;
      flex-shrink: 0;
      border-radius: 13px;
      color: var(--neon-cyan);
      background: var(--accent-soft);
      border: 1px solid rgba(34,211,238,0.40);
      box-shadow: 0 0 18px rgba(34,211,238,0.30), inset 0 0 14px rgba(34,211,238,0.12);
      filter: drop-shadow(0 0 4px rgba(34,211,238,0.5));
    }

    .brand-mark svg { width: 24px; height: 24px; }

    .brand-title {
      margin: 0;
      font-size: 19px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #fff;
      text-shadow: 0 0 12px rgba(34,211,238,0.45), 0 0 26px rgba(34,211,238,0.22);
    }

    .brand-subtitle {
      margin: 2px 0 0 0;
      font-size: 12px;
      color: var(--muted);
    }

    .hero-controls {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .hero-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      align-items: stretch;
    }

    .stat-card {
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 8px;
      background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.015));
      border: 1px solid var(--border-soft);
      border-radius: 16px;
      padding: 13px 15px;
      min-width: 0;
      transition: border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
    }

    .stat-card:hover {
      border-color: rgba(34,211,238,0.34);
      box-shadow: 0 0 24px rgba(34,211,238,0.14);
      transform: translateY(-2px);
    }

    .stat-card.accent {
      background: linear-gradient(160deg, rgba(34,211,238,0.14), rgba(176,107,255,0.06));
      border-color: rgba(34,211,238,0.34);
      box-shadow: inset 0 0 22px rgba(34,211,238,0.08), 0 0 22px rgba(34,211,238,0.10);
    }

    .stat-card.integrity:hover {
      border-color: rgba(255,61,154,0.34);
      box-shadow: 0 0 24px rgba(255,61,154,0.14);
    }

    .stat-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 6px 8px;
      flex-wrap: wrap;
    }

    .stat-main {
      display: flex;
      align-items: baseline;
      gap: 7px;
      min-width: 0;
    }

    .stat-number {
      font-size: 26px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #fff;
      font-variant-numeric: tabular-nums;
      line-height: 1.1;
    }

    .stat-card.accent .stat-number {
      color: var(--neon-cyan);
      text-shadow: var(--glow-cyan);
    }

    .stat-number.sm {
      font-size: 18px;
      font-weight: 600;
      color: var(--neon-blue);
      text-shadow: 0 0 10px rgba(56,189,248,0.45);
    }

    .stat-unit { font-size: 12px; color: var(--muted); font-weight: 600; }

    .rate-chart {
      position: relative;
      width: 100%;
      height: 46px;
      margin-top: 2px;
    }

    .rate-chart canvas {
      display: block;
      width: 100%;
      height: 100%;
    }

    .rate-chart-peak,
    .rate-chart-span {
      position: absolute;
      top: 0;
      font-size: 9.5px;
      font-weight: 600;
      letter-spacing: 0.02em;
      color: var(--muted-2);
      font-variant-numeric: tabular-nums;
      pointer-events: none;
      text-shadow: 0 0 6px rgba(4,5,10,0.9);
    }

    .rate-chart-peak { left: 0; color: var(--neon-cyan); opacity: 0.85; }
    .rate-chart-span { right: 0; }

    .stat-foot {
      font-size: 11px;
      color: var(--muted-2);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .stat-foot span { color: var(--muted); font-weight: 600; }

    .live-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--muted-2);
      flex-shrink: 0;
    }

    .live-dot.active {
      background: var(--neon-green);
      box-shadow: 0 0 0 0 rgba(43,255,136,0.5), 0 0 12px rgba(43,255,136,0.8);
      animation: pulse 1.6s ease-out infinite;
    }

    @keyframes pulse {
      0%   { box-shadow: 0 0 0 0 rgba(43,255,136,0.5), 0 0 12px rgba(43,255,136,0.8); }
      70%  { box-shadow: 0 0 0 8px rgba(43,255,136,0), 0 0 12px rgba(43,255,136,0.8); }
      100% { box-shadow: 0 0 0 0 rgba(43,255,136,0), 0 0 12px rgba(43,255,136,0.8); }
    }

    @media (prefers-reduced-motion: reduce) {
      .live-dot.active { animation: none; }
    }

    .seal-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 9px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      color: var(--muted);
      background: rgba(148,163,184,0.10);
      border: 1px solid rgba(148,163,184,0.18);
      white-space: nowrap;
    }

    .seal-badge.ok {
      color: #052e16;
      background: var(--neon-green);
      border-color: var(--neon-green);
      box-shadow: var(--glow-green);
    }

    .seal-badge.error {
      color: #fff;
      background: rgba(255,93,122,0.22);
      border-color: var(--danger);
      box-shadow: 0 0 10px rgba(255,93,122,0.45);
    }

    .seal-sha-row {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }

    .seal-sha {
      flex: 1;
      min-width: 0;
      font-size: 12px;
      color: var(--neon-pink);
      text-shadow: 0 0 8px rgba(255,61,154,0.4);
      background: rgba(5,7,14,0.7);
      border: 1px solid rgba(255,61,154,0.22);
      border-radius: 9px;
      padding: 5px 9px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .copy-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 30px;
      height: 30px;
      flex-shrink: 0;
      border-radius: 9px;
      background: rgba(148,163,184,0.10);
      border: 1px solid var(--border-soft);
      color: var(--muted);
      cursor: pointer;
      transition: 0.15s ease;
    }

    .copy-btn svg { width: 15px; height: 15px; }
    .copy-btn:hover:not(:disabled) { color: var(--neon-cyan); border-color: rgba(34,211,238,0.45); background: var(--accent-soft); box-shadow: 0 0 14px rgba(34,211,238,0.25); }
    .copy-btn:disabled { opacity: 0.4; cursor: default; }
    .copy-btn.copied { color: #052e16; border-color: var(--neon-green); background: var(--neon-green); box-shadow: var(--glow-green); }

    .stat-card.sizes { gap: 10px; }

    .status-label {
      color: var(--muted-2);
      font-size: 10px;
      margin-bottom: 4px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      white-space: nowrap;
    }

    .status-value {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: var(--text);
      white-space: nowrap;
    }

    .status-badge,
    .mode-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 36px;
      padding: 0 14px;
      border-radius: 999px;
      background: rgba(148,163,184,0.08);
      border: 1px solid rgba(148,163,184,0.18);
      color: var(--text);
      font-size: 13px;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      transition: 0.2s ease;
    }

    .mode-button:hover {
      border-color: rgba(34,211,238,0.5);
      background: var(--accent-soft);
      color: #ccfbff;
      box-shadow: var(--glow-cyan);
    }

    .status-badge.live,
    .mode-button.live {
      color: #052e16;
      border-color: var(--neon-green);
      background: var(--neon-green);
      box-shadow: var(--glow-green);
    }

    .mode-button.live:hover {
      color: #052e16;
      background: var(--neon-green);
      box-shadow: var(--glow-green);
    }

    .status-badge.retry {
      color: #1c1407;
      border-color: var(--neon-amber);
      background: var(--neon-amber);
      box-shadow: 0 0 10px rgba(255,176,32,0.5), 0 0 24px rgba(255,176,32,0.25);
    }

    .status-badge.error {
      color: #fff;
      border-color: var(--danger);
      background: rgba(255,93,122,0.22);
      box-shadow: 0 0 10px rgba(255,93,122,0.45);
    }

    .alert-banner {
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 14px 20px;
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(255,176,32,0.12), rgba(255,93,122,0.06));
      border: 1px solid rgba(255,176,32,0.40);
      box-shadow: 0 0 22px rgba(255,176,32,0.16), inset 0 0 18px rgba(255,176,32,0.06);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      animation: alertIn 0.32s ease-out;
    }

    .alert-banner[hidden] { display: none; }

    @keyframes alertIn {
      0%   { opacity: 0; transform: translateY(-8px); }
      100% { opacity: 1; transform: translateY(0); }
    }

    .alert-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 40px;
      height: 40px;
      flex-shrink: 0;
      border-radius: 12px;
      color: var(--neon-amber);
      background: rgba(255,176,32,0.12);
      border: 1px solid rgba(255,176,32,0.4);
      box-shadow: 0 0 16px rgba(255,176,32,0.3);
    }

    .alert-icon svg { width: 22px; height: 22px; }

    .alert-text { flex: 1; min-width: 0; }

    .alert-title {
      font-size: 15px;
      font-weight: 700;
      color: #ffd98a;
      text-shadow: 0 0 10px rgba(255,176,32,0.4);
    }

    .alert-detail {
      margin-top: 2px;
      font-size: 12.5px;
      color: var(--muted);
    }

    .alert-pulse {
      width: 12px;
      height: 12px;
      flex-shrink: 0;
      border-radius: 50%;
      background: var(--neon-amber);
      box-shadow: 0 0 0 0 rgba(255,176,32,0.55), 0 0 12px rgba(255,176,32,0.85);
      animation: alertPulse 1.5s ease-out infinite;
    }

    @keyframes alertPulse {
      0%   { box-shadow: 0 0 0 0 rgba(255,176,32,0.5), 0 0 12px rgba(255,176,32,0.85); }
      70%  { box-shadow: 0 0 0 9px rgba(255,176,32,0), 0 0 12px rgba(255,176,32,0.85); }
      100% { box-shadow: 0 0 0 0 rgba(255,176,32,0), 0 0 12px rgba(255,176,32,0.85); }
    }

    @media (prefers-reduced-motion: reduce) {
      .alert-banner { animation: none; }
      .alert-pulse { animation: none; }
    }

    .table-card {
      position: relative;
      background: linear-gradient(180deg, rgba(11,15,27,0.82), rgba(7,10,20,0.86));
      border: 1px solid var(--border);
      border-radius: 28px;
      box-shadow: var(--shadow), 0 0 30px rgba(176,107,255,0.08);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      overflow: hidden;
    }

    .table-card::before {
      content: "";
      position: absolute;
      top: -1px; left: 28px; right: 28px;
      height: 1px;
      background: linear-gradient(90deg, transparent, var(--neon-purple), var(--neon-cyan), transparent);
      opacity: 0.6;
    }

    .table-card-header {
      padding: 24px 28px 18px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
      border-bottom: 1px solid var(--border-soft);
    }

    .table-title {
      margin: 0;
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #fff;
      text-shadow: 0 0 12px rgba(176,107,255,0.4);
    }

    .table-subtitle {
      margin: 6px 0 0 0;
      color: var(--muted);
      font-size: 14px;
    }

    .toolbar {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }

    .field {
      display: grid;
      gap: 6px;
      min-width: 140px;
    }

    .field label {
      color: var(--muted-2);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .select {
      min-height: 42px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(7,10,20,0.9);
      color: var(--text);
      padding: 0 14px;
      font-size: 14px;
      outline: none;
      transition: 0.18s ease;
    }

    .select:hover { border-color: rgba(34,211,238,0.4); }
    .select:focus {
      border-color: var(--neon-cyan);
      box-shadow: 0 0 0 3px rgba(34,211,238,0.18), var(--glow-cyan);
    }

    .table-wrap {
      overflow: auto;
      padding: 8px 10px 12px 10px;
    }

    table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      min-width: 980px;
    }

    thead th {
      text-align: left;
      padding: 16px 18px;
      color: var(--neon-cyan);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.10em;
      font-weight: 700;
      position: sticky;
      top: 0;
      background: rgba(7,10,20,0.96);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid rgba(34,211,238,0.25);
      text-shadow: 0 0 8px rgba(34,211,238,0.35);
      z-index: 1;
    }

    tbody td {
      padding: 16px 18px;
      border-bottom: 1px solid rgba(34,211,238,0.07);
      font-size: 14px;
      color: var(--text);
      vertical-align: middle;
    }

    .cell-ip-src {
      color: #7dffea;
      font-weight: 600;
      text-shadow: 0 0 8px rgba(34,211,238,0.35);
    }

    .cell-ip-dst {
      color: #79c0ff;
      font-weight: 600;
      text-shadow: 0 0 8px rgba(56,189,248,0.3);
    }

    .cell-port-src {
      color: #ffd24a;
      font-weight: 700;
      text-shadow: 0 0 8px rgba(255,176,32,0.35);
    }

    .cell-port-dst {
      color: #ff6ba6;
      font-weight: 700;
      text-shadow: 0 0 8px rgba(255,61,154,0.35);
    }

    tbody tr { transition: box-shadow 0.15s ease; }
    tbody tr:hover td {
      background: rgba(34,211,238,0.06);
      box-shadow: inset 0 0 18px rgba(34,211,238,0.06);
    }

    @keyframes rowEnter {
      0%   { opacity: 0; }
      100% { opacity: 1; }
    }

    @keyframes rowFlash {
      0%   { background: rgba(34,211,238,0.20); box-shadow: inset 3px 0 0 var(--neon-cyan), inset 0 0 24px rgba(34,211,238,0.18); }
      100% { background: transparent; box-shadow: inset 3px 0 0 transparent, inset 0 0 24px transparent; }
    }

    tbody tr.row-enter { animation: rowEnter 0.4s ease-out; }
    tbody tr.row-enter td { animation: rowFlash 1.4s ease-out; }

    @media (prefers-reduced-motion: reduce) {
      tbody tr.row-enter,
      tbody tr.row-enter td { animation: none; }
    }

    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }

    .muted-cell { color: var(--muted); }

    .proto {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 56px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.04em;
      background: rgba(148,163,184,0.10);
      border: 1px solid rgba(148,163,184,0.16);
      color: var(--text);
    }

    .proto.tcp {
      color: var(--neon-cyan);
      background: rgba(34,211,238,0.12);
      border-color: rgba(34,211,238,0.45);
      box-shadow: 0 0 12px rgba(34,211,238,0.25), inset 0 0 8px rgba(34,211,238,0.10);
      text-shadow: 0 0 8px rgba(34,211,238,0.5);
    }

    .proto.udp {
      color: var(--neon-green);
      background: rgba(43,255,136,0.10);
      border-color: rgba(43,255,136,0.45);
      box-shadow: 0 0 12px rgba(43,255,136,0.22), inset 0 0 8px rgba(43,255,136,0.10);
      text-shadow: 0 0 8px rgba(43,255,136,0.5);
    }

    .proto.icmp {
      color: var(--neon-amber);
      background: rgba(255,176,32,0.10);
      border-color: rgba(255,176,32,0.45);
      box-shadow: 0 0 12px rgba(255,176,32,0.22), inset 0 0 8px rgba(255,176,32,0.10);
      text-shadow: 0 0 8px rgba(255,176,32,0.5);
    }

    .empty {
      padding: 44px 28px 54px 28px;
      text-align: center;
      color: var(--muted);
      font-size: 15px;
    }

    .empty-title {
      font-size: 18px;
      font-weight: 600;
      color: var(--text);
      margin-bottom: 8px;
    }

    .file-sizes-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 3px;
      width: 100%;
      min-width: 0;
    }

    .file-size-item {
      display: flex;
      flex-direction: column;
      gap: 1px;
      padding: 4px 6px;
      border-radius: 8px;
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(148,163,184,0.06);
      min-width: 0;
    }

    .file-size-item .size-label {
      display: flex;
      align-items: center;
      gap: 3px;
      color: var(--muted-2);
      font-size: 8px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      font-weight: 600;
      white-space: nowrap;
    }

    .file-size-item .size-dot {
      width: 5px;
      height: 5px;
      border-radius: 50%;
      display: inline-block;
      flex-shrink: 0;
    }

    .file-size-item .size-dot.hourly { background: var(--neon-cyan); box-shadow: 0 0 6px rgba(34,211,238,0.9); }
    .file-size-item .size-dot.daily { background: var(--neon-green); box-shadow: 0 0 6px rgba(43,255,136,0.9); }
    .file-size-item .size-dot.monthly { background: var(--neon-amber); box-shadow: 0 0 6px rgba(255,176,32,0.9); }
    .file-size-item .size-dot.total { background: var(--neon-purple); box-shadow: 0 0 6px rgba(176,107,255,0.9); }

    .file-size-item .size-value {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .file-size-item .size-value.hourly { color: #7dffea; text-shadow: 0 0 7px rgba(34,211,238,0.35); }
    .file-size-item .size-value.daily { color: #7dffb0; text-shadow: 0 0 7px rgba(43,255,136,0.35); }
    .file-size-item .size-value.monthly { color: #ffd98a; text-shadow: 0 0 7px rgba(255,176,32,0.35); }
    .file-size-item .size-value.total { color: #cfa9ff; text-shadow: 0 0 7px rgba(176,107,255,0.35); }

    .file-size-value-wrap {
      display: block;
      width: 100%;
    }

    @media (max-width: 1100px) {
      body { padding: 18px; }
      .hero-grid { grid-template-columns: 1fr 1fr; }
    }

    @media (max-width: 920px) {
      body { padding: 12px; }
      .hero, .table-card { border-radius: 22px; }
      .hero { padding: 18px; }
      .table-card-header { padding: 20px 20px 16px 20px; }
      .toolbar { width: 100%; }
      .field { width: 100%; }
      .hero-controls { width: 100%; }
    }

    @media (max-width: 560px) {
      .hero-grid { grid-template-columns: 1fr; }
      .file-sizes-grid { grid-template-columns: repeat(2, 1fr); }
    }
  </style>
</head>
<body>
  <div class="layout">
    <section class="hero">
      <div class="hero-top">
        <div class="brand">
          <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M3 12h4l2 6 4-14 2 8h6"/>
            </svg>
          </span>
          <div class="brand-text">
            <h1 class="brand-title">NetFlow Logger</h1>
            <p class="brand-subtitle">NetFlow v9 · saatlik mühürlü kayıt paneli</p>
          </div>
        </div>
        <div class="hero-controls">
          <span class="status-badge" id="connection" role="status" aria-live="polite">Bağlanıyor</span>
          <button type="button" class="mode-button live" id="live-toggle">Canlı SSE akışı</button>
        </div>
      </div>

      <div class="hero-grid">
        <div class="stat-card accent">
          <div class="stat-head">
            <span class="status-label">Akış hızı</span>
            <span class="live-dot" id="rate-dot" aria-hidden="true"></span>
          </div>
          <div class="stat-main">
            <span class="stat-number" id="throughput-rate">0</span>
            <span class="stat-unit">kayıt/sn</span>
          </div>
          <div class="rate-chart" title="Son 2 dakikalık akış hızı">
            <canvas id="rate-spark"></canvas>
            <span class="rate-chart-peak" id="rate-peak">tepe 0</span>
            <span class="rate-chart-span">son 2 dk</span>
          </div>
          <div class="stat-foot"><span id="throughput-total">0</span> toplam işlenen kayıt</div>
        </div>

        <div class="stat-card">
          <div class="stat-head"><span class="status-label">Son güncelleme</span></div>
          <div class="stat-main"><span class="stat-number sm mono" id="updated-at">-</span></div>
          <div class="stat-foot" id="active-file" title="Aktif log dosyası">Aktif dosya: -</div>
        </div>

        <div class="stat-card integrity">
          <div class="stat-head">
            <span class="status-label">Bütünlük mührü</span>
            <span class="seal-badge" id="seal-badge">Bekliyor</span>
          </div>
          <div class="seal-sha-row">
            <code class="seal-sha mono" id="seal-sha" title="Son SHA-256 özeti">SHA-256 henüz yok</code>
            <button type="button" class="copy-btn" id="copy-sha" title="SHA-256 kopyala" disabled aria-label="SHA-256 özetini kopyala">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>
              </svg>
            </button>
          </div>
          <div class="stat-foot" id="seal-detail" title="Son TSA durumu">TSA: bekleniyor</div>
        </div>

        <div class="stat-card sizes">
          <div class="stat-head"><span class="status-label">Dosya boyutları</span></div>
          <div class="file-sizes-grid">
            <div class="file-size-item">
              <span class="size-label"><span class="size-dot hourly"></span>Saatlik</span>
              <span class="size-value hourly" id="file-size-hourly">-</span>
            </div>
            <div class="file-size-item">
              <span class="size-label"><span class="size-dot daily"></span>Günlük</span>
              <span class="size-value daily" id="file-size-daily">-</span>
            </div>
            <div class="file-size-item">
              <span class="size-label"><span class="size-dot monthly"></span>Aylık</span>
              <span class="size-value monthly" id="file-size-monthly">-</span>
            </div>
            <div class="file-size-item">
              <span class="size-label"><span class="size-dot total"></span>Toplam</span>
              <span class="size-value total" id="file-size-total">-</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <div class="alert-banner" id="no-data-alert" role="alert" hidden>
      <span class="alert-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 9v4"/><path d="M12 17h.01"/>
          <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>
        </svg>
      </span>
      <div class="alert-text">
        <div class="alert-title">Log verisi gelmiyor</div>
        <div class="alert-detail" id="no-data-detail">Dinlenen porta NetFlow kaydı ulaşmıyor — arka planda kontrol ediliyor…</div>
      </div>
      <span class="alert-pulse" aria-hidden="true"></span>
    </div>

    <section class="table-card">
      <div class="table-card-header">
        <div>
          <h2 class="table-title">Log kayıtları</h2>
          <p class="table-subtitle" id="table-subtitle">Canlı modda bellekte tutulan en yeni 1000 kayıt sayfalı olarak gösterilir.</p>
        </div>
        <div class="toolbar">
          <div class="field">
            <label for="date-select">Gün</label>
            <select id="date-select" class="select">
              <option value="">Canlı görünüm</option>
            </select>
          </div>
          <div class="field">
            <label for="hour-select">Saat</label>
            <select id="hour-select" class="select" disabled>
              <option value="">Saat seç</option>
            </select>
          </div>
          <div class="field">
            <label for="limit-select">Satır sayısı</label>
            <select id="limit-select" class="select">
              <option value="50" selected>50</option>
              <option value="100">100</option>
              <option value="250">250</option>
              <option value="500">500</option>
            </select>
          </div>
          <div class="field">
            <label>Sayfa</label>
            <div class="pager">
              <button type="button" class="mode-button" id="prev-page">Önceki</button>
              <span class="pager-info" id="page-info">1 / 1</span>
              <button type="button" class="mode-button" id="next-page">Sonraki</button>
            </div>
          </div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Zaman</th>
              <th>Kaynak IP</th>
              <th>Kaynak Port</th>
              <th>Hedef IP</th>
              <th>Hedef Port</th>
              <th>Protokol</th>
              <th>Boyut</th>
            </tr>
          </thead>
          <tbody id="records"></tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    const updatedAtEl = document.getElementById('updated-at');
    const recordsEl = document.getElementById('records');
    const connectionEl = document.getElementById('connection');
    const dateSelectEl = document.getElementById('date-select');
    const hourSelectEl = document.getElementById('hour-select');
    const limitSelectEl = document.getElementById('limit-select');
    const liveToggleEl = document.getElementById('live-toggle');
    const tableSubtitleEl = document.getElementById('table-subtitle');
    const prevPageEl = document.getElementById('prev-page');
    const nextPageEl = document.getElementById('next-page');
    const pageInfoEl = document.getElementById('page-info');
    const fileSizeHourlyEl = document.getElementById('file-size-hourly');
    const fileSizeDailyEl = document.getElementById('file-size-daily');
    const fileSizeMonthlyEl = document.getElementById('file-size-monthly');
    const fileSizeTotalEl = document.getElementById('file-size-total');
    const throughputRateEl = document.getElementById('throughput-rate');
    const throughputTotalEl = document.getElementById('throughput-total');
    const rateDotEl = document.getElementById('rate-dot');
    const rateSparkEl = document.getElementById('rate-spark');
    const ratePeakEl = document.getElementById('rate-peak');
    const activeFileEl = document.getElementById('active-file');
    const sealBadgeEl = document.getElementById('seal-badge');
    const sealShaEl = document.getElementById('seal-sha');
    const sealDetailEl = document.getElementById('seal-detail');
    const copyShaEl = document.getElementById('copy-sha');
    const noDataEl = document.getElementById('no-data-alert');
    const noDataDetailEl = document.getElementById('no-data-detail');

    let eventSource = null;
    let livePollTimer = null;
    let currentMode = 'live';
    let currentPage = 1;

    let lastProcessed = null;
    let lastProcessedAt = 0;
    let rateEma = 0;
    let currentSha = '';

    // Canlı akış mini grafiği: rateEma değeri sabit aralıkla örneklenir ve son
    // 2 dakikalık pencere (120 örnek) bir halka tamponunda tutulur. Böylece grafik
    // zaman ekseni, olay sıklığından bağımsız ve düzgün olur.
    const RATE_SAMPLE_MS = 1000;
    const RATE_WINDOW = 120;
    const rateSamples = [];
    let rateSampleTimer = null;

    let liveRowsInit = false;
    let lastRowsTotal = null;

    // "Log gelmiyor" tespiti: processed_total bu süre boyunca artmazsa uyarı gösterilir.
    const IDLE_THRESHOLD_MS = 15000;
    let lastDataValue = null;
    let lastDataAt = performance.now();

    const numberFmt = new Intl.NumberFormat('tr-TR');

    function formatRate(value) {
      if (value >= 100) return numberFmt.format(Math.round(value));
      if (value >= 10) return value.toFixed(1);
      return value.toFixed(value > 0 ? 2 : 0);
    }

    function basename(path) {
      if (!path) return '';
      const clean = String(path).replace(/[\\/]+$/, '');
      const idx = Math.max(clean.lastIndexOf('/'), clean.lastIndexOf('\\'));
      return idx >= 0 ? clean.slice(idx + 1) : clean;
    }

    function updateThroughput(state) {
      const total = Number(state.processed_total);
      if (!Number.isFinite(total)) return;
      throughputTotalEl.textContent = numberFmt.format(total);

      const now = performance.now();
      if (lastProcessed !== null && now > lastProcessedAt) {
        const dt = (now - lastProcessedAt) / 1000;
        const delta = total - lastProcessed;
        if (dt >= 0.4 && delta >= 0) {
          const instant = delta / dt;
          rateEma = rateEma === 0 ? instant : rateEma * 0.6 + instant * 0.4;
        }
      }
      lastProcessed = total;
      lastProcessedAt = now;
      throughputRateEl.textContent = formatRate(rateEma);
      rateDotEl.classList.toggle('active', rateEma >= 0.05);
    }

    function resetThroughput() {
      lastProcessed = null;
      rateEma = 0;
      rateDotEl.classList.remove('active');
      throughputRateEl.textContent = '—';
      rateSamples.length = 0;
      drawRateChart();
    }

    // Canvas'ı yüksek DPI ekranlara göre ölçekler ve mevcut çizim bağlamını döndürür.
    function prepareRateCanvas() {
      if (!rateSparkEl) return null;
      const dpr = window.devicePixelRatio || 1;
      const w = rateSparkEl.clientWidth || rateSparkEl.parentElement.clientWidth || 220;
      const h = rateSparkEl.clientHeight || 46;
      const pw = Math.round(w * dpr);
      const ph = Math.round(h * dpr);
      if (rateSparkEl.width !== pw || rateSparkEl.height !== ph) {
        rateSparkEl.width = pw;
        rateSparkEl.height = ph;
      }
      const ctx = rateSparkEl.getContext('2d');
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      return { ctx, w, h };
    }

    // Son 2 dakikalık akış hızını neon alan grafiği olarak çizer.
    function drawRateChart() {
      const env = prepareRateCanvas();
      if (!env) return;
      const { ctx, w, h } = env;
      ctx.clearRect(0, 0, w, h);

      const pad = 4;
      const baseY = h - pad;
      const topY = pad + 8;

      // Eksen tabanı.
      ctx.strokeStyle = 'rgba(56,189,248,0.14)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, baseY + 0.5);
      ctx.lineTo(w, baseY + 0.5);
      ctx.stroke();

      const n = rateSamples.length;
      const peak = n ? Math.max(...rateSamples) : 0;
      ratePeakEl.textContent = 'tepe ' + formatRate(peak);

      if (n < 2 || peak <= 0) return;

      // X ekseni her zaman tam pencereyi temsil eder; veri sağdan sola akar.
      const stepX = w / (RATE_WINDOW - 1);
      const scaleY = (baseY - topY) / peak;
      const offset = RATE_WINDOW - n;
      const xAt = (i) => (offset + i) * stepX;
      const yAt = (v) => baseY - v * scaleY;

      // Dolgu alanı.
      const grad = ctx.createLinearGradient(0, topY, 0, baseY);
      grad.addColorStop(0, 'rgba(34,211,238,0.42)');
      grad.addColorStop(1, 'rgba(34,211,238,0.02)');
      ctx.beginPath();
      ctx.moveTo(xAt(0), baseY);
      for (let i = 0; i < n; i++) ctx.lineTo(xAt(i), yAt(rateSamples[i]));
      ctx.lineTo(xAt(n - 1), baseY);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      // Çizgi + neon parıltı.
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const x = xAt(i), y = yAt(rateSamples[i]);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      ctx.lineWidth = 1.8;
      ctx.strokeStyle = '#22d3ee';
      ctx.shadowColor = 'rgba(34,211,238,0.8)';
      ctx.shadowBlur = 6;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Son noktayı vurgula.
      const lx = xAt(n - 1), ly = yAt(rateSamples[n - 1]);
      ctx.beginPath();
      ctx.arc(lx, ly, 2.6, 0, Math.PI * 2);
      ctx.fillStyle = '#eafcff';
      ctx.shadowColor = 'rgba(34,211,238,0.9)';
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // Sabit aralıkla mevcut hızı örnekler; yalnızca canlı modda akar.
    function sampleRate() {
      if (currentMode !== 'live') return;
      rateSamples.push(rateEma > 0 ? rateEma : 0);
      if (rateSamples.length > RATE_WINDOW) rateSamples.shift();
      drawRateChart();
    }

    function startRateSampler() {
      if (rateSampleTimer) return;
      rateSampleTimer = setInterval(sampleRate, RATE_SAMPLE_MS);
    }

    window.addEventListener('resize', drawRateChart);

    // Canlı durum her geldiğinde toplam kayıt sayısını izler; arttıysa "veri akıyor"
    // zaman damgasını günceller (uyarıyı tetikleyen boşta kalma süresini sıfırlar).
    function noteDataActivity(state) {
      const total = Number(state.processed_total);
      if (!Number.isFinite(total)) {
        return;
      }
      if (lastDataValue === null || total > lastDataValue) {
        lastDataAt = performance.now();
      }
      lastDataValue = total;
    }

    // Canlı izlemeyi sıfırla: yeni başlatıldığında bir tolerans süresi tanı
    // (hemen uyarı çıkmasın).
    function resetDataFlowWatch() {
      lastDataValue = null;
      lastDataAt = performance.now();
      hideNoDataAlert();
    }

    function showNoDataAlert(idleMs) {
      const secs = Math.max(0, Math.round(idleMs / 1000));
      noDataDetailEl.textContent =
        'Dinlenen porta ' + secs + ' sn’dir NetFlow kaydı ulaşmıyor — arka planda kontrol ediliyor…';
      if (noDataEl.hidden) {
        noDataEl.hidden = false;
      }
    }

    function hideNoDataAlert() {
      if (!noDataEl.hidden) {
        noDataEl.hidden = true;
      }
    }

    // Arka planda sürekli çalışır: yalnızca canlı + 1. sayfada anlamlıdır.
    function evaluateDataFlow() {
      if (currentMode !== 'live' || currentPage !== 1) {
        hideNoDataAlert();
        return;
      }
      const idle = performance.now() - lastDataAt;
      if (idle > IDLE_THRESHOLD_MS) {
        showNoDataAlert(idle);
      } else {
        hideNoDataAlert();
      }
    }

    function updateIntegrity(state) {
      const file = state.active_file || '';
      activeFileEl.textContent = 'Aktif dosya: ' + (basename(file) || '-');
      activeFileEl.title = file || 'Aktif log dosyası';

      const sha = state.last_sha256 || '';
      currentSha = sha;
      if (sha) {
        sealShaEl.textContent = sha.slice(0, 12) + '…' + sha.slice(-12);
        sealShaEl.title = sha;
        copyShaEl.disabled = false;
      } else {
        sealShaEl.textContent = 'SHA-256 henüz yok';
        sealShaEl.title = 'Son SHA-256 özeti';
        copyShaEl.disabled = true;
      }

      const status = state.last_tsa_status || '';
      sealDetailEl.textContent = 'TSA: ' + (status || 'bekleniyor');
      sealDetailEl.title = status || 'Son TSA durumu';
      sealBadgeEl.className = 'seal-badge';
      if (!status) {
        sealBadgeEl.textContent = 'Bekliyor';
      } else if (/^OK/i.test(status)) {
        sealBadgeEl.textContent = 'Mühürlendi';
        sealBadgeEl.classList.add('ok');
      } else {
        sealBadgeEl.textContent = 'Hata';
        sealBadgeEl.classList.add('error');
      }
    }

    function formatTime(value) {
      if (!value) return '-';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleTimeString('tr-TR', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      });
    }

    function formatBytes(bytesValue) {
      const bytes = Number(bytesValue);
      if (!Number.isFinite(bytes)) return bytesValue || '-';
      if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
      if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
      if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
      return bytes + ' B';
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function parseRecord(record) {
      const parts = String(record || '').split('|');
      const proto = (parts[5] || '-').toUpperCase();
      return {
        time: formatTime(parts[0] || ''),
        srcIp: parts[1] || '-',
        srcPort: parts[3] || '-',
        dstIp: parts[2] || '-',
        dstPort: parts[4] || '-',
        proto,
        protoClass: proto.toLowerCase(),
        size: formatBytes(parts[7] || '0')
      };
    }

    function buildRowMarkup(record) {
      const item = parseRecord(record);
      return [
        '<tr>',
        '<td class="muted-cell mono">' + escapeHtml(item.time) + '</td>',
        '<td class="mono cell-ip-src">' + escapeHtml(item.srcIp) + '</td>',
        '<td class="mono cell-port-src">' + escapeHtml(item.srcPort) + '</td>',
        '<td class="mono cell-ip-dst">' + escapeHtml(item.dstIp) + '</td>',
        '<td class="mono cell-port-dst">' + escapeHtml(item.dstPort) + '</td>',
        '<td><span class="proto ' + escapeHtml(item.protoClass) + '">' + escapeHtml(item.proto) + '</span></td>',
        '<td class="muted-cell mono">' + escapeHtml(item.size) + '</td>',
        '</tr>'
      ].join('');
    }

    const emptyRowsMarkup = '<tr><td colspan="7" class="empty"><div class="empty-title">Kayıt bulunamadı</div><div>Seçilen gün ve saat için gösterilecek log kaydı yok.</div></td></tr>';

    // Statik (geçmiş / canlı olmayan) görünüm: tam yeniden çizim, sunucu sırasıyla.
    function renderRows(records) {
      liveRowsInit = false;
      lastRowsTotal = null;
      if (!records.length) {
        recordsEl.innerHTML = emptyRowsMarkup;
        return;
      }
      const rows = new Array(records.length);
      for (let i = 0; i < records.length; i += 1) {
        rows[i] = buildRowMarkup(records[i]);
      }
      recordsEl.innerHTML = rows.join('');
    }

    // Giriş animasyonu sınıfını ekler ve bittikten sonra kendi kendine temizler
    // (sınıfların satırlarda birikmesini önler).
    function markEntered(rowEls) {
      for (let i = 0; i < rowEls.length; i += 1) {
        rowEls[i].classList.add('row-enter');
      }
      setTimeout(() => {
        for (let i = 0; i < rowEls.length; i += 1) {
          rowEls[i].classList.remove('row-enter');
        }
      }, 1500);
    }

    // Canlı görünüm: en yeni kayıtlar üstte; yalnızca yeni gelenler animasyonla eklenir.
    function renderLiveRows(state) {
      const records = state.records || [];
      const total = Number(state.processed_total);
      const reversed = records.slice().reverse(); // en yeni en üstte

      if (!reversed.length) {
        recordsEl.innerHTML = emptyRowsMarkup;
        liveRowsInit = false;
        lastRowsTotal = Number.isFinite(total) ? total : null;
        return;
      }

      // İki yoklama arasında gelen yeni kayıt sayısı (monoton sayaçtan).
      let newCount;
      if (!liveRowsInit || lastRowsTotal === null || !Number.isFinite(total)) {
        newCount = reversed.length; // ilk yükleme / belirsizlik → tam çizim
      } else {
        newCount = total - lastRowsTotal;
        if (newCount < 0) newCount = reversed.length; // sayaç tutarsızsa tam çizim
      }
      if (newCount > reversed.length) newCount = reversed.length;

      // Taşınacak (yeniden kullanılacak) satırlar için DOM'da yeterli satır yoksa
      // (limit büyümesi, atlanan yoklama vb.) güvenli tarafta kalıp tam yeniden çizeriz.
      // Fazla satırlar zaten alttan kırpıldığı için yalnızca "yetersizlik" durumu önemlidir.
      const firstInit = !liveRowsInit;
      if (newCount !== reversed.length && recordsEl.childElementCount < reversed.length - newCount) {
        newCount = reversed.length;
      }

      if (newCount === 0) {
        // Yeni kayıt yok → DOM'a dokunma (titreme olmaz).
      } else if (newCount === reversed.length) {
        const rows = new Array(reversed.length);
        for (let i = 0; i < reversed.length; i += 1) {
          rows[i] = buildRowMarkup(reversed[i]);
        }
        recordsEl.innerHTML = rows.join('');
        if (!firstInit) {
          const animateN = Math.min(recordsEl.childElementCount, 14);
          markEntered(Array.prototype.slice.call(recordsEl.children, 0, animateN));
        }
      } else {
        // Yalnızca yeni gelenleri en üste ekle, eskileri alttan kırp.
        let html = '';
        for (let i = 0; i < newCount; i += 1) {
          html += buildRowMarkup(reversed[i]);
        }
        recordsEl.insertAdjacentHTML('afterbegin', html);
        const added = Array.prototype.slice.call(recordsEl.children, 0, newCount);
        while (recordsEl.childElementCount > reversed.length) {
          recordsEl.removeChild(recordsEl.lastElementChild);
        }
        markEntered(added);
      }

      liveRowsInit = true;
      if (Number.isFinite(total)) {
        lastRowsTotal = total;
      }
    }

    function setConnectionState(text, mode) {
      connectionEl.textContent = text;
      connectionEl.className = 'status-badge';
      if (mode) {
        connectionEl.classList.add(mode);
      }
    }

    function renderDateOptions(dates, selectedDate) {
      dateSelectEl.innerHTML = '<option value="">Canlı görünüm</option>';
      (dates || []).forEach((date) => {
        const option = document.createElement('option');
        option.value = date;
        option.textContent = date;
        if (date === selectedDate) {
          option.selected = true;
        }
        dateSelectEl.appendChild(option);
      });
    }

    function renderHourOptions(hours, selectedHour) {
      hourSelectEl.innerHTML = '<option value="">Saat seç</option>';
      (hours || []).forEach((hour) => {
        const option = document.createElement('option');
        option.value = hour;
        option.textContent = hour + ':00';
        if (hour === selectedHour) {
          option.selected = true;
        }
        hourSelectEl.appendChild(option);
      });
      hourSelectEl.disabled = !(hours && hours.length);
    }

    function applyMode(mode) {
      currentMode = mode;
      if (mode === 'historical') {
        liveToggleEl.classList.remove('live');
        tableSubtitleEl.textContent = 'Seçilen saatlik log dosyasının başından belirlenen satır sayısı gösterilir.';
      } else {
        liveToggleEl.classList.add('live');
        tableSubtitleEl.textContent = 'Canlı modda yeni kayıtlar üste eklenir, eskiler aşağı kayar. En yeni 1000 kayıt sayfalı tutulur.';
      }
    }

    let renderFrame = null;
    let pendingState = null;

    function commitRender(state) {
      if ((state.mode || 'live') === 'live' && currentMode === 'historical') {
        return;
      }
      applyMode(state.mode || 'live');
      currentPage = state.page || 1;
      renderDateOptions(state.available_dates || [], state.selected_date || '');
      renderHourOptions(state.available_hours || [], state.selected_hour || '');
      limitSelectEl.value = String(state.limit || 50);
      updatedAtEl.textContent = formatTime(state.updated_at || '');
      pageInfoEl.textContent = String(state.page || 1) + ' / ' + String(state.total_pages || 1);
      fileSizeHourlyEl.textContent = state.file_size || '-';
      fileSizeDailyEl.textContent = state.file_size_daily || '-';
      fileSizeMonthlyEl.textContent = state.file_size_monthly || '-';
      fileSizeTotalEl.textContent = state.file_size_total || '-';
      updateIntegrity(state);
      const isLive = (state.mode || 'live') === 'live';
      if (isLive) {
        updateThroughput(state);
        noteDataActivity(state);
      } else {
        resetThroughput();
      }
      prevPageEl.disabled = (state.page || 1) <= 1;
      nextPageEl.disabled = (state.page || 1) >= (state.total_pages || 1);
      if (isLive && (state.page || 1) === 1) {
        renderLiveRows(state);
      } else {
        renderRows(state.records || []);
      }
      evaluateDataFlow();
    }

    function render(state) {
      pendingState = state;
      if (renderFrame !== null) {
        return;
      }
      renderFrame = requestAnimationFrame(() => {
        if (pendingState) {
          commitRender(pendingState);
        }
        pendingState = null;
        renderFrame = null;
      });
    }

    function stopLiveStream() {
      if (eventSource) {
        eventSource.close();
        eventSource = null;
      }
      if (livePollTimer) {
        clearInterval(livePollTimer);
        livePollTimer = null;
      }
    }

    async function fetchState() {
      const params = new URLSearchParams();
      if (dateSelectEl.value) {
        params.set('date', dateSelectEl.value);
      }
      if (hourSelectEl.value) {
        params.set('hour', hourSelectEl.value);
      }
      params.set('limit', limitSelectEl.value || '50');
      params.set('page', String(currentPage || 1));

      const query = params.toString();
      const response = await fetch('/api/state' + (query ? ('?' + query) : ''), { cache: 'no-store' });
      if (!response.ok) {
        throw new Error('Log durumu alınamadı');
      }
      const state = await response.json();
      render(state);
      return state;
    }

    async function refreshHistorical() {
      stopLiveStream();
      setConnectionState('Geçmiş görünüm', null);
      await fetchState();
    }

    async function changePage(page) {
      currentPage = page;
      if (currentMode === 'historical') {
        await refreshHistorical();
        return;
      }
      await fetchState();
      if (currentPage === 1) {
        startLiveStream();
      } else {
        stopLiveStream();
        setConnectionState('Canlı akış yalnızca 1. sayfada aktif', null);
      }
    }

    async function pollLiveState() {
      try {
        const state = await fetchState();
        state.mode = 'live';
        render(state);
        setConnectionState('Canlı', 'live');
      } catch (error) {
        setConnectionState('Yeniden bağlanıyor', 'retry');
      }
    }

    // Canlı akış: SSE ile sunucudan anlık itme. Yeni NetFlow kaydı geldiği anda
    // tablo güncellenir (sabit aralıklı yoklama yerine olay tabanlı).
    function startLiveStream() {
      stopLiveStream();
      setConnectionState('Canlı', 'live');

      // SSE desteklenmiyorsa saniyelik yoklamaya düş.
      if (typeof window.EventSource === 'undefined') {
        startLivePolling();
        return;
      }

      const params = new URLSearchParams();
      params.set('limit', limitSelectEl.value || '50');
      eventSource = new EventSource('/events?' + params.toString());

      eventSource.addEventListener('state', (event) => {
        if (currentMode !== 'live' || currentPage !== 1) {
          return;
        }
        let state;
        try {
          state = JSON.parse(event.data);
        } catch (err) {
          return;
        }
        state.mode = 'live';
        render(state);
        setConnectionState('Canlı', 'live');
      });

      // EventSource bağlantı koptuğunda kendiliğinden yeniden bağlanır; bu sırada
      // durumu kullanıcıya bildiririz.
      eventSource.onerror = () => {
        setConnectionState('Yeniden bağlanıyor', 'retry');
      };
    }

    // Yedek yol: SSE yoksa saniyelik yoklama.
    function startLivePolling() {
      stopLiveStream();
      setConnectionState('Canlı', 'live');
      livePollTimer = setInterval(() => {
        if (currentMode !== 'live' || currentPage !== 1) {
          return;
        }
        void pollLiveState();
      }, 1000);
    }

    dateSelectEl.addEventListener('change', async () => {
      currentPage = 1;
      hourSelectEl.value = '';
      if (!dateSelectEl.value) {
        currentMode = 'live';
        await fetchState();
        startLiveStream();
        return;
      }
      stopLiveStream();
      currentMode = 'historical';
      await fetchState();
      setConnectionState('Saat seçimi bekleniyor', null);
      applyMode('historical');
    });

    hourSelectEl.addEventListener('change', async () => {
      currentPage = 1;
      if (!dateSelectEl.value || !hourSelectEl.value) {
        return;
      }
      await refreshHistorical();
    });

    limitSelectEl.addEventListener('change', async () => {
      currentPage = 1;
      if (dateSelectEl.value && hourSelectEl.value) {
        await refreshHistorical();
        return;
      }
      if (!dateSelectEl.value && !hourSelectEl.value) {
        await fetchState();
        startLiveStream();
        return;
      }
      await fetchState();
    });

    liveToggleEl.addEventListener('click', async () => {
      currentMode = 'live';
      currentPage = 1;
      dateSelectEl.value = '';
      hourSelectEl.innerHTML = '<option value="">Saat seç</option>';
      hourSelectEl.disabled = true;
      await fetchState();
      startLiveStream();
    });

    prevPageEl.addEventListener('click', async () => {
      if (currentPage <= 1) {
        return;
      }
      await changePage(currentPage - 1);
    });

    nextPageEl.addEventListener('click', async () => {
      await changePage(currentPage + 1);
    });

    copyShaEl.addEventListener('click', async () => {
      if (!currentSha) {
        return;
      }
      try {
        await navigator.clipboard.writeText(currentSha);
      } catch (error) {
        const helper = document.createElement('textarea');
        helper.value = currentSha;
        helper.style.position = 'fixed';
        helper.style.opacity = '0';
        document.body.appendChild(helper);
        helper.select();
        try { document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(helper);
      }
      copyShaEl.classList.add('copied');
      setTimeout(() => copyShaEl.classList.remove('copied'), 1200);
    });

    drawRateChart();
    startRateSampler();

    fetchState().then((state) => {
      if ((state.mode || 'live') === 'live') {
        startLiveStream();
      }
    }).catch((error) => {
      setConnectionState(error.message, 'error');
    });
  </script>
</body>
</html>`
