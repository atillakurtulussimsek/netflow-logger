package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
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
	dashboardMaxRecords     = 200
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
}

type DashboardHub struct {
	maxRecords int

	mu            sync.RWMutex
	records       []string
	activeFile    string
	lastSHA256    string
	lastTSAStatus string
	updatedAt     time.Time
	clients       map[chan []byte]struct{}
}

type DashboardState struct {
	Records       []string `json:"records"`
	ActiveFile    string   `json:"active_file"`
	LastSHA256    string   `json:"last_sha256"`
	LastTSAStatus string   `json:"last_tsa_status"`
	UpdatedAt     string   `json:"updated_at"`
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

func main() {
	cfg, err := loadConfig(defaultEnvPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	dashboard := NewDashboardHub(dashboardMaxRecords)
	app := &App{
		cfg:       cfg,
		session:   flowsession.New(),
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
	state := DashboardState{
		Records:       append([]string(nil), h.records...),
		ActiveFile:    h.activeFile,
		LastSHA256:    h.lastSHA256,
		LastTSAStatus: h.lastTSAStatus,
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
				if closeErr := a.logger.CloseCurrent(); closeErr != nil {
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

func (a *App) handleDashboardState(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(a.dashboard.Snapshot()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *App) handleDashboardEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	updates, unsubscribe := a.dashboard.Subscribe()
	defer unsubscribe()

	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case payload, ok := <-updates:
			if !ok {
				return
			}
			if _, err := fmt.Fprintf(w, "event: state\ndata: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		case <-keepAlive.C:
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (a *App) handlePacket(packetBytes []byte, addr net.Addr) error {
	decoder := netflow9.NewDecoder(nil, a.session)
	packet, err := decoder.Decode(packetBytes)
	if err != nil {
		return fmt.Errorf("netflow decode failed: %w", err)
	}

	records := extractFlowRecords(packet, a.cfg.Location)
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

func extractFlowRecords(packet *netflow9.Packet, location *time.Location) []FlowRecord {
	result := make([]FlowRecord, 0)
	for _, flowSet := range packet.DataFlowSets {
		for _, dataRecord := range flowSet.Records {
			record, ok := mapFlowRecord(packet.Header, dataRecord, location)
			if ok {
				result = append(result, record)
			}
		}
	}
	return result
}

func mapFlowRecord(header netflow9.PacketHeader, dataRecord netflow9.DataRecord, location *time.Location) (FlowRecord, bool) {
	values := make(map[string]interface{})
	for _, field := range dataRecord.Fields {
		if field.Translated == nil || field.Translated.Name == "" {
			continue
		}
		values[field.Translated.Name] = field.Translated.Value
	}

	srcIP := firstString(values, "sourceIPv4Address", "sourceIPv6Address")
	dstIP := firstString(values, "destinationIPv4Address", "destinationIPv6Address")
	srcPort, okSrcPort := firstUint16(values, "sourceTransportPort")
	dstPort, okDstPort := firstUint16(values, "destinationTransportPort")
	protocolNumber, okProtocol := firstUint8(values, "protocolIdentifier")
	packets, okPackets := firstUint64(values, "packetDeltaCount", "postPacketDeltaCount")
	bytesCount, okBytes := firstUint64(values, "octetDeltaCount", "postOctetDeltaCount")
	inputIf, okInputIf := firstUint32(values, "ingressInterface")
	outputIf, okOutputIf := firstUint32(values, "egressInterface")
	flowStart, okFlowStart := resolveFlowStart(values, header, location)
	flowEnd, okFlowEnd := resolveFlowEnd(values, header, location)

	if srcIP == "" || dstIP == "" || !okSrcPort || !okDstPort || !okProtocol || !okPackets || !okBytes || !okInputIf || !okOutputIf || !okFlowStart || !okFlowEnd {
		return FlowRecord{}, false
	}

	packetTime := time.Unix(int64(header.UnixSecs), 0).In(location)

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

func (h *HourlyLogger) CloseCurrent() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closeCurrentLocked()
}

func (h *HourlyLogger) rotateLocked(targetHour time.Time) error {
	if h.file == nil {
		return h.openLocked(targetHour)
	}
	if h.currentHour.Equal(targetHour) {
		return nil
	}
	if err := h.closeCurrentLocked(); err != nil {
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

func (h *HourlyLogger) closeCurrentLocked() error {
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
	if err := h.sealHourlyLog(currentPath); err != nil {
		return err
	}

	return nil
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
				Algorithm: oidSHA256,
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
	var outer contentInfo
	if _, err := asn1.Unmarshal(response, &outer); err != nil {
		return fmt.Errorf("unmarshal tsr content info failed: %w", err)
	}
	if !outer.ContentType.Equal(oidSignedData) {
		return fmt.Errorf("unexpected tsr content type: %s", outer.ContentType.String())
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
  <title>netio logger — log görüntüleyici</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #f2f2f3;
      --window: #1d1d31;
      --window-top: #171729;
      --line: rgba(255,255,255,0.06);
      --line-strong: rgba(255,255,255,0.08);
      --text-dim: #67677f;
      --text-soft: #7c7c92;
      --blue: #45bbff;
      --orange: #ff9617;
      --green: #26e57c;
      --white: #e8ebf4;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      font-family: Menlo, Monaco, Consolas, "SFMono-Regular", monospace;
      color: var(--white);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 10px 0;
    }

    .window {
      width: min(1702px, 100vw);
      min-height: 548px;
      background: var(--window);
      border-radius: 30px;
      overflow: hidden;
      box-shadow: 0 18px 48px rgba(11, 11, 20, 0.20);
    }

    .window-top {
      height: 80px;
      background: var(--window-top);
      display: flex;
      align-items: center;
      gap: 18px;
      padding: 0 32px;
      border-bottom: 1px solid var(--line);
    }

    .traffic-lights {
      display: flex;
      align-items: center;
      gap: 12px;
      flex: 0 0 auto;
    }

    .dot {
      width: 21px;
      height: 21px;
      border-radius: 50%;
      display: inline-block;
    }

    .dot.red { background: #ff6057; }
    .dot.yellow { background: #ffbd44; }
    .dot.green { background: #28c840; }

    .title {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 18px;
      color: var(--text-soft);
      letter-spacing: 0.01em;
    }

    .top-right {
      margin-left: auto;
      display: flex;
      align-items: center;
      gap: 12px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 13px;
      color: var(--text-soft);
    }

    .status-badge {
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.05);
      color: var(--white);
      font-size: 12px;
    }

    .status-badge.live { color: var(--green); }
    .status-badge.retry { color: var(--orange); }
    .status-badge.error { color: #ff7b7b; }

    .table-wrap {
      padding: 34px 44px 28px 44px;
    }

    .meta-bar {
      display: grid;
      grid-template-columns: 1.8fr 1.2fr 1.4fr 0.9fr;
      gap: 18px;
      margin-bottom: 26px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 12px;
      color: var(--text-dim);
    }

    .meta-item {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .meta-item strong {
      color: #9494ac;
      font-weight: 500;
      margin-right: 8px;
    }

    .header-row,
    .table-row {
      display: grid;
      grid-template-columns: 120px 2.25fr 120px 2.25fr 120px 120px 1.3fr;
      column-gap: 26px;
      align-items: center;
    }

    .header-row {
      padding: 10px 2px 18px 2px;
      border-bottom: 1px solid var(--line-strong);
      font-size: 17px;
      line-height: 1;
    }

    .table {
      margin-top: 10px;
      max-height: 340px;
      overflow: auto;
      padding-right: 6px;
    }

    .table-row {
      min-height: 40px;
      font-size: 18px;
      color: var(--white);
    }

    .col-time,
    .col-size,
    .header-time,
    .header-size {
      color: var(--text-dim);
    }

    .col-src,
    .col-dst,
    .header-src,
    .header-dst {
      color: var(--blue);
    }

    .col-sport,
    .col-dport,
    .header-sport,
    .header-dport {
      color: var(--orange);
    }

    .col-proto,
    .header-proto {
      color: var(--green);
    }

    .empty {
      color: var(--text-dim);
      padding: 20px 0 6px 0;
      font-size: 16px;
    }

    .table::-webkit-scrollbar {
      width: 8px;
      height: 8px;
    }

    .table::-webkit-scrollbar-thumb {
      background: rgba(255,255,255,0.10);
      border-radius: 999px;
    }

    .table::-webkit-scrollbar-track {
      background: transparent;
    }

    @media (max-width: 1100px) {
      body { padding: 0; }
      .window { border-radius: 0; min-height: 100vh; }
      .table-wrap { padding: 24px; }
      .meta-bar,
      .header-row,
      .table-row {
        min-width: 980px;
      }
      .table-container {
        overflow-x: auto;
      }
    }
  </style>
</head>
<body>
  <div class="window">
    <div class="window-top">
      <div class="traffic-lights">
        <span class="dot red"></span>
        <span class="dot yellow"></span>
        <span class="dot green"></span>
      </div>
      <div class="title">netio logger — log görüntüleyici</div>
      <div class="top-right">
        <span id="updated-at">-</span>
        <span class="status-badge" id="connection">Bağlanıyor</span>
      </div>
    </div>

    <div class="table-wrap">
      <div class="meta-bar">
        <div class="meta-item"><strong>Aktif dosya:</strong><span id="active-file">-</span></div>
        <div class="meta-item"><strong>Son SHA-256:</strong><span id="last-sha">-</span></div>
        <div class="meta-item"><strong>TSA:</strong><span id="last-tsa">-</span></div>
        <div class="meta-item"><strong>Kayıt:</strong><span id="record-count">0</span></div>
      </div>

      <div class="table-container">
        <div class="header-row">
          <div class="header-time">Zaman</div>
          <div class="header-src">Kaynak IP</div>
          <div class="header-sport">Port</div>
          <div class="header-dst">Hedef IP</div>
          <div class="header-dport">Port</div>
          <div class="header-proto">Proto</div>
          <div class="header-size">Boyut</div>
        </div>

        <div class="table" id="records"></div>
      </div>
    </div>
  </div>

  <script>
    const activeFileEl = document.getElementById('active-file');
    const lastShaEl = document.getElementById('last-sha');
    const lastTsaEl = document.getElementById('last-tsa');
    const updatedAtEl = document.getElementById('updated-at');
    const recordsEl = document.getElementById('records');
    const connectionEl = document.getElementById('connection');
    const recordCountEl = document.getElementById('record-count');

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
      if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
      if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
      if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
      return bytes + ' B';
    }

    function parseRecord(record) {
      const parts = String(record || '').split('|');
      return {
        raw: record,
        time: formatTime(parts[0] || ''),
        srcIp: parts[1] || '-',
        srcPort: parts[3] || '-',
        dstIp: parts[2] || '-',
        dstPort: parts[4] || '-',
        proto: parts[5] || '-',
        size: formatBytes(parts[7] || '0')
      };
    }

    function renderRows(records) {
      recordsEl.innerHTML = '';
      if (!records.length) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = 'Henüz kayıt yok';
        recordsEl.appendChild(empty);
        return;
      }

      [...records].reverse().forEach((record) => {
        const item = parseRecord(record);
        const row = document.createElement('div');
        row.className = 'table-row';
        row.innerHTML = [
          '<div class="col-time">' + item.time + '</div>',
          '<div class="col-src">' + item.srcIp + '</div>',
          '<div class="col-sport">' + item.srcPort + '</div>',
          '<div class="col-dst">' + item.dstIp + '</div>',
          '<div class="col-dport">' + item.dstPort + '</div>',
          '<div class="col-proto">' + item.proto + '</div>',
          '<div class="col-size">' + item.size + '</div>'
        ].join('');
        recordsEl.appendChild(row);
      });
    }

    function setConnectionState(text, mode) {
      connectionEl.textContent = text;
      connectionEl.className = 'status-badge';
      if (mode) {
        connectionEl.classList.add(mode);
      }
    }

    function render(state) {
      activeFileEl.textContent = state.active_file || '-';
      lastShaEl.textContent = state.last_sha256 || '-';
      lastTsaEl.textContent = state.last_tsa_status || '-';
      updatedAtEl.textContent = formatTime(state.updated_at || '');
      const records = state.records || [];
      recordCountEl.textContent = String(records.length);
      renderRows(records);
    }

    async function loadInitial() {
      const response = await fetch('/api/state', { cache: 'no-store' });
      if (!response.ok) {
        throw new Error('Başlangıç durumu alınamadı');
      }
      const state = await response.json();
      render(state);
    }

    function connectEvents() {
      const es = new EventSource('/events');
      es.addEventListener('state', (event) => {
        setConnectionState('Canlı', 'live');
        const state = JSON.parse(event.data);
        render(state);
      });
      es.onerror = () => {
        setConnectionState('Yeniden bağlanıyor', 'retry');
      };
      es.onopen = () => {
        setConnectionState('Canlı', 'live');
      };
    }

    loadInitial().catch((error) => {
      setConnectionState(error.message, 'error');
    }).finally(() => {
      connectEvents();
    });
  </script>
</body>
</html>`
