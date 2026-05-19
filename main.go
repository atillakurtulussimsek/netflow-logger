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
	packet, err := decodeNetFlowV9Packet(packetBytes, a.session)
	if err != nil {
		return fmt.Errorf("netflow decode failed: %w (len=%d version=%d count=%d)", err, len(packetBytes), packetVersion(packetBytes), packetCount(packetBytes))
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
      --bg: #0b1220;
      --panel: #111827;
      --panel-2: #0f172a;
      --panel-3: #162033;
      --border: rgba(148, 163, 184, 0.16);
      --border-soft: rgba(148, 163, 184, 0.10);
      --text: #e5e7eb;
      --muted: #94a3b8;
      --muted-2: #64748b;
      --accent: #60a5fa;
      --accent-2: #22c55e;
      --warn: #f59e0b;
      --danger: #f87171;
      --shadow: 0 20px 60px rgba(2, 6, 23, 0.45);
      --radius: 22px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at top left, rgba(96,165,250,0.16), transparent 28%),
        radial-gradient(circle at top right, rgba(34,197,94,0.10), transparent 22%),
        linear-gradient(180deg, #0b1120 0%, #09101b 100%);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      padding: 32px;
    }

    .layout {
      width: min(1440px, 100%);
      margin: 0 auto;
      display: grid;
      gap: 22px;
    }

    .hero {
      background: linear-gradient(180deg, rgba(17,24,39,0.96), rgba(15,23,42,0.96));
      border: 1px solid var(--border);
      border-radius: 28px;
      box-shadow: var(--shadow);
      padding: 28px 30px;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
      flex-wrap: wrap;
    }

    .hero-left {
      display: grid;
      gap: 12px;
    }

    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      color: var(--muted);
      font-size: 13px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .eyebrow-dot {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: linear-gradient(135deg, var(--accent), #2563eb);
      box-shadow: 0 0 18px rgba(96,165,250,0.7);
    }

    h1 {
      margin: 0;
      font-size: clamp(30px, 4vw, 42px);
      line-height: 1.05;
      font-weight: 700;
      letter-spacing: -0.03em;
    }

    .hero-subtitle {
      margin: 0;
      max-width: 760px;
      color: var(--muted);
      font-size: 15px;
      line-height: 1.65;
    }

    .hero-right {
      display: grid;
      gap: 12px;
      min-width: 240px;
    }

    .status-card {
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border-soft);
      border-radius: 18px;
      padding: 16px 18px;
    }

    .status-label {
      color: var(--muted-2);
      font-size: 12px;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .status-value {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 14px;
      color: var(--text);
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 34px;
      padding: 0 12px;
      border-radius: 999px;
      background: rgba(148,163,184,0.10);
      border: 1px solid rgba(148,163,184,0.16);
      color: var(--text);
      font-size: 13px;
      font-weight: 600;
    }

    .status-badge.live {
      color: #86efac;
      border-color: rgba(34,197,94,0.24);
      background: rgba(34,197,94,0.10);
    }

    .status-badge.retry {
      color: #fcd34d;
      border-color: rgba(245,158,11,0.24);
      background: rgba(245,158,11,0.10);
    }

    .status-badge.error {
      color: #fca5a5;
      border-color: rgba(248,113,113,0.24);
      background: rgba(248,113,113,0.10);
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 18px;
    }

    .metric {
      background: linear-gradient(180deg, rgba(17,24,39,0.98), rgba(15,23,42,0.98));
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 22px;
      min-width: 0;
    }

    .metric-label {
      font-size: 12px;
      color: var(--muted-2);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 12px;
    }

    .metric-value {
      font-size: 22px;
      font-weight: 700;
      line-height: 1.3;
      letter-spacing: -0.02em;
      word-break: break-word;
    }

    .metric-note {
      margin-top: 10px;
      color: var(--muted);
      font-size: 13px;
    }

    .table-card {
      background: linear-gradient(180deg, rgba(17,24,39,0.98), rgba(15,23,42,0.98));
      border: 1px solid var(--border);
      border-radius: 28px;
      box-shadow: var(--shadow);
      overflow: hidden;
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
    }

    .table-subtitle {
      margin: 6px 0 0 0;
      color: var(--muted);
      font-size: 14px;
    }

    .table-chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(96,165,250,0.10);
      border: 1px solid rgba(96,165,250,0.20);
      color: #bfdbfe;
      font-size: 13px;
      font-weight: 600;
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
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 600;
      position: sticky;
      top: 0;
      background: rgba(15,23,42,0.96);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-soft);
      z-index: 1;
    }

    tbody td {
      padding: 16px 18px;
      border-bottom: 1px solid rgba(148,163,184,0.08);
      font-size: 14px;
      color: var(--text);
      vertical-align: middle;
    }

    tbody tr:hover td {
      background: rgba(148,163,184,0.04);
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
      color: #93c5fd;
      background: rgba(59,130,246,0.12);
      border-color: rgba(59,130,246,0.22);
    }

    .proto.udp {
      color: #86efac;
      background: rgba(34,197,94,0.12);
      border-color: rgba(34,197,94,0.22);
    }

    .proto.icmp {
      color: #fcd34d;
      background: rgba(245,158,11,0.12);
      border-color: rgba(245,158,11,0.22);
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

    @media (max-width: 1100px) {
      body { padding: 18px; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }

    @media (max-width: 720px) {
      body { padding: 12px; }
      .hero, .metric, .table-card { border-radius: 22px; }
      .metrics { grid-template-columns: 1fr; }
      .hero { padding: 22px; }
      .table-card-header { padding: 20px 20px 16px 20px; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <section class="hero">
      <div class="hero-left">
        <div class="eyebrow"><span class="eyebrow-dot"></span> NetFlow izleme paneli</div>
        <h1>Canlı ağ akış görünürlüğü</h1>
        <p class="hero-subtitle">OPNsense üzerinden gelen NetFlow v9 kayıtlarını gerçek zamanlı izle, aktif saatlik dosyayı takip et ve zaman damgası akışının durumunu tek ekranda gör.</p>
      </div>
      <div class="hero-right">
        <div class="status-card">
          <div class="status-label">Bağlantı durumu</div>
          <div class="status-value"><span class="status-badge" id="connection">Bağlanıyor</span></div>
        </div>
        <div class="status-card">
          <div class="status-label">Son güncelleme</div>
          <div class="status-value" id="updated-at">-</div>
        </div>
      </div>
    </section>

    <section class="metrics">
      <article class="metric">
        <div class="metric-label">Aktif log dosyası</div>
        <div class="metric-value" id="active-file">-</div>
        <div class="metric-note">Yazım yapılan saatlik dosya</div>
      </article>
      <article class="metric">
        <div class="metric-label">Son SHA-256</div>
        <div class="metric-value mono" id="last-sha">-</div>
        <div class="metric-note">Mühürlenen son dosyanın özeti</div>
      </article>
      <article class="metric">
        <div class="metric-label">TSA durumu</div>
        <div class="metric-value" id="last-tsa">-</div>
        <div class="metric-note">FreeTSA işlem sonucu</div>
      </article>
      <article class="metric">
        <div class="metric-label">Bellekteki kayıt</div>
        <div class="metric-value" id="record-count">0</div>
        <div class="metric-note">Gösterilen son akış kaydı sayısı</div>
      </article>
    </section>

    <section class="table-card">
      <div class="table-card-header">
        <div>
          <h2 class="table-title">Son ağ akış kayıtları</h2>
          <p class="table-subtitle">En yeni 200 kayıt, zaman ve trafik özetiyle birlikte aşağıda listelenir.</p>
        </div>
        <div class="table-chip">Canlı SSE akışı</div>
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

    function renderRows(records) {
      recordsEl.innerHTML = '';
      if (!records.length) {
        recordsEl.innerHTML = '<tr><td colspan="7" class="empty"><div class="empty-title">Henüz kayıt yok</div><div>NetFlow akışı geldiğinde son kayıtlar burada listelenecek.</div></td></tr>';
        return;
      }

      [...records].reverse().forEach((record) => {
        const item = parseRecord(record);
        const row = document.createElement('tr');
        row.innerHTML = [
          '<td class="muted-cell mono">' + escapeHtml(item.time) + '</td>',
          '<td class="mono">' + escapeHtml(item.srcIp) + '</td>',
          '<td class="mono">' + escapeHtml(item.srcPort) + '</td>',
          '<td class="mono">' + escapeHtml(item.dstIp) + '</td>',
          '<td class="mono">' + escapeHtml(item.dstPort) + '</td>',
          '<td><span class="proto ' + escapeHtml(item.protoClass) + '">' + escapeHtml(item.proto) + '</span></td>',
          '<td class="muted-cell mono">' + escapeHtml(item.size) + '</td>'
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
