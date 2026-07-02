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
	configFile              = "config.json"
)

// Tehdit tespiti eşikleri. Kayan zaman penceresi içinde tek kaynak IP'nin
// davranışına bakılır (NetFlow akış verisi payload içermez, bu yüzden tespit
// hız/desen tabanlıdır).
const (
	threatWindow          = 60 * time.Second // değerlendirme penceresi
	threatBruteforceMin   = 15               // hassas porta bu kadar akış → brute-force
	threatPortScanMin     = 20               // tek hedefte bu kadar farklı port → dikey tarama
	threatHostSweepMin    = 25               // tek portta bu kadar farklı hedef → yatay tarama
	threatAlertTTL        = 5 * time.Minute  // güncellenmeyen uyarının panelde kalma süresi
	threatMaxAlerts       = 200              // panelde tutulan azami uyarı sayısı
	threatMaxSources      = 4096             // izlenen azami kaynak IP sayısı
	threatMaxEventsPerSrc = 2000             // kaynak başına tutulan azami olay sayısı
)

// Brute-force açısından hassas kabul edilen servis portları.
var sensitiveServicePorts = map[uint16]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3",
	135: "RPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 445: "SMB",
	1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
	5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elastic",
	11211: "Memcached", 27017: "MongoDB",
}

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
	analyzer  *ThreatAnalyzer
	whitelist *Whitelist
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
	analyzer   *ThreatAnalyzer

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
	packetsTotal   uint64
	activeFile     string
	lastSHA256     string
	lastTSAStatus  string
	updatedAt      time.Time
	threats        []ThreatAlert
	clients        map[chan []byte]struct{}
}

type DashboardState struct {
	Mode            string        `json:"mode"`
	Records         []string      `json:"records"`
	UpdatedAt       string        `json:"updated_at"`
	SelectedDate    string        `json:"selected_date"`
	SelectedHour    string        `json:"selected_hour"`
	Limit           int           `json:"limit"`
	Page            int           `json:"page"`
	TotalRecords    int           `json:"total_records"`
	TotalPages      int           `json:"total_pages"`
	FileSize        string        `json:"file_size"`
	FileSizeDaily   string        `json:"file_size_daily"`
	FileSizeMonthly string        `json:"file_size_monthly"`
	FileSizeTotal   string        `json:"file_size_total"`
	AvailableDates  []string      `json:"available_dates"`
	AvailableHours  []string      `json:"available_hours"`
	ActiveFile      string        `json:"active_file,omitempty"`
	LastSHA256      string        `json:"last_sha256,omitempty"`
	LastTSAStatus   string        `json:"last_tsa_status,omitempty"`
	ProcessedTotal  uint64        `json:"processed_total"`
	PacketsTotal    uint64        `json:"packets_total"`
	Threats         []ThreatAlert `json:"threats"`
}

// ThreatAlert, panele gönderilen JSON uyarı DTO'sudur.
type ThreatAlert struct {
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	SrcIP     string `json:"src_ip"`
	Target    string `json:"target"`
	Port      uint16 `json:"port,omitempty"`
	Service   string `json:"service,omitempty"`
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Detail    string `json:"detail"`
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
	whitelist := NewWhitelist(configFile)
	analyzer := NewThreatAnalyzer(dashboard, whitelist)
	app := &App{
		cfg:       cfg,
		session:   newPersistentSession(cfg.LogRoot),
		dashboard: dashboard,
		analyzer:  analyzer,
		whitelist: whitelist,
		logger: &HourlyLogger{
			cfg:        cfg,
			httpClient: &http.Client{Timeout: 30 * time.Second},
			dashboard:  dashboard,
			analyzer:   analyzer,
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

func (h *DashboardHub) AddRecord(record string, packets uint64) {
	h.mu.Lock()
	h.records = append(h.records, record)
	if len(h.records) > h.maxRecords {
		h.records = append([]string(nil), h.records[len(h.records)-h.maxRecords:]...)
	}
	h.processedTotal++
	h.packetsTotal += packets
	h.updatedAt = time.Now()
	snapshot := h.snapshotLocked()
	h.mu.Unlock()
	h.broadcastSnapshot(snapshot)
}

// ResetHourly, saatlik log rotasyonunda çağrılır ve pps grafiğini besleyen saatlik
// paket sayacını sıfırlar. processedTotal (boşta kalma tespiti için kullanılan
// monoton sayaç) bilinçli olarak korunur.
func (h *DashboardHub) ResetHourly() {
	h.mu.Lock()
	h.packetsTotal = 0
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
		PacketsTotal:   h.packetsTotal,
		Limit:          len(records),
		Page:           1,
		TotalRecords:   len(records),
		TotalPages:     1,
		Threats:        append([]ThreatAlert(nil), h.threats...),
	}
	if !h.updatedAt.IsZero() {
		state.UpdatedAt = h.updatedAt.Format(time.RFC3339)
	}
	return state
}

// SetThreats, uyarı listesini saklar ancak yayın yapmaz; bir sonraki AddRecord
// yayını güncel uyarıları taşıyacağı için akış sırasında tekrar yayını önler.
func (h *DashboardHub) SetThreats(alerts []ThreatAlert) {
	h.mu.Lock()
	h.threats = alerts
	h.mu.Unlock()
}

// PublishThreats, uyarı listesini saklar ve hemen yayınlar; trafik olmasa bile
// (ör. uyarı zaman aşımıyla düştüğünde) panelin güncellenmesini sağlar.
func (h *DashboardHub) PublishThreats(alerts []ThreatAlert) {
	h.mu.Lock()
	h.threats = alerts
	snapshot := h.snapshotLocked()
	h.mu.Unlock()
	h.broadcastSnapshot(snapshot)
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

// flowEvent, tek bir akış gözlemidir (kayan pencere için).
type flowEvent struct {
	ts      time.Time
	dstIP   string
	dstPort uint16
}

// sourceActivity, bir kaynak IP'nin penceredeki güncel olaylarını tutar.
type sourceActivity struct {
	events   []flowEvent
	lastSeen time.Time
}

// threatAlert, analizcinin dahili uyarı kaydıdır (zaman bilgisiyle).
type threatAlert struct {
	id        string
	rule      string
	severity  string
	title     string
	srcIP     string
	target    string
	port      uint16
	service   string
	count     int
	firstSeen time.Time
	lastSeen  time.Time
	detail    string
}

// ThreatAnalyzer, akışları arka planda sürekli analiz ederek brute-force ve
// port/host tarama gibi şüpheli desenleri tespit eder.
type ThreatAnalyzer struct {
	hub       *DashboardHub
	whitelist *Whitelist

	mu      sync.Mutex
	sources map[string]*sourceActivity
	alerts  map[string]*threatAlert
}

func NewThreatAnalyzer(hub *DashboardHub, whitelist *Whitelist) *ThreatAnalyzer {
	return &ThreatAnalyzer{
		hub:       hub,
		whitelist: whitelist,
		sources:   make(map[string]*sourceActivity),
		alerts:    make(map[string]*threatAlert),
	}
}

// Observe, her akış kaydında çağrılır; kaydı kayan pencereye ekler ve kuralları
// değerlendirir. Uyarılar değiştiyse hub'a saklar (yayını eşlik eden AddRecord yapar).
func (t *ThreatAnalyzer) Observe(record FlowRecord) {
	if t == nil || record.SrcIP == "" {
		return
	}
	// Whitelist'teki kaynaklar (tekil IP ya da CIDR blok) tehdit analizinde
	// tamamen yok sayılır.
	if t.whitelist.Contains(record.SrcIP) {
		return
	}
	src := record.SrcIP
	now := time.Now()

	t.mu.Lock()
	sa := t.sources[src]
	if sa == nil {
		if len(t.sources) >= threatMaxSources {
			t.evictIdleSourceLocked(now)
		}
		sa = &sourceActivity{}
		t.sources[src] = sa
	}
	sa.events = append(sa.events, flowEvent{ts: now, dstIP: record.DstIP, dstPort: record.DstPort})
	sa.lastSeen = now
	pruneEvents(sa, now)
	if len(sa.events) > threatMaxEventsPerSrc {
		sa.events = append([]flowEvent(nil), sa.events[len(sa.events)-threatMaxEventsPerSrc:]...)
	}

	changed := t.evaluateLocked(src, sa, now)
	var snapshot []ThreatAlert
	if changed {
		snapshot = t.snapshotAlertsLocked()
	}
	t.mu.Unlock()

	if changed {
		t.hub.SetThreats(snapshot)
	}
}

// Maintain, arka planda periyodik olarak çağrılır; boşta kalan kaynakları ve
// zaman aşımına uğrayan uyarıları temizler, değişiklik varsa hemen yayınlar.
func (t *ThreatAnalyzer) Maintain() {
	if t == nil {
		return
	}
	now := time.Now()

	t.mu.Lock()
	for src, sa := range t.sources {
		pruneEvents(sa, now)
		if len(sa.events) == 0 && now.Sub(sa.lastSeen) > threatWindow {
			delete(t.sources, src)
		}
	}
	changed := false
	for id, a := range t.alerts {
		if now.Sub(a.lastSeen) > threatAlertTTL {
			delete(t.alerts, id)
			changed = true
		}
	}
	var snapshot []ThreatAlert
	if changed {
		snapshot = t.snapshotAlertsLocked()
	}
	t.mu.Unlock()

	if changed {
		t.hub.PublishThreats(snapshot)
	}
}

// PurgeWhitelisted, whitelist'e yeni eklenen bir kaynağa ait izlenen olayları ve
// aktif uyarıları temizler; değişiklik olduysa paneli anında günceller. Böylece
// bir IP whitelist'e alındığında mevcut uyarısı da hemen kaybolur.
func (t *ThreatAnalyzer) PurgeWhitelisted() {
	if t == nil {
		return
	}
	t.mu.Lock()
	for src := range t.sources {
		if t.whitelist.Contains(src) {
			delete(t.sources, src)
		}
	}
	changed := false
	for id, a := range t.alerts {
		if t.whitelist.Contains(a.srcIP) {
			delete(t.alerts, id)
			changed = true
		}
	}
	var snapshot []ThreatAlert
	if changed {
		snapshot = t.snapshotAlertsLocked()
	}
	t.mu.Unlock()

	if changed {
		t.hub.PublishThreats(snapshot)
	}
}

// evaluateLocked, kaynağın penceredeki olaylarını üç kural açısından değerlendirir.
func (t *ThreatAnalyzer) evaluateLocked(src string, sa *sourceActivity, now time.Time) bool {
	type portAgg struct {
		count   int
		ipCount map[string]int
	}
	portMap := make(map[uint16]*portAgg)            // hedef port → toplam akış + farklı hedef IP'ler
	portsPerDst := make(map[string]map[uint16]bool) // hedef IP → farklı portlar

	for _, e := range sa.events {
		pa := portMap[e.dstPort]
		if pa == nil {
			pa = &portAgg{ipCount: make(map[string]int)}
			portMap[e.dstPort] = pa
		}
		pa.count++
		pa.ipCount[e.dstIP]++

		ps := portsPerDst[e.dstIP]
		if ps == nil {
			ps = make(map[uint16]bool)
			portsPerDst[e.dstIP] = ps
		}
		ps[e.dstPort] = true
	}

	windowSec := int(threatWindow.Seconds())
	changed := false

	// Kural 1 — Brute-force / servis flood: hassas bir porta çok sayıda akış.
	for port, pa := range portMap {
		svc, sensitive := sensitiveServicePorts[port]
		if !sensitive || pa.count < threatBruteforceMin {
			continue
		}
		target, hostN := dominantTarget(pa.ipCount)
		var detail string
		if hostN > 1 {
			detail = fmt.Sprintf("%s son %d sn içinde %d hedefte %s (%d) portuna %d bağlantı denemesi yaptı.",
				src, windowSec, hostN, svc, port, pa.count)
		} else {
			detail = fmt.Sprintf("%s son %d sn içinde %s:%d hedefine %d bağlantı denemesi yaptı.",
				src, windowSec, target, port, pa.count)
		}
		if t.upsertLocked(&threatAlert{
			id:       src + "|bruteforce|" + strconv.Itoa(int(port)),
			rule:     "bruteforce",
			severity: "high",
			title:    svc + " brute-force denemesi",
			srcIP:    src,
			target:   target,
			port:     port,
			service:  svc,
			count:    pa.count,
			detail:   detail,
		}, now) {
			changed = true
		}
	}

	// Kural 2 — Dikey port tarama: tek hedefte çok sayıda farklı port.
	for dstIP, ports := range portsPerDst {
		if len(ports) < threatPortScanMin {
			continue
		}
		if t.upsertLocked(&threatAlert{
			id:       src + "|portscan|" + dstIP,
			rule:     "portscan",
			severity: "medium",
			title:    "Dikey port tarama",
			srcIP:    src,
			target:   dstIP,
			count:    len(ports),
			detail: fmt.Sprintf("%s son %d sn içinde %s üzerinde %d farklı porta erişti.",
				src, windowSec, dstIP, len(ports)),
		}, now) {
			changed = true
		}
	}

	// Kural 3 — Yatay host tarama: tek portu çok sayıda farklı hedefte deneme.
	for port, pa := range portMap {
		if len(pa.ipCount) < threatHostSweepMin {
			continue
		}
		svc := sensitiveServicePorts[port]
		if t.upsertLocked(&threatAlert{
			id:       src + "|hostsweep|" + strconv.Itoa(int(port)),
			rule:     "hostsweep",
			severity: "medium",
			title:    "Yatay host tarama",
			srcIP:    src,
			target:   strconv.Itoa(len(pa.ipCount)) + " host",
			port:     port,
			service:  svc,
			count:    len(pa.ipCount),
			detail: fmt.Sprintf("%s son %d sn içinde %s portunu %d farklı hedefte taradı.",
				src, windowSec, portLabel(port), len(pa.ipCount)),
		}, now) {
			changed = true
		}
	}

	return changed
}

// upsertLocked, uyarıyı ekler ya da mevcut olanı günceller. Yeni uyarı veya
// sayacın artması "değişiklik" sayılır (yayın tetikler).
func (t *ThreatAnalyzer) upsertLocked(a *threatAlert, now time.Time) bool {
	if existing := t.alerts[a.id]; existing != nil {
		grew := a.count > existing.count
		existing.count = a.count
		existing.target = a.target
		existing.detail = a.detail
		existing.severity = a.severity
		existing.lastSeen = now
		return grew
	}
	a.firstSeen = now
	a.lastSeen = now
	if len(t.alerts) >= threatMaxAlerts {
		t.evictOldestAlertLocked()
	}
	t.alerts[a.id] = a
	return true
}

func (t *ThreatAnalyzer) snapshotAlertsLocked() []ThreatAlert {
	list := make([]*threatAlert, 0, len(t.alerts))
	for _, a := range t.alerts {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].severity != list[j].severity {
			return severityRank(list[i].severity) > severityRank(list[j].severity)
		}
		return list[i].lastSeen.After(list[j].lastSeen)
	})
	out := make([]ThreatAlert, 0, len(list))
	for _, a := range list {
		out = append(out, ThreatAlert{
			Rule:      a.rule,
			Severity:  a.severity,
			Title:     a.title,
			SrcIP:     a.srcIP,
			Target:    a.target,
			Port:      a.port,
			Service:   a.service,
			Count:     a.count,
			FirstSeen: a.firstSeen.Format(time.RFC3339),
			LastSeen:  a.lastSeen.Format(time.RFC3339),
			Detail:    a.detail,
		})
	}
	return out
}

func (t *ThreatAnalyzer) evictOldestAlertLocked() {
	var oldestID string
	var oldest time.Time
	for id, a := range t.alerts {
		if oldestID == "" || a.lastSeen.Before(oldest) {
			oldestID = id
			oldest = a.lastSeen
		}
	}
	if oldestID != "" {
		delete(t.alerts, oldestID)
	}
}

func (t *ThreatAnalyzer) evictIdleSourceLocked(now time.Time) {
	var oldestSrc string
	var oldest time.Time
	for src, sa := range t.sources {
		if oldestSrc == "" || sa.lastSeen.Before(oldest) {
			oldestSrc = src
			oldest = sa.lastSeen
		}
	}
	if oldestSrc != "" {
		delete(t.sources, oldestSrc)
	}
}

func pruneEvents(sa *sourceActivity, now time.Time) {
	cutoff := now.Add(-threatWindow)
	idx := 0
	for idx < len(sa.events) && sa.events[idx].ts.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		sa.events = append([]flowEvent(nil), sa.events[idx:]...)
	}
}

// appConfig, config.json'un tamamını temsil eder. İleride yeni ayarlar
// eklendiğinde bu yapıya alan eklenmesi yeterlidir.
type appConfig struct {
	SourceIPWhitelist []string `json:"source_ip_whitelist"`
}

// Whitelist, tehdit analizinde görmezden gelinecek kaynak IP adreslerini ve CIDR
// bloklarını tutar. Girişler config.json içinde kalıcı olarak saklanır ve süreç
// yeniden başlatıldığında geri yüklenir.
type Whitelist struct {
	path string

	mu      sync.RWMutex
	entries []string     // kullanıcının eklediği sırayla normalize edilmiş girişler
	ips     map[string]struct{}
	nets    []*net.IPNet
}

// NewWhitelist, verilen config.json yolundan whitelist'i yükler (yoksa boş başlar).
func NewWhitelist(path string) *Whitelist {
	w := &Whitelist{
		path: path,
		ips:  make(map[string]struct{}),
	}
	w.load()
	return w
}

// load, config.json'daki whitelist girişlerini okuyup dahili indeksleri kurar.
func (w *Whitelist) load() {
	data, err := os.ReadFile(w.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("config read failed: %v", err)
		}
		return
	}
	var cfg appConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("config parse failed: %v", err)
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, raw := range cfg.SourceIPWhitelist {
		norm, err := normalizeWhitelistEntry(raw)
		if err != nil {
			log.Printf("config: geçersiz whitelist girişi atlandı %q: %v", raw, err)
			continue
		}
		w.addNormalizedLocked(norm)
	}
}

// Contains, verilen IP adresinin whitelist'te (tekil ya da bir CIDR blok içinde)
// olup olmadığını döndürür.
func (w *Whitelist) Contains(ipStr string) bool {
	if w == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if _, ok := w.ips[ip.String()]; ok {
		return true
	}
	for _, n := range w.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Entries, mevcut whitelist girişlerinin kopyasını (eklenme sırasıyla) döndürür.
func (w *Whitelist) Entries() []string {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]string(nil), w.entries...)
}

// Add, bir IP adresi veya CIDR bloğunu whitelist'e ekler. Giriş normalize edilir,
// doğrulanır ve kalıcı olarak kaydedilir. Zaten mevcutsa sessizce başarılı olur.
func (w *Whitelist) Add(entry string) error {
	norm, err := normalizeWhitelistEntry(entry)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.addNormalizedLocked(norm) {
		w.persistLocked()
	}
	return nil
}

// Remove, bir girişi whitelist'ten kaldırır. Giriş normalize edilerek eşleştirilir.
func (w *Whitelist) Remove(entry string) error {
	norm, err := normalizeWhitelistEntry(entry)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	idx := -1
	for i, e := range w.entries {
		if e == norm {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	w.entries = append(w.entries[:idx], w.entries[idx+1:]...)
	w.rebuildLocked()
	w.persistLocked()
	return nil
}

// addNormalizedLocked, normalize edilmiş bir girişi ekler; yeni eklendiyse true
// döndürür (w.mu kilitli olmalı).
func (w *Whitelist) addNormalizedLocked(norm string) bool {
	for _, e := range w.entries {
		if e == norm {
			return false
		}
	}
	w.entries = append(w.entries, norm)
	w.indexEntryLocked(norm)
	return true
}

// indexEntryLocked, tek bir girişi arama indekslerine ekler (w.mu kilitli olmalı).
func (w *Whitelist) indexEntryLocked(norm string) {
	if strings.Contains(norm, "/") {
		if _, ipnet, err := net.ParseCIDR(norm); err == nil {
			w.nets = append(w.nets, ipnet)
		}
		return
	}
	if ip := net.ParseIP(norm); ip != nil {
		w.ips[ip.String()] = struct{}{}
	}
}

// rebuildLocked, arama indekslerini entries listesinden yeniden kurar (w.mu kilitli olmalı).
func (w *Whitelist) rebuildLocked() {
	w.ips = make(map[string]struct{})
	w.nets = nil
	for _, e := range w.entries {
		w.indexEntryLocked(e)
	}
}

// persistLocked, whitelist'i config.json'a atomik biçimde yazar (w.mu kilitli olmalı).
func (w *Whitelist) persistLocked() {
	cfg := appConfig{SourceIPWhitelist: append([]string(nil), w.entries...)}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Printf("config marshal failed: %v", err)
		return
	}
	if dir := filepath.Dir(w.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("config dir create failed: %v", err)
			return
		}
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Printf("config write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, w.path); err != nil {
		log.Printf("config rename failed: %v", err)
	}
}

// normalizeWhitelistEntry, bir IP veya CIDR girişini doğrular ve kanonik biçimine
// dönüştürür. Geçersizse Türkçe bir hata döndürür.
func normalizeWhitelistEntry(entry string) (string, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", errors.New("boş giriş")
	}
	if strings.Contains(entry, "/") {
		_, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			return "", fmt.Errorf("geçersiz CIDR bloğu: %s", entry)
		}
		return ipnet.String(), nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return "", fmt.Errorf("geçersiz IP adresi: %s", entry)
	}
	return ip.String(), nil
}

// dominantTarget, en çok hedeflenen IP'yi ve farklı hedef sayısını döndürür.
func dominantTarget(ipCount map[string]int) (string, int) {
	best := ""
	bestN := -1
	for ip, n := range ipCount {
		if n > bestN {
			best = ip
			bestN = n
		}
	}
	return best, len(ipCount)
}

func portLabel(port uint16) string {
	if svc, ok := sensitiveServicePorts[port]; ok {
		return fmt.Sprintf("%s (%d)", svc, port)
	}
	return strconv.Itoa(int(port))
}

func severityRank(sev string) int {
	switch sev {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
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

	// Tehdit analizcisinin bakım döngüsü: boşta kalan kaynakları ve süresi dolan
	// uyarıları arka planda periyodik olarak temizler.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.analyzer.Maintain()
			}
		}
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
	mux.Handle("/api/whitelist", a.basicAuth(http.HandlerFunc(a.handleWhitelist)))
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

// handleWhitelist, kaynak IP whitelist'ini yönetir: GET listeler, POST tekil giriş
// ekler, DELETE (entry sorgu parametresiyle) siler. Her değişiklik config.json'a
// kalıcı yazılır ve tehdit analizcisi güncellenir.
func (a *App) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeWhitelist(w)
	case http.MethodPost:
		var body struct {
			Entry string `json:"entry"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, "geçersiz istek gövdesi", http.StatusBadRequest)
			return
		}
		if err := a.whitelist.Add(body.Entry); err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.analyzer.PurgeWhitelisted()
		a.writeWhitelist(w)
	case http.MethodDelete:
		if err := a.whitelist.Remove(r.URL.Query().Get("entry")); err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.writeWhitelist(w)
	default:
		writeJSONError(w, "desteklenmeyen metot", http.StatusMethodNotAllowed)
	}
}

func (a *App) writeWhitelist(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string][]string{"entries": a.whitelist.Entries()})
}

func writeJSONError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
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

	h.analyzer.Observe(record)

	line := formatFlowRecord(record)
	if _, err := h.file.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("write log line failed: %w", err)
	}
	if err := h.file.Sync(); err != nil {
		return fmt.Errorf("sync log file failed: %w", err)
	}

	h.dashboard.AddRecord(line, record.Packets)
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
	// Yeni saate geçişte pps grafiğini besleyen saatlik paket sayacını sıfırla.
	h.dashboard.ResetHourly()
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

    .status-ribbon {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 4px 2px;
      padding: 8px 12px;
      border-radius: 14px;
      background: linear-gradient(180deg, rgba(8,12,22,0.7), rgba(6,9,18,0.78));
      border: 1px solid var(--border-soft);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
    }

    .ribbon-item {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      min-width: 0;
      padding: 2px 8px;
    }

    .ribbon-conn { padding-left: 2px; }

    .ribbon-item .status-badge,
    .ribbon-item .seal-badge {
      min-height: 26px;
    }

    .ribbon-item .status-badge {
      padding: 0 12px;
      font-size: 12px;
    }

    .ribbon-ico {
      width: 15px;
      height: 15px;
      flex-shrink: 0;
      color: var(--accent);
      opacity: 0.82;
    }

    .ribbon-label {
      color: var(--muted-2);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 600;
      white-space: nowrap;
    }

    .ribbon-value {
      color: var(--text);
      font-size: 12px;
      font-weight: 600;
      font-variant-numeric: tabular-nums;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .ribbon-file { flex: 1 1 auto; min-width: 100px; }
    .ribbon-file .ribbon-value {
      max-width: 100%;
      color: var(--neon-blue);
      text-shadow: 0 0 8px rgba(56,189,248,0.3);
    }

    .ribbon-sep {
      width: 1px;
      height: 18px;
      flex-shrink: 0;
      background: linear-gradient(180deg, transparent, rgba(148,163,184,0.28), transparent);
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

    .stat-card.sizes { gap: 10px; grid-column: span 2; }

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

    /* Ribbon tehdit rozeti */
    .threat-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 24px;
      min-height: 22px;
      padding: 0 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
      color: var(--neon-green);
      background: rgba(43,255,136,0.12);
      border: 1px solid rgba(43,255,136,0.4);
      transition: 0.2s ease;
    }

    .threat-badge.active {
      color: #fff;
      background: rgba(255,93,122,0.22);
      border-color: var(--danger);
      box-shadow: 0 0 10px rgba(255,93,122,0.5), 0 0 22px rgba(255,93,122,0.28);
      animation: threatPulse 1.5s ease-out infinite;
    }

    @keyframes threatPulse {
      0%   { box-shadow: 0 0 0 0 rgba(255,93,122,0.5), 0 0 12px rgba(255,93,122,0.7); }
      70%  { box-shadow: 0 0 0 8px rgba(255,93,122,0), 0 0 12px rgba(255,93,122,0.7); }
      100% { box-shadow: 0 0 0 0 rgba(255,93,122,0), 0 0 12px rgba(255,93,122,0.7); }
    }

    /* Güvenlik izleme paneli */
    .threat-card {
      position: relative;
      background: linear-gradient(180deg, rgba(11,15,27,0.82), rgba(7,10,20,0.86));
      border: 1px solid var(--border-soft);
      border-radius: 22px;
      box-shadow: var(--shadow), 0 0 24px rgba(43,255,136,0.06);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      padding: 18px 22px 20px 22px;
      transition: border-color 0.25s ease, box-shadow 0.25s ease;
    }

    .threat-card.has-threats {
      border-color: rgba(255,93,122,0.42);
      box-shadow: var(--shadow), 0 0 30px rgba(255,93,122,0.14);
    }

    .threat-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      flex-wrap: wrap;
    }

    .threat-heading {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }

    .threat-mark {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 38px;
      height: 38px;
      flex-shrink: 0;
      border-radius: 12px;
      color: var(--neon-green);
      background: rgba(43,255,136,0.10);
      border: 1px solid rgba(43,255,136,0.32);
      box-shadow: inset 0 0 12px rgba(43,255,136,0.10);
    }

    .threat-card.has-threats .threat-mark {
      color: var(--danger);
      background: rgba(255,93,122,0.12);
      border-color: rgba(255,93,122,0.38);
      box-shadow: inset 0 0 12px rgba(255,93,122,0.12);
    }

    .threat-mark svg { width: 21px; height: 21px; }

    .threat-title {
      margin: 0;
      display: flex;
      align-items: center;
      gap: 9px;
      font-size: 16px;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: #fff;
    }

    .threat-count {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 22px;
      padding: 1px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      color: #fff;
      background: rgba(255,93,122,0.22);
      border: 1px solid var(--danger);
      box-shadow: 0 0 10px rgba(255,93,122,0.4);
    }

    .threat-subtitle {
      margin: 3px 0 0 0;
      font-size: 12px;
      color: var(--muted);
    }

    .threat-status {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }

    .threat-status.ok {
      color: var(--neon-green);
      background: rgba(43,255,136,0.10);
      border: 1px solid rgba(43,255,136,0.35);
    }

    .threat-status.alert {
      color: #fff;
      background: rgba(255,93,122,0.20);
      border: 1px solid var(--danger);
      box-shadow: 0 0 12px rgba(255,93,122,0.35);
    }

    .threat-list {
      display: grid;
      gap: 10px;
      margin-top: 16px;
    }

    .threat-empty {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 14px 4px 6px 4px;
      color: var(--muted);
      font-size: 13px;
    }

    .threat-empty svg { width: 20px; height: 20px; color: var(--neon-green); flex-shrink: 0; }
    .threat-empty[hidden], .threat-count[hidden] { display: none; }

    .threat-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(148,163,184,0.10);
      border-left-width: 3px;
    }

    .threat-item.high {
      border-color: rgba(255,93,122,0.16);
      border-left-color: var(--danger);
      background: linear-gradient(180deg, rgba(255,93,122,0.07), rgba(255,255,255,0.01));
    }

    .threat-item.medium {
      border-color: rgba(255,176,32,0.16);
      border-left-color: var(--neon-amber);
      background: linear-gradient(180deg, rgba(255,176,32,0.06), rgba(255,255,255,0.01));
    }

    .threat-sev {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      min-width: 58px;
      padding: 4px 9px;
      border-radius: 999px;
      font-size: 10px;
      font-weight: 800;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }

    .threat-item.high .threat-sev {
      color: #fff;
      background: rgba(255,93,122,0.22);
      border: 1px solid var(--danger);
      box-shadow: 0 0 10px rgba(255,93,122,0.35);
    }

    .threat-item.medium .threat-sev {
      color: #1c1407;
      background: var(--neon-amber);
      border: 1px solid var(--neon-amber);
      box-shadow: 0 0 10px rgba(255,176,32,0.35);
    }

    .threat-body { min-width: 0; flex: 1; }

    .threat-item-title {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      font-size: 14px;
      font-weight: 700;
      color: var(--text);
    }

    .threat-hits {
      font-size: 11px;
      font-weight: 700;
      color: var(--neon-amber);
      font-variant-numeric: tabular-nums;
      padding: 1px 7px;
      border-radius: 999px;
      background: rgba(255,176,32,0.10);
      border: 1px solid rgba(255,176,32,0.30);
    }

    .threat-item.high .threat-hits {
      color: #ffb4c2;
      background: rgba(255,93,122,0.12);
      border-color: rgba(255,93,122,0.32);
    }

    .threat-meta {
      margin-top: 4px;
      font-size: 12px;
      color: var(--muted);
      line-height: 1.5;
    }

    .threat-meta .mono {
      color: var(--neon-blue);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }

    .threat-time {
      flex-shrink: 0;
      font-size: 11px;
      color: var(--muted-2);
      font-variant-numeric: tabular-nums;
      white-space: nowrap;
      padding-top: 2px;
    }

    /* Güvenlik uyarıları — üst kontrol butonu */
    .threat-toggle {
      gap: 8px;
      position: relative;
    }

    .threat-toggle svg {
      width: 16px;
      height: 16px;
    }

    .threat-toggle-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 20px;
      height: 20px;
      padding: 0 6px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      font-variant-numeric: tabular-nums;
      color: #fff;
      background: rgba(255,93,122,0.9);
      border: 1px solid var(--danger);
    }

    .threat-toggle-badge[hidden] { display: none; }

    .threat-toggle.active {
      color: #fff;
      border-color: var(--danger);
      background: rgba(255,93,122,0.16);
      box-shadow: 0 0 10px rgba(255,93,122,0.4);
      animation: threatPulse 1.5s ease-out infinite;
    }

    .threat-toggle.active:hover {
      color: #fff;
      border-color: var(--danger);
      background: rgba(255,93,122,0.24);
      box-shadow: 0 0 12px rgba(255,93,122,0.5);
    }

    /* Güvenlik uyarıları — açılır modal */
    .threat-modal {
      position: fixed;
      inset: 0;
      z-index: 120;
      display: flex;
      align-items: flex-start;
      justify-content: center;
      padding: 7vh 20px 24px 20px;
      overflow-y: auto;
    }

    .threat-modal[hidden] { display: none; }

    .threat-modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(4,7,14,0.66);
      backdrop-filter: blur(6px);
      -webkit-backdrop-filter: blur(6px);
      animation: threatFade 0.2s ease;
    }

    .threat-modal-panel {
      position: relative;
      width: 100%;
      max-width: 720px;
      margin: 0 auto;
      animation: threatPop 0.22s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .threat-close {
      position: absolute;
      top: 16px;
      right: 16px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 10px;
      color: var(--muted);
      background: rgba(148,163,184,0.08);
      border: 1px solid rgba(148,163,184,0.18);
      cursor: pointer;
      transition: 0.2s ease;
    }

    .threat-close svg { width: 16px; height: 16px; }

    .threat-close:hover {
      color: #fff;
      border-color: rgba(255,93,122,0.5);
      background: rgba(255,93,122,0.16);
    }

    .threat-modal .threat-list {
      max-height: 62vh;
      overflow-y: auto;
    }

    @keyframes threatFade {
      from { opacity: 0; }
      to   { opacity: 1; }
    }

    @keyframes threatPop {
      from { opacity: 0; transform: translateY(-12px) scale(0.98); }
      to   { opacity: 1; transform: none; }
    }

    /* Whitelist — görmezden gelinen kaynaklar bölümü */
    .whitelist-section {
      margin-top: 20px;
      padding-top: 18px;
      border-top: 1px solid var(--border-soft);
    }

    .whitelist-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
      font-weight: 700;
      color: #fff;
    }

    .whitelist-title svg {
      width: 17px;
      height: 17px;
      color: var(--neon-green);
      flex-shrink: 0;
    }

    .whitelist-sub {
      margin: 5px 0 0 0;
      font-size: 12px;
      line-height: 1.55;
      color: var(--muted);
    }

    .whitelist-sub .mono {
      color: var(--neon-blue);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }

    .whitelist-form {
      display: flex;
      gap: 8px;
      margin-top: 14px;
    }

    .whitelist-input {
      flex: 1;
      min-width: 0;
      min-height: 42px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(7,10,20,0.9);
      color: var(--text);
      padding: 0 14px;
      font-size: 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      outline: none;
      transition: 0.18s ease;
    }

    .whitelist-input::placeholder { color: var(--muted-2); }
    .whitelist-input:hover { border-color: rgba(34,211,238,0.4); }
    .whitelist-input:focus {
      border-color: var(--neon-cyan);
      box-shadow: 0 0 0 3px rgba(34,211,238,0.18), var(--glow-cyan);
    }

    .whitelist-add {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 42px;
      padding: 0 18px;
      border-radius: 14px;
      border: 1px solid var(--neon-green);
      background: var(--neon-green);
      color: #052e16;
      font-size: 13px;
      font-weight: 700;
      cursor: pointer;
      white-space: nowrap;
      transition: 0.18s ease;
    }

    .whitelist-add:hover { box-shadow: var(--glow-green); }

    .whitelist-error {
      margin-top: 10px;
      padding: 9px 12px;
      border-radius: 12px;
      font-size: 12px;
      color: #ffb4c2;
      background: rgba(255,93,122,0.1);
      border: 1px solid rgba(255,93,122,0.32);
    }

    .whitelist-error[hidden] { display: none; }

    .whitelist-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
    }

    .whitelist-empty {
      font-size: 12px;
      color: var(--muted-2);
    }

    .whitelist-chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 8px 6px 12px;
      border-radius: 999px;
      background: rgba(148,163,184,0.08);
      border: 1px solid rgba(148,163,184,0.18);
      font-size: 13px;
      font-weight: 600;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      color: var(--text);
    }

    .whitelist-chip.cidr {
      color: #ccfbff;
      border-color: rgba(34,211,238,0.32);
      background: rgba(34,211,238,0.08);
    }

    .whitelist-remove {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 20px;
      height: 20px;
      border-radius: 999px;
      border: none;
      background: rgba(148,163,184,0.14);
      color: var(--muted);
      cursor: pointer;
      transition: 0.15s ease;
    }

    .whitelist-remove:hover {
      background: rgba(255,93,122,0.2);
      color: #fff;
    }

    .whitelist-remove svg { width: 12px; height: 12px; }

    @media (prefers-reduced-motion: reduce) {
      .threat-badge.active { animation: none; }
      .threat-toggle.active { animation: none; }
      .threat-modal-backdrop,
      .threat-modal-panel { animation: none; }
    }

    @media (max-width: 560px) {
      .threat-item { flex-wrap: wrap; }
      .threat-time { width: 100%; padding-top: 0; }
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

    .cell-proto { white-space: nowrap; }
    .proto { cursor: default; }
    .proto.svc { min-width: 64px; }
    .proto .lock {
      width: 11px;
      height: 11px;
      margin-right: 4px;
      flex-shrink: 0;
      opacity: 0.9;
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
      .ribbon-file { flex-basis: 100%; }
    }

    @media (max-width: 560px) {
      .hero-grid { grid-template-columns: 1fr; }
      .stat-card.sizes { grid-column: auto; }
      .file-sizes-grid { grid-template-columns: repeat(2, 1fr); }
      .status-ribbon { gap: 6px 4px; }
      .ribbon-sep { display: none; }
      .ribbon-item { flex-basis: calc(50% - 4px); }
      .ribbon-conn { flex-basis: 100%; }
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
          <button type="button" class="mode-button live" id="live-toggle">Canlı SSE akışı</button>
          <button type="button" class="mode-button threat-toggle" id="threat-toggle" aria-haspopup="dialog" aria-expanded="false" title="Güvenlik uyarılarını göster">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5z"/><path d="M12 8v4"/><path d="M12 16h.01"/>
            </svg>
            <span>Güvenlik uyarıları</span>
            <span class="threat-toggle-badge" id="threat-toggle-count" hidden>0</span>
          </button>
        </div>
      </div>

      <div class="status-ribbon" role="status" aria-live="polite">
        <span class="ribbon-item ribbon-conn">
          <span class="status-badge" id="connection">Bağlanıyor</span>
        </span>
        <span class="ribbon-sep" aria-hidden="true"></span>
        <span class="ribbon-item">
          <svg class="ribbon-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>
          </svg>
          <span class="ribbon-label">Son güncelleme</span>
          <span class="ribbon-value mono" id="updated-at">-</span>
        </span>
        <span class="ribbon-sep" aria-hidden="true"></span>
        <span class="ribbon-item ribbon-file">
          <svg class="ribbon-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M14 3v5h5"/><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/>
          </svg>
          <span class="ribbon-label">Aktif dosya</span>
          <span class="ribbon-value mono" id="active-file" title="Aktif log dosyası">-</span>
        </span>
        <span class="ribbon-sep" aria-hidden="true"></span>
        <span class="ribbon-item">
          <svg class="ribbon-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/>
          </svg>
          <span class="ribbon-label">Bütünlük</span>
          <span class="seal-badge" id="seal-badge">Bekliyor</span>
        </span>
        <span class="ribbon-sep" aria-hidden="true"></span>
        <span class="ribbon-item">
          <svg class="ribbon-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5z"/><path d="M12 8v4"/><path d="M12 16h.01"/>
          </svg>
          <span class="ribbon-label">Tehdit</span>
          <span class="threat-badge" id="threat-badge">0</span>
        </span>
      </div>

      <div class="hero-grid">
        <div class="stat-card accent">
          <div class="stat-head">
            <span class="status-label">Akış hızı</span>
            <span class="live-dot" id="rate-dot" aria-hidden="true"></span>
          </div>
          <div class="stat-main">
            <span class="stat-number" id="throughput-rate">0</span>
            <span class="stat-unit">pps</span>
          </div>
          <div class="rate-chart" title="Son 2 dakikalık paket akış hızı (paket/sn)">
            <canvas id="rate-spark"></canvas>
            <span class="rate-chart-peak" id="rate-peak">tepe 0</span>
            <span class="rate-chart-span">son 2 dk</span>
          </div>
        </div>

        <div class="stat-card integrity">
          <div class="stat-head">
            <span class="status-label">Bütünlük mührü</span>
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

    <div class="threat-modal" id="threat-modal" hidden>
      <div class="threat-modal-backdrop" data-threat-close></div>
      <section class="threat-card threat-modal-panel" id="threat-card" role="dialog" aria-modal="true" aria-labelledby="threat-modal-title">
        <button type="button" class="threat-close" data-threat-close aria-label="Güvenlik panelini kapat">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
          </svg>
        </button>
        <div class="threat-header">
          <div class="threat-heading">
            <span class="threat-mark" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5z"/><path d="M12 8v4"/><path d="M12 16h.01"/>
              </svg>
            </span>
            <div>
              <h2 class="threat-title" id="threat-modal-title">Güvenlik izleme
                <span class="threat-count" id="threat-count" hidden>0</span>
              </h2>
              <p class="threat-subtitle">Akış trafiği arka planda sürekli analiz edilir; brute-force ve port/host tarama denemeleri tespit edilir.</p>
            </div>
          </div>
          <span class="threat-status ok" id="threat-status">Şüpheli aktivite yok</span>
        </div>
        <div class="threat-list" id="threat-list">
          <div class="threat-empty" id="threat-empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5z"/><path d="M9 12l2 2 4-4"/>
            </svg>
            <span>Şu an şüpheli bir aktivite tespit edilmedi.</span>
          </div>
        </div>

        <div class="whitelist-section">
          <div class="whitelist-head">
            <span class="whitelist-title">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="9"/>
              </svg>
              Görmezden gelinen kaynaklar
            </span>
            <p class="whitelist-sub">Buraya eklenen kaynak IP adresleri veya CIDR blokları (ör. <span class="mono">10.0.0.0/24</span>) tehdit analizinde tamamen yok sayılır. Ayarlar <span class="mono">config.json</span> içinde kalıcı tutulur.</p>
          </div>
          <form class="whitelist-form" id="whitelist-form" autocomplete="off">
            <input type="text" class="whitelist-input" id="whitelist-input" placeholder="192.168.1.10 veya 10.0.0.0/24" spellcheck="false" aria-label="Whitelist girişi" />
            <button type="submit" class="whitelist-add">Ekle</button>
          </form>
          <div class="whitelist-error" id="whitelist-error" role="alert" hidden></div>
          <div class="whitelist-list" id="whitelist-list">
            <div class="whitelist-empty" id="whitelist-empty">Henüz görmezden gelinen kaynak eklenmedi.</div>
          </div>
        </div>
      </section>
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
    const threatCardEl = document.getElementById('threat-card');
    const threatListEl = document.getElementById('threat-list');
    const threatEmptyEl = document.getElementById('threat-empty');
    const threatCountEl = document.getElementById('threat-count');
    const threatStatusEl = document.getElementById('threat-status');
    const threatBadgeEl = document.getElementById('threat-badge');
    const threatModalEl = document.getElementById('threat-modal');
    const threatToggleEl = document.getElementById('threat-toggle');
    const threatToggleCountEl = document.getElementById('threat-toggle-count');
    const whitelistFormEl = document.getElementById('whitelist-form');
    const whitelistInputEl = document.getElementById('whitelist-input');
    const whitelistErrorEl = document.getElementById('whitelist-error');
    const whitelistListEl = document.getElementById('whitelist-list');
    const whitelistEmptyEl = document.getElementById('whitelist-empty');

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

    // pps her zaman tam sayı olarak gösterilir; binlik ayırıcıyla biçimlenir.
    function formatRate(value) {
      return numberFmt.format(Math.max(0, Math.round(value)));
    }

    function basename(path) {
      if (!path) return '';
      const clean = String(path).replace(/[\\/]+$/, '');
      const idx = Math.max(clean.lastIndexOf('/'), clean.lastIndexOf('\\'));
      return idx >= 0 ? clean.slice(idx + 1) : clean;
    }

    // Akış hızı, saatlik sıfırlanan toplam paket sayacının (packets_total) türevinden
    // pps (paket/sn) olarak hesaplanır. Saat dönümünde sayaç sıfırlandığında (total
    // düşer) baz değer yenilenir; o örnek atlanır, böylece sahte bir sıçrama olmaz.
    function updateThroughput(state) {
      const total = Number(state.packets_total);
      if (!Number.isFinite(total)) return;

      const now = performance.now();
      if (lastProcessed !== null && total < lastProcessed) {
        // Saatlik sıfırlama: bazı yeniden hizala, hızı koru.
        lastProcessed = total;
        lastProcessedAt = now;
        return;
      }
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
      rateDotEl.classList.toggle('active', rateEma >= 1);
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
      activeFileEl.textContent = basename(file) || '-';
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

    // Yaygın (well-known) portlar → servis adı eşlemesi. Yalnızca arayüzde
    // gösterim amaçlı; log dosyalarına yazılmaz.
    const PORT_SERVICES = {
      20: 'FTP', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
      43: 'WHOIS', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
      80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 111: 'RPC', 119: 'NNTP',
      123: 'NTP', 135: 'RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS',
      143: 'IMAP', 161: 'SNMP', 162: 'SNMP', 179: 'BGP', 194: 'IRC',
      389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'IKE',
      514: 'Syslog', 515: 'LPD', 520: 'RIP', 546: 'DHCPv6', 547: 'DHCPv6',
      587: 'SMTP', 623: 'IPMI', 636: 'LDAPS', 853: 'DoT', 873: 'rsync',
      989: 'FTPS', 990: 'FTPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS',
      1194: 'OpenVPN', 1433: 'MSSQL', 1521: 'Oracle', 1701: 'L2TP',
      1723: 'PPTP', 1812: 'RADIUS', 1813: 'RADIUS', 1883: 'MQTT',
      1900: 'SSDP', 2049: 'NFS', 3128: 'Proxy', 3268: 'LDAP', 3306: 'MySQL',
      3389: 'RDP', 3478: 'STUN', 4500: 'IPsec', 5060: 'SIP', 5061: 'SIP-TLS',
      5222: 'XMPP', 5353: 'mDNS', 5432: 'PostgreSQL', 5900: 'VNC',
      5938: 'TeamViewer', 6379: 'Redis', 6443: 'K8s-API', 8000: 'HTTP-Alt',
      8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8883: 'MQTT-TLS', 8888: 'HTTP-Alt',
      9092: 'Kafka', 9200: 'Elastic', 9300: 'Elastic', 10000: 'Webmin',
      11211: 'Memcached', 27017: 'MongoDB', 51820: 'WireGuard'
    };

    // Şifreli/güvenli servisler (yeşil rozetle vurgulanır).
    const SECURE_SERVICES = {
      'SSH': 1, 'HTTPS': 1, 'HTTPS-Alt': 1, 'SMTPS': 1, 'IMAPS': 1,
      'POP3S': 1, 'LDAPS': 1, 'FTPS': 1, 'DoT': 1, 'SIP-TLS': 1,
      'MQTT-TLS': 1, 'OpenVPN': 1, 'WireGuard': 1, 'IPsec': 1, 'IKE': 1
    };

    // Kaynak ve hedef portlardan servisi tespit eder. Sunucu portu genelde
    // küçük/bilinen olandır; iki port da eşleşiyorsa küçük port numarasını baz alır.
    function lookupService(srcPort, dstPort) {
      const s = PORT_SERVICES[srcPort];
      const d = PORT_SERVICES[dstPort];
      let name = '', port = '';
      if (s && d) {
        if (parseInt(srcPort, 10) <= parseInt(dstPort, 10)) { name = s; port = srcPort; }
        else { name = d; port = dstPort; }
      } else if (d) { name = d; port = dstPort; }
      else if (s) { name = s; port = srcPort; }
      if (!name) return null;
      return { name, port, secure: !!SECURE_SERVICES[name] };
    }

    function parseRecord(record) {
      const parts = String(record || '').split('|');
      const proto = (parts[5] || '-').toUpperCase();
      const srcPort = parts[3] || '-';
      const dstPort = parts[4] || '-';
      const svc = lookupService(srcPort, dstPort);
      return {
        time: formatTime(parts[0] || ''),
        srcIp: parts[1] || '-',
        srcPort,
        dstIp: parts[2] || '-',
        dstPort,
        proto,
        protoClass: proto.toLowerCase(),
        service: svc ? svc.name : '',
        servicePort: svc ? svc.port : '',
        serviceSecure: svc ? svc.secure : false,
        size: formatBytes(parts[7] || '0')
      };
    }

    function buildRowMarkup(record) {
      const item = parseRecord(record);
      // Yaygın port eşleşmesi varsa TCP/UDP yerine servis adı gösterilir;
      // yoksa taşıma protokolü gösterilir. Renk taşıma protokolüne göre kalır.
      const protoLabel = item.service || item.proto;
      const protoTitle = item.service
        ? item.proto + ' · Port ' + item.servicePort + ' · ' + item.service
        : item.proto;
      const lock = (item.service && item.serviceSecure)
        ? '<svg class="lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>'
        : '';
      const protoClass = item.protoClass + (item.service ? ' svc' : '');
      return [
        '<tr>',
        '<td class="muted-cell mono">' + escapeHtml(item.time) + '</td>',
        '<td class="mono cell-ip-src">' + escapeHtml(item.srcIp) + '</td>',
        '<td class="mono cell-port-src">' + escapeHtml(item.srcPort) + '</td>',
        '<td class="mono cell-ip-dst">' + escapeHtml(item.dstIp) + '</td>',
        '<td class="mono cell-port-dst">' + escapeHtml(item.dstPort) + '</td>',
        '<td class="cell-proto">'
          + '<span class="proto ' + escapeHtml(protoClass) + '" title="' + escapeHtml(protoTitle) + '">' + lock + escapeHtml(protoLabel) + '</span>'
          + '</td>',
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

    const THREAT_RULE_LABELS = {
      bruteforce: 'Brute-force',
      portscan: 'Port tarama',
      hostsweep: 'Host tarama'
    };
    let lastThreatSig = null;

    // Güvenlik panelini ve ribbon tehdit rozetini gelen uyarı listesine göre günceller.
    function updateThreats(threats) {
      const list = Array.isArray(threats) ? threats : [];
      const count = list.length;

      if (threatBadgeEl) {
        threatBadgeEl.textContent = String(count);
        threatBadgeEl.classList.toggle('active', count > 0);
      }
      if (threatToggleEl) {
        threatToggleEl.classList.toggle('active', count > 0);
        threatToggleEl.title = count > 0
          ? (count + ' aktif güvenlik uyarısı — görüntülemek için tıkla')
          : 'Güvenlik uyarılarını göster';
      }
      if (threatToggleCountEl) {
        threatToggleCountEl.textContent = String(count);
        threatToggleCountEl.hidden = count === 0;
      }
      threatCardEl.classList.toggle('has-threats', count > 0);
      if (threatCountEl) {
        threatCountEl.textContent = String(count);
        threatCountEl.hidden = count === 0;
      }
      if (threatStatusEl) {
        threatStatusEl.textContent = count > 0 ? (count + ' aktif uyarı') : 'Şüpheli aktivite yok';
        threatStatusEl.className = 'threat-status ' + (count > 0 ? 'alert' : 'ok');
      }

      // Gereksiz DOM yenilemesini önlemek için imza karşılaştırması.
      const sig = JSON.stringify(list);
      if (sig === lastThreatSig) {
        return;
      }
      lastThreatSig = sig;

      Array.prototype.slice.call(threatListEl.querySelectorAll('.threat-item')).forEach(function(n){ n.remove(); });

      if (count === 0) {
        if (threatEmptyEl) threatEmptyEl.hidden = false;
        return;
      }
      if (threatEmptyEl) threatEmptyEl.hidden = true;

      const rows = list.map(function(a){
        const sev = a.severity === 'high' ? 'high' : 'medium';
        const sevLabel = sev === 'high' ? 'Yüksek' : 'Orta';
        const rule = THREAT_RULE_LABELS[a.rule] || 'Şüpheli';
        const hits = a.count ? '<span class="threat-hits">' + escapeHtml(String(a.count)) + '×</span>' : '';
        const detail = a.detail ? escapeHtml(a.detail) : (rule + ' tespit edildi.');
        return '<div class="threat-item ' + sev + '">'
          + '<span class="threat-sev">' + sevLabel + '</span>'
          + '<div class="threat-body">'
          +   '<div class="threat-item-title">' + escapeHtml(a.title || rule) + hits + '</div>'
          +   '<div class="threat-meta">' + detail + '</div>'
          + '</div>'
          + '<span class="threat-time">' + escapeHtml(formatTime(a.last_seen || '')) + '</span>'
          + '</div>';
      }).join('');
      threatListEl.insertAdjacentHTML('beforeend', rows);
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
      if (Array.isArray(state.threats)) {
        updateThreats(state.threats);
      }
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
      closeThreatModal();
      currentMode = 'live';
      currentPage = 1;
      dateSelectEl.value = '';
      hourSelectEl.innerHTML = '<option value="">Saat seç</option>';
      hourSelectEl.disabled = true;
      await fetchState();
      startLiveStream();
    });

    // Güvenlik uyarıları modalı: üst kontroldeki buton (ve ribbon rozeti) ile
    // canlı akış ile güvenlik ekranı arasında geçiş sağlar.
    let threatLastFocus = null;

    function openThreatModal() {
      if (!threatModalEl || !threatModalEl.hidden) return;
      threatLastFocus = document.activeElement;
      threatModalEl.hidden = false;
      if (threatToggleEl) threatToggleEl.setAttribute('aria-expanded', 'true');
      loadWhitelist();
      const closeBtn = threatModalEl.querySelector('.threat-close');
      if (closeBtn) closeBtn.focus();
    }

    function closeThreatModal() {
      if (!threatModalEl || threatModalEl.hidden) return;
      threatModalEl.hidden = true;
      if (threatToggleEl) threatToggleEl.setAttribute('aria-expanded', 'false');
      if (threatLastFocus && typeof threatLastFocus.focus === 'function') {
        threatLastFocus.focus();
      }
      threatLastFocus = null;
    }

    function toggleThreatModal() {
      if (threatModalEl && threatModalEl.hidden) {
        openThreatModal();
      } else {
        closeThreatModal();
      }
    }

    if (threatToggleEl) {
      threatToggleEl.addEventListener('click', toggleThreatModal);
    }
    if (threatBadgeEl) {
      threatBadgeEl.style.cursor = 'pointer';
      threatBadgeEl.setAttribute('role', 'button');
      threatBadgeEl.setAttribute('tabindex', '0');
      threatBadgeEl.setAttribute('title', 'Güvenlik uyarılarını göster');
      threatBadgeEl.addEventListener('click', openThreatModal);
      threatBadgeEl.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          openThreatModal();
        }
      });
    }
    if (threatModalEl) {
      threatModalEl.addEventListener('click', (event) => {
        if (event.target.closest('[data-threat-close]')) {
          closeThreatModal();
        }
      });
    }
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        closeThreatModal();
      }
    });

    // Whitelist yönetimi: görmezden gelinen kaynak IP/CIDR girişlerini listeler,
    // ekler ve siler. Değişiklikler /api/whitelist üzerinden config.json'a yazılır.
    function showWhitelistError(msg) {
      if (!whitelistErrorEl) return;
      if (msg) {
        whitelistErrorEl.textContent = msg;
        whitelistErrorEl.hidden = false;
      } else {
        whitelistErrorEl.textContent = '';
        whitelistErrorEl.hidden = true;
      }
    }

    function renderWhitelist(entries) {
      if (!whitelistListEl) return;
      const list = Array.isArray(entries) ? entries : [];
      Array.prototype.slice.call(whitelistListEl.querySelectorAll('.whitelist-chip')).forEach(function(n){ n.remove(); });
      if (whitelistEmptyEl) whitelistEmptyEl.hidden = list.length > 0;
      if (list.length === 0) return;
      const html = list.map(function(entry){
        const cidr = entry.indexOf('/') >= 0 ? ' cidr' : '';
        return '<span class="whitelist-chip' + cidr + '">'
          + '<span>' + escapeHtml(entry) + '</span>'
          + '<button type="button" class="whitelist-remove" data-entry="' + escapeHtml(entry) + '" aria-label="' + escapeHtml(entry) + ' kaydını kaldır">'
          +   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>'
          + '</button>'
          + '</span>';
      }).join('');
      whitelistListEl.insertAdjacentHTML('beforeend', html);
    }

    async function loadWhitelist() {
      try {
        const response = await fetch('/api/whitelist', { cache: 'no-store' });
        if (!response.ok) throw new Error('liste alınamadı');
        const data = await response.json();
        renderWhitelist(data.entries);
      } catch (error) {
        showWhitelistError('Whitelist yüklenemedi.');
      }
    }

    async function submitWhitelist(entry) {
      showWhitelistError('');
      try {
        const response = await fetch('/api/whitelist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ entry: entry }),
        });
        const data = await response.json().catch(function(){ return {}; });
        if (!response.ok) {
          showWhitelistError(data.error || 'Giriş eklenemedi.');
          return false;
        }
        renderWhitelist(data.entries);
        return true;
      } catch (error) {
        showWhitelistError('Giriş eklenemedi.');
        return false;
      }
    }

    async function removeWhitelist(entry) {
      showWhitelistError('');
      try {
        const response = await fetch('/api/whitelist?entry=' + encodeURIComponent(entry), { method: 'DELETE' });
        const data = await response.json().catch(function(){ return {}; });
        if (!response.ok) {
          showWhitelistError(data.error || 'Giriş kaldırılamadı.');
          return;
        }
        renderWhitelist(data.entries);
      } catch (error) {
        showWhitelistError('Giriş kaldırılamadı.');
      }
    }

    if (whitelistFormEl) {
      whitelistFormEl.addEventListener('submit', async (event) => {
        event.preventDefault();
        const value = (whitelistInputEl.value || '').trim();
        if (!value) return;
        const ok = await submitWhitelist(value);
        if (ok) {
          whitelistInputEl.value = '';
          whitelistInputEl.focus();
        }
      });
    }
    if (whitelistListEl) {
      whitelistListEl.addEventListener('click', (event) => {
        const btn = event.target.closest('.whitelist-remove');
        if (btn) removeWhitelist(btn.getAttribute('data-entry'));
      });
    }

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
