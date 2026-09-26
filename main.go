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
	blocklistFile           = "blocklist.json"
)

// Zararlı IP kara listesi ayarları.
const (
	// blocklistRetention, bir IP zararlı olarak tespit edildikten sonra kara
	// listede kalacağı asgari süredir. Her yeni tespit bu süreyi tazeler, böylece
	// aktif bir saldırgan pencereyi sürekli uzatır; saldırı dursa bile IP son
	// tespitten itibaren en az bu süre boyunca listede kalır.
	blocklistRetention = 7 * 24 * time.Hour // 7 gün
	// blocklistPersistThrottle, mevcut bir kaydın süresi tazelendiğinde diske
	// yazma sıklığını sınırlar (yeni IP ve silme işlemleri her zaman anında yazılır).
	blocklistPersistThrottle = 30 * time.Second
)

// Tehdit tespiti eşikleri. Kayan zaman penceresi içinde tek kaynak IP'nin
// davranışına bakılır (NetFlow akış verisi payload içermez, bu yüzden tespit
// hız/desen tabanlıdır).
const (
	threatWindow          = 60 * time.Second // değerlendirme penceresi
	threatBruteforceMin   = 8                // hassas porta bu kadar akış → brute-force
	threatPortScanMin     = 12               // tek hedefte bu kadar farklı port → dikey tarama
	threatHostSweepMin    = 15               // tek portta bu kadar farklı hedef → yatay tarama
	threatAlertTTL        = 3 * time.Minute  // güncellenmeyen (hareketsiz) uyarının panelde kalma süresi
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
	// BlocklistToken, /blocklist düz metin endpoint'ini korur. Boşsa endpoint
	// tamamen devre dışıdır (403).
	BlocklistToken string
	// BlocklistAllowNets tanımlıysa /blocklist endpoint'ine yalnızca bu ağlardan
	// (ör. OPNsense WAN IP'si) gelen istekler kabul edilir.
	BlocklistAllowNets []*net.IPNet
}

type App struct {
	cfg       Config
	session   flowsession.Session
	logger    *HourlyLogger
	dashboard *DashboardHub
	analyzer  *ThreatAnalyzer
	whitelist *Whitelist
	blocklist *Blocklist
	geo       *GeoResolver
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
	blocklist := NewBlocklist(blocklistFile, blocklistRetention, whitelist)
	analyzer := NewThreatAnalyzer(dashboard, whitelist, blocklist)
	app := &App{
		cfg:       cfg,
		session:   newPersistentSession(cfg.LogRoot),
		dashboard: dashboard,
		analyzer:  analyzer,
		whitelist: whitelist,
		blocklist: blocklist,
		geo:       NewGeoResolver(),
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

	allowNets, err := parseAllowNets(env["BLOCKLIST_ALLOW_IPS"])
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		ListenAddress:      firstNonEmpty(env["NETFLOW_LISTEN_ADDRESS"], defaultListenAddress),
		DashboardAddress:   firstNonEmpty(env["DASHBOARD_ADDRESS"], defaultDashboardAddress),
		DashboardUser:      strings.TrimSpace(env["DASHBOARD_USERNAME"]),
		DashboardPass:      strings.TrimSpace(env["DASHBOARD_PASSWORD"]),
		TSAURL:             firstNonEmpty(env["TSA_URL"], defaultTSAURL),
		LogRoot:            firstNonEmpty(env["LOG_ROOT"], defaultLogRoot),
		Location:           location,
		DebugFlowMapping:   strings.EqualFold(strings.TrimSpace(env["DEBUG_FLOW_MAPPING"]), "true"),
		BlocklistToken:     strings.TrimSpace(env["BLOCKLIST_TOKEN"]),
		BlocklistAllowNets: allowNets,
	}

	if cfg.DashboardUser == "" || cfg.DashboardPass == "" {
		return Config{}, errors.New("DASHBOARD_USERNAME and DASHBOARD_PASSWORD must be set in .env")
	}

	return cfg, nil
}

// parseAllowNets, virgülle ayrılmış IP/CIDR listesini (BLOCKLIST_ALLOW_IPS)
// *net.IPNet dilimine çevirir. Tekil IP'ler /32 (IPv4) veya /128 (IPv6) olur.
// Boş girdi nil döndürür (kısıtlama yok).
func parseAllowNets(raw string) ([]*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			_, n, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("BLOCKLIST_ALLOW_IPS geçersiz CIDR: %s", part)
			}
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, fmt.Errorf("BLOCKLIST_ALLOW_IPS geçersiz IP: %s", part)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
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

// ThreatsSnapshot, yalnızca güncel tehdit uyarılarının bir kopyasını döndürür.
// Modal açıkken hafif yoklama için tam durum anlık görüntüsünden (kayıtlar, dosya
// boyutları vb.) daha ucuzdur.
func (h *DashboardHub) ThreatsSnapshot() []ThreatAlert {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]ThreatAlert(nil), h.threats...)
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
	blocklist *Blocklist

	mu      sync.Mutex
	sources map[string]*sourceActivity
	alerts  map[string]*threatAlert
}

func NewThreatAnalyzer(hub *DashboardHub, whitelist *Whitelist, blocklist *Blocklist) *ThreatAnalyzer {
	return &ThreatAnalyzer{
		hub:       hub,
		whitelist: whitelist,
		blocklist: blocklist,
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

	changed, reason := t.evaluateLocked(src, sa, now)
	var snapshot []ThreatAlert
	if changed {
		snapshot = t.snapshotAlertsLocked()
	}
	t.mu.Unlock()

	if changed {
		// Zararlı olarak işaretlenen kaynağı kalıcı kara listeye ekle/tazele.
		// Disk yazımı t.mu dışında yapılır ki analiz sıcak yolu kilitli kalmasın.
		t.blocklist.Add(src, reason)
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

	// Dosyaya elle eklenmiş/çıkarılmış manuel kayıtları belleğe yansıt, ardından
	// süresi dolan (manuel olmayan) sistem kayıtlarını temizle.
	t.blocklist.SyncManual()
	t.blocklist.PurgeExpired()

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
	// Whitelist'e alınan IP'ler kara listeden de düşürülür.
	t.blocklist.PurgeWhitelisted()
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
// İkinci dönüş değeri, tetiklenen en yüksek önem dereceli kuralın adıdır (kara
// liste kaydında sebep olarak saklanır); değişiklik yoksa boştur.
func (t *ThreatAnalyzer) evaluateLocked(src string, sa *sourceActivity, now time.Time) (bool, string) {
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
	reason := ""
	reasonRank := 0
	// mark, tetiklenen kuralı en yüksek önem derecesine göre "sebep" olarak seçer.
	mark := func(severity, rule string) {
		if r := severityRank(severity); r >= reasonRank {
			reasonRank = r
			reason = rule
		}
	}

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
			mark("high", "bruteforce")
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
			mark("medium", "portscan")
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
			mark("medium", "hostsweep")
		}
	}

	return changed, reason
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
	entries []string // kullanıcının eklediği sırayla normalize edilmiş girişler
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

// blocklistEntry, tespit edilen zararlı bir kaynak IP'nin kalıcı kaydıdır.
type blocklistEntry struct {
	IP   string `json:"ip"`
	Rule string `json:"rule"`
	Hits int    `json:"hits"`
	// Manual, elle (dosyaya doğrudan ya da API ile) eklenmiş kayıtları işaretler.
	// Manuel kayıtlar kalıcıdır: süre aşımıyla temizlenmez ve sistem dosyayı yeniden
	// yazdığında korunur. Elle eklerken kaydın içine `"manual": true` yazılmalıdır.
	Manual    bool      `json:"manual,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at"`
}

// active, kaydın kara listede geçerli sayılıp sayılmadığını döndürür. Manuel
// kayıtlar her zaman geçerlidir; sistem kayıtları ise yalnızca süresi dolmadıysa.
func (e *blocklistEntry) active(now time.Time) bool {
	return e.Manual || e.ExpiresAt.After(now)
}

// blocklistFileFormat, blocklist.json'un disk biçimidir.
type blocklistFileFormat struct {
	Entries []blocklistEntry `json:"entries"`
}

// Blocklist, tehdit analizinin zararlı olarak işaretlediği kaynak IP'leri
// blocklist.json içinde kalıcı olarak tutar. Her IP, en son tespitten itibaren
// retention süresi (7 gün) boyunca listede kalır; süresi dolanlar temizlenir.
// Liste, OPNsense gibi güvenlik duvarlarının "alias URL table" özelliğiyle
// çekebilmesi için düz metin bir endpoint üzerinden yayınlanır.
type Blocklist struct {
	path      string
	retention time.Duration
	whitelist *Whitelist

	mu          sync.Mutex
	entries     map[string]*blocklistEntry
	lastPersist time.Time
}

// NewBlocklist, verilen yoldan kara listeyi yükler (yoksa boş başlar). Yüklerken
// süresi dolmuş ve whitelist'e alınmış girişler atlanır.
func NewBlocklist(path string, retention time.Duration, whitelist *Whitelist) *Blocklist {
	b := &Blocklist{
		path:      path,
		retention: retention,
		whitelist: whitelist,
		entries:   make(map[string]*blocklistEntry),
	}
	b.load()
	return b
}

// load, blocklist.json'daki geçerli (süresi dolmamış, whitelist dışı) kayıtları okur.
func (b *Blocklist) load() {
	data, err := os.ReadFile(b.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("blocklist read failed: %v", err)
		}
		return
	}
	var f blocklistFileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("blocklist parse failed: %v", err)
		return
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	loaded := 0
	for i := range f.Entries {
		e := f.Entries[i]
		// Manuel kayıtlar süresine bakılmaksızın korunur; sistem kayıtları yalnızca
		// süresi dolmadıysa yüklenir.
		if e.IP == "" || !e.active(now) {
			continue
		}
		// Whitelist yalnızca sistem kayıtlarını eler; manuel kayıt kullanıcının
		// bilinçli bir kararıdır ve korunur.
		if !e.Manual && b.whitelist.Contains(e.IP) {
			continue
		}
		cp := e
		b.entries[e.IP] = &cp
		loaded++
	}
	if loaded > 0 {
		log.Printf("loaded %d active blocklist entr(ies) from %s", loaded, b.path)
	}
}

// Add, bir kaynak IP'yi kara listeye ekler ya da mevcut kaydın süresini tazeler.
// Her çağrı son görülme zamanını günceller ve bitişi now+retention'a taşır, böylece
// IP son tespitten itibaren en az retention süresi boyunca listede kalır.
func (b *Blocklist) Add(ip, rule string) {
	if b == nil || ip == "" {
		return
	}
	// Whitelist'teki IP'ler asla kara listeye girmez (savunma amaçlı çift kontrol).
	if b.whitelist.Contains(ip) {
		return
	}
	now := time.Now()
	b.mu.Lock()
	e := b.entries[ip]
	isNew := e == nil
	if isNew {
		e = &blocklistEntry{IP: ip, FirstSeen: now}
		b.entries[ip] = e
	}
	e.LastSeen = now
	e.Hits++
	if rule != "" {
		e.Rule = rule
	}
	// Manuel kayıtlar kalıcıdır; sistem tespiti bunların süresini/işaretini bozmaz.
	if !e.Manual {
		e.ExpiresAt = now.Add(b.retention)
	}
	// Yeni IP anında yazılır; yalnızca süre tazelemelerinde disk yazımı kısılır.
	b.maybePersistLocked(isNew)
	b.mu.Unlock()
}

// Snapshot, süresi dolmamış kayıtları son görülmeye göre (yeni → eski) sıralı döndürür.
func (b *Blocklist) Snapshot() []blocklistEntry {
	if b == nil {
		return nil
	}
	now := time.Now()
	b.mu.Lock()
	out := make([]blocklistEntry, 0, len(b.entries))
	for _, e := range b.entries {
		if !e.active(now) {
			continue
		}
		out = append(out, *e)
	}
	b.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// IPs, düz metin endpoint için geçerli (süresi dolmamış, whitelist dışı) IP'leri
// kararlı bir sırayla döndürür.
func (b *Blocklist) IPs() []string {
	if b == nil {
		return nil
	}
	snap := b.Snapshot()
	out := make([]string, 0, len(snap))
	for _, e := range snap {
		if b.whitelist.Contains(e.IP) {
			continue
		}
		out = append(out, e.IP)
	}
	return out
}

// PurgeExpired, retention süresi geçen kayıtları siler; değişiklik olursa yazar.
func (b *Blocklist) PurgeExpired() {
	if b == nil {
		return
	}
	now := time.Now()
	b.mu.Lock()
	changed := false
	for ip, e := range b.entries {
		// Manuel kayıtlar süre aşımıyla silinmez.
		if !e.Manual && !e.ExpiresAt.After(now) {
			delete(b.entries, ip)
			changed = true
		}
	}
	if changed {
		b.persistLocked()
	}
	b.mu.Unlock()
}

// PurgeWhitelisted, whitelist'e alınmış IP'leri kara listeden düşürür.
func (b *Blocklist) PurgeWhitelisted() {
	if b == nil {
		return
	}
	b.mu.Lock()
	changed := false
	for ip, e := range b.entries {
		// Manuel kayıtlar kullanıcının bilinçli kararıdır; whitelist ile çakışsa
		// bile dosyadan silinmez (endpoint çıktısı IPs() içinde zaten whitelist
		// ile filtrelenir).
		if !e.Manual && b.whitelist.Contains(ip) {
			delete(b.entries, ip)
			changed = true
		}
	}
	if changed {
		b.persistLocked()
	}
	b.mu.Unlock()
}

// maybePersistLocked, yeni kayıt/silme dışındaki süre tazelemelerinde disk yazımını
// blocklistPersistThrottle ile kısar (b.mu kilitli olmalı).
func (b *Blocklist) maybePersistLocked(force bool) {
	if force || time.Since(b.lastPersist) > blocklistPersistThrottle {
		b.persistLocked()
	}
}

// SyncManual, dosyaya elle eklenmiş/çıkarılmış manuel kayıtları belleğe yansıtır.
// Çalışma zamanında (süreç yeniden başlatılmadan) yapılan manuel düzenlemelerin
// endpoint'e ve sonraki yazımlara yansıması için periyodik olarak çağrılır.
func (b *Blocklist) SyncManual() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.syncManualFromFileLocked()
	b.mu.Unlock()
}

// syncManualFromFileLocked, blocklist.json'daki manuel (`"manual": true`) kayıtları
// bellekle uzlaştırır: dosyada olanları ekler/günceller, dosyadan silinmiş manuel
// kayıtları bellekten düşürür. Sistem (manuel olmayan) kayıtlarına dokunmaz; onlar
// tamamen bellekten yönetilir. Böylece dosya, manuel kayıtlar için kaynak olur ve
// sistem dosyayı yeniden yazarken manuel kayıtlar asla ezilmez (b.mu kilitli olmalı).
func (b *Blocklist) syncManualFromFileLocked() {
	data, err := os.ReadFile(b.path)
	if err != nil {
		return // dosya yoksa/okunamıyorsa senkron atlanır
	}
	var f blocklistFileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("blocklist manual sync parse failed: %v", err)
		return
	}
	fileManual := make(map[string]blocklistEntry)
	for i := range f.Entries {
		e := f.Entries[i]
		if e.Manual && e.IP != "" {
			fileManual[e.IP] = e
		}
	}
	// Dosyadan kaldırılmış manuel kayıtları bellekten de düş.
	for ip, e := range b.entries {
		if e.Manual {
			if _, ok := fileManual[ip]; !ok {
				delete(b.entries, ip)
			}
		}
	}
	// Dosyadaki manuel kayıtları belleğe al/güncelle.
	now := time.Now()
	for ip, e := range fileManual {
		cp := e
		cp.Manual = true
		if cp.FirstSeen.IsZero() {
			cp.FirstSeen = now
		}
		if cp.LastSeen.IsZero() {
			cp.LastSeen = now
		}
		b.entries[ip] = &cp
	}
}

// persistLocked, kara listeyi IP'ye göre sıralı ve atomik biçimde diske yazar
// (b.mu kilitli olmalı). Yazmadan önce dosyadaki manuel kayıtları belleğe okur ki
// çalışma zamanında elle eklenmiş kayıtlar üzerine yazılıp kaybolmasın.
func (b *Blocklist) persistLocked() {
	b.syncManualFromFileLocked()
	b.writeFileLocked()
}

// writeFileLocked, bellekteki kayıtları IP'ye göre sıralı ve atomik biçimde diske
// yazar (b.mu kilitli olmalı). persistLocked'ın aksine dosyayla senkronlamaz;
// çağıran, b.entries'in yazılmak istenen son durumu içerdiğinden emin olmalıdır.
// Bu ayrım, henüz dosyada olmayan yeni bir manuel kaydın (AddManual) senkron
// sırasında yanlışlıkla silinmesini önlemek için gereklidir.
func (b *Blocklist) writeFileLocked() {
	list := make([]blocklistEntry, 0, len(b.entries))
	for _, e := range b.entries {
		list = append(list, *e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })

	data, err := json.MarshalIndent(blocklistFileFormat{Entries: list}, "", "  ")
	if err != nil {
		log.Printf("blocklist marshal failed: %v", err)
		return
	}
	if dir := filepath.Dir(b.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("blocklist dir create failed: %v", err)
			return
		}
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Printf("blocklist write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, b.path); err != nil {
		log.Printf("blocklist rename failed: %v", err)
		return
	}
	b.lastPersist = time.Now()
}

// AddManual, bir kaynak IP'yi kalıcı (manuel) kara liste kaydı olarak ekler. Manuel
// kayıtlar süre aşımıyla temizlenmez ve yalnızca blocklist.json içinde tutulur;
// config.json'a hiç dokunulmaz. Böylece IP'ler web arayüzünden config dosyasıyla
// uğraşmadan engellenebilir. Whitelist'teki IP'ler engellenemez.
func (b *Blocklist) AddManual(ip, reason string) error {
	if b == nil {
		return errors.New("kara liste kullanılamıyor")
	}
	norm, err := normalizeBlocklistIP(ip)
	if err != nil {
		return err
	}
	if b.whitelist.Contains(norm) {
		return fmt.Errorf("%s whitelist'te olduğundan engellenemez", norm)
	}
	reason = strings.TrimSpace(reason)
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	// Eşzamanlı dosya düzenlemelerinin ezilmemesi için önce dosyadaki manuel
	// kayıtları belleğe al; ardından yeni kaydı ekleyip writeFileLocked ile yaz.
	// persistLocked kullanılmaz: tekrar senkronlarsa, henüz dosyada olmayan bu
	// yeni manuel kayıt silinir.
	b.syncManualFromFileLocked()
	e := b.entries[norm]
	if e == nil {
		e = &blocklistEntry{IP: norm, FirstSeen: now}
		b.entries[norm] = e
	}
	e.Manual = true
	e.LastSeen = now
	e.Hits++
	if reason != "" {
		e.Rule = reason
	} else if e.Rule == "" {
		e.Rule = "Panelden elle engellendi"
	}
	b.writeFileLocked()
	return nil
}

// RemoveManual, manuel olarak engellenmiş bir IP'yi kara listeden kaldırır. Yalnızca
// manuel kayıtlar kaldırılabilir; sistemin tespit ettiği kayıtlar retention süresince
// otomatik yönetilir. IP sistemce tekrar tespit edilirse yeniden listeye girer.
func (b *Blocklist) RemoveManual(ip string) error {
	if b == nil {
		return errors.New("kara liste kullanılamıyor")
	}
	norm, err := normalizeBlocklistIP(ip)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.syncManualFromFileLocked()
	e := b.entries[norm]
	if e == nil || !e.Manual {
		return fmt.Errorf("%s manuel engel listesinde bulunamadı", norm)
	}
	delete(b.entries, norm)
	b.writeFileLocked()
	return nil
}

// normalizeBlocklistIP, tek bir IP adresini doğrular ve kanonik biçimine getirir.
// Kara liste kayıtları IP bazlıdır (CIDR desteklenmez); geçersiz girişte hata döner.
func normalizeBlocklistIP(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("IP adresi boş olamaz")
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("geçersiz IP adresi: %s", s)
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
	mux.Handle("/api/blocklist", a.basicAuth(http.HandlerFunc(a.handleBlocklistAPI)))
	mux.Handle("/api/threats", a.basicAuth(http.HandlerFunc(a.handleThreats)))
	mux.Handle("/api/ip", a.basicAuth(http.HandlerFunc(a.handleIPInfo)))
	mux.Handle("/events", a.basicAuth(http.HandlerFunc(a.handleDashboardEvents)))
	// Düz metin kara liste: OPNsense alias URL table için. Basic auth yerine
	// token (ve opsiyonel IP kısıtı) ile korunur; firewall'lar Basic auth göndermez.
	mux.Handle("/blocklist", http.HandlerFunc(a.handleBlocklist))
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

// handleBlocklist, zararlı IP kara listesini OPNsense'in okuyabileceği düz metin
// olarak döndürür: her satırda bir IP, HTML/JSON/boş satır olmadan. OPNsense'te
// Firewall → Aliases → tür "URL Table (IPs)" olarak bu endpoint tanımlanır:
//
//	https://<host>:<port>/blocklist?token=<BLOCKLIST_TOKEN>
func (a *App) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.blocklistAuthorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	// İstek anında dosyadaki manuel düzenlemeleri belleğe yansıt; böylece elle
	// eklenen/çıkarılan manuel kayıtlar 5 sn'lik bakım döngüsünü beklemeden
	// endpoint'e anında yansır.
	a.blocklist.SyncManual()
	for _, ip := range a.blocklist.IPs() {
		fmt.Fprintln(w, ip)
	}
}

// handleBlocklistAPI, kara listeyi panel için yönetir (basic auth arkasında):
//   - GET: aktif kayıtları ayrıntılı JSON olarak döndürür.
//   - POST: gövdedeki IP'yi manuel (kalıcı) olarak engeller.
//   - DELETE: ?ip=<adres> ile verilen manuel engeli kaldırır.
//
// Manuel engeller yalnızca blocklist.json'a yazılır; config.json'a dokunulmaz.
func (a *App) handleBlocklistAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeBlocklist(w)
	case http.MethodPost:
		var body struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, "geçersiz istek gövdesi", http.StatusBadRequest)
			return
		}
		if err := a.blocklist.AddManual(body.IP, body.Reason); err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.writeBlocklist(w)
	case http.MethodDelete:
		if err := a.blocklist.RemoveManual(r.URL.Query().Get("ip")); err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.writeBlocklist(w)
	default:
		writeJSONError(w, "desteklenmeyen metot", http.StatusMethodNotAllowed)
	}
}

// handleThreats, yalnızca güncel güvenlik uyarılarını JSON döndürür. Güvenlik modalı
// açık olduğu sürece paneli (tablo sayfasından/modundan bağımsız) canlı tutmak için
// hafif bir yoklama endpoint'idir.
func (a *App) handleThreats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	threats := a.dashboard.ThreatsSnapshot()
	if threats == nil {
		threats = []ThreatAlert{}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"threats": threats})
}

// IP ayrıntı modalı ayarları.
const (
	// geoCacheTTL, ip-api.com yanıtlarının bellekte tutulma süresidir.
	geoCacheTTL = 24 * time.Hour
	// geoRateLimit, ip-api.com ücretsiz katmanının dakikalık istek sınırıdır (45);
	// güvenlik payı için biraz altında tutulur.
	geoRateLimit = 40
	// ipInfoTopN, trafik özetinde listelenen en çok konuşulan eş/port sayısıdır.
	ipInfoTopN = 5
)

// IPGeo, ip-api.com'dan dönen konum ve ağ sahibi bilgisidir.
type IPGeo struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`
	Proxy       bool   `json:"proxy"`
	Hosting     bool   `json:"hosting"`
	Mobile      bool   `json:"mobile"`
}

type geoCacheEntry struct {
	geo     *IPGeo
	errMsg  string
	expires time.Time
}

// GeoResolver, genel IP adreslerinin konum/ASN bilgisini ip-api.com üzerinden
// sorgular. Yanıtlar önbelleğe alınır ve dakikalık istek sınırı aşılmaz.
type GeoResolver struct {
	baseURL string
	client  *http.Client

	mu       sync.Mutex
	cache    map[string]geoCacheEntry
	requests []time.Time
}

func NewGeoResolver() *GeoResolver {
	return &GeoResolver{
		baseURL: "http://ip-api.com/json/",
		client:  &http.Client{Timeout: 4 * time.Second},
		cache:   make(map[string]geoCacheEntry),
	}
}

// Lookup, IP'nin konum bilgisini döndürür; hata durumunda kullanıcıya
// gösterilecek kısa bir açıklama döner.
func (g *GeoResolver) Lookup(ctx context.Context, ip string) (*IPGeo, string) {
	if g == nil {
		return nil, "konum servisi devre dışı"
	}
	now := time.Now()
	g.mu.Lock()
	if e, ok := g.cache[ip]; ok && now.Before(e.expires) {
		g.mu.Unlock()
		return e.geo, e.errMsg
	}
	cutoff := now.Add(-time.Minute)
	kept := g.requests[:0]
	for _, t := range g.requests {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	g.requests = kept
	if len(g.requests) >= geoRateLimit {
		g.mu.Unlock()
		return nil, "konum servisi istek sınırına ulaşıldı, biraz sonra tekrar deneyin"
	}
	g.requests = append(g.requests, now)
	g.mu.Unlock()

	geo, errMsg, cacheable := g.fetch(ctx, ip)
	if cacheable {
		g.mu.Lock()
		g.cache[ip] = geoCacheEntry{geo: geo, errMsg: errMsg, expires: now.Add(geoCacheTTL)}
		g.mu.Unlock()
	}
	return geo, errMsg
}

// fetch, ip-api.com'a tek bir istek atar. Ağ hataları önbelleğe alınmaz.
func (g *GeoResolver) fetch(ctx context.Context, ip string) (*IPGeo, string, bool) {
	url := g.baseURL + ip + "?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "konum sorgusu oluşturulamadı", false
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, "konum servisine ulaşılamadı", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("konum servisi hata döndürdü (%d)", resp.StatusCode), false
	}
	var body struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		Proxy       bool   `json:"proxy"`
		Hosting     bool   `json:"hosting"`
		Mobile      bool   `json:"mobile"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body); err != nil {
		return nil, "konum yanıtı okunamadı", false
	}
	if body.Status != "success" {
		return nil, "konum bulunamadı: " + body.Message, true
	}
	return &IPGeo{
		Country:     body.Country,
		CountryCode: body.CountryCode,
		Region:      body.RegionName,
		City:        body.City,
		ISP:         body.ISP,
		Org:         body.Org,
		AS:          body.AS,
		Proxy:       body.Proxy,
		Hosting:     body.Hosting,
		Mobile:      body.Mobile,
	}, "", true
}

// ipScope, IP adresinin ağ sınıfını Türkçe olarak döndürür; ikinci değer
// adresin genel (internet üzerinde yönlendirilebilir) olup olmadığıdır.
func ipScope(ip net.IP) (string, bool) {
	switch {
	case ip.IsLoopback():
		return "Loopback", false
	case ip.IsPrivate():
		return "Özel ağ", false
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "Link-local", false
	case ip.IsMulticast():
		return "Multicast", false
	case ip.IsUnspecified():
		return "Belirtilmemiş", false
	case ip.Equal(net.IPv4bcast):
		return "Broadcast", false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xC0 == 64 {
		return "CGNAT", false
	}
	return "Genel", true
}

// IPPeerStat, trafik özetindeki karşı taraf IP istatistiğidir.
type IPPeerStat struct {
	IP    string `json:"ip"`
	Flows int    `json:"flows"`
	Bytes uint64 `json:"bytes"`
}

// IPPortStat, trafik özetindeki servis portu istatistiğidir.
type IPPortStat struct {
	Port     uint64 `json:"port"`
	Protocol string `json:"protocol"`
	Flows    int    `json:"flows"`
	Bytes    uint64 `json:"bytes"`
}

// IPTrafficSummary, bellekteki kayıtlardan IP için çıkarılan trafik özetidir.
type IPTrafficSummary struct {
	Flows     int          `json:"flows"`
	Outbound  int          `json:"outbound"`
	Inbound   int          `json:"inbound"`
	Packets   uint64       `json:"packets"`
	Bytes     uint64       `json:"bytes"`
	BytesOut  uint64       `json:"bytes_out"`
	BytesIn   uint64       `json:"bytes_in"`
	FirstSeen string       `json:"first_seen,omitempty"`
	LastSeen  string       `json:"last_seen,omitempty"`
	TopPeers  []IPPeerStat `json:"top_peers"`
	TopPorts  []IPPortStat `json:"top_ports"`
}

// IPInfoResponse, /api/ip yanıtıdır.
type IPInfoResponse struct {
	IP          string           `json:"ip"`
	Version     int              `json:"version"`
	Scope       string           `json:"scope"`
	Public      bool             `json:"public"`
	PTR         []string         `json:"ptr"`
	Whitelisted bool             `json:"whitelisted"`
	Blocked     *blocklistEntry  `json:"blocked,omitempty"`
	Threats     []ThreatAlert    `json:"threats"`
	Geo         *IPGeo           `json:"geo,omitempty"`
	GeoError    string           `json:"geo_error,omitempty"`
	Summary     IPTrafficSummary `json:"summary"`
	Records     []string         `json:"records"`
	Scanned     int              `json:"scanned"`
}

// summarizeIPTraffic, kayıtlar içinden IP'nin kaynak veya hedef olduğu akışları
// süzer (en yeni en üstte) ve trafik özetini çıkarır.
func summarizeIPTraffic(records []string, ip string) ([]string, IPTrafficSummary) {
	var sum IPTrafficSummary
	matched := make([]string, 0)
	peers := make(map[string]*IPPeerStat)
	ports := make(map[string]*IPPortStat)
	var first, last time.Time

	for i := len(records) - 1; i >= 0; i-- {
		rec := records[i]
		parts := strings.Split(rec, "|")
		if len(parts) < 8 {
			continue
		}
		src, dst := parts[1], parts[2]
		var peer string
		outbound := false
		switch ip {
		case src:
			peer, outbound = dst, true
		case dst:
			peer = src
		default:
			continue
		}
		matched = append(matched, rec)

		pkts, _ := strconv.ParseUint(parts[6], 10, 64)
		byts, _ := strconv.ParseUint(parts[7], 10, 64)
		sum.Flows++
		sum.Packets += pkts
		sum.Bytes += byts
		if outbound {
			sum.Outbound++
			sum.BytesOut += byts
		} else {
			sum.Inbound++
			sum.BytesIn += byts
		}
		if t, err := time.Parse(time.RFC3339, parts[0]); err == nil {
			if first.IsZero() || t.Before(first) {
				first = t
			}
			if t.After(last) {
				last = t
			}
		}

		p := peers[peer]
		if p == nil {
			p = &IPPeerStat{IP: peer}
			peers[peer] = p
		}
		p.Flows++
		p.Bytes += byts

		// Servis portu: sunucu tarafı genelde küçük numaralı porttur.
		sp, _ := strconv.ParseUint(parts[3], 10, 64)
		dp, _ := strconv.ParseUint(parts[4], 10, 64)
		svc := dp
		if sp != 0 && (dp == 0 || sp < dp) {
			svc = sp
		}
		key := parts[5] + "/" + strconv.FormatUint(svc, 10)
		ps := ports[key]
		if ps == nil {
			ps = &IPPortStat{Port: svc, Protocol: parts[5]}
			ports[key] = ps
		}
		ps.Flows++
		ps.Bytes += byts
	}

	if !first.IsZero() {
		sum.FirstSeen = first.Format(time.RFC3339)
		sum.LastSeen = last.Format(time.RFC3339)
	}

	sum.TopPeers = make([]IPPeerStat, 0, len(peers))
	for _, p := range peers {
		sum.TopPeers = append(sum.TopPeers, *p)
	}
	sort.Slice(sum.TopPeers, func(i, j int) bool {
		if sum.TopPeers[i].Flows != sum.TopPeers[j].Flows {
			return sum.TopPeers[i].Flows > sum.TopPeers[j].Flows
		}
		return sum.TopPeers[i].IP < sum.TopPeers[j].IP
	})
	if len(sum.TopPeers) > ipInfoTopN {
		sum.TopPeers = sum.TopPeers[:ipInfoTopN]
	}

	sum.TopPorts = make([]IPPortStat, 0, len(ports))
	for _, p := range ports {
		sum.TopPorts = append(sum.TopPorts, *p)
	}
	sort.Slice(sum.TopPorts, func(i, j int) bool {
		if sum.TopPorts[i].Flows != sum.TopPorts[j].Flows {
			return sum.TopPorts[i].Flows > sum.TopPorts[j].Flows
		}
		return sum.TopPorts[i].Port < sum.TopPorts[j].Port
	})
	if len(sum.TopPorts) > ipInfoTopN {
		sum.TopPorts = sum.TopPorts[:ipInfoTopN]
	}
	return matched, sum
}

// handleIPInfo, ?ip=<adres> için IP ayrıntılarını döndürür: ağ sınıfı, ters DNS,
// whitelist/kara liste durumu, aktif tehditler, konum/ASN (yalnızca genel IP'ler
// için ip-api.com) ve bellekteki son kayıtlardan IP'nin trafiği.
func (a *App) handleIPInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "desteklenmeyen metot", http.StatusMethodNotAllowed)
		return
	}
	parsed := net.ParseIP(strings.TrimSpace(r.URL.Query().Get("ip")))
	if parsed == nil {
		writeJSONError(w, "geçersiz IP adresi", http.StatusBadRequest)
		return
	}
	ip := parsed.String()
	// lite=1: modal açıkken yapılan periyodik tazelemelerde ters DNS ve konum
	// sorguları atlanır; yalnızca trafik ve güvenlik durumu döner.
	lite := r.URL.Query().Get("lite") == "1"

	resp := IPInfoResponse{IP: ip, Version: 6, PTR: []string{}, Threats: []ThreatAlert{}}
	if parsed.To4() != nil {
		resp.Version = 4
	}
	resp.Scope, resp.Public = ipScope(parsed)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	if !lite {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dnsCtx, dnsCancel := context.WithTimeout(ctx, 2*time.Second)
			defer dnsCancel()
			if names, err := net.DefaultResolver.LookupAddr(dnsCtx, ip); err == nil {
				for _, n := range names {
					resp.PTR = append(resp.PTR, strings.TrimSuffix(n, "."))
				}
			}
		}()
	}
	if resp.Public && !lite {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp.Geo, resp.GeoError = a.geo.Lookup(ctx, ip)
		}()
	}

	resp.Whitelisted = a.whitelist.Contains(ip)
	for _, e := range a.blocklist.Snapshot() {
		if e.IP == ip {
			entry := e
			resp.Blocked = &entry
			break
		}
	}
	if a.dashboard != nil {
		for _, t := range a.dashboard.ThreatsSnapshot() {
			if t.SrcIP == ip {
				resp.Threats = append(resp.Threats, t)
			}
		}
		records := a.dashboard.Snapshot().Records
		resp.Scanned = len(records)
		resp.Records, resp.Summary = summarizeIPTraffic(records, ip)
	} else {
		resp.Records, resp.Summary = summarizeIPTraffic(nil, ip)
	}

	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// writeBlocklist, güncel kara liste durumunu JSON olarak yazar.
func (a *App) writeBlocklist(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	a.blocklist.SyncManual()
	entries := a.blocklist.Snapshot()
	if entries == nil {
		entries = []blocklistEntry{}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"entries":      entries,
		"retention_h":  int(blocklistRetention.Hours()),
		"total_active": len(entries),
	})
}

// blocklistAuthorized, /blocklist endpoint'i için token ve opsiyonel IP kısıtını
// doğrular. BLOCKLIST_TOKEN tanımlı değilse endpoint tamamen devre dışıdır.
func (a *App) blocklistAuthorized(r *http.Request) bool {
	// Opsiyonel IP kısıtlaması: tanımlıysa yalnızca izin verilen ağlar kabul edilir.
	if len(a.cfg.BlocklistAllowNets) > 0 {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(strings.TrimSpace(host))
		allowed := false
		if ip != nil {
			for _, n := range a.cfg.BlocklistAllowNets {
				if n.Contains(ip) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return false
		}
	}

	expected := a.cfg.BlocklistToken
	if expected == "" {
		return false
	}
	got := r.URL.Query().Get("token")
	if got == "" {
		got = bearerToken(r)
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

// bearerToken, "Authorization: Bearer <token>" başlığından token'ı çıkarır.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
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
  <meta name="color-scheme" content="dark">
  <title>netflow logger panel</title>
  <style>
    /* ── Tasarım belirteçleri ─────────────────────────────────────────── */
    :root {
      color-scheme: dark;
      --bg: #060809;
      --surface: #0b1011;
      --surface-2: #0f1617;
      --surface-3: #152021;
      --line: #1b2729;
      --line-2: #2a3a3c;
      --text: #d6e4df;
      --text-2: #a0b5ae;
      --text-3: #72887f;
      --green: #3ee08a;
      --green-rgb: 62, 224, 138;
      --green-soft: rgba(62, 224, 138, 0.10);
      --cyan: #5ccaf2;
      --cyan-soft: rgba(92, 202, 242, 0.10);
      --amber: #f5b83d;
      --amber-soft: rgba(245, 184, 61, 0.10);
      --red: #ff6170;
      --red-soft: rgba(255, 97, 112, 0.10);
      --violet: #b59dff;
      --violet-soft: rgba(181, 157, 255, 0.10);
      --font-mono: "JetBrains Mono", "SF Mono", "Cascadia Code", "Fira Code", ui-monospace, Menlo, Consolas, monospace;
      --radius: 3px;
      --ease: cubic-bezier(0.2, 0.7, 0.2, 1);
      --dur: 180ms;
      --s1: 4px; --s2: 8px; --s3: 12px; --s4: 16px; --s5: 20px; --s6: 24px;
    }

    *, *::before, *::after { box-sizing: border-box; }

    html { -webkit-text-size-adjust: 100%; }

    body {
      margin: 0;
      min-height: 100vh;
      background-color: var(--bg);
      background-image:
        linear-gradient(rgba(var(--green-rgb), 0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(var(--green-rgb), 0.025) 1px, transparent 1px);
      background-size: 32px 32px;
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 14px;
      line-height: 1.5;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "zero" 1, "calt" 0;
    }

    /* CRT tarama çizgileri: çok düşük opaklıkta, yalnızca doku için. */
    body::after {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background: repeating-linear-gradient(0deg, rgba(0, 0, 0, 0.18) 0 1px, transparent 1px 3px);
      opacity: 0.35;
      z-index: 100;
    }

    ::selection { background: rgba(var(--green-rgb), 0.28); color: #fff; }

    button, input, select { font: inherit; color: inherit; }
    button { cursor: pointer; touch-action: manipulation; }
    button:disabled { cursor: not-allowed; }

    :focus-visible {
      outline: 2px solid var(--green);
      outline-offset: 2px;
    }

    svg { display: block; flex: none; }

    .mono { font-family: var(--font-mono); }

    .skip-link {
      position: absolute;
      left: var(--s4);
      top: -48px;
      padding: var(--s2) var(--s3);
      background: var(--green);
      color: #041109;
      font-weight: 700;
      z-index: 200;
      transition: top var(--dur) var(--ease);
    }
    .skip-link:focus { top: var(--s2); }

    /* ── Üst çubuk ───────────────────────────────────────────────────── */
    .topbar {
      position: sticky;
      top: 0;
      z-index: 40;
      background: rgba(6, 8, 9, 0.92);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      border-bottom: 1px solid var(--line);
    }

    .topbar-inner {
      width: min(1600px, 100%);
      margin: 0 auto;
      padding: var(--s3) var(--s5);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: var(--s4);
    }

    .brand { display: flex; align-items: center; gap: var(--s3); min-width: 0; }

    .brand-mark {
      width: 36px; height: 36px;
      display: grid; place-items: center;
      border: 1px solid rgba(var(--green-rgb), 0.45);
      border-radius: var(--radius);
      color: var(--green);
      background: var(--green-soft);
    }
    .brand-mark svg { width: 20px; height: 20px; }

    .brand-text { min-width: 0; }

    .brand-title {
      margin: 0;
      font-size: 16px;
      font-weight: 700;
      letter-spacing: 0.01em;
      color: var(--text);
      display: flex;
      align-items: center;
      white-space: nowrap;
    }
    .brand-title .host { color: var(--green); }
    .brand-title .sep { color: var(--text-3); }
    .brand-title .path { color: var(--cyan); }

    .caret {
      display: inline-block;
      width: 8px; height: 16px;
      margin-left: 6px;
      background: var(--green);
      animation: blink 1.1s steps(1) infinite;
    }

    .brand-sub {
      margin: 2px 0 0;
      font-size: 12px;
      color: var(--text-3);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .actions { display: flex; align-items: center; gap: var(--s2); flex: none; }

    /* ── Butonlar ────────────────────────────────────────────────────── */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: var(--s2);
      min-height: 40px;
      padding: 0 var(--s4);
      border: 1px solid var(--line-2);
      border-radius: var(--radius);
      background: var(--surface-2);
      color: var(--text-2);
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      white-space: nowrap;
      transition: color var(--dur) var(--ease), border-color var(--dur) var(--ease), background-color var(--dur) var(--ease);
    }
    .btn svg { width: 16px; height: 16px; }
    .btn:hover:not(:disabled) { color: var(--text); border-color: var(--text-3); background: var(--surface-3); }
    .btn:active:not(:disabled) { transform: translateY(1px); }
    .btn:disabled { opacity: 0.4; }

    .btn-live .dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--text-3);
    }
    .btn-live.live {
      color: var(--green);
      border-color: rgba(var(--green-rgb), 0.5);
      background: var(--green-soft);
    }
    .btn-live.live .dot {
      background: var(--green);
      box-shadow: 0 0 0 0 rgba(var(--green-rgb), 0.6);
      animation: pulse 1.8s var(--ease) infinite;
    }

    .btn-threat .count {
      min-width: 22px;
      padding: 1px 6px;
      border-radius: 2px;
      background: var(--red);
      color: #1a0306;
      font-size: 12px;
      font-weight: 800;
      text-align: center;
    }
    .btn-threat.active {
      color: var(--red);
      border-color: rgba(255, 97, 112, 0.55);
      background: var(--red-soft);
    }
    .btn-threat[aria-expanded="true"] { border-color: var(--text-3); }

    .icon-btn {
      width: 40px; height: 40px;
      display: inline-grid; place-items: center;
      border: 1px solid var(--line-2);
      border-radius: var(--radius);
      background: var(--surface-2);
      color: var(--text-2);
      transition: color var(--dur) var(--ease), border-color var(--dur) var(--ease);
    }
    .icon-btn svg { width: 16px; height: 16px; }
    .icon-btn:hover:not(:disabled) { color: var(--green); border-color: rgba(var(--green-rgb), 0.5); }
    .icon-btn:disabled { opacity: 0.35; }
    .icon-btn .ico-done { display: none; }
    .icon-btn.copied { color: var(--green); border-color: var(--green); }
    .icon-btn.copied .ico-copy { display: none; }
    .icon-btn.copied .ico-done { display: block; }

    /* ── Durum satırı (tmux/vim status bar) ──────────────────────────── */
    .statusline {
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }

    .statusline-inner {
      width: min(1600px, 100%);
      margin: 0 auto;
      padding: 0 var(--s5);
      display: flex;
      align-items: stretch;
      overflow-x: auto;
      scrollbar-width: none;
    }
    .statusline-inner::-webkit-scrollbar { display: none; }

    .sl-item {
      display: flex;
      align-items: center;
      gap: var(--s2);
      padding: var(--s2) var(--s4);
      border-right: 1px solid var(--line);
      white-space: nowrap;
      min-height: 40px;
    }
    .sl-item:first-child { padding-left: 0; }
    .sl-item:last-child { border-right: 0; }

    .sl-key {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-3);
    }

    .sl-val { font-size: 13px; color: var(--text); }

    .sl-file { min-width: 0; }
    .sl-file .sl-val {
      max-width: 38ch;
      overflow: hidden;
      text-overflow: ellipsis;
      color: var(--cyan);
    }

    /* Durum etiketleri: renk + metin + işaret birlikte kullanılır. */
    .status-badge, .seal-badge, .threat-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      font-weight: 600;
      color: var(--text-2);
    }
    .status-badge::before, .seal-badge::before {
      content: "";
      width: 7px; height: 7px;
      border-radius: 50%;
      background: var(--text-3);
    }
    .status-badge.live { color: var(--green); }
    .status-badge.live::before { background: var(--green); animation: pulse 1.8s var(--ease) infinite; }
    .status-badge.retry { color: var(--amber); }
    .status-badge.retry::before { background: var(--amber); animation: blink 0.9s steps(1) infinite; }
    .status-badge.error { color: var(--red); }
    .status-badge.error::before { background: var(--red); }

    .seal-badge.ok { color: var(--green); }
    .seal-badge.ok::before { background: var(--green); }
    .seal-badge.error { color: var(--red); }
    .seal-badge.error::before { background: var(--red); }

    .threat-badge {
      min-width: 28px;
      justify-content: center;
      padding: 2px 8px;
      border: 1px solid var(--line-2);
      border-radius: 2px;
      background: transparent;
      cursor: pointer;
    }
    .threat-badge:hover { border-color: var(--text-3); color: var(--text); }
    .threat-badge.active {
      color: #1a0306;
      background: var(--red);
      border-color: var(--red);
    }

    /* ── Ana yerleşim ────────────────────────────────────────────────── */
    .shell {
      width: min(1600px, 100%);
      margin: 0 auto;
      padding: var(--s5);
      display: grid;
      gap: var(--s4);
    }

    .panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      min-width: 0;
    }

    .panel-head {
      display: flex;
      align-items: center;
      gap: var(--s2);
      padding: var(--s2) var(--s4);
      min-height: 40px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }

    .panel-tag {
      font-size: 11px;
      font-weight: 700;
      color: var(--green);
      letter-spacing: 0.06em;
    }
    .panel-tag::before { content: "["; color: var(--text-3); }
    .panel-tag::after { content: "]"; color: var(--text-3); }

    .panel-title {
      margin: 0;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--text-2);
    }

    .panel-head .spacer { flex: 1; }

    .panel-meta { font-size: 12px; color: var(--text-3); }

    .panel-sub {
      margin: 2px 0 0;
      font-size: 12px;
      color: var(--text-3);
    }

    /* ── Gösterge kartları ───────────────────────────────────────────── */
    .metrics {
      display: grid;
      grid-template-columns: minmax(0, 1.5fr) minmax(0, 1fr) minmax(0, 1fr);
      gap: var(--s4);
    }

    .metric-body { padding: var(--s4); display: grid; gap: var(--s3); }

    .live-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--line-2);
      transition: background-color var(--dur) var(--ease);
    }
    .live-dot.active { background: var(--green); animation: pulse 1.8s var(--ease) infinite; }

    .rate-top {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: var(--s3);
      flex-wrap: wrap;
    }

    .metric-value { display: flex; align-items: baseline; gap: var(--s2); }

    .stat-number {
      font-size: 40px;
      font-weight: 700;
      line-height: 1;
      letter-spacing: -0.02em;
      color: var(--green);
      text-shadow: 0 0 18px rgba(var(--green-rgb), 0.25);
    }

    .stat-unit {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-3);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .rate-legend { display: flex; gap: var(--s3); font-size: 12px; color: var(--text-3); }
    .rate-legend strong { color: var(--text-2); font-weight: 600; }

    .rate-chart {
      position: relative;
      height: 88px;
      border: 1px solid var(--line);
      border-radius: 2px;
      background:
        linear-gradient(rgba(var(--green-rgb), 0.05) 1px, transparent 1px) 0 0 / 100% 25%,
        var(--bg);
    }
    .rate-chart canvas { position: absolute; inset: 0; width: 100%; height: 100%; }

    .sha-label {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-3);
    }

    .sha-row { display: flex; align-items: center; gap: var(--s2); }

    .seal-sha {
      flex: 1;
      min-width: 0;
      padding: var(--s2) var(--s3);
      min-height: 40px;
      display: flex;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 2px;
      background: var(--bg);
      color: var(--cyan);
      font-size: 13px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .seal-foot {
      font-size: 12px;
      color: var(--text-2);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .seal-foot::before { content: "› "; color: var(--green); }

    .kv { margin: 0; display: grid; gap: 2px; }

    .kv-row {
      display: flex;
      align-items: baseline;
      gap: var(--s2);
      padding: 6px 0;
    }
    .kv-row dt {
      display: flex;
      align-items: center;
      gap: var(--s2);
      color: var(--text-2);
      font-size: 13px;
    }
    .kv-row dt { flex: 1; min-width: 0; }
    .kv-row dt::after {
      content: "";
      flex: 1;
      min-width: 16px;
      border-bottom: 1px dotted var(--line-2);
      transform: translateY(4px);
    }
    .kv-row dd { margin: 0; font-size: 14px; font-weight: 600; color: var(--text); }
    .kv-row.total { margin-top: var(--s1); padding-top: var(--s2); border-top: 1px solid var(--line); }
    .kv-row.total dt { color: var(--text); font-weight: 700; }
    .kv-row.total dd { color: var(--green); }

    .kv-dot { width: 8px; height: 8px; border-radius: 1px; }
    .kv-dot.hourly { background: var(--cyan); }
    .kv-dot.daily { background: var(--violet); }
    .kv-dot.monthly { background: var(--amber); }
    .kv-dot.total { background: var(--green); }

    /* ── "Log gelmiyor" uyarısı ──────────────────────────────────────── */
    .alert-banner {
      display: flex;
      align-items: center;
      gap: var(--s3);
      padding: var(--s3) var(--s4);
      border: 1px solid rgba(245, 184, 61, 0.5);
      border-left-width: 4px;
      border-radius: var(--radius);
      background: var(--amber-soft);
      color: var(--amber);
    }
    .alert-banner[hidden] { display: none; }
    .alert-icon svg { width: 20px; height: 20px; }
    .alert-text { flex: 1; min-width: 0; }
    .alert-title {
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .alert-detail { font-size: 13px; color: var(--text); }
    .alert-pulse {
      width: 10px; height: 10px;
      background: var(--amber);
      animation: blink 1s steps(1) infinite;
    }

    /* ── Log tablosu ─────────────────────────────────────────────────── */
    .log-head {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: var(--s4);
      flex-wrap: wrap;
      padding: var(--s3) var(--s4);
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }

    .log-title { display: flex; align-items: baseline; gap: var(--s2); min-width: 0; }
    .log-title .panel-title { font-size: 13px; }

    .toolbar { display: flex; align-items: flex-end; gap: var(--s3); flex-wrap: wrap; }

    .field { display: grid; gap: 4px; }
    .field label, .field .field-label {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-3);
    }

    .select {
      appearance: none;
      -webkit-appearance: none;
      min-width: 132px;
      min-height: 40px;
      padding: 0 34px 0 var(--s3);
      border: 1px solid var(--line-2);
      border-radius: var(--radius);
      background:
        url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2372887f' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E") no-repeat right 10px center / 14px,
        var(--bg);
      color: var(--text);
      font-size: 13px;
      cursor: pointer;
      transition: border-color var(--dur) var(--ease);
    }
    .select:hover:not(:disabled) { border-color: var(--text-3); }
    .select:disabled { opacity: 0.4; cursor: not-allowed; }
    .select option { background: var(--surface-2); color: var(--text); }

    .pager { display: flex; align-items: center; gap: var(--s2); }
    .pager .btn { padding: 0 var(--s3); }
    .pager-info {
      min-width: 72px;
      text-align: center;
      font-size: 13px;
      color: var(--text);
    }

    .table-wrap {
      overflow: auto;
      max-height: 72vh;
    }

    .log-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    .log-table thead th {
      position: sticky;
      top: 0;
      z-index: 1;
      padding: 10px var(--s4);
      background: var(--surface-2);
      border-bottom: 1px solid var(--line-2);
      text-align: left;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-3);
      white-space: nowrap;
    }
    .log-table th.num, .log-table td.num { text-align: right; }

    .log-table tbody td {
      padding: 7px var(--s4);
      border-bottom: 1px solid var(--line);
      white-space: nowrap;
      color: var(--text);
    }
    .log-table tbody tr { transition: background-color var(--dur) var(--ease); }
    .log-table tbody tr:nth-child(even) { background: rgba(255, 255, 255, 0.012); }
    .log-table tbody tr:hover { background: var(--surface-3); }

    .cell-time { color: var(--text-3); }
    .cell-ip-src { color: var(--cyan); }
    .cell-ip-dst { color: var(--violet); }
    .cell-port { color: var(--text-2); }
    .cell-size { color: var(--text-2); }

    .arrow { color: var(--text-3); padding: 0 !important; width: 1ch; }

    .row-enter { animation: rowEnter 1.4s var(--ease); }
    .row-enter td:first-child { box-shadow: inset 2px 0 0 var(--green); }

    .proto {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 1px 7px;
      border: 1px solid currentColor;
      border-radius: 2px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.06em;
      color: var(--text-2);
    }
    .proto .lock { width: 11px; height: 11px; color: var(--green); }
    .proto.tcp { color: var(--cyan); background: var(--cyan-soft); }
    .proto.udp { color: var(--amber); background: var(--amber-soft); }
    .proto.icmp, .proto.icmpv6 { color: var(--violet); background: var(--violet-soft); }

    .empty-row td { padding: 56px var(--s4) !important; text-align: center; color: var(--text-3); white-space: normal !important; }
    .empty-title { color: var(--text-2); font-weight: 700; margin-bottom: 4px; }
    .empty-title::before { content: "$ "; color: var(--green); }

    /* ── Güvenlik çekmecesi ──────────────────────────────────────────── */
    .threat-modal {
      position: fixed;
      inset: 0;
      z-index: 60;
      display: flex;
      justify-content: flex-end;
    }
    .threat-modal[hidden] { display: none; }

    .threat-modal-backdrop {
      position: absolute;
      inset: 0;
      background: rgba(2, 4, 5, 0.72);
      backdrop-filter: blur(3px);
      -webkit-backdrop-filter: blur(3px);
      animation: fadeIn var(--dur) var(--ease);
    }

    .threat-modal-panel {
      position: relative;
      width: min(600px, 100%);
      height: 100%;
      display: flex;
      flex-direction: column;
      background: var(--surface);
      border-left: 1px solid var(--line-2);
      box-shadow: -24px 0 48px rgba(0, 0, 0, 0.5);
      animation: slideIn 240ms var(--ease);
      overscroll-behavior: contain;
    }
    .threat-modal-panel.has-threats { border-left-color: rgba(255, 97, 112, 0.6); }

    .drawer-head {
      display: grid;
      gap: var(--s3);
      padding: var(--s4) var(--s5);
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }

    .drawer-title-row { display: flex; align-items: flex-start; gap: var(--s3); }

    .threat-mark {
      width: 36px; height: 36px;
      display: grid; place-items: center;
      border: 1px solid var(--line-2);
      border-radius: var(--radius);
      color: var(--green);
      flex: none;
    }
    .threat-mark svg { width: 18px; height: 18px; }
    .has-threats .threat-mark { color: var(--red); border-color: rgba(255, 97, 112, 0.55); background: var(--red-soft); }

    .drawer-title-text { flex: 1; min-width: 0; }

    .threat-title {
      margin: 0;
      display: flex;
      align-items: center;
      gap: var(--s2);
      font-size: 15px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }

    .threat-count {
      padding: 1px 7px;
      border-radius: 2px;
      background: var(--red);
      color: #1a0306;
      font-size: 12px;
      font-weight: 800;
    }

    .threat-subtitle { margin: 4px 0 0; font-size: 12px; color: var(--text-3); line-height: 1.55; }

    .threat-status {
      display: inline-flex;
      align-items: center;
      gap: var(--s2);
      justify-self: start;
      padding: 4px 10px;
      border: 1px solid currentColor;
      border-radius: 2px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }
    .threat-status::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
    .threat-status.ok { color: var(--green); background: var(--green-soft); }
    .threat-status.alert { color: var(--red); background: var(--red-soft); }
    .threat-status.alert::before { animation: blink 0.9s steps(1) infinite; }

    .drawer-body {
      flex: 1;
      overflow-y: auto;
      padding: var(--s4) var(--s5) var(--s6);
      display: grid;
      align-content: start;
      gap: var(--s5);
    }

    .drawer-section { display: grid; gap: var(--s3); }

    .section-head { display: grid; gap: 4px; }

    .section-title {
      display: flex;
      align-items: center;
      gap: var(--s2);
      margin: 0;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--text-2);
    }
    .section-title svg { width: 14px; height: 14px; color: var(--text-3); }
    .section-title::before { content: "//"; color: var(--green); }

    .section-sub { margin: 0; font-size: 12px; color: var(--text-3); line-height: 1.6; }
    .section-sub .mono { color: var(--text-2); }

    .threat-list { display: grid; gap: var(--s2); }

    .threat-empty {
      display: flex;
      align-items: center;
      gap: var(--s3);
      padding: var(--s4);
      border: 1px dashed var(--line-2);
      border-radius: var(--radius);
      font-size: 13px;
      color: var(--text-2);
    }
    .threat-empty[hidden] { display: none; }
    .threat-empty svg { width: 18px; height: 18px; color: var(--green); }

    .threat-item {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: var(--s3);
      padding: var(--s3);
      border: 1px solid var(--line);
      border-left: 3px solid var(--amber);
      border-radius: var(--radius);
      background: var(--surface-2);
    }
    .threat-item.high { border-left-color: var(--red); }

    .threat-sev {
      align-self: start;
      padding: 2px 6px;
      border: 1px solid currentColor;
      border-radius: 2px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--amber);
    }
    .threat-item.high .threat-sev { color: var(--red); background: var(--red-soft); }

    .threat-body { min-width: 0; display: grid; gap: 4px; }

    .threat-item-title {
      display: flex;
      align-items: center;
      gap: var(--s2);
      flex-wrap: wrap;
      font-size: 13px;
      font-weight: 700;
      color: var(--text);
    }

    .threat-hits {
      padding: 0 6px;
      border-radius: 2px;
      background: var(--surface-3);
      color: var(--text-2);
      font-size: 11px;
      font-weight: 700;
    }

    .threat-meta { font-size: 12px; color: var(--text-2); line-height: 1.55; overflow-wrap: anywhere; }

    .threat-actions { display: flex; flex-wrap: wrap; gap: var(--s2); margin-top: 4px; }

    .chip-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      min-height: 32px;
      padding: 0 10px;
      border: 1px solid var(--line-2);
      border-radius: 2px;
      background: var(--bg);
      color: var(--text-2);
      font-size: 12px;
      font-weight: 600;
      transition: color var(--dur) var(--ease), border-color var(--dur) var(--ease), background-color var(--dur) var(--ease);
    }
    .chip-btn svg { width: 13px; height: 13px; }
    .chip-btn:hover:not(:disabled) { color: var(--text); border-color: var(--text-3); }

    .threat-copy-ip { color: var(--cyan); }
    .threat-copy-ip.copied { color: var(--green); border-color: var(--green); }
    .threat-copy-ip.copied .threat-copy-label::after { content: " ✓"; }

    .threat-ban { color: var(--red); border-color: rgba(255, 97, 112, 0.45); }
    .threat-ban:hover:not(:disabled) { color: #1a0306; background: var(--red); border-color: var(--red); }
    .threat-ban.banned, .threat-ban:disabled { color: var(--text-3); border-color: var(--line-2); background: transparent; opacity: 1; }

    .threat-time { align-self: start; font-size: 12px; color: var(--text-3); }

    .inline-form { display: flex; gap: var(--s2); }

    .text-input {
      flex: 1;
      min-width: 0;
      min-height: 40px;
      padding: 0 var(--s3);
      border: 1px solid var(--line-2);
      border-radius: var(--radius);
      background: var(--bg);
      color: var(--text);
      font-size: 13px;
      transition: border-color var(--dur) var(--ease);
    }
    .text-input::placeholder { color: var(--text-3); }
    .text-input:hover { border-color: var(--text-3); }
    .text-input:focus-visible { outline-offset: 0; border-color: var(--green); }

    .btn-danger { color: var(--red); border-color: rgba(255, 97, 112, 0.5); background: var(--red-soft); }
    .btn-danger:hover:not(:disabled) { color: #1a0306; background: var(--red); border-color: var(--red); }

    .btn-accent { color: var(--green); border-color: rgba(var(--green-rgb), 0.5); background: var(--green-soft); }
    .btn-accent:hover:not(:disabled) { color: #041109; background: var(--green); border-color: var(--green); }

    .form-error {
      padding: var(--s2) var(--s3);
      border: 1px solid rgba(255, 97, 112, 0.5);
      border-radius: 2px;
      background: var(--red-soft);
      color: var(--red);
      font-size: 12px;
    }
    .form-error::before { content: "ERR "; font-weight: 800; }
    .form-error[hidden] { display: none; }

    .chip-list { display: flex; flex-wrap: wrap; gap: var(--s2); }

    .list-empty { font-size: 12px; color: var(--text-3); }
    .list-empty::before { content: "∅ "; }
    .list-empty[hidden] { display: none; }

    .entry-chip {
      display: inline-flex;
      align-items: center;
      gap: var(--s2);
      min-height: 32px;
      padding: 0 4px 0 10px;
      border: 1px solid var(--line-2);
      border-radius: 2px;
      background: var(--surface-2);
      font-size: 12px;
      color: var(--text);
    }
    .entry-chip.cidr { border-style: dashed; }
    .entry-chip.blocked { border-color: rgba(255, 97, 112, 0.45); }
    .entry-chip.blocked .entry-ip { color: var(--red); }
    .entry-chip.allowed .entry-ip { color: var(--green); }

    .entry-rule { color: var(--text-3); font-size: 11px; max-width: 24ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .entry-remove {
      width: 26px; height: 26px;
      display: grid; place-items: center;
      border: 0;
      border-radius: 2px;
      background: transparent;
      color: var(--text-3);
      transition: color var(--dur) var(--ease), background-color var(--dur) var(--ease);
    }
    .entry-remove svg { width: 12px; height: 12px; }
    .entry-remove:hover { color: var(--red); background: var(--red-soft); }

    .drawer-divider { height: 1px; background: var(--line); }

    /* ── IP bağlantıları ─────────────────────────────────────────────── */
    .ip-link {
      padding: 0;
      border: 0;
      background: none;
      color: inherit;
      font: inherit;
      text-decoration: underline dotted transparent;
      text-underline-offset: 3px;
      transition: text-decoration-color var(--dur) var(--ease), color var(--dur) var(--ease);
    }
    .ip-link:hover { text-decoration-color: currentColor; color: var(--text); }

    /* ── IP ayrıntı modalı ───────────────────────────────────────────── */
    .ip-modal {
      position: fixed;
      inset: 0;
      z-index: 70;
      display: grid;
      place-items: center;
      padding: var(--s5);
    }
    .ip-modal[hidden] { display: none; }

    .ip-modal-backdrop {
      position: absolute;
      inset: 0;
      background: rgba(2, 4, 5, 0.78);
      backdrop-filter: blur(3px);
      -webkit-backdrop-filter: blur(3px);
      animation: fadeIn var(--dur) var(--ease);
    }

    .ip-dialog {
      position: relative;
      width: min(1180px, 100%);
      max-height: calc(100vh - 40px);
      display: flex;
      flex-direction: column;
      background: var(--surface);
      border: 1px solid var(--line-2);
      border-radius: var(--radius);
      box-shadow: 0 24px 64px rgba(0, 0, 0, 0.6);
      animation: popIn 200ms var(--ease);
    }

    .ip-head {
      display: flex;
      align-items: flex-start;
      gap: var(--s3);
      padding: var(--s4) var(--s5);
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }

    .ip-head-main { flex: 1; min-width: 0; display: grid; gap: var(--s2); }

    .ip-title-row { display: flex; align-items: center; gap: var(--s2); flex-wrap: wrap; }

    .ip-title {
      margin: 0;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: var(--cyan);
      overflow-wrap: anywhere;
    }
    .ip-title::before { content: "$ whois "; color: var(--text-3); font-size: 13px; font-weight: 500; letter-spacing: 0; }

    .ip-ptr { font-size: 12px; color: var(--text-2); overflow-wrap: anywhere; }
    .ip-ptr::before { content: "ptr › "; color: var(--green); }

    .tag-row { display: flex; flex-wrap: wrap; gap: 6px; }

    .tag {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 8px;
      border: 1px solid var(--line-2);
      border-radius: 2px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      color: var(--text-2);
    }
    .tag.ok { color: var(--green); border-color: rgba(var(--green-rgb), 0.45); background: var(--green-soft); }
    .tag.warn { color: var(--amber); border-color: rgba(245, 184, 61, 0.45); background: var(--amber-soft); }
    .tag.bad { color: var(--red); border-color: rgba(255, 97, 112, 0.5); background: var(--red-soft); }
    .tag.info { color: var(--cyan); border-color: rgba(92, 202, 242, 0.4); background: var(--cyan-soft); }

    .ip-head-actions { display: flex; gap: var(--s2); flex: none; }

    .ip-body {
      flex: 1;
      overflow-y: auto;
      padding: var(--s4) var(--s5) var(--s5);
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: var(--s4);
      align-content: start;
    }

    .ip-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: var(--s3);
    }

    .ip-card {
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface-2);
      min-width: 0;
    }
    .ip-card-head {
      padding: var(--s2) var(--s3);
      border-bottom: 1px solid var(--line);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--text-2);
    }
    .ip-card-head::before { content: "// "; color: var(--green); }
    .ip-card-body { padding: var(--s3); display: grid; gap: 6px; }

    .ip-kv { display: grid; grid-template-columns: 11ch minmax(0, 1fr); gap: var(--s2); font-size: 12px; }
    .ip-kv dt { color: var(--text-3); }
    .ip-kv dd { margin: 0; color: var(--text); overflow-wrap: anywhere; }

    .ip-note { font-size: 12px; color: var(--text-3); }

    .ip-threat {
      display: grid;
      gap: 2px;
      padding: var(--s2);
      border-left: 3px solid var(--amber);
      background: var(--bg);
      font-size: 12px;
    }
    .ip-threat.high { border-left-color: var(--red); }
    .ip-threat strong { color: var(--text); }
    .ip-threat span { color: var(--text-2); }

    .ip-stats {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface-2);
    }
    .ip-stat { padding: var(--s3); border-right: 1px solid var(--line); min-width: 0; }
    .ip-stat:last-child { border-right: 0; }
    .ip-stat-label {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-3);
    }
    .ip-stat-value {
      margin-top: 2px;
      font-size: 18px;
      font-weight: 700;
      color: var(--text);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .ip-stat-value.green { color: var(--green); }
    .ip-stat-sub { font-size: 11px; color: var(--text-3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    .ip-tops { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--s3); }

    .top-list { margin: 0; padding: 0; list-style: none; display: grid; gap: 4px; }
    .top-item {
      position: relative;
      display: flex;
      align-items: center;
      gap: var(--s2);
      padding: 5px var(--s2);
      font-size: 12px;
      isolation: isolate;
    }
    .top-bar {
      position: absolute;
      inset: 0 auto 0 0;
      background: rgba(var(--green-rgb), 0.08);
      border-right: 1px solid rgba(var(--green-rgb), 0.35);
      z-index: -1;
    }
    .top-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text); }
    .top-name .ip-link { color: var(--violet); }
    .top-val { color: var(--text-2); white-space: nowrap; }

    .ip-traffic { border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; }
    .ip-traffic-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: var(--s3);
      flex-wrap: wrap;
      padding: var(--s2) var(--s3);
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }
    .ip-traffic .table-wrap { max-height: 46vh; }

    .dir {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }
    .dir.out { color: var(--amber); }
    .dir.in { color: var(--cyan); }

    .log-table td.self { color: var(--text); font-weight: 700; }

    .ip-loading {
      padding: 48px var(--s4);
      text-align: center;
      color: var(--text-3);
      font-size: 13px;
    }
    .ip-loading::after {
      content: "▌";
      margin-left: 4px;
      color: var(--green);
      animation: blink 1s steps(1) infinite;
    }

    /* ── Animasyonlar ────────────────────────────────────────────────── */
    @keyframes blink { 50% { opacity: 0; } }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(var(--green-rgb), 0.55); }
      70% { box-shadow: 0 0 0 6px rgba(var(--green-rgb), 0); }
      100% { box-shadow: 0 0 0 0 rgba(var(--green-rgb), 0); }
    }
    @keyframes rowEnter {
      from { background-color: rgba(var(--green-rgb), 0.16); }
      to { background-color: transparent; }
    }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    @keyframes popIn { from { transform: translateY(8px); opacity: 0; } to { transform: none; opacity: 1; } }
    @keyframes slideIn { from { transform: translateX(24px); opacity: 0; } to { transform: none; opacity: 1; } }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
      .caret { opacity: 1; }
    }

    /* ── Duyarlı düzen ───────────────────────────────────────────────── */
    @media (max-width: 1180px) {
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .metric-rate { grid-column: 1 / -1; }
    }

    @media (max-width: 1000px) {
      .ip-grid { grid-template-columns: minmax(0, 1fr); }
      .ip-stats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .ip-stat:nth-child(3n) { border-right: 0; }
    }

    @media (max-width: 720px) {
      .topbar-inner, .statusline-inner, .shell { padding-left: var(--s4); padding-right: var(--s4); }
      .shell { padding-top: var(--s4); padding-bottom: var(--s4); }
      .brand-sub { display: none; }
      .brand-mark { display: none; }
      .btn .btn-text { display: none; }
      .btn { padding: 0 var(--s3); }
      .metrics { grid-template-columns: minmax(0, 1fr); }
      .stat-number { font-size: 34px; }
      .toolbar { width: 100%; display: grid; grid-template-columns: 1fr 1fr; }
      .toolbar .field-pager { grid-column: 1 / -1; }
      .select { width: 100%; min-width: 0; }
      .pager { justify-content: space-between; }
      .drawer-head, .drawer-body { padding-left: var(--s4); padding-right: var(--s4); }
      .threat-item { grid-template-columns: 1fr; }
      .threat-time { order: -1; }
      .ip-modal { padding: 0; }
      .ip-dialog { max-height: 100vh; height: 100%; border: 0; border-radius: 0; }
      .ip-head, .ip-body { padding-left: var(--s4); padding-right: var(--s4); }
      .ip-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .ip-stat:nth-child(2n) { border-right: 0; }
      .ip-stat { border-bottom: 1px solid var(--line); }
      .ip-tops { grid-template-columns: minmax(0, 1fr); }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#log-panel">Log kayıtlarına geç</a>

  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 12h4l2 6 4-14 2 8h6"/>
          </svg>
        </span>
        <div class="brand-text">
          <h1 class="brand-title"><span class="host">netflow</span><span class="sep">@</span><span>logger</span><span class="sep">:</span><span class="path">~</span><span class="sep">$</span><span class="caret" aria-hidden="true"></span></h1>
          <p class="brand-sub">NetFlow v9 · saatlik mühürlü kayıt paneli</p>
        </div>
      </div>
      <nav class="actions" aria-label="Görünüm">
        <button type="button" class="btn btn-live live" id="live-toggle" title="Canlı SSE akışına dön">
          <span class="dot" aria-hidden="true"></span>
          <span id="live-toggle-label">Canlı</span>
        </button>
        <button type="button" class="btn btn-threat" id="threat-toggle" aria-haspopup="dialog" aria-expanded="false" aria-controls="threat-modal" title="Güvenlik uyarılarını göster">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5z"/><path d="M12 8v4"/><path d="M12 16h.01"/>
          </svg>
          <span class="btn-text">Güvenlik</span>
          <span class="count" id="threat-toggle-count" hidden>0</span>
        </button>
      </nav>
    </div>
  </header>

  <div class="statusline">
    <div class="statusline-inner">
      <div class="sl-item">
        <span class="sl-key">Bağlantı</span>
        <span class="status-badge" id="connection" role="status" aria-live="polite">Bağlanıyor</span>
      </div>
      <div class="sl-item">
        <span class="sl-key">Güncelleme</span>
        <span class="sl-val" id="updated-at">-</span>
      </div>
      <div class="sl-item sl-file">
        <span class="sl-key">Dosya</span>
        <span class="sl-val" id="active-file" title="Aktif log dosyası">-</span>
      </div>
      <div class="sl-item">
        <span class="sl-key">Mühür</span>
        <span class="seal-badge" id="seal-badge">Bekliyor</span>
      </div>
      <div class="sl-item">
        <span class="sl-key">Tehdit</span>
        <span class="threat-badge" id="threat-badge">0</span>
      </div>
    </div>
  </div>

  <main class="shell">
    <section class="metrics" aria-label="Özet göstergeler">
      <article class="panel metric-rate">
        <header class="panel-head">
          <span class="panel-tag">01</span>
          <h2 class="panel-title">Akış hızı</h2>
          <span class="spacer"></span>
          <span class="live-dot" id="rate-dot" aria-hidden="true"></span>
        </header>
        <div class="metric-body">
          <div class="rate-top">
            <div class="metric-value">
              <span class="stat-number" id="throughput-rate">0</span>
              <span class="stat-unit">paket/sn</span>
            </div>
            <div class="rate-legend">
              <span id="rate-peak">tepe 0</span>
              <span>son 2 dk</span>
            </div>
          </div>
          <div class="rate-chart">
            <canvas id="rate-spark" role="img" aria-label="Son 2 dakikalık paket akış hızı grafiği"></canvas>
          </div>
        </div>
      </article>

      <article class="panel">
        <header class="panel-head">
          <span class="panel-tag">02</span>
          <h2 class="panel-title">Bütünlük mührü</h2>
        </header>
        <div class="metric-body">
          <span class="sha-label">Son SHA-256 özeti</span>
          <div class="sha-row">
            <code class="seal-sha" id="seal-sha" title="Son SHA-256 özeti">SHA-256 henüz yok</code>
            <button type="button" class="icon-btn" id="copy-sha" title="SHA-256 kopyala" disabled aria-label="SHA-256 özetini kopyala">
              <svg class="ico-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>
              </svg>
              <svg class="ico-done" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M20 6 9 17l-5-5"/>
              </svg>
            </button>
          </div>
          <div class="seal-foot" id="seal-detail" title="Son TSA durumu">TSA: bekleniyor</div>
        </div>
      </article>

      <article class="panel">
        <header class="panel-head">
          <span class="panel-tag">03</span>
          <h2 class="panel-title">Dosya boyutları</h2>
        </header>
        <div class="metric-body">
          <dl class="kv">
            <div class="kv-row">
              <dt><span class="kv-dot hourly" aria-hidden="true"></span>Saatlik</dt>
              <dd id="file-size-hourly">-</dd>
            </div>
            <div class="kv-row">
              <dt><span class="kv-dot daily" aria-hidden="true"></span>Günlük</dt>
              <dd id="file-size-daily">-</dd>
            </div>
            <div class="kv-row">
              <dt><span class="kv-dot monthly" aria-hidden="true"></span>Aylık</dt>
              <dd id="file-size-monthly">-</dd>
            </div>
            <div class="kv-row total">
              <dt><span class="kv-dot total" aria-hidden="true"></span>Toplam</dt>
              <dd id="file-size-total">-</dd>
            </div>
          </dl>
        </div>
      </article>
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

    <section class="panel log-panel" id="log-panel" tabindex="-1" aria-labelledby="log-title">
      <header class="log-head">
        <div>
          <div class="log-title">
            <span class="panel-tag">04</span>
            <h2 class="panel-title" id="log-title">Log kayıtları</h2>
          </div>
          <p class="panel-sub" id="table-subtitle">Canlı modda bellekte tutulan en yeni 1000 kayıt sayfalı olarak gösterilir.</p>
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
            <label for="limit-select">Satır</label>
            <select id="limit-select" class="select">
              <option value="50" selected>50</option>
              <option value="100">100</option>
              <option value="250">250</option>
              <option value="500">500</option>
            </select>
          </div>
          <div class="field field-pager">
            <span class="field-label" id="pager-label">Sayfa</span>
            <div class="pager" role="group" aria-labelledby="pager-label">
              <button type="button" class="btn" id="prev-page" aria-label="Önceki sayfa">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m15 18-6-6 6-6"/></svg>
              </button>
              <span class="pager-info" id="page-info" aria-live="polite">1 / 1</span>
              <button type="button" class="btn" id="next-page" aria-label="Sonraki sayfa">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 18 6-6-6-6"/></svg>
              </button>
            </div>
          </div>
        </div>
      </header>
      <div class="table-wrap">
        <table class="log-table">
          <thead>
            <tr>
              <th scope="col">Zaman</th>
              <th scope="col">Kaynak IP</th>
              <th scope="col" class="num">Kaynak Port</th>
              <th scope="col" class="arrow" aria-hidden="true"></th>
              <th scope="col">Hedef IP</th>
              <th scope="col" class="num">Hedef Port</th>
              <th scope="col">Protokol</th>
              <th scope="col" class="num">Boyut</th>
            </tr>
          </thead>
          <tbody id="records"></tbody>
        </table>
      </div>
    </section>
  </main>

  <div class="threat-modal" id="threat-modal" hidden>
    <div class="threat-modal-backdrop" data-threat-close></div>
    <section class="threat-card threat-modal-panel" id="threat-card" role="dialog" aria-modal="true" aria-labelledby="threat-modal-title">
      <header class="drawer-head">
        <div class="drawer-title-row">
          <span class="threat-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5z"/><path d="M12 8v4"/><path d="M12 16h.01"/>
            </svg>
          </span>
          <div class="drawer-title-text">
            <h2 class="threat-title" id="threat-modal-title">Güvenlik izleme
              <span class="threat-count" id="threat-count" hidden>0</span>
            </h2>
            <p class="threat-subtitle">Akış trafiği arka planda sürekli analiz edilir; brute-force ve port/host tarama denemeleri tespit edilir.</p>
          </div>
          <button type="button" class="icon-btn threat-close" data-threat-close aria-label="Güvenlik panelini kapat">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
            </svg>
          </button>
        </div>
        <span class="threat-status ok" id="threat-status" role="status">Şüpheli aktivite yok</span>
      </header>

      <div class="drawer-body">
        <div class="drawer-section">
          <div class="section-head">
            <h3 class="section-title">Aktif uyarılar</h3>
          </div>
          <div class="threat-list" id="threat-list">
            <div class="threat-empty" id="threat-empty">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5z"/><path d="M9 12l2 2 4-4"/>
              </svg>
              <span>Şu an şüpheli bir aktivite tespit edilmedi.</span>
            </div>
          </div>
        </div>

        <div class="drawer-divider" aria-hidden="true"></div>

        <div class="drawer-section">
          <div class="section-head">
            <h3 class="section-title">Engellenen kaynaklar</h3>
            <p class="section-sub">Buraya eklenen IP adresleri kalıcı olarak kara listeye alınır ve <span class="mono">/blocklist</span> endpoint'i üzerinden güvenlik duvarına (OPNsense) yansır. Kayıtlar <span class="mono">blocklist.json</span> içinde tutulur; <span class="mono">config.json</span>'a dokunulmaz.</p>
          </div>
          <form class="inline-form" id="blocklist-form" autocomplete="off">
            <input type="text" class="text-input" id="blocklist-input" placeholder="203.0.113.5" spellcheck="false" aria-label="Engellenecek IP" />
            <button type="submit" class="btn btn-danger">Engelle</button>
          </form>
          <div class="form-error" id="blocklist-error" role="alert" hidden></div>
          <div class="chip-list" id="blocklist-list">
            <div class="list-empty" id="blocklist-empty">Elle engellenen kaynak yok.</div>
          </div>
        </div>

        <div class="drawer-divider" aria-hidden="true"></div>

        <div class="drawer-section">
          <div class="section-head">
            <h3 class="section-title">Görmezden gelinen kaynaklar</h3>
            <p class="section-sub">Buraya eklenen kaynak IP adresleri veya CIDR blokları (ör. <span class="mono">10.0.0.0/24</span>) tehdit analizinde tamamen yok sayılır. Ayarlar <span class="mono">config.json</span> içinde kalıcı tutulur.</p>
          </div>
          <form class="inline-form" id="whitelist-form" autocomplete="off">
            <input type="text" class="text-input" id="whitelist-input" placeholder="192.168.1.10 veya 10.0.0.0/24" spellcheck="false" aria-label="Whitelist girişi" />
            <button type="submit" class="btn btn-accent">Ekle</button>
          </form>
          <div class="form-error" id="whitelist-error" role="alert" hidden></div>
          <div class="chip-list" id="whitelist-list">
            <div class="list-empty" id="whitelist-empty">Henüz görmezden gelinen kaynak eklenmedi.</div>
          </div>
        </div>
      </div>
    </section>
  </div>

  <div class="ip-modal" id="ip-modal" hidden>
    <div class="ip-modal-backdrop" data-ip-close></div>
    <section class="ip-dialog" id="ip-dialog" role="dialog" aria-modal="true" aria-labelledby="ip-title">
      <header class="ip-head">
        <div class="ip-head-main">
          <div class="ip-title-row">
            <h2 class="ip-title" id="ip-title">-</h2>
          </div>
          <div class="ip-ptr" id="ip-ptr" hidden></div>
          <div class="tag-row" id="ip-tags"></div>
        </div>
        <div class="ip-head-actions">
          <button type="button" class="icon-btn" id="ip-copy" aria-label="IP adresini kopyala" title="IP adresini kopyala">
            <svg class="ico-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>
            </svg>
            <svg class="ico-done" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M20 6 9 17l-5-5"/>
            </svg>
          </button>
          <button type="button" class="icon-btn ip-close" data-ip-close aria-label="IP ayrıntılarını kapat">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
            </svg>
          </button>
        </div>
      </header>
      <div class="ip-body" id="ip-body">
        <div class="ip-loading" id="ip-loading">IP bilgileri alınıyor</div>
        <div class="form-error" id="ip-error" role="alert" hidden></div>
        <div id="ip-content" hidden>
          <div class="ip-grid">
            <div class="ip-card">
              <div class="ip-card-head">Kimlik</div>
              <dl class="ip-card-body ip-kv" id="ip-identity"></dl>
            </div>
            <div class="ip-card">
              <div class="ip-card-head">Konum / ASN</div>
              <div class="ip-card-body" id="ip-geo"></div>
            </div>
            <div class="ip-card">
              <div class="ip-card-head">Güvenlik</div>
              <div class="ip-card-body" id="ip-security"></div>
            </div>
          </div>

          <div class="ip-stats" id="ip-stats" style="margin-top: 16px"></div>

          <div class="ip-tops" style="margin-top: 16px">
            <div class="ip-card">
              <div class="ip-card-head">En çok konuşulan eşler</div>
              <div class="ip-card-body"><ul class="top-list" id="ip-top-peers"></ul></div>
            </div>
            <div class="ip-card">
              <div class="ip-card-head">En çok kullanılan servisler</div>
              <div class="ip-card-body"><ul class="top-list" id="ip-top-ports"></ul></div>
            </div>
          </div>

          <div class="ip-traffic" style="margin-top: 16px">
            <div class="ip-traffic-head">
              <span class="panel-title">Trafik kayıtları</span>
              <span class="panel-meta" id="ip-scan-note"></span>
            </div>
            <div class="table-wrap">
              <table class="log-table">
                <thead>
                  <tr>
                    <th scope="col">Zaman</th>
                    <th scope="col">Yön</th>
                    <th scope="col">Kaynak IP</th>
                    <th scope="col" class="num">Kaynak Port</th>
                    <th scope="col" class="arrow" aria-hidden="true"></th>
                    <th scope="col">Hedef IP</th>
                    <th scope="col" class="num">Hedef Port</th>
                    <th scope="col">Protokol</th>
                    <th scope="col" class="num">Boyut</th>
                  </tr>
                </thead>
                <tbody id="ip-records"></tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>

  <script>
    'use strict';

    const $ = (id) => document.getElementById(id);

    const updatedAtEl = $('updated-at');
    const recordsEl = $('records');
    const connectionEl = $('connection');
    const dateSelectEl = $('date-select');
    const hourSelectEl = $('hour-select');
    const limitSelectEl = $('limit-select');
    const liveToggleEl = $('live-toggle');
    const liveToggleLabelEl = $('live-toggle-label');
    const tableSubtitleEl = $('table-subtitle');
    const prevPageEl = $('prev-page');
    const nextPageEl = $('next-page');
    const pageInfoEl = $('page-info');
    const fileSizeHourlyEl = $('file-size-hourly');
    const fileSizeDailyEl = $('file-size-daily');
    const fileSizeMonthlyEl = $('file-size-monthly');
    const fileSizeTotalEl = $('file-size-total');
    const throughputRateEl = $('throughput-rate');
    const rateDotEl = $('rate-dot');
    const rateSparkEl = $('rate-spark');
    const ratePeakEl = $('rate-peak');
    const activeFileEl = $('active-file');
    const sealBadgeEl = $('seal-badge');
    const sealShaEl = $('seal-sha');
    const sealDetailEl = $('seal-detail');
    const copyShaEl = $('copy-sha');
    const noDataEl = $('no-data-alert');
    const noDataDetailEl = $('no-data-detail');
    const threatCardEl = $('threat-card');
    const threatListEl = $('threat-list');
    const threatEmptyEl = $('threat-empty');
    const threatCountEl = $('threat-count');
    const threatStatusEl = $('threat-status');
    const threatBadgeEl = $('threat-badge');
    const threatModalEl = $('threat-modal');
    const threatToggleEl = $('threat-toggle');
    const threatToggleCountEl = $('threat-toggle-count');
    const whitelistFormEl = $('whitelist-form');
    const whitelistInputEl = $('whitelist-input');
    const whitelistErrorEl = $('whitelist-error');
    const whitelistListEl = $('whitelist-list');
    const whitelistEmptyEl = $('whitelist-empty');
    const blocklistFormEl = $('blocklist-form');
    const blocklistInputEl = $('blocklist-input');
    const blocklistErrorEl = $('blocklist-error');
    const blocklistListEl = $('blocklist-list');
    const blocklistEmptyEl = $('blocklist-empty');

    const ICON_X = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>';
    const ICON_COPY = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
    const ICON_BAN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg>';
    const ICON_INFO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>';
    const ICON_LOCK = '<svg class="lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>';

    let eventSource = null;
    let livePollTimer = null;
    let currentMode = 'live';
    let currentPage = 1;

    let lastProcessed = null;
    let lastProcessedAt = 0;
    let rateEma = 0;
    let currentSha = '';

    // Canlı akış grafiği: rateEma sabit aralıkla örneklenir; son 2 dakika
    // (120 örnek) bir halka tamponda tutulur. Zaman ekseni olay sıklığından bağımsızdır.
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

    function cssVar(name) {
      return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    function formatRate(value) {
      return numberFmt.format(Math.max(0, Math.round(value)));
    }

    function basename(path) {
      if (!path) return '';
      const clean = String(path).replace(/[\\/]+$/, '');
      const idx = Math.max(clean.lastIndexOf('/'), clean.lastIndexOf('\\'));
      return idx >= 0 ? clean.slice(idx + 1) : clean;
    }

    // Akış hızı, saatlik sıfırlanan packets_total sayacının türevinden pps olarak
    // hesaplanır. Saat dönümünde sayaç düşerse baz yenilenir; sahte sıçrama olmaz.
    function updateThroughput(state) {
      const total = Number(state.packets_total);
      if (!Number.isFinite(total)) return;

      const now = performance.now();
      if (lastProcessed !== null && total < lastProcessed) {
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

    function prepareRateCanvas() {
      if (!rateSparkEl) return null;
      const dpr = window.devicePixelRatio || 1;
      const w = rateSparkEl.clientWidth || 300;
      const h = rateSparkEl.clientHeight || 88;
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

    // Son 2 dakikalık akış hızını fosfor yeşili basamaklı alan grafiği olarak çizer.
    function drawRateChart() {
      const env = prepareRateCanvas();
      if (!env) return;
      const { ctx, w, h } = env;
      ctx.clearRect(0, 0, w, h);

      const n = rateSamples.length;
      const peak = n ? Math.max.apply(null, rateSamples) : 0;
      ratePeakEl.innerHTML = 'tepe <strong>' + formatRate(peak) + '</strong>';
      rateSparkEl.setAttribute('aria-label', 'Son 2 dakikalık paket akış hızı grafiği, tepe ' + formatRate(peak) + ' paket/sn');

      if (n < 2 || peak <= 0) return;

      const green = cssVar('--green') || '#3ee08a';
      const rgb = cssVar('--green-rgb') || '62, 224, 138';
      const padTop = 8;
      const baseY = h - 1;
      const stepX = w / (RATE_WINDOW - 1);
      const scaleY = (baseY - padTop) / peak;
      const offset = RATE_WINDOW - n;
      const xAt = (i) => (offset + i) * stepX;
      const yAt = (v) => baseY - v * scaleY;

      const grad = ctx.createLinearGradient(0, padTop, 0, baseY);
      grad.addColorStop(0, 'rgba(' + rgb + ', 0.32)');
      grad.addColorStop(1, 'rgba(' + rgb + ', 0.02)');

      ctx.beginPath();
      ctx.moveTo(xAt(0), baseY);
      for (let i = 0; i < n; i++) ctx.lineTo(xAt(i), yAt(rateSamples[i]));
      ctx.lineTo(xAt(n - 1), baseY);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const x = xAt(i), y = yAt(rateSamples[i]);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.lineJoin = 'round';
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = green;
      ctx.stroke();

      // Tepe çizgisi (kesikli).
      const py = Math.round(yAt(peak)) + 0.5;
      ctx.setLineDash([3, 4]);
      ctx.strokeStyle = 'rgba(' + rgb + ', 0.35)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, py);
      ctx.lineTo(w, py);
      ctx.stroke();
      ctx.setLineDash([]);

      // Son nokta: terminal imleci gibi küçük kare.
      const lx = xAt(n - 1), ly = yAt(rateSamples[n - 1]);
      ctx.fillStyle = green;
      ctx.fillRect(Math.min(lx, w - 4) - 2, ly - 2, 5, 5);
    }

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

    let resizeFrame = null;
    window.addEventListener('resize', () => {
      if (resizeFrame !== null) return;
      resizeFrame = requestAnimationFrame(() => {
        resizeFrame = null;
        drawRateChart();
      });
    });

    function noteDataActivity(state) {
      const total = Number(state.processed_total);
      if (!Number.isFinite(total)) return;
      if (lastDataValue === null || total > lastDataValue) {
        lastDataAt = performance.now();
      }
      lastDataValue = total;
    }

    function showNoDataAlert(idleMs) {
      const secs = Math.max(0, Math.round(idleMs / 1000));
      noDataDetailEl.textContent =
        'Dinlenen porta ' + secs + ' sn’dir NetFlow kaydı ulaşmıyor — arka planda kontrol ediliyor…';
      if (noDataEl.hidden) noDataEl.hidden = false;
    }

    function hideNoDataAlert() {
      if (!noDataEl.hidden) noDataEl.hidden = true;
    }

    // Yalnızca canlı + 1. sayfada anlamlıdır.
    function evaluateDataFlow() {
      if (currentMode !== 'live' || currentPage !== 1) {
        hideNoDataAlert();
        return;
      }
      const idle = performance.now() - lastDataAt;
      if (idle > IDLE_THRESHOLD_MS) showNoDataAlert(idle);
      else hideNoDataAlert();
    }

    function updateIntegrity(state) {
      const file = state.active_file || '';
      activeFileEl.textContent = basename(file) || '-';
      activeFileEl.title = file || 'Aktif log dosyası';

      const sha = state.last_sha256 || '';
      currentSha = sha;
      if (sha) {
        sealShaEl.textContent = sha.slice(0, 16) + '…' + sha.slice(-16);
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
      return date.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
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

    // Yaygın portlar → servis adı. Yalnızca arayüzde gösterim amaçlı.
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

    // Şifreli/güvenli servisler (kilit simgesiyle vurgulanır).
    const SECURE_SERVICES = {
      'SSH': 1, 'HTTPS': 1, 'HTTPS-Alt': 1, 'SMTPS': 1, 'IMAPS': 1,
      'POP3S': 1, 'LDAPS': 1, 'FTPS': 1, 'DoT': 1, 'SIP-TLS': 1,
      'MQTT-TLS': 1, 'OpenVPN': 1, 'WireGuard': 1, 'IPsec': 1, 'IKE': 1
    };

    // Sunucu portu genelde küçük/bilinen olandır; iki port da eşleşirse küçüğü baz alınır.
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

    function ipLink(ip) {
      if (!ip || ip === '-') return escapeHtml(ip);
      return '<button type="button" class="ip-link" data-ip="' + escapeHtml(ip) + '" title="' + escapeHtml(ip) + ' ayrıntıları">' + escapeHtml(ip) + '</button>';
    }

    function protoMarkup(item) {
      const protoLabel = item.service || item.proto;
      const protoTitle = item.service
        ? item.proto + ' · Port ' + item.servicePort + ' · ' + item.service
        : item.proto;
      const lock = (item.service && item.serviceSecure) ? ICON_LOCK : '';
      return '<span class="proto ' + escapeHtml(item.protoClass) + '" title="' + escapeHtml(protoTitle) + '">' + lock + escapeHtml(protoLabel) + '</span>';
    }

    function buildRowMarkup(record) {
      const item = parseRecord(record);
      // Bilinen port eşleşirse servis adı, yoksa taşıma protokolü gösterilir;
      // renk her zaman taşıma protokolüne göredir.
      const protoLabel = item.service || item.proto;
      const protoTitle = item.service
        ? item.proto + ' · Port ' + item.servicePort + ' · ' + item.service
        : item.proto;
      const lock = (item.service && item.serviceSecure) ? ICON_LOCK : '';
      return '<tr>'
        + '<td class="cell-time">' + escapeHtml(item.time) + '</td>'
        + '<td class="cell-ip-src">' + ipLink(item.srcIp) + '</td>'
        + '<td class="num cell-port">' + escapeHtml(item.srcPort) + '</td>'
        + '<td class="arrow" aria-hidden="true">→</td>'
        + '<td class="cell-ip-dst">' + ipLink(item.dstIp) + '</td>'
        + '<td class="num cell-port">' + escapeHtml(item.dstPort) + '</td>'
        + '<td><span class="proto ' + escapeHtml(item.protoClass) + '" title="' + escapeHtml(protoTitle) + '">' + lock + escapeHtml(protoLabel) + '</span></td>'
        + '<td class="num cell-size">' + escapeHtml(item.size) + '</td>'
        + '</tr>';
    }

    const emptyRowsMarkup = '<tr class="empty-row"><td colspan="8"><div class="empty-title">kayıt bulunamadı</div><div>Seçilen gün ve saat için gösterilecek log kaydı yok.</div></td></tr>';

    // Statik (geçmiş) görünüm: tam yeniden çizim, sunucu sırasıyla.
    function renderRows(records) {
      liveRowsInit = false;
      lastRowsTotal = null;
      if (!records.length) {
        recordsEl.innerHTML = emptyRowsMarkup;
        return;
      }
      recordsEl.innerHTML = records.map(buildRowMarkup).join('');
    }

    // Giriş vurgusunu ekler ve bittikten sonra temizler.
    function markEntered(rowEls) {
      rowEls.forEach((el) => el.classList.add('row-enter'));
      setTimeout(() => rowEls.forEach((el) => el.classList.remove('row-enter')), 1500);
    }

    // Canlı görünüm: en yeni kayıtlar üstte; yalnızca yeni gelenler vurguyla eklenir.
    function renderLiveRows(state) {
      const records = state.records || [];
      const total = Number(state.processed_total);
      const reversed = records.slice().reverse();

      if (!reversed.length) {
        recordsEl.innerHTML = emptyRowsMarkup;
        liveRowsInit = false;
        lastRowsTotal = Number.isFinite(total) ? total : null;
        return;
      }

      let newCount;
      if (!liveRowsInit || lastRowsTotal === null || !Number.isFinite(total)) {
        newCount = reversed.length;
      } else {
        newCount = total - lastRowsTotal;
        if (newCount < 0) newCount = reversed.length;
      }
      if (newCount > reversed.length) newCount = reversed.length;

      // Yeniden kullanılacak satır sayısı DOM'da yoksa güvenli tarafta kalıp tam çizeriz.
      const firstInit = !liveRowsInit;
      if (newCount !== reversed.length && recordsEl.childElementCount < reversed.length - newCount) {
        newCount = reversed.length;
      }

      if (newCount === 0) {
        // Yeni kayıt yok → DOM'a dokunma.
      } else if (newCount === reversed.length) {
        recordsEl.innerHTML = reversed.map(buildRowMarkup).join('');
        if (!firstInit) {
          markEntered(Array.prototype.slice.call(recordsEl.children, 0, Math.min(recordsEl.childElementCount, 14)));
        }
      } else {
        let html = '';
        for (let i = 0; i < newCount; i += 1) html += buildRowMarkup(reversed[i]);
        recordsEl.insertAdjacentHTML('afterbegin', html);
        const added = Array.prototype.slice.call(recordsEl.children, 0, newCount);
        while (recordsEl.childElementCount > reversed.length) {
          recordsEl.removeChild(recordsEl.lastElementChild);
        }
        markEntered(added);
      }

      liveRowsInit = true;
      if (Number.isFinite(total)) lastRowsTotal = total;
    }

    function setConnectionState(text, mode) {
      connectionEl.textContent = text;
      connectionEl.className = 'status-badge' + (mode ? ' ' + mode : '');
    }

    function renderDateOptions(dates, selectedDate) {
      dateSelectEl.innerHTML = '<option value="">Canlı görünüm</option>';
      (dates || []).forEach((date) => {
        const option = document.createElement('option');
        option.value = date;
        option.textContent = date;
        if (date === selectedDate) option.selected = true;
        dateSelectEl.appendChild(option);
      });
    }

    function renderHourOptions(hours, selectedHour) {
      hourSelectEl.innerHTML = '<option value="">Saat seç</option>';
      (hours || []).forEach((hour) => {
        const option = document.createElement('option');
        option.value = hour;
        option.textContent = hour + ':00';
        if (hour === selectedHour) option.selected = true;
        hourSelectEl.appendChild(option);
      });
      hourSelectEl.disabled = !(hours && hours.length);
    }

    function applyMode(mode) {
      currentMode = mode;
      const live = mode !== 'historical';
      liveToggleEl.classList.toggle('live', live);
      liveToggleLabelEl.textContent = live ? 'Canlı' : 'Canlıya dön';
      tableSubtitleEl.textContent = live
        ? 'Canlı modda yeni kayıtlar üste eklenir, eskiler aşağı kayar. En yeni 1000 kayıt sayfalı tutulur.'
        : 'Seçilen saatlik log dosyasının başından belirlenen satır sayısı gösterilir.';
    }

    const THREAT_RULE_LABELS = {
      bruteforce: 'Brute-force',
      portscan: 'Port tarama',
      hostsweep: 'Host tarama'
    };
    let lastThreatSig = null;
    let lastThreatList = null;
    // Şu an manuel engelli IP'ler; tehdit satırındaki "Banla" butonunun durumunu belirler.
    const bannedIps = new Set();
    let lastBlocklistSig = null;

    function updateThreats(threats) {
      const list = Array.isArray(threats) ? threats : [];
      lastThreatList = list;
      const count = list.length;
      const active = count > 0;

      threatBadgeEl.textContent = String(count);
      threatBadgeEl.classList.toggle('active', active);
      threatToggleEl.classList.toggle('active', active);
      threatToggleEl.title = active
        ? (count + ' aktif güvenlik uyarısı — görüntülemek için tıkla')
        : 'Güvenlik uyarılarını göster';
      threatToggleCountEl.textContent = String(count);
      threatToggleCountEl.hidden = !active;
      threatCardEl.classList.toggle('has-threats', active);
      threatCountEl.textContent = String(count);
      threatCountEl.hidden = !active;
      threatStatusEl.textContent = active ? (count + ' aktif uyarı') : 'Şüpheli aktivite yok';
      threatStatusEl.className = 'threat-status ' + (active ? 'alert' : 'ok');

      // Banlı IP kümesi de imzaya katılır ki buton durumu tazelensin.
      const sig = JSON.stringify(list) + '|' + Array.from(bannedIps).sort().join(',');
      if (sig === lastThreatSig) return;
      lastThreatSig = sig;

      threatListEl.querySelectorAll('.threat-item').forEach((n) => n.remove());
      threatEmptyEl.hidden = active;
      if (!active) return;

      const rows = list.map((a) => {
        const sev = a.severity === 'high' ? 'high' : 'medium';
        const sevLabel = sev === 'high' ? 'Yüksek' : 'Orta';
        const rule = THREAT_RULE_LABELS[a.rule] || 'Şüpheli';
        const hits = a.count ? '<span class="threat-hits">' + escapeHtml(String(a.count)) + '×</span>' : '';
        const detail = a.detail ? escapeHtml(a.detail) : (rule + ' tespit edildi.');
        const ip = a.src_ip ? String(a.src_ip) : '';
        const copyIp = ip
          ? '<button type="button" class="chip-btn threat-copy-ip" data-ip="' + escapeHtml(ip) + '" title="Kaynak IP adresini kopyala">'
            + ICON_COPY + '<span class="threat-copy-label">' + escapeHtml(ip) + '</span></button>'
          : '';
        const detailBtn = ip
          ? '<button type="button" class="chip-btn ip-link-btn" data-ip="' + escapeHtml(ip) + '" title="IP ayrıntılarını ve trafiğini göster">'
            + ICON_INFO + '<span>Ayrıntı</span></button>'
          : '';
        const banned = ip && bannedIps.has(ip);
        const banBtn = ip
          ? '<button type="button" class="chip-btn threat-ban' + (banned ? ' banned' : '') + '" data-ip="' + escapeHtml(ip) + '"'
            + ' data-reason="' + escapeHtml(a.title || rule) + '"' + (banned ? ' disabled' : '')
            + ' title="Bu IP\'yi kalıcı olarak engelle">'
            + ICON_BAN + '<span>' + (banned ? 'Engellendi' : 'Banla') + '</span></button>'
          : '';
        return '<div class="threat-item ' + sev + '">'
          + '<span class="threat-sev">' + sevLabel + '</span>'
          + '<div class="threat-body">'
          +   '<div class="threat-item-title">' + escapeHtml(a.title || rule) + hits + '</div>'
          +   '<div class="threat-meta">' + detail + '</div>'
          +   '<div class="threat-actions">' + copyIp + detailBtn + banBtn + '</div>'
          + '</div>'
          + '<span class="threat-time">' + escapeHtml(formatTime(a.last_seen || '')) + '</span>'
          + '</div>';
      }).join('');
      threatListEl.insertAdjacentHTML('beforeend', rows);
    }

    let renderFrame = null;
    let pendingState = null;

    function commitRender(state) {
      const mode = state.mode || 'live';
      if (mode === 'live' && currentMode === 'historical') return;
      applyMode(mode);
      currentPage = state.page || 1;
      const totalPages = state.total_pages || 1;
      renderDateOptions(state.available_dates || [], state.selected_date || '');
      renderHourOptions(state.available_hours || [], state.selected_hour || '');
      limitSelectEl.value = String(state.limit || 50);
      updatedAtEl.textContent = formatTime(state.updated_at || '');
      pageInfoEl.textContent = currentPage + ' / ' + totalPages;
      fileSizeHourlyEl.textContent = state.file_size || '-';
      fileSizeDailyEl.textContent = state.file_size_daily || '-';
      fileSizeMonthlyEl.textContent = state.file_size_monthly || '-';
      fileSizeTotalEl.textContent = state.file_size_total || '-';
      updateIntegrity(state);
      if (Array.isArray(state.threats)) updateThreats(state.threats);
      const isLive = mode === 'live';
      if (isLive) {
        updateThroughput(state);
        noteDataActivity(state);
      } else {
        resetThroughput();
      }
      prevPageEl.disabled = currentPage <= 1;
      nextPageEl.disabled = currentPage >= totalPages;
      if (isLive && currentPage === 1) renderLiveRows(state);
      else renderRows(state.records || []);
      evaluateDataFlow();
    }

    function render(state) {
      pendingState = state;
      if (renderFrame !== null) return;
      renderFrame = requestAnimationFrame(() => {
        if (pendingState) commitRender(pendingState);
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
      if (dateSelectEl.value) params.set('date', dateSelectEl.value);
      if (hourSelectEl.value) params.set('hour', hourSelectEl.value);
      params.set('limit', limitSelectEl.value || '50');
      params.set('page', String(currentPage || 1));

      const response = await fetch('/api/state?' + params.toString(), { cache: 'no-store' });
      if (!response.ok) throw new Error('Log durumu alınamadı');
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
        setConnectionState('Canlı akış yalnızca 1. sayfada', null);
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

    // Canlı akış: SSE ile sunucudan anlık itme.
    function startLiveStream() {
      stopLiveStream();
      setConnectionState('Canlı', 'live');

      if (typeof window.EventSource === 'undefined') {
        startLivePolling();
        return;
      }

      const params = new URLSearchParams();
      params.set('limit', limitSelectEl.value || '50');
      eventSource = new EventSource('/events?' + params.toString());

      eventSource.addEventListener('state', (event) => {
        let state;
        try {
          state = JSON.parse(event.data);
        } catch (err) {
          return;
        }
        setConnectionState('Canlı', 'live');
        // Tehdit rozeti, tablonun sayfa/modundan bağımsız olarak her zaman güncellenir.
        if (Array.isArray(state.threats)) updateThreats(state.threats);
        if (currentMode !== 'live' || currentPage !== 1) return;
        state.mode = 'live';
        render(state);
      });

      eventSource.onerror = () => {
        setConnectionState('Yeniden bağlanıyor', 'retry');
      };
    }

    // Yedek yol: SSE yoksa saniyelik yoklama.
    function startLivePolling() {
      stopLiveStream();
      setConnectionState('Canlı', 'live');
      livePollTimer = setInterval(() => {
        if (currentMode !== 'live' || currentPage !== 1) return;
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
      if (!dateSelectEl.value || !hourSelectEl.value) return;
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

    // ── Güvenlik çekmecesi ─────────────────────────────────────────────
    let threatLastFocus = null;
    let securityPollTimer = null;

    // Çekmece açıkken tehditleri (/api/threats) ve kara listeyi (/api/blocklist)
    // SSE'den bağımsız olarak tazeler; geçmiş modda veya 2+. sayfada da güncel kalır.
    async function refreshSecurityPanel() {
      try {
        const res = await fetch('/api/threats', { cache: 'no-store' });
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.threats)) updateThreats(data.threats);
        }
      } catch (err) { /* geçici hata: sonraki yoklamada tekrar denenir */ }
      loadBlocklist();
    }

    function startSecurityPoll() {
      if (securityPollTimer !== null) return;
      securityPollTimer = setInterval(refreshSecurityPanel, 4000);
    }

    function stopSecurityPoll() {
      if (securityPollTimer !== null) {
        clearInterval(securityPollTimer);
        securityPollTimer = null;
      }
    }

    function openThreatModal() {
      if (!threatModalEl.hidden) return;
      threatLastFocus = document.activeElement;
      threatModalEl.hidden = false;
      document.body.style.overflow = 'hidden';
      threatToggleEl.setAttribute('aria-expanded', 'true');
      loadWhitelist();
      refreshSecurityPanel();
      startSecurityPoll();
      const closeBtn = threatModalEl.querySelector('.threat-close');
      if (closeBtn) closeBtn.focus();
    }

    function closeThreatModal() {
      if (threatModalEl.hidden) return;
      threatModalEl.hidden = true;
      if (ipModalEl.hidden) document.body.style.overflow = '';
      stopSecurityPoll();
      threatToggleEl.setAttribute('aria-expanded', 'false');
      if (threatLastFocus && typeof threatLastFocus.focus === 'function') threatLastFocus.focus();
      threatLastFocus = null;
    }

    threatToggleEl.addEventListener('click', () => {
      if (threatModalEl.hidden) openThreatModal();
      else closeThreatModal();
    });

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

    threatModalEl.addEventListener('click', (event) => {
      if (event.target.closest('[data-threat-close]')) closeThreatModal();
    });

    // Tab odağını verilen diyalog içinde tutar.
    function trapFocus(event, container) {
      const focusables = Array.prototype.filter.call(
        container.querySelectorAll('button, input, [tabindex]:not([tabindex="-1"])'),
        (el) => !el.disabled && el.offsetParent !== null
      );
      if (!focusables.length) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (event.shiftKey && (document.activeElement === first || !container.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !container.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    }

    // Esc en üstteki diyaloğu kapatır; Tab odağı en üstteki diyalogda kalır.
    document.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape' && event.key !== 'Tab') return;
      let top = null;
      let close = null;
      if (!ipModalEl.hidden) { top = ipDialogEl; close = closeIpModal; }
      else if (!threatModalEl.hidden) { top = threatCardEl; close = closeThreatModal; }
      if (!top) return;
      if (event.key === 'Escape') {
        close();
        return;
      }
      trapFocus(event, top);
    });

    function showFormError(el, msg) {
      el.textContent = msg || '';
      el.hidden = !msg;
    }

    function chipMarkup(kind, value, extra, removeAttr, removeLabel) {
      return '<span class="entry-chip ' + kind + '">'
        + '<span class="entry-ip">' + (value.indexOf('/') >= 0 ? escapeHtml(value) : ipLink(value)) + '</span>' + extra
        + '<button type="button" class="entry-remove" ' + removeAttr + '="' + escapeHtml(value) + '" aria-label="' + escapeHtml(removeLabel) + '">' + ICON_X + '</button>'
        + '</span>';
    }

    // Whitelist: görmezden gelinen kaynak IP/CIDR girişleri (/api/whitelist → config.json).
    function renderWhitelist(entries) {
      const list = Array.isArray(entries) ? entries : [];
      whitelistListEl.querySelectorAll('.entry-chip').forEach((n) => n.remove());
      whitelistEmptyEl.hidden = list.length > 0;
      if (!list.length) return;
      const html = list.map((entry) => chipMarkup(
        'allowed' + (entry.indexOf('/') >= 0 ? ' cidr' : ''),
        entry, '', 'data-entry', entry + ' kaydını kaldır'
      )).join('');
      whitelistListEl.insertAdjacentHTML('beforeend', html);
    }

    async function jsonRequest(url, options) {
      const response = await fetch(url, options);
      const data = await response.json().catch(() => ({}));
      return { ok: response.ok, data };
    }

    async function loadWhitelist() {
      try {
        const response = await fetch('/api/whitelist', { cache: 'no-store' });
        if (!response.ok) throw new Error('liste alınamadı');
        const data = await response.json();
        renderWhitelist(data.entries);
      } catch (error) {
        showFormError(whitelistErrorEl, 'Whitelist yüklenemedi.');
      }
    }

    async function submitWhitelist(entry) {
      showFormError(whitelistErrorEl, '');
      try {
        const res = await jsonRequest('/api/whitelist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ entry: entry })
        });
        if (!res.ok) {
          showFormError(whitelistErrorEl, res.data.error || 'Giriş eklenemedi.');
          return false;
        }
        renderWhitelist(res.data.entries);
        return true;
      } catch (error) {
        showFormError(whitelistErrorEl, 'Giriş eklenemedi.');
        return false;
      }
    }

    async function removeWhitelist(entry) {
      showFormError(whitelistErrorEl, '');
      try {
        const res = await jsonRequest('/api/whitelist?entry=' + encodeURIComponent(entry), { method: 'DELETE' });
        if (!res.ok) {
          showFormError(whitelistErrorEl, res.data.error || 'Giriş kaldırılamadı.');
          return;
        }
        renderWhitelist(res.data.entries);
      } catch (error) {
        showFormError(whitelistErrorEl, 'Giriş kaldırılamadı.');
      }
    }

    whitelistFormEl.addEventListener('submit', async (event) => {
      event.preventDefault();
      const value = (whitelistInputEl.value || '').trim();
      if (!value) return;
      if (await submitWhitelist(value)) {
        whitelistInputEl.value = '';
        whitelistInputEl.focus();
      }
    });

    whitelistListEl.addEventListener('click', (event) => {
      const btn = event.target.closest('.entry-remove');
      if (btn) removeWhitelist(btn.getAttribute('data-entry'));
    });

    // Manuel kara liste (/api/blocklist → blocklist.json; config.json'a dokunulmaz).
    // Banlı küme değiştiyse tehdit satırları yeniden çizilir.
    function syncBannedIps(entries) {
      const next = new Set();
      (Array.isArray(entries) ? entries : []).forEach((e) => {
        if (e && e.ip) next.add(String(e.ip));
      });
      let changed = next.size !== bannedIps.size;
      if (!changed) next.forEach((ip) => { if (!bannedIps.has(ip)) changed = true; });
      if (!changed) return;
      bannedIps.clear();
      next.forEach((ip) => bannedIps.add(ip));
      lastThreatSig = null;
      if (lastThreatList) updateThreats(lastThreatList);
    }

    function renderBlocklist(entries) {
      const list = (Array.isArray(entries) ? entries : []).filter((e) => e && e.manual);
      // İmza değişmediyse DOM'a dokunma → yoklamada titreme olmaz.
      const sig = JSON.stringify(list.map((e) => [e.ip, e.rule]));
      if (sig === lastBlocklistSig) return;
      lastBlocklistSig = sig;
      blocklistListEl.querySelectorAll('.entry-chip').forEach((n) => n.remove());
      blocklistEmptyEl.hidden = list.length > 0;
      if (!list.length) return;
      const html = list.map((e) => {
        const ip = String(e.ip);
        const rule = e.rule ? '<span class="entry-rule" title="' + escapeHtml(String(e.rule)) + '">' + escapeHtml(String(e.rule)) + '</span>' : '';
        return chipMarkup('blocked', ip, rule, 'data-ip', ip + ' engelini kaldır');
      }).join('');
      blocklistListEl.insertAdjacentHTML('beforeend', html);
    }

    async function loadBlocklist() {
      try {
        const response = await fetch('/api/blocklist', { cache: 'no-store' });
        if (!response.ok) throw new Error('liste alınamadı');
        const data = await response.json();
        syncBannedIps(data.entries);
        renderBlocklist(data.entries);
      } catch (error) {
        showFormError(blocklistErrorEl, 'Engel listesi yüklenemedi.');
      }
    }

    async function submitBlock(ip, reason) {
      showFormError(blocklistErrorEl, '');
      try {
        const res = await jsonRequest('/api/blocklist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: ip, reason: reason || '' })
        });
        if (!res.ok) {
          showFormError(blocklistErrorEl, res.data.error || 'IP engellenemedi.');
          return false;
        }
        syncBannedIps(res.data.entries);
        renderBlocklist(res.data.entries);
        return true;
      } catch (error) {
        showFormError(blocklistErrorEl, 'IP engellenemedi.');
        return false;
      }
    }

    async function removeBlock(ip) {
      showFormError(blocklistErrorEl, '');
      try {
        const res = await jsonRequest('/api/blocklist?ip=' + encodeURIComponent(ip), { method: 'DELETE' });
        if (!res.ok) {
          showFormError(blocklistErrorEl, res.data.error || 'Engel kaldırılamadı.');
          return;
        }
        syncBannedIps(res.data.entries);
        renderBlocklist(res.data.entries);
      } catch (error) {
        showFormError(blocklistErrorEl, 'Engel kaldırılamadı.');
      }
    }

    blocklistFormEl.addEventListener('submit', async (event) => {
      event.preventDefault();
      const value = (blocklistInputEl.value || '').trim();
      if (!value) return;
      if (await submitBlock(value, 'Panelden elle engellendi')) {
        blocklistInputEl.value = '';
        blocklistInputEl.focus();
      }
    });

    blocklistListEl.addEventListener('click', (event) => {
      const btn = event.target.closest('.entry-remove');
      if (btn) removeBlock(btn.getAttribute('data-ip'));
    });

    prevPageEl.addEventListener('click', async () => {
      if (currentPage <= 1) return;
      await changePage(currentPage - 1);
    });

    nextPageEl.addEventListener('click', async () => {
      await changePage(currentPage + 1);
    });

    async function copyToClipboard(text) {
      try {
        await navigator.clipboard.writeText(text);
      } catch (error) {
        const helper = document.createElement('textarea');
        helper.value = text;
        helper.style.position = 'fixed';
        helper.style.opacity = '0';
        document.body.appendChild(helper);
        helper.select();
        try { document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(helper);
      }
    }

    function flashCopied(el) {
      el.classList.add('copied');
      setTimeout(() => el.classList.remove('copied'), 1200);
    }

    copyShaEl.addEventListener('click', async () => {
      if (!currentSha) return;
      await copyToClipboard(currentSha);
      flashCopied(copyShaEl);
    });

    // Tehdit satırlarındaki "IP kopyala" ve "Banla" butonları (event delegation).
    threatListEl.addEventListener('click', async (event) => {
      const banBtn = event.target.closest('.threat-ban');
      if (banBtn) {
        const ip = banBtn.getAttribute('data-ip');
        if (!ip || banBtn.classList.contains('banned') || banBtn.disabled) return;
        banBtn.disabled = true;
        const ok = await submitBlock(ip, banBtn.getAttribute('data-reason') || '');
        if (!ok) banBtn.disabled = false;
        return;
      }
      const btn = event.target.closest('.threat-copy-ip');
      if (!btn) return;
      const ip = btn.getAttribute('data-ip');
      if (!ip) return;
      await copyToClipboard(ip);
      flashCopied(btn);
    });

    // ── IP ayrıntı modalı ─────────────────────────────────────────────
    const ipModalEl = $('ip-modal');
    const ipDialogEl = $('ip-dialog');
    const ipTitleEl = $('ip-title');
    const ipPtrEl = $('ip-ptr');
    const ipTagsEl = $('ip-tags');
    const ipCopyEl = $('ip-copy');
    const ipBodyEl = $('ip-body');
    const ipLoadingEl = $('ip-loading');
    const ipErrorEl = $('ip-error');
    const ipContentEl = $('ip-content');
    const ipIdentityEl = $('ip-identity');
    const ipGeoEl = $('ip-geo');
    const ipSecurityEl = $('ip-security');
    const ipStatsEl = $('ip-stats');
    const ipTopPeersEl = $('ip-top-peers');
    const ipTopPortsEl = $('ip-top-ports');
    const ipRecordsEl = $('ip-records');
    const ipScanNoteEl = $('ip-scan-note');

    // Modal açıkken trafik bu aralıkla tazelenir (konum/DNS tekrar sorgulanmaz).
    const IP_REFRESH_MS = 3000;
    let ipCurrent = '';
    let ipLastFocus = null;
    let ipRefreshTimer = null;
    let ipRequestSeq = 0;
    let ipRecordsSig = '';

    const dateTimeFmt = new Intl.DateTimeFormat('tr-TR', {
      day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    });

    function formatDateTime(value) {
      if (!value) return '-';
      const d = new Date(value);
      return Number.isNaN(d.getTime()) ? value : dateTimeFmt.format(d);
    }

    function kvRow(key, value) {
      return '<dt>' + escapeHtml(key) + '</dt><dd>' + value + '</dd>';
    }

    function tag(text, kind) {
      return '<span class="tag' + (kind ? ' ' + kind : '') + '">' + escapeHtml(text) + '</span>';
    }

    function serviceName(port) {
      return PORT_SERVICES[port] || '';
    }

    function renderIpStatic(info) {
      ipPtrEl.textContent = (info.ptr || []).join(', ');
      ipPtrEl.hidden = !(info.ptr && info.ptr.length);

      const tags = [tag('IPv' + info.version, 'info'), tag(info.scope, info.public ? '' : 'ok')];
      if (info.whitelisted) tags.push(tag('Whitelist', 'ok'));
      if (info.blocked) tags.push(tag(info.blocked.manual ? 'Elle engellendi' : 'Kara listede', 'bad'));
      if (info.threats && info.threats.length) tags.push(tag(info.threats.length + ' aktif uyarı', 'bad'));
      if (info.geo && info.geo.hosting) tags.push(tag('Hosting', 'warn'));
      if (info.geo && info.geo.proxy) tags.push(tag('Proxy / VPN', 'warn'));
      if (info.geo && info.geo.mobile) tags.push(tag('Mobil', ''));
      ipTagsEl.innerHTML = tags.join('');

      ipIdentityEl.innerHTML =
        kvRow('Adres', escapeHtml(info.ip)) +
        kvRow('Sürüm', 'IPv' + info.version) +
        kvRow('Ağ sınıfı', escapeHtml(info.scope)) +
        kvRow('Ters DNS', info.ptr && info.ptr.length ? escapeHtml(info.ptr.join(', ')) : '<span class="ip-note">kayıt yok</span>');

      if (!info.public) {
        ipGeoEl.innerHTML = '<p class="ip-note">Özel/yerel adres; konum sorgulanmaz.</p>';
      } else if (info.geo) {
        const g = info.geo;
        const place = [g.city, g.region].filter(Boolean).join(', ');
        ipGeoEl.innerHTML = '<dl class="ip-kv">'
          + kvRow('Ülke', escapeHtml((g.country || '-') + (g.country_code ? ' (' + g.country_code + ')' : '')))
          + kvRow('Şehir', escapeHtml(place || '-'))
          + kvRow('ISP', escapeHtml(g.isp || '-'))
          + kvRow('Kurum', escapeHtml(g.org || '-'))
          + kvRow('ASN', escapeHtml(g.as || '-'))
          + '</dl><p class="ip-note">Kaynak: ip-api.com</p>';
      } else {
        ipGeoEl.innerHTML = '<p class="ip-note">' + escapeHtml(info.geo_error || 'Konum bilgisi alınamadı.') + '</p>';
      }

      let sec = '<dl class="ip-kv">'
        + kvRow('Whitelist', info.whitelisted ? '<span style="color:var(--green)">Evet — analiz dışı</span>' : 'Hayır');
      if (info.blocked) {
        const b = info.blocked;
        sec += kvRow('Kara liste', '<span style="color:var(--red)">' + (b.manual ? 'Elle engellendi' : 'Otomatik') + '</span>')
          + kvRow('Neden', escapeHtml(b.rule || '-'))
          + (b.manual ? '' : kvRow('Bitiş', escapeHtml(formatDateTime(b.expires_at))));
      } else {
        sec += kvRow('Kara liste', 'Hayır');
      }
      sec += '</dl>';
      if (info.threats && info.threats.length) {
        sec += info.threats.map((t) => '<div class="ip-threat ' + (t.severity === 'high' ? 'high' : '') + '">'
          + '<strong>' + escapeHtml(t.title || THREAT_RULE_LABELS[t.rule] || 'Şüpheli') + (t.count ? ' · ' + escapeHtml(String(t.count)) + '×' : '') + '</strong>'
          + '<span>' + escapeHtml(t.detail || '') + '</span></div>').join('');
      } else {
        sec += '<p class="ip-note">Aktif tehdit uyarısı yok.</p>';
      }
      ipSecurityEl.innerHTML = sec;
    }

    function statCell(label, value, sub, green) {
      return '<div class="ip-stat"><div class="ip-stat-label">' + escapeHtml(label) + '</div>'
        + '<div class="ip-stat-value' + (green ? ' green' : '') + '" title="' + escapeHtml(value) + '">' + escapeHtml(value) + '</div>'
        + '<div class="ip-stat-sub">' + escapeHtml(sub || '\u00a0') + '</div></div>';
    }

    function renderTopList(el, items, labelFn, emptyText) {
      if (!items || !items.length) {
        el.innerHTML = '<li class="ip-note">' + escapeHtml(emptyText) + '</li>';
        return;
      }
      const max = Math.max.apply(null, items.map((i) => i.flows)) || 1;
      el.innerHTML = items.map((i) => '<li class="top-item">'
        + '<span class="top-bar" style="width:' + Math.max(2, Math.round(i.flows / max * 100)) + '%"></span>'
        + '<span class="top-name">' + labelFn(i) + '</span>'
        + '<span class="top-val">' + numberFmt.format(i.flows) + ' akış · ' + escapeHtml(formatBytes(i.bytes)) + '</span>'
        + '</li>').join('');
    }

    function buildIpRowMarkup(record, ip) {
      const item = parseRecord(record);
      const out = item.srcIp === ip;
      const dir = out
        ? '<span class="dir out">↑ Giden</span>'
        : '<span class="dir in">↓ Gelen</span>';
      return '<tr>'
        + '<td class="cell-time">' + escapeHtml(item.time) + '</td>'
        + '<td>' + dir + '</td>'
        + '<td class="cell-ip-src' + (out ? ' self' : '') + '">' + (out ? escapeHtml(item.srcIp) : ipLink(item.srcIp)) + '</td>'
        + '<td class="num cell-port">' + escapeHtml(item.srcPort) + '</td>'
        + '<td class="arrow" aria-hidden="true">→</td>'
        + '<td class="cell-ip-dst' + (out ? '' : ' self') + '">' + (out ? ipLink(item.dstIp) : escapeHtml(item.dstIp)) + '</td>'
        + '<td class="num cell-port">' + escapeHtml(item.dstPort) + '</td>'
        + '<td>' + protoMarkup(item) + '</td>'
        + '<td class="num cell-size">' + escapeHtml(item.size) + '</td>'
        + '</tr>';
    }

    function renderIpTraffic(info) {
      const s = info.summary || {};
      ipStatsEl.innerHTML =
        statCell('Akış', numberFmt.format(s.flows || 0), '', true) +
        statCell('Giden', numberFmt.format(s.outbound || 0), formatBytes(s.bytes_out || 0)) +
        statCell('Gelen', numberFmt.format(s.inbound || 0), formatBytes(s.bytes_in || 0)) +
        statCell('Toplam veri', formatBytes(s.bytes || 0), numberFmt.format(s.packets || 0) + ' paket') +
        statCell('İlk görülme', s.first_seen ? formatTime(s.first_seen) : '-', s.first_seen ? formatDateTime(s.first_seen) : '') +
        statCell('Son görülme', s.last_seen ? formatTime(s.last_seen) : '-', s.last_seen ? formatDateTime(s.last_seen) : '');

      renderTopList(ipTopPeersEl, s.top_peers, (p) => ipLink(p.ip), 'Kayıt yok.');
      renderTopList(ipTopPortsEl, s.top_ports, (p) => {
        const name = serviceName(p.port);
        return escapeHtml(p.protocol + '/' + p.port) + (name ? ' <span style="color:var(--text-3)">· ' + escapeHtml(name) + '</span>' : '');
      }, 'Kayıt yok.');

      ipScanNoteEl.textContent = 'Bellekteki son ' + numberFmt.format(info.scanned || 0) + ' kayıt içinde ' + numberFmt.format((info.records || []).length) + ' eşleşme';

      const records = info.records || [];
      const sig = records.length + '|' + (records[0] || '');
      if (sig === ipRecordsSig) return;
      ipRecordsSig = sig;
      ipRecordsEl.innerHTML = records.length
        ? records.map((r) => buildIpRowMarkup(r, info.ip)).join('')
        : '<tr class="empty-row"><td colspan="9"><div class="empty-title">trafik yok</div><div>Bu IP bellekteki son kayıtlarda görünmüyor.</div></td></tr>';
    }

    async function fetchIpInfo(ip, lite) {
      const seq = ++ipRequestSeq;
      const response = await fetch('/api/ip?ip=' + encodeURIComponent(ip) + (lite ? '&lite=1' : ''), { cache: 'no-store' });
      const data = await response.json().catch(() => ({}));
      if (seq !== ipRequestSeq || ip !== ipCurrent) return null;
      if (!response.ok) throw new Error(data.error || 'IP bilgisi alınamadı');
      return data;
    }

    async function loadIp(ip) {
      ipCurrent = ip;
      ipRecordsSig = '';
      ipTitleEl.textContent = ip;
      ipPtrEl.hidden = true;
      ipTagsEl.innerHTML = '';
      ipContentEl.hidden = true;
      showFormError(ipErrorEl, '');
      ipLoadingEl.hidden = false;
      ipBodyEl.scrollTop = 0;
      try {
        const info = await fetchIpInfo(ip, false);
        if (!info) return;
        renderIpStatic(info);
        renderIpTraffic(info);
        ipContentEl.hidden = false;
      } catch (error) {
        showFormError(ipErrorEl, error.message);
      } finally {
        if (ip === ipCurrent) ipLoadingEl.hidden = true;
      }
    }

    async function refreshIp() {
      if (!ipCurrent || ipContentEl.hidden) return;
      try {
        const info = await fetchIpInfo(ipCurrent, true);
        if (info) renderIpTraffic(info);
      } catch (error) { /* geçici hata: sonraki yoklamada tekrar denenir */ }
    }

    function openIpModal(ip) {
      if (!ip) return;
      if (ipModalEl.hidden) {
        ipLastFocus = document.activeElement;
        ipModalEl.hidden = false;
        document.body.style.overflow = 'hidden';
        ipRefreshTimer = setInterval(refreshIp, IP_REFRESH_MS);
      }
      loadIp(ip);
      const closeBtn = ipModalEl.querySelector('.ip-close');
      if (closeBtn) closeBtn.focus();
    }

    function closeIpModal() {
      if (ipModalEl.hidden) return;
      ipModalEl.hidden = true;
      ipCurrent = '';
      ipRequestSeq++;
      if (ipRefreshTimer !== null) {
        clearInterval(ipRefreshTimer);
        ipRefreshTimer = null;
      }
      if (threatModalEl.hidden) document.body.style.overflow = '';
      if (ipLastFocus && typeof ipLastFocus.focus === 'function' && document.contains(ipLastFocus)) ipLastFocus.focus();
      ipLastFocus = null;
    }

    ipModalEl.addEventListener('click', (event) => {
      if (event.target.closest('[data-ip-close]')) closeIpModal();
    });

    ipCopyEl.addEventListener('click', async () => {
      if (!ipCurrent) return;
      await copyToClipboard(ipCurrent);
      flashCopied(ipCopyEl);
    });

    // Sayfadaki tüm IP bağlantıları (tablo, tehditler, listeler, eşler) tek dinleyiciyle.
    document.addEventListener('click', (event) => {
      const link = event.target.closest('.ip-link, .ip-link-btn');
      if (!link) return;
      event.preventDefault();
      openIpModal(link.getAttribute('data-ip'));
    });

    drawRateChart();
    startRateSampler();

    fetchState().then((state) => {
      if ((state.mode || 'live') === 'live') startLiveStream();
    }).catch((error) => {
      setConnectionState(error.message, 'error');
    });
  </script>
</body>
</html>`
