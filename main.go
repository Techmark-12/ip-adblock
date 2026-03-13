package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

// ==================== CONFIGURATION ====================

type Config struct {
	DNSPort        string   `json:"dns_port"`    // Non-privileged port for Render (e.g., 8053)
	WebPort        string   `json:"web_port"`    // Render web port (default 10000)
	DoHEnabled     bool     `json:"doh_enabled"` // DNS-over-HTTPS
	DoHPath        string   `json:"doh_path"`    // e.g., /dns-query
	UpstreamDNS    []string `json:"upstream_dns"`
	Blocklists     []string `json:"blocklists"`
	BlockingMode   string   `json:"blocking_mode"` // "nxdomain", "null_ip", "refused"
	CustomBlockIP  string   `json:"custom_block_ip"`
	UpdateInterval int      `json:"update_interval_hours"`
	AuthToken      string   `json:"auth_token"` // For DoH authentication
}

var defaultConfig = Config{
	DNSPort:     "8053",  // Non-privileged for Render
	WebPort:     "10000", // Render default
	DoHEnabled:  true,
	DoHPath:     "/dns-query",
	UpstreamDNS: []string{"8.8.8.8:53", "1.1.1.1:53"},
	Blocklists: []string{
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"https://adaway.org/hosts.txt",
		"https://v.firebog.net/hosts/AdguardDNS.txt",
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/light.txt",
	},
	BlockingMode:   "null_ip",
	CustomBlockIP:  "0.0.0.0",
	UpdateInterval: 24,
	AuthToken:      "", // Set via env RENDER_AUTH_TOKEN
}

// ==================== BLOCKLIST MANAGER ====================

type BlocklistManager struct {
	mu           sync.RWMutex
	blockedMap   map[string]struct{}
	blockedRegex []*regexp.Regexp
	cache        map[string]*DNSCacheEntry
	cacheMu      sync.RWMutex
	config       *Config
	upstream     []string
	stats        *Stats
}

type DNSCacheEntry struct {
	Response *dns.Msg
	Expires  time.Time
}

type Stats struct {
	mu              sync.RWMutex
	TotalQueries    int64
	BlockedQueries  int64
	CachedQueries   int64
	UpstreamQueries int64
	StartTime       time.Time
}

func NewBlocklistManager(cfg *Config) *BlocklistManager {
	return &BlocklistManager{
		blockedMap: make(map[string]struct{}),
		cache:      make(map[string]*DNSCacheEntry),
		config:     cfg,
		upstream:   cfg.UpstreamDNS,
		stats:      &Stats{StartTime: time.Now()},
	}
}

func (bm *BlocklistManager) isBlocked(domain string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	domain = strings.ToLower(domain)
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Check exact match
	if _, ok := bm.blockedMap[domain]; ok {
		return true
	}

	// Check parent domains
	labels := dns.SplitDomainName(domain)
	for i := 0; i < len(labels); i++ {
		checkDomain := dns.Fqdn(strings.Join(labels[i:], "."))
		if _, ok := bm.blockedMap[checkDomain]; ok {
			return true
		}
	}

	// Check regex patterns
	for _, re := range bm.blockedRegex {
		if re.MatchString(domain) {
			return true
		}
	}

	return false
}

func (bm *BlocklistManager) addDomain(domain string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = dns.Fqdn(domain)

	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.blockedMap[domain] = struct{}{}
}

func (bm *BlocklistManager) addRegex(pattern string) {
	re, err := regexp.Compile(pattern)
	if err == nil {
		bm.mu.Lock()
		bm.blockedRegex = append(bm.blockedRegex, re)
		bm.mu.Unlock()
	}
}

func (bm *BlocklistManager) getCache(key string) *dns.Msg {
	bm.cacheMu.RLock()
	entry, ok := bm.cache[key]
	bm.cacheMu.RUnlock()

	if !ok || time.Now().After(entry.Expires) {
		return nil
	}

	bm.stats.mu.Lock()
	bm.stats.CachedQueries++
	bm.stats.mu.Unlock()

	return entry.Response.Copy()
}

func (bm *BlocklistManager) setCache(key string, msg *dns.Msg, ttl uint32) {
	bm.cacheMu.Lock()
	defer bm.cacheMu.Unlock()

	// Simple eviction if too large
	if len(bm.cache) >= 10000 {
		bm.cache = make(map[string]*DNSCacheEntry)
	}

	bm.cache[key] = &DNSCacheEntry{
		Response: msg.Copy(),
		Expires:  time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (bm *BlocklistManager) fetchBlocklists() {
	log.Println("🔄 Updating blocklists...")

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	newBlocked := make(map[string]struct{})

	for _, listURL := range bm.config.Blocklists {
		log.Printf("📥 Fetching: %s", listURL)

		resp, err := client.Get(listURL)
		if err != nil {
			log.Printf("❌ Failed to fetch %s: %v", listURL, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
				domain := fields[1]
				if !strings.Contains(domain, "*") && !strings.HasPrefix(domain, "#") {
					newBlocked[dns.Fqdn(strings.ToLower(domain))] = struct{}{}
				}
			} else if len(fields) == 1 && !strings.Contains(fields[0], "*") {
				newBlocked[dns.Fqdn(strings.ToLower(fields[0]))] = struct{}{}
			}
		}
	}

	bm.mu.Lock()
	bm.blockedMap = newBlocked
	bm.mu.Unlock()

	log.Printf("✅ Blocklist updated: %d domains blocked", len(newBlocked))
}

func (bm *BlocklistManager) startAutoUpdate() {
	ticker := time.NewTicker(time.Duration(bm.config.UpdateInterval) * time.Hour)
	go func() {
		bm.fetchBlocklists()
		for {
			<-ticker.C
			bm.fetchBlocklists()
		}
	}()
}

// ==================== DNS HANDLER (UDP/TCP) ====================

type DNSHandler struct {
	manager *BlocklistManager
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	question := r.Question[0]
	domain := question.Name

	h.manager.stats.mu.Lock()
	h.manager.stats.TotalQueries++
	h.manager.stats.mu.Unlock()

	// Check cache
	cacheKey := fmt.Sprintf("%s:%d", domain, question.Qtype)
	if cached := h.manager.getCache(cacheKey); cached != nil {
		cached.Id = r.Id
		w.WriteMsg(cached)
		return
	}

	// Check blocklist
	if h.manager.isBlocked(domain) {
		h.manager.stats.mu.Lock()
		h.manager.stats.BlockedQueries++
		h.manager.stats.mu.Unlock()

		switch h.manager.config.BlockingMode {
		case "nxdomain":
			m.Rcode = dns.RcodeNameError
		case "null_ip":
			if question.Qtype == dns.TypeA {
				rr := &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("0.0.0.0"),
				}
				m.Answer = append(m.Answer, rr)
			} else if question.Qtype == dns.TypeAAAA {
				rr := &dns.AAAA{
					Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("::"),
				}
				m.Answer = append(m.Answer, rr)
			}
		case "refused":
			m.Rcode = dns.RcodeRefused
		}

		w.WriteMsg(m)
		return
	}

	// Forward to upstream
	h.manager.stats.mu.Lock()
	h.manager.stats.UpstreamQueries++
	h.manager.stats.mu.Unlock()

	resp, err := h.forwardQuery(r)
	if err != nil {
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	if len(resp.Answer) > 0 {
		var ttl uint32 = 300
		if len(resp.Answer) > 0 {
			ttl = resp.Answer[0].Header().Ttl
		}
		h.manager.setCache(cacheKey, resp, ttl)
	}

	resp.Id = r.Id
	w.WriteMsg(resp)
}

func (h *DNSHandler) forwardQuery(r *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	for _, server := range h.manager.upstream {
		m, _, err := c.Exchange(r, server)
		if err == nil {
			return m, nil
		}
	}
	return nil, fmt.Errorf("all upstreams failed")
}

// ==================== MOCK WRITER FOR DOH ====================

type mockResponseWriter struct {
	msg *dns.Msg
}

func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.msg = msg
	return nil
}

func (m *mockResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (m *mockResponseWriter) Close() error              { return nil }
func (m *mockResponseWriter) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (m *mockResponseWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{} }
func (m *mockResponseWriter) TsigStatus() error         { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)       {}
func (m *mockResponseWriter) Hijack()                   {}

// ==================== DNS-OVER-HTTPS (DoH) ====================

type DoHServer struct {
	manager *BlocklistManager
	config  *Config
}

func NewDoHServer(manager *BlocklistManager, config *Config) *DoHServer {
	return &DoHServer{manager: manager, config: config}
}

func (d *DoHServer) HandleDoH(c *gin.Context) {
	// Check auth token if configured
	if d.config.AuthToken != "" {
		auth := c.GetHeader("Authorization")
		if auth != "Bearer "+d.config.AuthToken {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			return
		}
	}

	var msg *dns.Msg

	if c.Request.Method == "GET" {
		dnsQuery := c.Query("dns")
		if dnsQuery == "" {
			c.JSON(400, gin.H{"error": "Missing dns parameter"})
			return
		}
		// Base64URL decode
		data, err := base64.RawURLEncoding.DecodeString(dnsQuery)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid base64"})
			return
		}
		msg = new(dns.Msg)
		err = msg.Unpack(data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid DNS message"})
			return
		}
	} else {
		// POST - read body
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(400, gin.H{"error": "Bad request"})
			return
		}
		msg = new(dns.Msg)
		err = msg.Unpack(body)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid DNS message"})
			return
		}
	}

	// Process query using existing logic
	handler := &DNSHandler{manager: d.manager}
	writer := &mockResponseWriter{}
	handler.ServeDNS(writer, msg)

	if writer.msg == nil {
		c.JSON(500, gin.H{"error": "Failed to process query"})
		return
	}

	// Pack response
	packed, err := writer.msg.Pack()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to pack response"})
		return
	}

	c.Data(200, "application/dns-message", packed)
}

// ==================== WEB API ====================

type WebServer struct {
	manager *BlocklistManager
	engine  *gin.Engine
	config  *Config
	doh     *DoHServer
}

func NewWebServer(manager *BlocklistManager, config *Config) *WebServer {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	ws := &WebServer{
		manager: manager,
		engine:  r,
		config:  config,
		doh:     NewDoHServer(manager, config),
	}

	ws.setupRoutes()
	return ws
}

func (ws *WebServer) setupRoutes() {
	// Health check for Render
	ws.engine.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"time":    time.Now(),
			"version": "1.0.0-render",
		})
	})

	// DoH endpoint (DNS-over-HTTPS)
	if ws.config.DoHEnabled {
		ws.engine.POST(ws.config.DoHPath, ws.doh.HandleDoH)
		ws.engine.GET(ws.config.DoHPath, ws.doh.HandleDoH)
		log.Printf("🔒 DoH enabled at: %s", ws.config.DoHPath)
	}

	// API Routes
	api := ws.engine.Group("/api")
	{
		api.GET("/stats", ws.getStats)
		api.GET("/blocked", ws.getBlockedDomains)
		api.POST("/block", ws.addBlockDomain)
		api.DELETE("/block/:domain", ws.removeBlockDomain)
		api.POST("/update-blocklists", ws.triggerUpdate)
	}

	// Dashboard
	ws.engine.Static("/static", "./static")
	ws.engine.LoadHTMLGlob("templates/*")
	ws.engine.GET("/", ws.dashboard)
}

func (ws *WebServer) dashboard(c *gin.Context) {
	ws.manager.stats.mu.RLock()
	stats := map[string]interface{}{
		"total":           ws.manager.stats.TotalQueries,
		"blocked":         ws.manager.stats.BlockedQueries,
		"cached":          ws.manager.stats.CachedQueries,
		"upstream":        ws.manager.stats.UpstreamQueries,
		"uptime":          time.Since(ws.manager.stats.StartTime).String(),
		"blocked_domains": len(ws.manager.blockedMap),
		"doh_url":         "https://" + c.Request.Host + ws.config.DoHPath,
	}
	ws.manager.stats.mu.RUnlock()

	c.HTML(http.StatusOK, "index.html", stats)
}

// FIXED: Removed defer, using explicit Lock/Unlock pattern
func (ws *WebServer) getStats(c *gin.Context) {
	ws.manager.stats.mu.RLock()
	totalQueries := ws.manager.stats.TotalQueries
	blockedQueries := ws.manager.stats.BlockedQueries
	cachedQueries := ws.manager.stats.CachedQueries
	upstreamQueries := ws.manager.stats.UpstreamQueries
	uptimeSeconds := time.Since(ws.manager.stats.StartTime).Seconds()
	ws.manager.stats.mu.RUnlock()

	ws.manager.mu.RLock()
	blockedDomains := len(ws.manager.blockedMap)
	ws.manager.mu.RUnlock()

	c.JSON(200, gin.H{
		"total_queries":    totalQueries,
		"blocked_queries":  blockedQueries,
		"cached_queries":   cachedQueries,
		"upstream_queries": upstreamQueries,
		"uptime_seconds":   uptimeSeconds,
		"blocked_domains":  blockedDomains,
	})
}

func (ws *WebServer) getBlockedDomains(c *gin.Context) {
	ws.manager.mu.RLock()
	domains := make([]string, 0, len(ws.manager.blockedMap))
	for d := range ws.manager.blockedMap {
		domains = append(domains, d)
	}
	ws.manager.mu.RUnlock()

	c.JSON(200, gin.H{
		"count":   len(domains),
		"domains": domains,
	})
}

func (ws *WebServer) addBlockDomain(c *gin.Context) {
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	ws.manager.addDomain(req.Domain)
	c.JSON(200, gin.H{"message": "Domain blocked", "domain": req.Domain})
}

func (ws *WebServer) removeBlockDomain(c *gin.Context) {
	domain := c.Param("domain")
	domain = dns.Fqdn(domain)

	ws.manager.mu.Lock()
	delete(ws.manager.blockedMap, domain)
	ws.manager.mu.Unlock()

	c.JSON(200, gin.H{"message": "Domain unblocked", "domain": domain})
}

func (ws *WebServer) triggerUpdate(c *gin.Context) {
	go ws.manager.fetchBlocklists()
	c.JSON(200, gin.H{"message": "Blocklist update triggered"})
}

func (ws *WebServer) Run(addr string) error {
	return ws.engine.Run(addr)
}

// ==================== TEMPLATES ====================

func createTemplates() {
	os.MkdirAll("templates", 0755)
	os.MkdirAll("static", 0755)

	indexHTML := `<!DOCTYPE html>
<html>
<head>
    <title>GoBlock Render - DNS AdBlocker</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { 
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 30px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        .subtitle { opacity: 0.9; }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card { 
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        .stat-value { 
            font-size: 2.5em; 
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-label { opacity: 0.8; font-size: 0.9em; }
        .section { 
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        h2 { margin-bottom: 15px; color: #64b5f6; }
        .btn {
            background: #64b5f6;
            color: #fff;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            margin-right: 10px;
            margin-bottom: 10px;
        }
        .btn:hover { background: #42a5f5; }
        .input-group { display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; }
        input[type="text"] {
            flex: 1;
            min-width: 200px;
            padding: 12px;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 8px;
            color: #fff;
            font-size: 1em;
        }
        code {
            background: rgba(0,0,0,0.3);
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #81c784;
            word-break: break-all;
        }
        .info-box {
            background: rgba(0,0,0,0.2);
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid #64b5f6;
        }
        .warning {
            background: rgba(255,152,0,0.2);
            border-left-color: #ff9800;
        }
        .success {
            background: rgba(76,175,80,0.2);
            border-left-color: #4caf50;
        }
        @media (max-width: 600px) {
            h1 { font-size: 1.8em; }
            .stats-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ GoBlock on Render</h1>
            <p class="subtitle">Cloud DNS AdBlocker with DoH Support</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{.total}}</div>
                <div class="stat-label">Total Queries</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.blocked}}</div>
                <div class="stat-label">Blocked</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.cached}}</div>
                <div class="stat-label">Cached</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.blocked_domains}}</div>
                <div class="stat-label">Blocked Domains</div>
            </div>
        </div>

        <div class="section">
            <h2>☁️ Render Deployment Info</h2>
            <div class="info-box success">
                <strong>✅ DoH Endpoint Active</strong><br>
                URL: <code>{{.doh_url}}</code>
            </div>
            <p>Since Render doesn't expose port 53, use DNS-over-HTTPS (DoH) instead.</p>
        </div>

        <div class="section">
            <h2>🔧 Router Setup (IP-Only Solution)</h2>
            <div class="info-box warning">
                <strong>⚠️ Your router only accepts IPs, not URLs</strong>
            </div>
            <p><strong>Option 1: Local DNS Forwarder (Recommended)</strong></p>
            <p>Run this on a Raspberry Pi or local server:</p>
            <pre style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; overflow-x: auto;"><code>#!/bin/bash
# Install cloudflared
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x cloudflared-linux-amd64
sudo mv cloudflared-linux-amd64 /usr/local/bin/cloudflared

# Run DNS proxy to your Render DoH
sudo cloudflared proxy-dns --port 53 --upstream https://{{.doh_url}}</code></pre>
            
            <p style="margin-top: 15px;"><strong>Option 2: Use Cloudflare Tunnel</strong></p>
            <p>Install cloudflared on Render to get a static subdomain:</p>
            <code>cloudflared tunnel --url http://localhost:10000</code>
        </div>

        <div class="section">
            <h2>⚡ Quick Actions</h2>
            <div class="input-group">
                <input type="text" id="domainInput" placeholder="Enter domain to block">
                <button class="btn" onclick="blockDomain()">Block</button>
            </div>
            <button class="btn" onclick="updateBlocklists()">🔄 Update Blocklists</button>
            <button class="btn" onclick="showStats()">📊 Refresh Stats</button>
        </div>

        <div class="section">
            <h2>📱 Client Configuration</h2>
            <p><strong>Android (Private DNS):</strong></p>
            <code>{{.doh_url}}</code>
            
            <p style="margin-top: 10px;"><strong>iOS (DNS Profile):</strong></p>
            <p>Use "DNSCloak" app or Apple Configurator with DoH URL</p>
            
            <p style="margin-top: 10px;"><strong>Firefox:</strong></p>
            <p>Settings → Network Settings → Enable DNS over HTTPS → Custom → <code>{{.doh_url}}</code></p>
        </div>
    </div>

    <script>
        async function blockDomain() {
            const domain = document.getElementById('domainInput').value;
            if (!domain) return;
            const res = await fetch('/api/block', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain})
            });
            const data = await res.json();
            alert(data.message);
        }
        async function updateBlocklists() {
            const res = await fetch('/api/update-blocklists', {method: 'POST'});
            const data = await res.json();
            alert(data.message);
        }
        async function showStats() {
            const res = await fetch('/api/stats');
            const stats = await res.json();
            document.querySelectorAll('.stat-value')[0].textContent = stats.total_queries;
            document.querySelectorAll('.stat-value')[1].textContent = stats.blocked_queries;
            document.querySelectorAll('.stat-value')[2].textContent = stats.cached_queries;
        }
        setInterval(showStats, 10000);
    </script>
</body>
</html>`

	os.WriteFile("templates/index.html", []byte(indexHTML), 0644)
}

// ==================== MAIN ====================

func main() {
	createTemplates()

	config := defaultConfig

	// Override with env vars (Render sets these)
	if port := os.Getenv("PORT"); port != "" {
		config.WebPort = port
	}
	if token := os.Getenv("RENDER_AUTH_TOKEN"); token != "" {
		config.AuthToken = token
	}

	manager := NewBlocklistManager(&config)
	manager.startAutoUpdate()

	// Start DNS server on non-privileged port (for local testing)
	dnsHandler := &DNSHandler{manager: manager}

	go func() {
		server := &dns.Server{
			Addr:    ":" + config.DNSPort,
			Net:     "udp",
			Handler: dnsHandler,
		}
		log.Printf("📡 DNS server starting on port %s (UDP)", config.DNSPort)
		if err := server.ListenAndServe(); err != nil {
			log.Printf("DNS UDP error: %v", err)
		}
	}()

	go func() {
		server := &dns.Server{
			Addr:    ":" + config.DNSPort,
			Net:     "tcp",
			Handler: dnsHandler,
		}
		log.Printf("📡 DNS server starting on port %s (TCP)", config.DNSPort)
		if err := server.ListenAndServe(); err != nil {
			log.Printf("DNS TCP error: %v", err)
		}
	}()

	// Start Web + DoH server
	webServer := NewWebServer(manager, &config)

	log.Printf("🚀 Starting GoBlock on Render...")
	log.Printf("🌐 Web Dashboard: http://0.0.0.0:%s", config.WebPort)
	log.Printf("💊 DoH Endpoint: http://0.0.0.0:%s%s", config.WebPort, config.DoHPath)

	if err := webServer.Run("0.0.0.0:" + config.WebPort); err != nil {
		log.Fatalf("Web server failed: %v", err)
	}
}
