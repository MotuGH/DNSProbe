package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var web embed.FS

type Config struct {
	Domains    []string   `json:"domains"`
	Endpoints  []Endpoint `json:"endpoints"`
	Transports []string   `json:"transports"`
	Types      []string   `json:"types"`
	Rounds     int        `json:"rounds"`
	Interval   int        `json:"interval"`
	DNSSEC     bool       `json:"dnssec"`
}
type Run struct {
	ID        string          `json:"id"`
	Started   time.Time       `json:"started"`
	Finished  *time.Time      `json:"finished"`
	State     string          `json:"state"`
	Config    Config          `json:"config"`
	Results   []Result        `json:"results"`
	Progress  int             `json:"progress"`
	Total     int             `json:"total"`
	Error     string          `json:"error"`
	Benchmark json.RawMessage `json:"benchmark,omitempty"`
}

var mu sync.Mutex
var current *Run
var cancelRun context.CancelFunc
var dataDir string
var token string

func id() string {
	b := make([]byte, 12)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func validateConfig(c *Config) error {
	if len(c.Domains) < 1 || len(c.Domains) > 50 || len(c.Endpoints) < 1 || len(c.Endpoints) > 128 || len(c.Transports) < 1 || len(c.Types) < 1 || c.Rounds < 1 || c.Rounds > 1440 || c.Interval < 1 || c.Interval > 3600 {
		return fmt.Errorf("недопустимые параметры теста")
	}
	if measurementCount(*c) > 100000 {
		return fmt.Errorf("максимум 100000 измерений за прогон")
	}
	for i, d := range c.Domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if _, ok := dns.IsDomainName(d); !ok || strings.ContainsAny(d, " /:@\\\n\r\t") || strings.HasPrefix(d, "-") || len(d) == 0 {
			return fmt.Errorf("некорректный домен: %s (используйте punycode для IDN)", d)
		}
		for _, ch := range d {
			if ch > 127 {
				return fmt.Errorf("используйте punycode для IDN")
			}
		}
		c.Domains[i] = d
	}
	seen := map[string]bool{}
	for _, e := range c.Endpoints {
		if e.Name == "" || seen[e.Name] || (e.IP != "" && net.ParseIP(e.IP) == nil) || e.Disabled {
			return fmt.Errorf("укажите уникальное имя и IP DNS-сервера")
		}
		seen[e.Name] = true
		for _, ip := range []string{e.DoHIP, e.DoTIP, e.DoQIP} {
			if ip != "" && net.ParseIP(ip) == nil {
				return fmt.Errorf("неверный bootstrap IP")
			}
		}
		for _, t := range c.Transports {
			if !e.supports(t) {
				continue
			}
			if (t == "udp" || t == "tcp") && net.ParseIP(e.IP) == nil {
				return fmt.Errorf("для UDP/TCP нужен IP: %s", e.Name)
			}
			if t == "dot" {
				if !validHostname(e.Host) {
					return fmt.Errorf("нужно TLS-имя сервера")
				}
			}
			if t == "doh" || t == "doh3" || t == "doq" {
				raw, scheme := e.URL, "https"
				if t == "doq" {
					raw, scheme = e.QUIC, "quic"
				}
				u, err := url.Parse(raw)
				if err != nil || u.Scheme != scheme || !validHostname(u.Hostname()) || u.User != nil || u.Fragment != "" {
					return fmt.Errorf("неверный HTTPS URL для DoH")
				}
				if t == "doq" && (u.Path != "" || u.RawQuery != "") {
					return fmt.Errorf("DoQ URL не должен содержать путь или query")
				}
				if u.Port() != "" {
					p, err := strconv.Atoi(u.Port())
					if err != nil || p < 1 || p > 65535 {
						return fmt.Errorf("неверный порт DoH")
					}
				}
			}
		}
	}
	for _, t := range c.Transports {
		if t != "udp" && t != "tcp" && t != "dot" && t != "doh" && t != "doh3" && t != "doq" {
			return fmt.Errorf("неизвестный транспорт")
		}
	}
	for _, t := range c.Types {
		if t != "A" && t != "AAAA" {
			return fmt.Errorf("поддерживаются A и AAAA")
		}
	}
	if measurementCount(*c) == 0 {
		return fmt.Errorf("у выбранных серверов нет выбранных транспортов")
	}
	return nil
}
func validHostname(s string) bool {
	if s == "" || strings.ContainsAny(s, " /:@\\\r\n\t") || strings.HasPrefix(s, "-") {
		return false
	}
	_, ok := dns.IsDomainName(s)
	return ok || net.ParseIP(s) != nil
}
func measurementCount(c Config) int {
	paths := 0
	for _, e := range c.Endpoints {
		for _, t := range c.Transports {
			if e.supports(t) {
				paths++
			}
		}
	}
	return paths * len(c.Domains) * len(c.Types) * c.Rounds
}
func persist(r *Run) error {
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	p := filepath.Join(dataDir, r.ID+".json")
	if e = os.WriteFile(p+".tmp", b, 0600); e != nil {
		return e
	}
	return os.Rename(p+".tmp", p)
}
func execute(ctx context.Context, r *Run) {
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now().UTC()
		r.Finished = &now
		if ctx.Err() != nil {
			r.State = "stopped"
		} else {
			r.State = "done"
		}
		if err := persist(r); err != nil {
			r.Error = "Ошибка сохранения: " + err.Error()
		}
		cancelRun = nil
	}()
	for round := 1; round <= r.Config.Rounds; round++ {
		var batch []Result
		for _, ep := range r.Config.Endpoints {
			for _, t := range r.Config.Transports {
				if !ep.supports(t) {
					continue
				}
				for _, d := range r.Config.Domains {
					for _, typ := range r.Config.Types {
						if ctx.Err() != nil {
							return
						}
						row := probe(ctx, ep, t, d, typ, round, r.Config.DNSSEC)
						batch = append(batch, row)
						mu.Lock()
						r.Results = append(r.Results, row)
						r.Progress++
						mu.Unlock()
						select {
						case <-ctx.Done():
							return
						case <-time.After(100 * time.Millisecond):
						}
					}
				}
			}
		}
		compare(batch)
		mu.Lock()
		copy(r.Results[len(r.Results)-len(batch):], batch)
		if e := persist(r); e != nil {
			r.Error = e.Error()
		}
		mu.Unlock()
		if round < r.Config.Rounds {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(r.Config.Interval) * time.Second):
			}
		}
	}
}
func writeJSON(w http.ResponseWriter, x any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(x)
}
func decode(w http.ResponseWriter, r *http.Request, x any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 524288)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(x); e != nil {
		http.Error(w, e.Error(), 400)
		return false
	}
	return true
}
func start(w http.ResponseWriter, r *http.Request) {
	var c Config
	if !decode(w, r, &c) {
		return
	}
	if e := validateConfig(&c); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if cancelRun != nil {
		http.Error(w, "Тест уже выполняется", 409)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancelRun = cancel
	current = &Run{ID: id(), Started: time.Now().UTC(), State: "running", Config: c, Results: []Result{}, Total: measurementCount(c)}
	go execute(ctx, current)
	writeJSON(w, current)
}
func benchmark(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config  Config `json:"config"`
		QPS     int    `json:"qps"`
		Seconds int    `json:"seconds"`
	}
	if !decode(w, r, &req) {
		return
	}
	c := req.Config
	c.Rounds = 1
	c.Interval = 1
	if e := validateConfig(&c); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	if len(c.Endpoints) != 1 || len(c.Transports) != 1 || len(c.Types) != 1 || req.QPS < 1 || req.QPS > 100 || req.Seconds < 1 || req.Seconds > 300 {
		http.Error(w, "Выберите один сервер, транспорт, тип; QPS 1–100, время 1–300 с", 400)
		return
	}
	exe, _ := os.Executable()
	bin := filepath.Join(filepath.Dir(exe), "dnspyre.exe")
	if _, e := os.Stat(bin); e != nil {
		http.Error(w, "dnspyre.exe не найден рядом с приложением", 503)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if cancelRun != nil {
		http.Error(w, "Тест уже выполняется", 409)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Seconds+15)*time.Second)
	cancelRun = cancel
	r0 := &Run{ID: id(), Started: time.Now().UTC(), State: "benchmark", Config: c, Results: []Result{}}
	current = r0
	ep := c.Endpoints[0]
	server := ep.IP
	t := c.Transports[0]
	args := []string{"--json", "--no-progress", "--no-color", "--concurrency=1", "--rate-limit=" + strconv.Itoa(req.QPS), "--duration=" + strconv.Itoa(req.Seconds) + "s", "--type=" + c.Types[0]}
	if t == "doh3" {
		args = append(args, "--doh-protocol=3")
	}
	if t == "doq" {
		server = ep.QUIC
	}
	if t == "doh" || t == "doh3" {
		server = ep.URL
	}
	if t == "dot" {
		server = ep.Host
		args = append(args, "--dot")
	}
	if t == "tcp" {
		args = append(args, "--tcp")
	}
	args = append(args, "--server="+server)
	args = append(args, c.Domains...)
	go func() {
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		out, err := cmd.Output()
		mu.Lock()
		defer mu.Unlock()
		now := time.Now().UTC()
		r0.Finished = &now
		r0.State = "done"
		if ctx.Err() != nil {
			r0.State = "stopped"
		}
		if err != nil {
			r0.Error = err.Error()
			if e, ok := err.(*exec.ExitError); ok {
				r0.Error += " " + string(e.Stderr)
			}
		}
		if json.Valid(out) {
			r0.Benchmark = out
		} else if len(out) > 0 {
			r0.Error += " Invalid JSON: " + string(out)
		}
		if e := persist(r0); e != nil {
			r0.Error += " " + e.Error()
		}
		cancelRun = nil
	}()
	writeJSON(w, r0)
}
func main() {
	if existingDNSProbe("http://127.0.0.1:8765") {
		openBrowser("http://127.0.0.1:8765")
		return
	}

	exe, _ := os.Executable()
	dataDir = filepath.Join(filepath.Dir(exe), "history")
	if e := os.MkdirAll(dataDir, 0700); e != nil {
		log.Fatal(e)
	}
	token = id()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"app": "DNSProbe", "version": "quic-audit-2"})
	})
	assets, _ := fs.Sub(web, "web")
	mux.Handle("/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("GET /api/meta", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"token": token, "endpoints": defaults})
	})
	mux.HandleFunc("POST /api/start", start)
	mux.HandleFunc("POST /api/benchmark", benchmark)
	mux.HandleFunc("POST /api/stop", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if cancelRun != nil {
			cancelRun()
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/current", func(w http.ResponseWriter, r *http.Request) { mu.Lock(); defer mu.Unlock(); writeJSON(w, current) })
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		entries, _ := os.ReadDir(dataDir)
		type historyEntry struct {
			ID      string    `json:"id"`
			Started time.Time `json:"started"`
		}
		items := []historyEntry{}
		for _, e := range entries {
			name := strings.TrimSuffix(e.Name(), ".json")
			decoded, err := hex.DecodeString(name)
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || err != nil || len(decoded) != 12 {
				continue
			}
			item := historyEntry{ID: name}
			data, err := os.ReadFile(filepath.Join(dataDir, e.Name()))
			if err != nil {
				continue
			}
			var metadata struct {
				Started time.Time `json:"started"`
			}
			if json.Unmarshal(data, &metadata) == nil {
				item.Started = metadata.Started
			}
			if item.Started.IsZero() {
				if info, err := e.Info(); err == nil {
					item.Started = info.ModTime()
				}
			}
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Started.Equal(items[j].Started) {
				return items[i].ID < items[j].ID
			}
			return items[i].Started.After(items[j].Started)
		})
		writeJSON(w, items)
	})
	mux.HandleFunc("GET /api/history/{id}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("id")
		b, e := hex.DecodeString(name)
		if e != nil || len(b) != 12 {
			http.Error(w, "invalid id", 400)
			return
		}
		p := filepath.Join(dataDir, name+".json")
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, p)
	})
	ln, e := net.Listen("tcp", "127.0.0.1:8765")
	if e != nil {
		if existingDNSProbe("http://127.0.0.1:8765") {
			openBrowser("http://127.0.0.1:8765")
			return
		}
		fmt.Println("Не удалось открыть порт 8765:", e, "\nЗакройте другое приложение на этом порту. Нажмите Enter для выхода.")
		fmt.Scanln()
		return
	}
	origin := "http://" + ln.Addr().String()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.Host != ln.Addr().String() {
			http.Error(w, "invalid host", 403)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != origin {
			http.Error(w, "invalid origin", 403)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("X-DNSProbe-Token") != token {
			http.Error(w, "invalid token", 403)
			return
		}
		mux.ServeHTTP(w, r)
	})
	fmt.Println("DNSProbe: " + origin + "\nОставьте это окно открытым. История: " + dataDir)
	if os.Getenv("DNSPROBE_NO_BROWSER") == "" {
		go func() {
			for i := 0; i < 20; i++ {
				if existingDNSProbe(origin) {
					openBrowser(origin)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	log.Fatal((&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(ln))
}
