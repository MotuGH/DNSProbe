package main

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

// Opt-in observations, never an assertion of global availability or correctness.
func TestCatalogLive(t *testing.T) {
	if os.Getenv("DNSPROBE_CATALOG_CHECK") != "1" {
		t.Skip("opt-in live network check")
	}
	var rows []Result
	var lock sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, ep := range defaults {
		if ep.Name != ep.Profile || ep.Disabled {
			continue
		}
		for _, transport := range []string{"doh", "dot"} {
			if !ep.supports(transport) {
				continue
			}
			wg.Add(1)
			go func(e Endpoint, tr string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				r := probe(context.Background(), e, tr, "example.com", "A", 1, false)
				lock.Lock()
				rows = append(rows, r)
				lock.Unlock()
			}(ep, transport)
		}
	}
	wg.Wait()
	data, err := json.MarshalIndent(map[string]any{"checked": time.Now().UTC(), "scope": "Одиночные запросы example.com A из текущей сети; без DNSSEC. Не подтверждение корректности или глобальной доступности.", "results": rows}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("catalog-live-check.json", data, 0600); err != nil {
		t.Fatal(err)
	}
	ok := 0
	for _, r := range rows {
		if r.Error == "" {
			ok++
		}
	}
	t.Logf("%d/%d received DNS responses; details in catalog-live-check.json", ok, len(rows))
}

func TestQUICLive(t *testing.T) {
	if os.Getenv("DNSPROBE_QUIC_CHECK") != "1" {
		t.Skip("opt-in live QUIC check")
	}
	var rows []Result
	for _, name := range []string{"Cloudflare", "AdGuard Default", "ControlD Free p0", "DNS-AI"} {
		e := findProfile(t, name)
		for _, tr := range []string{"doh3", "doq"} {
			if !e.supports(tr) {
				continue
			}
			r := probe(context.Background(), e, tr, "cloudflare.com", "A", 1, true)
			rows = append(rows, r)
			t.Logf("%s %s DNSSEC=%s error=%s", name, tr, r.DNSSEC, r.Error)
		}
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	if err := os.WriteFile("quic-live-check.json", b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestQUICAudit(t *testing.T) {
	path := os.Getenv("DNSPROBE_QUIC_AUDIT")
	if path == "" {
		t.Skip("opt-in full catalog QUIC audit")
	}
	var candidates []struct {
		Endpoint  Endpoint `json:"endpoint"`
		Transport string   `json:"transport"`
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &candidates); err != nil {
		t.Fatal(err)
	}
	var rows []Result
	var lock sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, c := range candidates {
		wg.Add(1)
		go func(e Endpoint, tr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for round := 1; round <= 2; round++ {
				r := probe(context.Background(), e, tr, "example.com", "A", round, false)
				lock.Lock()
				rows = append(rows, r)
				lock.Unlock()
			}
		}(c.Endpoint, c.Transport)
	}
	wg.Wait()
	b, err = json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("quic-audit.json", b, 0600); err != nil {
		t.Fatal(err)
	}
	ok := 0
	for _, r := range rows {
		if r.Error == "" {
			ok++
		}
	}
	t.Logf("%d/%d responses; see quic-audit.json", ok, len(rows))
}
