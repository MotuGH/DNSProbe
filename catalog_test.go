package main

import (
	"strings"
	"testing"
)

func findProfile(t *testing.T, name string) Endpoint {
	t.Helper()
	for _, e := range defaults {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("missing %s", name)
	return Endpoint{}
}
func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	profiles := map[string]bool{}
	for _, e := range defaults {
		if seen[e.Name] {
			t.Fatal("duplicate name", e.Name)
		}
		seen[e.Name] = true
		profiles[e.Profile] = true
		if len(e.Sources) == 0 || e.Checked == "" {
			t.Fatal("missing provenance", e.Name)
		}
		if e.Disabled {
			continue
		}
		c := Config{Domains: []string{"example.com"}, Endpoints: []Endpoint{e}, Transports: []string{"udp", "tcp", "dot", "doh", "doh3", "doq"}, Types: []string{"A"}, Rounds: 1, Interval: 1}
		if err := validateConfig(&c); err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
	}
	if len(profiles) != 40 {
		t.Fatal("missing profiles", len(profiles))
	}
}
func TestSplitTLSNames(t *testing.T) {
	e := findProfile(t, "DNS.SB")
	_, doh := e.destination("doh")
	_, dot := e.destination("dot")
	if doh != "doh.sb" || dot != "dot.sb" {
		t.Fatal(doh, dot)
	}
	c := Config{Domains: []string{"example.com"}, Endpoints: []Endpoint{e}, Transports: []string{"doh", "dot"}, Types: []string{"A"}, Rounds: 1, Interval: 1}
	if err := validateConfig(&c); err != nil {
		t.Fatal(err)
	}
}
func TestControlDBootstrap(t *testing.T) {
	e := findProfile(t, "ControlD Free p2")
	a, s := e.destination("doh")
	if a != "76.76.2.11:443" || s != "freedns.controld.com" {
		t.Fatal(a, s)
	}
	a, s = e.destination("dot")
	if a != "76.76.2.11:853" || s != "p2.freedns.controld.com" {
		t.Fatal(a, s)
	}
	a, _ = e.destination("udp")
	if a != "76.76.2.2:53" {
		t.Fatal(a)
	}
}
func TestOnlySupportedPathsCount(t *testing.T) {
	e := findProfile(t, "MSK-IX DNS")
	u := findProfile(t, "UncensoredDNS Anycast")
	c := Config{Domains: []string{"example.com"}, Endpoints: []Endpoint{e, u}, Transports: []string{"udp", "tcp", "dot", "doh"}, Types: []string{"A"}, Rounds: 3, Interval: 1}
	if measurementCount(c) != 12 {
		t.Fatal(measurementCount(c))
	}
	if u.supports("udp") || e.supports("doh") {
		t.Fatal("unsupported path allowed")
	}
}
func TestDoHCustomPort(t *testing.T) {
	e := Endpoint{Name: "local", IP: "127.0.0.1", Host: "dot.example", URL: "https://doh.example:8443/dns-query"}
	a, s := e.destination("doh")
	if a != "127.0.0.1:8443" || s != "doh.example" {
		t.Fatal(a, s)
	}
}
func TestByNameNotPlainIP(t *testing.T) {
	e := findProfile(t, "CleanBrowsing Security")
	a, s := e.destination("doh")
	if a != "doh.cleanbrowsing.org:443" || s != "doh.cleanbrowsing.org" {
		t.Fatal(a, s)
	}
	a, _ = e.destination("udp")
	if !strings.HasPrefix(a, "185.228.168.9:") {
		t.Fatal(a)
	}
}
