package main

import (
	"context"
	"crypto"
	"github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

func TestSpecialAddresses(t *testing.T) {
	for _, s := range []string{"198.18.1.188", "100.64.0.1", "192.168.1.1", "2001:db8::1", "127.0.0.1"} {
		if !specialIP(net.ParseIP(s)) {
			t.Fatalf("missed %s", s)
		}
	}
	if specialIP(net.ParseIP("104.16.132.229")) {
		t.Fatal("public address flagged")
	}
}

func TestResponseMatching(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	if match(q, r) != nil {
		t.Fatal("valid reply rejected")
	}
	r.Id++
	if match(q, r) == nil {
		t.Fatal("wrong ID accepted")
	}
	r.SetReply(q)
	r.Question = []dns.Question{{Name: "evil.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	if match(q, r) == nil {
		t.Fatal("wrong question accepted")
	}
}
func TestCDNAndNXDOMAIN(t *testing.T) {
	a := []Result{{Round: 1, Domain: "example.com", Type: "A", Rcode: "NOERROR", IPs: []string{"1.1.1.1"}, Status: "insufficient"}, {Round: 1, Domain: "example.com", Type: "A", Rcode: "NOERROR", IPs: []string{"8.8.8.8"}, Status: "insufficient"}}
	compare(a)
	if a[0].Status != "insufficient" {
		t.Fatal("CDN differences flagged")
	}
	a[1].Rcode = "NXDOMAIN"
	a[1].IPs = nil
	compare(a)
	if a[0].Status != "suspicious" {
		t.Fatal("NXDOMAIN contradiction missed")
	}
	a[0].Status = "passed"
	a[0].DNSSEC = "validated"
	compare(a)
	if a[0].Status != "passed" {
		t.Fatal("validated answer downgraded")
	}
}
func TestRoundIsolation(t *testing.T) {
	a := []Result{{Round: 1, Domain: "a.test", Type: "A", Rcode: "NXDOMAIN", Status: "insufficient"}, {Round: 2, Domain: "a.test", Type: "A", Rcode: "NOERROR", IPs: []string{"1.1.1.1"}, Status: "insufficient"}}
	compare(a)
	if a[0].Status != "insufficient" {
		t.Fatal("different rounds compared")
	}
}
func TestDNSSECSignature(t *testing.T) {
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	priv, e := key.Generate(256)
	if e != nil {
		t.Fatal(e)
	}
	rr, _ := dns.NewRR("www.example. 300 IN A 192.0.2.1")
	set := []dns.RR{rr}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: dns.TypeA, Algorithm: key.Algorithm, Labels: 2, OrigTtl: 300, Expiration: uint32(time.Now().Add(time.Hour).Unix()), Inception: uint32(time.Now().Add(-time.Hour).Unix()), KeyTag: key.KeyTag(), SignerName: "example."}
	if e = sig.Sign(priv.(crypto.Signer), set); e != nil {
		t.Fatal(e)
	}
	if !verify(set, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, "example.") {
		t.Fatal("valid signature rejected")
	}
	rr.(*dns.A).A = net.ParseIP("192.0.2.2")
	if verify(set, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, "example.") {
		t.Fatal("tampered data accepted")
	}
}
func TestADIsNotProof(t *testing.T) {
	m := new(dns.Msg)
	m.AuthenticatedData = true
	rr, _ := dns.NewRR("example. 60 IN A 192.0.2.1")
	m.Answer = []dns.RR{rr}
	v := validator{ctx: context.Background(), cache: map[string][]*dns.DNSKEY{}}
	if v.answer(m, dns.Question{Name: "example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}) == nil {
		t.Fatal("AD trusted without signature")
	}
}
func TestConfigRejectsArgumentInjection(t *testing.T) {
	c := Config{Domains: []string{"@secret.txt"}, Endpoints: defaults[:1], Transports: []string{"udp"}, Types: []string{"A"}, Rounds: 1, Interval: 1}
	if validateConfig(&c) == nil {
		t.Fatal("file argument accepted")
	}
	c.Domains = []string{"--help"}
	if validateConfig(&c) == nil {
		t.Fatal("CLI flag accepted")
	}
	c.Domains = []string{"example.com"}
	if e := validateConfig(&c); e != nil {
		t.Fatal(e)
	}
}
