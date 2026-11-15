package main

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

// IANA root-anchors.xml, retrieved 2026-11-15. No trust is placed in AD.
var rootDigests = map[string]bool{
	"E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D": true,
	"683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16": true,
}

type validator struct {
	ctx       context.Context
	ep        Endpoint
	transport string
	cache     map[string][]*dns.DNSKEY
}

func (v *validator) fetch(name string, t uint16) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(name, t)
	q.SetEdns0(1232, true)
	q.CheckingDisabled = true
	m, _, err := exchange(v.ctx, v.ep, v.transport, q)
	if err != nil {
		return nil, err
	}
	if m.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%s %s: %s", name, dns.TypeToString[t], dns.RcodeToString[m.Rcode])
	}
	return m, nil
}
func rrset(m *dns.Msg, name string, t uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range m.Answer {
		if strings.EqualFold(rr.Header().Name, name) && rr.Header().Rrtype == t {
			out = append(out, rr)
		}
	}
	return out
}
func sigs(m *dns.Msg, name string, t uint16) []*dns.RRSIG {
	var out []*dns.RRSIG
	for _, rr := range m.Answer {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == t && strings.EqualFold(s.Hdr.Name, name) {
			out = append(out, s)
		}
	}
	return out
}
func verify(set []dns.RR, ss []*dns.RRSIG, keys []*dns.DNSKEY, zone string) bool {
	for _, s := range ss {
		if !strings.EqualFold(s.SignerName, zone) || !s.ValidityPeriod(time.Now()) {
			continue
		}
		for _, k := range keys {
			if k.Flags&256 != 0 && k.Flags&128 == 0 && k.Protocol == 3 && s.KeyTag == k.KeyTag() && s.Verify(k, set) == nil {
				return true
			}
		}
	}
	return false
}
func (v *validator) keys(zone string, depth int) ([]*dns.DNSKEY, error) {
	zone = strings.ToLower(zone)
	if depth > 20 {
		return nil, fmt.Errorf("цепочка DNSSEC слишком длинная")
	}
	if k, ok := v.cache[zone]; ok {
		return k, nil
	}
	m, err := v.fetch(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	set := rrset(m, zone, dns.TypeDNSKEY)
	var all, trusted []*dns.DNSKEY
	for _, rr := range set {
		all = append(all, rr.(*dns.DNSKEY))
	}
	if zone == "." {
		for _, k := range all {
			d := k.ToDS(dns.SHA256)
			if d != nil && rootDigests[strings.ToUpper(d.Digest)] {
				trusted = append(trusted, k)
			}
		}
	} else {
		dsmsg, e := v.fetch(zone, dns.TypeDS)
		if e != nil {
			return nil, e
		}
		dsset := rrset(dsmsg, zone, dns.TypeDS)
		if len(dsset) == 0 {
			return nil, fmt.Errorf("нет подтверждённой DS-цепочки для %s", zone)
		}
		good := false
		for _, s := range sigs(dsmsg, zone, dns.TypeDS) {
			parent := strings.ToLower(s.SignerName)
			if parent == zone || !dns.IsSubDomain(parent, zone) {
				continue
			}
			pk, e := v.keys(parent, depth+1)
			if e == nil && verify(dsset, []*dns.RRSIG{s}, pk, parent) {
				good = true
				break
			}
		}
		if !good {
			return nil, fmt.Errorf("не удалось подтвердить DS для %s", zone)
		}
		for _, k := range all {
			for _, rr := range dsset {
				ds := rr.(*dns.DS)
				if ds.DigestType != dns.SHA256 && ds.DigestType != dns.SHA384 {
					continue
				}
				d := k.ToDS(ds.DigestType)
				if d != nil && d.KeyTag == ds.KeyTag && d.Algorithm == ds.Algorithm && strings.EqualFold(d.Digest, ds.Digest) {
					trusted = append(trusted, k)
				}
			}
		}
	}
	if !verify(set, sigs(m, zone, dns.TypeDNSKEY), trusted, zone) {
		return nil, fmt.Errorf("не удалось подтвердить DNSKEY %s", zone)
	}
	v.cache[zone] = all
	return all, nil
}
func (v *validator) answer(m *dns.Msg, q dns.Question) error {
	name := q.Name
	for hop := 0; hop < 16; hop++ {
		typ := q.Qtype
		set := rrset(m, name, typ)
		if len(set) == 0 {
			typ = dns.TypeCNAME
			set = rrset(m, name, typ)
		}
		if len(set) == 0 {
			return fmt.Errorf("нет полной подписанной цепочки ответа")
		}
		valid := false
		for _, s := range sigs(m, name, typ) {
			if !dns.IsSubDomain(s.SignerName, name) {
				continue
			}
			if int(s.Labels) != dns.CountLabel(name) {
				continue
			} // wildcard proof requires NSEC validation
			keys, err := v.keys(s.SignerName, 0)
			if err == nil && verify(set, []*dns.RRSIG{s}, keys, s.SignerName) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("подпись/цепочка не подтверждена (включая unsigned и wildcard)")
		}
		if typ == q.Qtype {
			return nil
		}
		name = set[0].(*dns.CNAME).Target
	}
	return fmt.Errorf("слишком длинная CNAME-цепочка")
}
