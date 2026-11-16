package main

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Endpoint struct {
	QUIC         string   `json:"quic,omitempty"`
	DoQIP        string   `json:"doq_ip,omitempty"`
	Name         string   `json:"name"`
	IP           string   `json:"ip"`
	Host         string   `json:"host"`
	URL          string   `json:"url"`
	Profile      string   `json:"profile,omitempty"`
	Transports   []string `json:"transports,omitempty"`
	DoHIP        string   `json:"doh_ip,omitempty"`
	DoTIP        string   `json:"dot_ip,omitempty"`
	ByName       bool     `json:"by_name,omitempty"`
	Policy       string   `json:"policy,omitempty"`
	Note         string   `json:"note,omitempty"`
	Sources      []string `json:"sources,omitempty"`
	Checked      string   `json:"checked,omitempty"`
	Verification string   `json:"verification,omitempty"`
	Default      bool     `json:"default,omitempty"`
	Disabled     bool     `json:"disabled,omitempty"`
}

//go:embed catalog.json
var catalogJSON []byte
var defaults = loadCatalog()

func loadCatalog() []Endpoint {
	var eps []Endpoint
	if err := json.Unmarshal(catalogJSON, &eps); err != nil {
		panic(err)
	}
	return eps
}
func (e Endpoint) supports(t string) bool {
	if e.Disabled {
		return false
	}
	if len(e.Transports) == 0 {
		return true
	}
	for _, p := range e.Transports {
		if p == t {
			return true
		}
	}
	return false
}

// DoH's URL hostname and DoT's authentication name may be different.
func (e Endpoint) destination(t string) (address, sni string) {
	target := e.IP
	port := "53"
	if t == "doh" || t == "doh3" {
		u, _ := url.Parse(e.URL)
		sni = u.Hostname()
		port = u.Port()
		if port == "" {
			port = "443"
		}
		if e.ByName || target == "" {
			target = sni
		}
		if e.DoHIP != "" {
			target = e.DoHIP
		}
	}
	if t == "dot" {
		sni = e.Host
		port = "853"
		if e.ByName || target == "" {
			target = sni
		}
		if e.DoTIP != "" {
			target = e.DoTIP
		}
	}
	if t == "doq" {
		u, _ := url.Parse(e.QUIC)
		sni = u.Hostname()
		port = u.Port()
		if port == "" {
			port = "853"
		}
		if e.ByName || target == "" {
			target = sni
		}
		if e.DoQIP != "" {
			target = e.DoQIP
		}
	}
	return net.JoinHostPort(target, port), sni
}

type Result struct {
	At        time.Time `json:"at"`
	Round     int       `json:"round"`
	Server    string    `json:"server"`
	Transport string    `json:"transport"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	MS        float64   `json:"ms"`
	Rcode     string    `json:"rcode"`
	Answers   []string  `json:"answers"`
	IPs       []string  `json:"ips"`
	AD        bool      `json:"ad"`
	Fallback  bool      `json:"fallback"`
	Status    string    `json:"status"`
	DNSSEC    string    `json:"dnssec"`
	Notes     []string  `json:"notes"`
	Error     string    `json:"error"`
	Route     string    `json:"route,omitempty"`
	Policy    string    `json:"policy,omitempty"`
}

// Each query uses a fresh connection. DoH bootstrap is pinned to the configured
// IP while HTTPS Host/SNI and normal certificate validation use the hostname.
func exchange(ctx context.Context, ep Endpoint, transport string, q *dns.Msg) (*dns.Msg, bool, error) {
	address, sni := ep.destination(transport)
	if transport == "doq" {
		m, err := exchangeDoQ(ctx, address, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13}, q)
		return m, false, err
	}
	if transport == "doh" || transport == "doh3" {
		wire, err := q.Pack()
		if err != nil {
			return nil, false, err
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: sni}, ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			}}
		defer tr.CloseIdleConnections()
		var rt http.RoundTripper = tr
		if transport == "doh3" {
			h3 := newH3Transport(address, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13})
			defer h3.Close()
			rt = h3
		}
		req, err := http.NewRequestWithContext(ctx, "POST", ep.URL, bytes.NewReader(wire))
		if err != nil {
			return nil, false, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := (&http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			return nil, false, err
		}
		defer resp.Body.Close()
		if transport == "doh3" && resp.ProtoMajor != 3 {
			return nil, false, fmt.Errorf("HTTP/3 was not negotiated")
		}
		if resp.StatusCode != 200 {
			return nil, false, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
		}
		if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/dns-message") {
			return nil, false, fmt.Errorf("unexpected DoH content type")
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if err != nil {
			return nil, false, err
		}
		m := new(dns.Msg)
		err = m.Unpack(data)
		if err == nil {
			err = match(q, m)
		}
		return m, false, err
	}
	c := &dns.Client{Net: transport, Timeout: 5 * time.Second}
	if transport == "dot" {
		c.Net = "tcp-tls"
		c.TLSConfig = &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}
	}
	m, _, err := c.ExchangeContext(ctx, q, address)
	fallback := false
	if err == nil && m.Truncated && transport == "udp" {
		c.Net = "tcp"
		m, _, err = c.ExchangeContext(ctx, q, net.JoinHostPort(ep.IP, "53"))
		fallback = true
	}
	if err == nil {
		err = match(q, m)
	}
	return m, fallback, err
}
func match(q, m *dns.Msg) error {
	if !m.Response || m.Id != q.Id || len(m.Question) != 1 || m.Question[0].Qtype != q.Question[0].Qtype || m.Question[0].Qclass != q.Question[0].Qclass || !strings.EqualFold(m.Question[0].Name, q.Question[0].Name) {
		return fmt.Errorf("DNS response does not match request")
	}
	if m.Truncated {
		return fmt.Errorf("truncated response")
	}
	return nil
}
func probe(parent context.Context, ep Endpoint, transport, domain, typ string, round int, validate bool) Result {
	r := Result{At: time.Now().UTC(), Round: round, Server: ep.Name, Transport: transport, Domain: domain, Type: typ, Status: "insufficient", DNSSEC: "not_checked", Answers: []string{}, IPs: []string{}, Notes: []string{}}
	r.Route, _ = ep.destination(transport)
	r.Policy = ep.Policy
	if ep.Policy == "smart" {
		addNote(&r, "Smart DNS: оператор может намеренно перенаправлять отдельные домены; это не независимый эталон ответа.")
	}
	if ep.Policy == "filter" {
		addNote(&r, "Фильтрующий профиль: NXDOMAIN или пустой адрес могут быть политикой резолвера.")
	}
	if transport == "doh" || transport == "dot" || transport == "doh3" || transport == "doq" {
		target, _, _ := net.SplitHostPort(r.Route)
		if net.ParseIP(target) == nil {
			addNote(&r, "Адрес шифрованного сервера определяется системным DNS; TLS-сертификат проверяется.")
		}
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(domain), dns.StringToType[typ])
	q.SetEdns0(1232, true)
	start := time.Now()
	m, fallback, err := exchange(ctx, ep, transport, q)
	r.MS = float64(time.Since(start).Microseconds()) / 1000
	r.Fallback = fallback
	if err != nil {
		r.Status = "error"
		r.Error = err.Error()
		return r
	}
	r.Rcode = dns.RcodeToString[m.Rcode]
	r.AD = m.AuthenticatedData
	for _, rr := range m.Answer {
		if rr.Header().Rrtype != dns.TypeRRSIG {
			r.Answers = append(r.Answers, rr.String())
		}
		switch a := rr.(type) {
		case *dns.A:
			r.IPs = append(r.IPs, a.A.String())
		case *dns.AAAA:
			r.IPs = append(r.IPs, a.AAAA.String())
		}
	}
	sort.Strings(r.IPs)
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		r.Status = "error"
		r.Notes = append(r.Notes, "DNS-код ошибки: "+r.Rcode)
	}
	for _, ip := range r.IPs {
		p := net.ParseIP(ip)
		if specialIP(p) {
			r.Status = "suspicious"
			r.Notes = append(r.Notes, "Служебный/непубличный адрес: "+ip+"; возможны VPN Fake-IP, split DNS или фильтрация")
		}
	}
	if validate && m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
		vc, stop := context.WithTimeout(parent, 20*time.Second)
		defer stop()
		v := validator{ctx: vc, ep: ep, transport: transport, cache: map[string][]*dns.DNSKEY{}}
		if err := v.answer(m, q.Question[0]); err != nil {
			switch {
			case errors.Is(err, errNoAnswerSignature):
				r.DNSSEC = "no_signature"
			case errors.Is(err, errInvalidAnswerSignature):
				r.DNSSEC = "invalid_signature"
				r.Status = "error"
			default:
				r.DNSSEC = "indeterminate"
			}
			r.Notes = append(r.Notes, "DNSSEC: "+err.Error())
		} else {
			r.DNSSEC = "validated"
			if r.Status == "insufficient" {
				r.Status = "passed"
			}
		}
	} else if validate {
		r.DNSSEC = "indeterminate"
		r.Notes = append(r.Notes, "Отрицательные ответы NSEC/NSEC3 в этой версии не валидируются")
	}
	return r
}

func specialIP(p net.IP) bool {
	if p.IsPrivate() || p.IsLoopback() || p.IsUnspecified() || p.IsLinkLocalUnicast() || p.IsMulticast() {
		return true
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "100::/64"} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(p) {
			return true
		}
	}
	return false
}

// Compare only the same question in the same round. Agreement is observational,
// never cryptographic proof. CDN address differences alone are not suspicious.
func compare(rows []Result) {
	for i := range rows {
		r := &rows[i]
		if r.Error != "" {
			continue
		}
		for j := range rows {
			p := &rows[j]
			if i == j || p.Error != "" || p.Domain != r.Domain || p.Type != r.Type || p.Round != r.Round {
				continue
			}
			if (r.Rcode == "NXDOMAIN" && len(p.IPs) > 0) || (p.Rcode == "NXDOMAIN" && len(r.IPs) > 0) {
				if r.Status != "error" && r.DNSSEC != "validated" {
					r.Status = "suspicious"
				}
				addNote(r, "NXDOMAIN расходится с положительным ответом другого пути; это не доказательство цензуры")
			}
			if len(r.IPs) > 0 && len(p.IPs) > 0 && strings.Join(r.IPs, ",") != strings.Join(p.IPs, ",") {
				addNote(r, "IP-адреса различаются между путями; возможны CDN/геобалансировка")
			}
		}
	}
}
func addNote(r *Result, s string) {
	for _, n := range r.Notes {
		if n == s {
			return
		}
	}
	r.Notes = append(r.Notes, s)
}
