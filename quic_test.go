package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func quicTestTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	s := httptest.NewTLSServer(nil)
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return s.TLS.Clone(), &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS13}
}
func TestDoQWireAndValidation(t *testing.T) {
	for _, mode := range []string{"ok", "wrong-id", "wrong-question", "bad-length", "extra-message", "untrusted", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			serverTLS, clientTLS := quicTestTLS(t)
			serverTLS.NextProtos = []string{"doq"}
			listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			go func() {
				conn, err := listener.Accept(ctx)
				if err != nil {
					return
				}
				defer conn.CloseWithError(0, "")
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				data, err := io.ReadAll(stream)
				if err != nil {
					return
				}
				if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
					t.Error("invalid query framing")
					return
				}
				q := new(dns.Msg)
				if err = q.Unpack(data[2:]); err != nil {
					t.Error(err)
					return
				}
				if q.Id != 0 {
					t.Error("wire ID is not zero")
				}
				if mode == "cancel" {
					cancel()
					<-conn.Context().Done()
					return
				}
				m := new(dns.Msg)
				m.SetReply(q)
				if mode == "wrong-id" {
					m.Id = 123
				}
				if mode == "wrong-question" {
					m.Question[0].Name = "other.example."
				}
				wire, _ := m.Pack()
				frame := make([]byte, 2+len(wire))
				binary.BigEndian.PutUint16(frame, uint16(len(wire)))
				copy(frame[2:], wire)
				if mode == "bad-length" {
					frame[1]++
				}
				if mode == "extra-message" {
					frame = append(frame, frame...)
				}
				stream.Write(frame)
				stream.Close()
				<-conn.Context().Done()
			}()
			if mode == "untrusted" {
				clientTLS.RootCAs = x509.NewCertPool()
			}
			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			id := q.Id
			m, err := exchangeDoQ(ctx, listener.Addr().String(), clientTLS, q)
			if mode == "ok" {
				if err != nil {
					t.Fatal(err)
				}
				if m.Id != id || q.Id != id {
					t.Fatal("caller ID changed")
				}
			} else if err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}
func TestHTTP3StrictTransport(t *testing.T) {
	serverTLS, clientTLS := quicTestTLS(t)
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: serverTLS, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 {
			t.Error("not HTTP3")
		}
		w.Write([]byte("h3"))
	})}
	defer server.Close()
	go server.Serve(socket)
	tr := newH3Transport(socket.LocalAddr().String(), clientTLS)
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/test", nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 3 {
		t.Fatal(resp.Proto)
	}
	// A TCP-only HTTPS server cannot satisfy the strict H3 transport.
	tcp := httptest.NewTLSServer(nil)
	defer tcp.Close()
	tr2 := newH3Transport(tcp.Listener.Addr().String(), clientTLS)
	defer tr2.Close()
	short, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	req, _ = http.NewRequestWithContext(short, "GET", "https://example.com/test", nil)
	if resp, err := (&http.Client{Transport: tr2}).Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("unexpected fallback")
	}
}
