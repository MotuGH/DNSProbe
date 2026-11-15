package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func newH3Transport(address string, config *tls.Config) *http3.Transport {
	return &http3.Transport{TLSClientConfig: config, Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
		return quic.DialAddr(ctx, address, tc, qc)
	}}
}

// RFC 9250: ALPN doq, zero message ID, one length-prefixed message per stream.
func exchangeDoQ(ctx context.Context, address string, config *tls.Config, q *dns.Msg) (*dns.Msg, error) {
	tc := config.Clone()
	tc.NextProtos = []string{"doq"}
	tc.MinVersion = tls.VersionTLS13
	conn, err := quic.DialAddr(ctx, address, tc, &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "")
	stop := context.AfterFunc(ctx, func() { conn.CloseWithError(3, "request cancelled") })
	defer stop()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		stream.SetDeadline(deadline)
	}
	query := q.Copy()
	query.Id = 0
	wire, err := query.Pack()
	if err != nil {
		return nil, err
	}
	if len(wire) > 65535 {
		return nil, fmt.Errorf("DoQ query too large")
	}
	framed := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(framed, uint16(len(wire)))
	copy(framed[2:], wire)
	if _, err = stream.Write(framed); err != nil {
		return nil, err
	}
	if err = stream.Close(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(stream, 65538))
	if err != nil {
		return nil, err
	}
	if len(data) < 2 || int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 {
		return nil, fmt.Errorf("invalid DoQ message framing")
	}
	m := new(dns.Msg)
	if err = m.Unpack(data[2:]); err != nil {
		return nil, err
	}
	if err = match(query, m); err != nil {
		return nil, err
	}
	m.Id = q.Id
	return m, nil
}
