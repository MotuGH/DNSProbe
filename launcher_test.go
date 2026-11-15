package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExistingInstanceDetection(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{{`{"app":"DNSProbe"}`, true}, {`{"app":"Other"}`, false}, {`<html>other server</html>`, false}} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(tc.body)) }))
		if got := existingDNSProbe(s.URL); got != tc.want {
			t.Errorf("got %v want %v", got, tc.want)
		}
		s.Close()
	}
}
