package user

import (
	"net/http"
	"testing"
)

func TestGetOrigin(t *testing.T) {
	tests := []struct {
		name          string
		originHeader  string
		refererHeader string
		want          string
	}{
		{"no headers", "", "", ""},
		{"only Origin", "https://foo.example", "", "https://foo.example"},
		{"only Referer", "", "https://bar.example/path", "https://bar.example/path"},
		{"both headers (Origin wins)", "https://foo.example", "https://bar.example/path", "https://foo.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Header: make(http.Header)}
			if tt.originHeader != "" {
				req.Header.Set("Origin", tt.originHeader)
			}
			if tt.refererHeader != "" {
				req.Header.Set("Referer", tt.refererHeader)
			}

			got := getOrigin(req)
			if got != tt.want {
				t.Errorf("getOrigin() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestGetDomain(t *testing.T) {
	tests := []struct {
		name          string
		originHeader  string
		refererHeader string
		want          string
	}{
		{"empty origin", "", "", ""},
		{"simple host", "example.com", "", "example.com"},
		{"single-label", "localhost", "", "localhost"},
		{"two-label domain", "foo.bar", "", "foo.bar"},
		{"one subdomain", "api.example.com", "", "example.com"},
		{"deep subdomains", "a.b.c.example.co.uk", "", "co.uk"},
		{"use Referer fallback", "", "sub.test.org/path", "test.org/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Header: make(http.Header)}
			if tt.originHeader != "" {
				req.Header.Set("Origin", tt.originHeader)
			}
			if tt.refererHeader != "" {
				req.Header.Set("Referer", tt.refererHeader)
			}

			d := getDomain(req)
			if d != tt.want {
				t.Errorf("getDomain() = %q; want %q", d, tt.want)
			}
		})
	}
}
