package utils

import (
	"net/http"
	"net/url"
	"strings"
)

func GetDomain(r *http.Request) string {
	origin := getOrigin(r)
	if origin == "" {
		return ""
	}
	if !strings.HasPrefix(origin, "http") {
		origin = "https://" + origin
	}
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	// u.Host is "dev.example.com:3000", but Hostname() drops the ":3000"
	host := u.Hostname() // => "dev.example.com"
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		// covers "localhost" or "example.com"
		return host
	}
	// take the last two labels: "example.com"
	n := len(parts)
	return parts[n-2] + "." + parts[n-1]
}

func getOrigin(r *http.Request) string {
	if v := r.Header.Get("Origin"); v != "" {
		return v
	}
	if v := r.Header.Get("Referer"); v != "" {
		return v
	}
	return ""
}
