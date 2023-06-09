package oar

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Router is an http.Handler that redirects incoming OAuth 2.0 callbacks to
// a domain specified in the `state` parameter.
//
// # Usage
//
// The `state` parameter must be base64 encoded JSON object with a `redirect` field
// that contains the URL to redirect to. The `redirect` field must be a valid
// URL with a host, according to [url.ParseRequestURI].
//
// The state parameter will be propagated to the redirect URL as a query
// parameter unchanged.
//
// The redirect URL may have its own query parameters, which will be merged with
// the incoming request's query parameters. If the redirect URL already has a
// `state` parameter, it will be overwritten.
//
// # Security
//
// The redirect field's host must match one of the domain patterns specified in
// the Domains field. If the Domains field is empty, the router will not
// redirect any requests.
//
// The router will also check the `Origin` header of the incoming request
// and only allow requests from domains that match one of the patterns
// specified in the Origins field. If the Origins field is empty, the router
// will not allow requests from any domain.
//
// The router will log all redirects using the Logger function. If the Logger
// function is nil, no logs will be written.
type Router struct {
	// Domains is a list of allowed domain patterns that incoming requests can
	// redirect to. `*` is unsafe, allowing a secure code to be sent to any domain.
	Domains []string
	// Origins is a list of allowed origin patterns that controls which domains
	// can make requests to this server. `*` is unsafe, allowing any domain to
	// route through this server.
	Origins []string

	// Logger is the function used to log actions taken by the router. If nil,
	// no logs will be written. The simplest logger is [log.Printf].
	Logger func(format string, v ...interface{})
}

// IsUnsafe returns true if the router is configured with an unsafe domain
// pattern that allows redirects to any domain.
func (r *Router) IsUnsafe() bool {
	for _, pattern := range r.Domains {
		if pattern == "*" {
			return true
		}
	}
	return false
}

// ServeHTTP handles an incoming request.
func (r *Router) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	origin := request.Header.Get("Origin")
	if !matchDomain(strings.Split(origin, "."), r.Origins) {
		r.log("request blocked: origin is not allowed: %s", origin)
		http.Error(w, "origin is not allowed", http.StatusForbidden)
		return
	}

	u, err := r.parseIncoming(request.URL)
	if err != nil {
		r.log("request blocked: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	host := strings.Split(u.Host, ":")[0]
	if !matchDomain(strings.Split(host, "."), r.Domains) {
		r.log("request blocked: domain is not allowed: %s", host)
		http.Error(w, "domain is not allowed", http.StatusForbidden)
		return
	}

	originDisplay := fallback(origin, "???")
	r.log("redirecting %s -> %s", originDisplay, u.Host)

	http.Redirect(w, request, u.String(), http.StatusFound)
}

func (r *Router) parseIncoming(u *url.URL) (*url.URL, error) {
	incoming := u.Query()
	stateBytes := incoming.Get("state")
	if stateBytes == "" {
		return nil, errors.New("state is required")
	}

	stateB64, err := url.QueryUnescape(stateBytes)
	if err != nil {
		return nil, fmt.Errorf("state is not url encoded: %s", err)
	}

	if stateB64 == "" {
		return nil, errors.New("state is empty")
	}

	stateJSON, err := base64.StdEncoding.DecodeString(stateB64)
	if err != nil {
		return nil, fmt.Errorf("state is not base64 encoded: %s", err)
	}

	var state authState
	err = json.Unmarshal(stateJSON, &state)
	if err != nil {
		return nil, fmt.Errorf("state is invalid json: %s", err)
	}

	out, err := url.ParseRequestURI(state.Redirect)
	if err != nil {
		return nil, fmt.Errorf("state.redirect is invalid URL: %s", err)
	}

	if out.Host == "" {
		return nil, errors.New("state.redirect is missing host")
	}

	embed := out.Query()
	merged := make(url.Values, len(incoming)+len(embed))
	for k, v := range incoming {
		for _, vv := range v {
			merged.Add(k, vv)
		}
	}

	for k, v := range embed {
		for _, vv := range v {
			merged.Add(k, vv)
		}
	}

	out.RawQuery = merged.Encode()
	return out, nil
}

func (r *Router) log(format string, v ...interface{}) {
	if r.Logger != nil {
		r.Logger(format, v...)
	}
}

// ParseDomainPatterns parses a comma separated list of domain patterns.
// Patterns are a list of domain parts separated by `.`. `*` is a wildcard
// that matches any domain part. For example, `*.example.com` matches
// `foo.example.com` and `bar.example.com` but not `example.com`.
// A single `*` matches any domain, and empty patterns are ignored.
func ParseDomainPatterns(str string) []string {
	domains := strings.Split(str, ",")
	patterns := make([]string, 0, len(domains))
	for _, domain := range domains {
		if strings.TrimSpace(domain) == "" {
			continue
		}
		parts := strings.Split(domain, ".")
		switch {
		case len(parts) == 0:
			continue
		case len(parts) == 1 && parts[0] == "*":
			return []string{"*"}
		case len(parts) == 1:
			log.Fatalf("invalid domain pattern: %s", domain)
		}
		patterns = append(patterns, domain)
	}
	return patterns
}

func headerOr(h http.Header, key, fallback string) string {
	if value := h.Get(key); value != "" {
		return value
	}
	return fallback
}

func matchDomain(hostParts []string, patterns []string) bool {
	for _, pattern := range patterns {
		pparts := strings.Split(pattern, ".")

		if len(pparts) > len(hostParts) {
			continue
		}

		match := true
		for i, part := range pparts {
			if part != "*" && part != hostParts[i] {
				match = false
				break
			}
		}

		if match {
			return true
		}
	}

	return false
}

func fallback(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

type authState struct {
	Redirect string `json:"redirect"`
}
