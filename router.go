package oar

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
// the [oar.Router.Targets] field. If the [oar.Router.Targets] field is empty,
// the router will not redirect any requests.
//
// The router will also check the `Origin` header of the incoming request and
// only allow requests from domains that match one of the patterns specified in
// the [oar.Router.Origins] field. If the [oar.Router.Origins] field is empty,
// the router will not allow requests from any domain.
//
// The router will log all redirects using the function specified by
// [oar.Router.Logger]. If the field is nil, no logs will be written.
type Router struct {
	// Targets is a list of allowed domain patterns that incoming requests can
	// redirect to. `*` is unsafe, allowing a secure code to be sent to any domain.
	Targets []string

	// Origins is a list of allowed domain patterns that controls which domains
	// can make requests to this server. `*` is unsafe, allowing any domain to
	// route through this server.
	Origins []string

	// Logger is the function used to log actions taken by the router. If nil,
	// no logs will be written. The simplest logger is [log.Printf].
	Logger func(format string, v ...interface{})
}

func Unsafe() *Router {
	return &Router{
		Targets: []string{"*"},
		Origins: []string{"*"},
	}
}

// IsUnsafe returns true if the router is configured with an unsafe domain
// pattern that allows redirects to any domain.
func (r *Router) IsUnsafe() bool {
	for _, pattern := range r.Targets {
		if pattern == "*" {
			return true
		}
	}
	return false
}

// ServeHTTP handles an incoming request.
func (r *Router) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		r.badRequestf(w, "method not allowed: %s", request.Method)
		return
	}

	path := request.URL.Path
	if path != "" && path != "/" {
		r.badRequestf(w, "path not allowed: %s", request.URL.Path)
		return
	}

	var originHost string
	if r.Origins[0] != "*" { // do not validate origins when Origins: ["*"]
		originURL, err := r.parseOrigin(request.Header.Get("Origin"))
		if err != nil {
			r.blockRequestf(w, "invalid origin: %s", err)
			return
		}
		originHost = originURL.Host
	}

	targetURL, err := r.parseTarget(request.URL)
	if err != nil {
		r.badRequestf(w, "invalid state: %s", err)
		return
	}

	if !matchURL(targetURL, r.Targets) {
		r.blockRequestf(w, "target is not allowed: %s", targetURL.Host)
		return
	}

	r.logf("redirecting %s -> %s", originHost, targetURL.Host)

	http.Redirect(w, request, targetURL.String(), http.StatusFound)
}

func (r *Router) parseOrigin(origin string) (*url.URL, error) {
	originURL, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("parse origin: %w", err)
	}

	if originURL.Scheme == "" {
		return originURL, fmt.Errorf("origin is missing scheme: %s", origin)
	}

	if originURL.Host == "" {
		return originURL, fmt.Errorf("origin is missing host: %s", origin)
	}

	if !matchURL(originURL, r.Origins) {
		return originURL, fmt.Errorf("origin is not allowed: %s", originURL.Host)
	}
	return originURL, nil
}

func (r *Router) parseTarget(u *url.URL) (*url.URL, error) {
	incoming := u.Query()
	stateBytes := incoming.Get("state")
	if stateBytes == "" {
		return nil, errors.New("state is required")
	}

	stateB64, err := url.QueryUnescape(stateBytes)
	if err != nil {
		return nil, fmt.Errorf("state is not url encoded: %w", err)
	}

	if strings.TrimSpace(stateB64) == "" {
		return nil, errors.New("state is empty")
	}

	stateJSON, err := base64.StdEncoding.DecodeString(stateB64)
	if err != nil {
		return nil, fmt.Errorf("state is not base64 encoded: %w", err)
	}

	var state authState
	err = json.Unmarshal(stateJSON, &state)
	if err != nil {
		return nil, fmt.Errorf("state is invalid json: %w", err)
	}

	if state.Redirect == "" {
		return nil, errors.New("state is missing redirect")
	}

	out, err := url.ParseRequestURI(state.Redirect)
	if err != nil {
		return nil, fmt.Errorf("state.redirect is invalid URL: %w", err)
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

func (r *Router) badRequestf(w http.ResponseWriter, format string, v ...interface{}) {
	r.errRequestf(w, http.StatusBadRequest, "bad request: %s", format, v...)
}

func (r *Router) blockRequestf(w http.ResponseWriter, format string, v ...interface{}) {
	r.errRequestf(w, http.StatusForbidden, "request blocked: %s", format, v...)
}

func (r *Router) errRequestf(w http.ResponseWriter, status int, errMsgf, format string, v ...interface{}) {
	reason := fmt.Sprintf(format, v...)
	r.logf(errMsgf, reason)
	http.Error(w, reason, status)
}

func (r *Router) logf(format string, v ...interface{}) {
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
	set := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if domain = strings.TrimSpace(domain); domain == "" {
			continue
		}

		if _, ok := set[domain]; ok {
			continue
		}
		set[domain] = struct{}{}

		parts := strings.Split(domain, ".")
		if len(parts) == 1 {
			if parts[0] == "*" {
				return []string{"*"}
			}
			panic("invalid domain pattern: " + domain)
		}
		patterns = append(patterns, domain)
	}
	return patterns
}

func matchURL(u *url.URL, patterns []string) bool {
	hostParts := strings.Split(u.Host, ".")

	for _, pattern := range patterns {
		pparts := strings.Split(pattern, ".")

		if len(pparts) > len(hostParts) {
			continue
		}

		match := true
		i, j := len(pparts)-1, len(hostParts)-1
		for i >= 0 && j >= 0 {
			ppart := pparts[i]
			hpart := hostParts[j]

			if ppart == "*" {
				break
			}

			if ppart != hpart {
				match = false
				break
			}

			i--
			j--
		}

		if match {
			return true
		}
	}

	return false
}

type authState struct {
	Redirect string `json:"redirect"`
}
