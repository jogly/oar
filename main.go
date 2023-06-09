package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type aauthState struct {
	Redirect string `json:"redirect"`
}

func main() {
	domainPatterns := parseDomainPatterns(envOr("ALLOWED_DOMAINS", "*"))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		incoming := r.URL.Query()
		stateBytes := incoming.Get("state")
		if stateBytes == "" {
			http.Error(w, "state is required", http.StatusBadRequest)
			return
		}

		stateB64, err := url.QueryUnescape(stateBytes)
		if err != nil {
			http.Error(w, "state is malformed", http.StatusBadRequest)
		}

		if stateB64 == "" {
			http.Error(w, "state is empty", http.StatusBadRequest)
		}

		stateJSON, err := base64.StdEncoding.DecodeString(stateB64)
		if err != nil {
			http.Error(w, "state is not base64", http.StatusBadRequest)
		}

		var state aauthState
		err = json.Unmarshal(stateJSON, &state)
		if err != nil {
			http.Error(w, fmt.Sprintf("state is invalid json: %s", err), http.StatusBadRequest)
		}

		u, err := url.ParseRequestURI(state.Redirect)
		if err != nil {
			fmt.Println(string(stateJSON))
			http.Error(w, fmt.Sprintf("state.redirect is invalid URL: %s", err), http.StatusBadRequest)
			return
		}

		if u.Host == "" {
			http.Error(w, "state.redirect is missing host", http.StatusBadRequest)
		}

		host := strings.Split(u.Host, ":")[0]
		hostParts := strings.Split(host, ".")

		if !matchDomain(hostParts, domainPatterns) {
			http.Error(w, "state.redirect is not allowed", http.StatusBadRequest)
			return
		}

		embed := u.Query()
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

		u.RawQuery = merged.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})

	port := envOr("PORT", "8080")
	host := envOr("HOST", "")

	addr := net.JoinHostPort(host, port)

	log.Printf("Listening on %s", addr)
	http.ListenAndServe(addr, nil)
}

func envOr(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func parseDomainPatterns(str string) [][]string {
	domains := strings.Split(str, ",")
	patterns := make([][]string, len(domains))
	for i, domain := range domains {
		patterns[i] = strings.Split(domain, ".")
	}
	return patterns
}

func matchDomain(hostParts []string, patterns [][]string) bool {
	for _, pattern := range patterns {
		if len(pattern) > len(hostParts) {
			continue
		}

		match := true
		for i, part := range pattern {
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
