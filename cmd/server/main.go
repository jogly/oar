package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/jogly/oauth-router/oar"
)

func main() {
	router := &oar.Router{
		Domains: oar.ParseDomainPatterns(envOr("ALLOWED_DOMAINS", "*")),
		Origins: oar.ParseDomainPatterns(envOr("ALLOWED_ORIGINS", "*")),
		Logger:  log.Printf,
	}

	if router.IsUnsafe() {
		log.Print("unsafe domain pattern '*' allows secure codes to be sent to any domain")
	}

	log.Print(fmt.Sprintf("allowed domains: %v", router.Domains))
	log.Print(fmt.Sprintf("allowed origins: %v", router.Origins))

	http.Handle("/", router)

	port := envOr("PORT", "8080")
	host := envOr("HOST", "")

	addr := net.JoinHostPort(host, port)

	log.Printf("listening on %s", addr)
	http.ListenAndServe(addr, nil) // nolint: errcheck
}

func envOr(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func strToBool(s string) bool {
	switch strings.ToLower(s) {
	case "true", "yes", "1":
		return true
	default:
		return false
	}
}
