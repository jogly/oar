package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"time"

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

	log.Printf("allowed domains: %v", router.Domains)
	log.Printf("allowed origins: %v", router.Origins)

	http.Handle("/", router)

	port := envOr("PORT", "8080")
	host := envOr("HOST", "")

	addr := net.JoinHostPort(host, port)

	log.Printf("listening on %s", addr)
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: strToDuration(envOr("READ_HEADER_TIMEOUT", "5s")),
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func strToDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Fatalf("invalid duration: %s", err)
	}
	return d
}
