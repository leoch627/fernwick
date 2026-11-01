// Command server is the self-hosted update, rules, download and telemetry endpoint
// for the desktop client. See server/README.md for deployment.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8787", "HTTP listen address; put a TLS reverse proxy in front")
	downloadListen := flag.String("download-listen", "", "separate listen address for the download page and files; empty serves them on -listen too")
	data := flag.String("data", "/var/lib/v2board-endpoint", "data directory")
	origin := flag.String("origin", os.Getenv("PUBLIC_ORIGIN"), "public https origin of the API, e.g. https://api.example.com")
	downloads := flag.String("download-origin", os.Getenv("DOWNLOAD_ORIGIN"), "public https origin of the download domain, used in signed file URLs; defaults to -origin")
	keyFile := flag.String("key-file", os.Getenv("SIGNING_KEY_FILE"), "PKCS#8 Ed25519 private key (or set SIGNING_KEY)")
	trustProxy := flag.Bool("trust-proxy", true, "take the client address from X-Real-IP / X-Forwarded-For")
	telemetryDays := flag.Int("telemetry-days", 30, "days to keep telemetry")
	reportDays := flag.Int("report-days", 90, "days to keep problem reports")
	printToken := flag.Bool("print-admin-token", false, "print the /admin token derived from the signing key and exit")
	flag.Parse()

	key := os.Getenv("SIGNING_KEY")
	if *keyFile != "" {
		raw, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
		key = string(raw)
	}
	if key == "" {
		log.Fatal("no signing key: set SIGNING_KEY or -key-file")
	}
	if *printToken {
		fmt.Println(adminToken(key))
		return
	}
	server, err := NewServer(*data, *origin, *downloads, key, *trustProxy)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		// Releases are valid for 24 hours and policies for 72; renew well before either lapses.
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			if _, _, err := server.Renew(false); err != nil {
				log.Printf("renew: %v", err)
			}
			server.Prune(*telemetryDays, *reportDays)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	servers := []*http.Server{}
	if *downloadListen == "" {
		servers = append(servers, &http.Server{Addr: *listen, Handler: server})
	} else {
		servers = append(servers, &http.Server{Addr: *listen, Handler: server.API()}, &http.Server{Addr: *downloadListen, Handler: server.Downloads()})
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range servers {
			_ = s.Shutdown(shutdown)
		}
	}()
	log.Printf("serving API %s and downloads %s, data in %s", server.origin, server.downloads, *data)
	failed := make(chan error, len(servers))
	for _, s := range servers {
		s.ReadHeaderTimeout, s.IdleTimeout = 10*time.Second, 120*time.Second
		go func() {
			log.Printf("listening on %s", s.Addr)
			failed <- s.ListenAndServe()
		}()
	}
	for range servers {
		if err := <-failed; err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}
