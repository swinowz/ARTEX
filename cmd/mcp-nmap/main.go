// Command mcp-nmap is ARTEX's bounded nmap capability MCP server (issue #15).
//
// It speaks the MCP stdio transport. Register it in ARTEX with:
//
//	transport: stdio
//	command:   mcp-nmap
//	env:       {"ARTEX_SCOPE_MANIFEST": "...", "ARTEX_SCOPE_PUBKEY": "..."}
//
// The signed mission manifest is mandatory; without it the server fails closed.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/Autumn-27/artex/mcps/nmap"
	"github.com/Autumn-27/artex/scope"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("[mcp-nmap] ")
	artifacts := flag.String("artifacts", envOr("ARTEX_MCP_NMAP_ARTIFACT_DIR", "data/mcp-nmap"), "directory for raw nmap XML artifacts")
	timeout := flag.Duration("timeout", 15*time.Minute, "per-scan timeout")
	flag.Parse()

	g, err := scope.FromEnv()
	if err != nil {
		log.Fatalf("mission scope: %v", err)
	}
	if g.Unscoped() {
		log.Printf("WARNING: unscoped development mode; every discover call will be denied")
	}
	s := nmap.New(g, *artifacts)
	s.Timeout = *timeout
	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
