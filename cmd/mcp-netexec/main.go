// Command mcp-netexec is ARTEX's bounded NetExec inventory capability server
// (issue #17).
//
// It speaks the MCP stdio transport. Register it in ARTEX with:
//
//	transport:       stdio
//	command:         mcp-netexec
//	task_credentials: true
//	env:             {"ARTEX_SCOPE_MANIFEST": "...", "ARTEX_SCOPE_PUBKEY": "..."}
//
// The signed mission manifest is mandatory; without it the server fails closed.
// The task's test accounts arrive in ARTEX_TASK_CREDENTIALS, injected by the
// core for this run only.
package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/Autumn-27/artex/mcps/adcore"
	"github.com/Autumn-27/artex/mcps/netexec"
	"github.com/Autumn-27/artex/scope"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("[mcp-netexec] ")
	artifacts := flag.String("artifacts", envOr("ARTEX_MCP_NETEXEC_ARTIFACT_DIR", "data/mcp-netexec"), "directory for redacted nxc logs")
	binary := flag.String("netexec", envOr("ARTEX_MCP_NETEXEC_BIN", "nxc"), "NetExec binary")
	timeout := flag.Duration("timeout", netexec.DefaultTimeout, "per-call budget")
	flag.Parse()

	g, err := scope.FromEnv()
	if err != nil {
		log.Fatalf("mission scope: %v", err)
	}
	if g.Unscoped() {
		log.Printf("WARNING: unscoped development mode; every inventory call will be denied")
	}
	creds, err := adcore.FromEnv()
	if err != nil {
		log.Fatalf("task credentials: %v", err)
	}
	log.Printf("%d task credential(s) available", creds.Len())

	s := netexec.New(g, creds, *artifacts)
	s.Binary = *binary
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
