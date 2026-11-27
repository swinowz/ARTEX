// Command mcp-enum4linux is ARTEX's bounded enum4linux-ng enumeration
// capability server (issue #17).
//
// It speaks the MCP stdio transport. Register it in ARTEX with:
//
//	transport:        stdio
//	command:          mcp-enum4linux
//	task_credentials: true
//	env:              {"ARTEX_SCOPE_MANIFEST": "...", "ARTEX_SCOPE_PUBKEY": "..."}
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
	"github.com/Autumn-27/artex/mcps/enum4linux"
	"github.com/Autumn-27/artex/scope"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("[mcp-enum4linux] ")
	artifacts := flag.String("artifacts", envOr("ARTEX_MCP_E4L_ARTIFACT_DIR", "data/mcp-enum4linux"), "directory for redacted JSON exports")
	binary := flag.String("enum4linux", envOr("ARTEX_MCP_E4L_BIN", "enum4linux-ng"), "enum4linux-ng binary")
	timeout := flag.Duration("timeout", enum4linux.DefaultTimeout, "per-call budget")
	flag.Parse()

	g, err := scope.FromEnv()
	if err != nil {
		log.Fatalf("mission scope: %v", err)
	}
	if g.Unscoped() {
		log.Printf("WARNING: unscoped development mode; every enumerate call will be denied")
	}
	creds, err := adcore.FromEnv()
	if err != nil {
		log.Fatalf("task credentials: %v", err)
	}
	log.Printf("%d task credential(s) available", creds.Len())

	s := enum4linux.New(g, creds, *artifacts)
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
