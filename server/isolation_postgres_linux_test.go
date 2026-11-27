//go:build linux

package server

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// This is run by scripts/isolated-isolation-proof.sh against its own PostgreSQL
// container. Prove that the endpoint is reachable with the server credential
// before accepting the self-test's passwordless connection failure as evidence.
func TestIsolationSelfTestWithPostgres(t *testing.T) {
	dsn := os.Getenv("ARTEX_ISOLATION_PROOF_DSN")
	if dsn == "" {
		t.Skip("set ARTEX_ISOLATION_PROOF_DSN for the isolated PostgreSQL proof")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("server credential cannot reach PostgreSQL: %v", err)
	}
	defer conn.Close(context.Background())
	var one int
	if err := conn.QueryRow(ctx, "select 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("PostgreSQL query failed: result %d, error %v", one, err)
	}
	for _, db := range dsnProbeHosts(cfg) {
		err := connectWithoutPassword(&db)
		if err == nil {
			t.Fatalf("PostgreSQL accepted a passwordless connection at %s:%d", db.Host, db.Port)
		}
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "password") && !strings.Contains(msg, "sasl") && !strings.Contains(msg, "scram") {
			t.Fatalf("passwordless connection failed for a reason other than authentication: %v", err)
		}
	}
	f := newIsolationRootFixture(t)
	targets := f.targets()
	targets.DSN = dsn
	if err := IsolationSelfTest(f.priv, targets); err != nil {
		t.Fatalf("root server with executor uid %d and isolated PostgreSQL: %v", f.priv.UID, err)
	}
}
