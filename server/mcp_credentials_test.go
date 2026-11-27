package server

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcps/adcore"
)

func credTaskCtx(taskID int64) context.Context {
	return agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID})
}

func TestWithTaskCredentials(t *testing.T) {
	load := func(int64) ([]db.TaskCredential, error) {
		return []db.TaskCredential{
			{ID: 12, Domain: "LAB.LOCAL", Username: "alice", Password: "pw1"},
			{ID: 13, Domain: "LAB.LOCAL", Username: "bob", Password: "pw2"},
			{ID: 14, Domain: "LAB.LOCAL", Username: "nopw"}, // user-declared, no password
		}, nil
	}

	t.Run("flag off keeps the env untouched", func(t *testing.T) {
		m := &db.MCPServer{Transport: "stdio"}
		env, err := withTaskCredentials(credTaskCtx(5), m, map[string]string{"A": "b"}, load, false)
		if err != nil || len(env) != 1 || env["A"] != "b" {
			t.Fatalf("env = %v, err = %v", env, err)
		}
	})

	t.Run("flag on injects the task accounts", func(t *testing.T) {
		m := &db.MCPServer{Transport: "stdio", TaskCredentials: true}
		env, err := withTaskCredentials(credTaskCtx(5), m, map[string]string{"A": "b"}, load, false)
		if err != nil {
			t.Fatal(err)
		}
		raw, ok := env[adcore.EnvCredentials]
		if !ok {
			t.Fatal("credentials were not injected")
		}
		creds, err := adcore.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(creds) != 2 { // the account without a password is skipped
			t.Fatalf("creds = %+v", creds)
		}
		if creds[0].Ref != "12" || creds[0].Username != "alice" || creds[0].Secret != "pw1" {
			t.Fatalf("first credential = %+v", creds[0])
		}
		if env["A"] != "b" {
			t.Fatal("configured env was lost")
		}
	})

	t.Run("chat run starts without credentials", func(t *testing.T) {
		m := &db.MCPServer{Transport: "stdio", TaskCredentials: true}
		env, err := withTaskCredentials(context.Background(), m, nil, load, false)
		if err != nil || env[adcore.EnvCredentials] != "" {
			t.Fatalf("env = %v, err = %v", env, err)
		}
	})

	t.Run("sandbox mode is refused", func(t *testing.T) {
		m := &db.MCPServer{Transport: "stdio", TaskCredentials: true}
		if _, err := withTaskCredentials(credTaskCtx(5), m, nil, load, true); err == nil {
			t.Fatal("sandboxed run accepted task credentials")
		}
	})

	t.Run("remote transports are not injected", func(t *testing.T) {
		m := &db.MCPServer{Transport: "http", TaskCredentials: true}
		env, err := withTaskCredentials(credTaskCtx(5), m, nil, load, false)
		if err != nil || env[adcore.EnvCredentials] != "" {
			t.Fatalf("env = %v, err = %v", env, err)
		}
	})
}
