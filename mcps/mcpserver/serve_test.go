package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testTools() []Tool {
	return []Tool{{
		Name:        "run",
		Description: "d",
		Schema:      map[string]any{"type": "object", "additionalProperties": false},
		Call: func(_ context.Context, args json.RawMessage) (any, error) {
			var in struct {
				Target string `json:"target"`
			}
			if err := DecodeStrict(args, &in); err != nil {
				return nil, err
			}
			if in.Target == "fail" {
				return nil, errors.New("boom")
			}
			return map[string]any{"target": in.Target}, nil
		},
	}}
}

func TestServeProtocol(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run","arguments":{"target":"x"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run","arguments":{"target":"fail"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run","arguments":{"target":"x","extra":1}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"nope"}`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`,
	}, "\n")
	var out bytes.Buffer
	if err := Serve(context.Background(), strings.NewReader(in), &out, "fixture", testTools()...); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 7 {
		t.Fatalf("responses = %d: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `"protocolVersion":"2025-03-26"`) || !strings.Contains(lines[0], `"name":"fixture"`) {
		t.Fatalf("initialize: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"additionalProperties":false`) {
		t.Fatalf("tools/list: %s", lines[1])
	}
	if !strings.Contains(lines[2], `\"target\": \"x\"`) {
		t.Fatalf("call result: %s", lines[2])
	}
	if !strings.Contains(lines[3], `"isError":true`) || !strings.Contains(lines[3], "boom") {
		t.Fatalf("tool error: %s", lines[3])
	}
	if !strings.Contains(lines[4], `"isError":true`) {
		t.Fatalf("unknown field accepted: %s", lines[4])
	}
	if !strings.Contains(lines[5], `"code":-32601`) {
		t.Fatalf("unknown method: %s", lines[5])
	}
	if !strings.Contains(lines[6], `"result":{}`) {
		t.Fatalf("ping: %s", lines[6])
	}
}

func TestServeToleratesGarbage(t *testing.T) {
	var out bytes.Buffer
	if err := Serve(context.Background(), strings.NewReader("not json\n[]\n"), &out, "fixture", testTools()...); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("garbage produced output: %q", out.String())
	}
}
