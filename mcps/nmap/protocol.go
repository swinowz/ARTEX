package nmap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
)

// protocolVersion mirrors the MCP versions ARTEX's client negotiates.
const protocolVersion = "2025-11-25"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve runs the line-delimited JSON-RPC MCP server until in is exhausted.
// stdout carries protocol frames only; diagnostics go to stderr in main.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue // notifications and malformed frames are ignored
		}
		if len(req.ID) == 0 {
			continue // notification: no response
		}
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
		switch req.Method {
		case "initialize":
			resp.Result = map[string]any{
				"protocolVersion": negotiateVersion(req.Params),
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "nmap", "version": "0"},
			}
		case "ping":
			resp.Result = map[string]any{}
		case "tools/list":
			resp.Result = map[string]any{"tools": []map[string]any{{
				"name":        "discover",
				"description": ToolDescription,
				"inputSchema": ToolSchema(),
			}}}
		case "tools/call":
			resp.Result, resp.Error = s.toolCall(ctx, req.Params)
		default:
			resp.Error = &rpcError{Code: -32601, Message: "unknown method " + req.Method}
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func negotiateVersion(params json.RawMessage) string {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	switch p.ProtocolVersion {
	case "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25":
		return p.ProtocolVersion
	}
	return protocolVersion
}

func (s *Server) toolCall(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	if call.Name != "discover" {
		return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
	}
	req, err := decodeRequest(call.Arguments)
	if err != nil {
		return toolError("invalid discover input: " + err.Error()), nil
	}
	res, err := s.Discover(ctx, req)
	if err != nil {
		return toolError(err.Error()), nil
	}
	raw, _ := json.MarshalIndent(res, "", "  ")
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(raw)}}}, nil
}

func toolError(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": strings.TrimSpace(text)}},
		"isError": true,
	}
}
