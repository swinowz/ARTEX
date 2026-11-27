// Package mcpserver is the line-delimited JSON-RPC stdio loop shared by ARTEX's
// capability servers. It exposes a closed tool list and nothing else: a server
// supplies its own bounded arguments and validation.
package mcpserver

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

// Tool is one bounded operation.
type Tool struct {
	Name        string
	Description string
	Schema      map[string]any
	// Call runs the operation. The returned value is marshalled as the tool
	// result text; an error is reported to the model as a tool error.
	Call func(ctx context.Context, args json.RawMessage) (any, error)
}

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

// Serve runs the MCP server until in is exhausted. stdout carries protocol
// frames only; diagnostics belong on stderr.
func Serve(ctx context.Context, in io.Reader, out io.Writer, serverName string, tools ...Tool) error {
	byName := make(map[string]Tool, len(tools))
	list := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		byName[t.Name] = t
		list = append(list, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.Schema,
		})
	}

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
				"serverInfo":      map[string]any{"name": serverName, "version": "0"},
			}
		case "ping":
			resp.Result = map[string]any{}
		case "tools/list":
			resp.Result = map[string]any{"tools": list}
		case "tools/call":
			resp.Result, resp.Error = callTool(ctx, byName, req.Params)
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

func callTool(ctx context.Context, tools map[string]Tool, params json.RawMessage) (any, *rpcError) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	tool, ok := tools[call.Name]
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
	}
	res, err := tool.Call(ctx, call.Arguments)
	if err != nil {
		return ToolError(err.Error()), nil
	}
	raw, _ := json.MarshalIndent(res, "", "  ")
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(raw)}}}, nil
}

// ToolError is the MCP error frame for a failed call.
func ToolError(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": strings.TrimSpace(text)}},
		"isError": true,
	}
}

// DecodeStrict decodes tool arguments and rejects unknown fields, so a model
// cannot smuggle an extra flag through a typo or an injection attempt.
func DecodeStrict(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
