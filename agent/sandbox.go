package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// CommandSandbox is a task-scoped execution backend. File tools remain confined
// to their existing run directory, mounted at the same path by this backend.
type CommandSandbox interface {
	Execute(context.Context, int64, string, string, time.Duration, []string) ([]byte, error)
}

func (w *Worker) SetSandbox(s CommandSandbox) { w.sandbox = s }

type sandboxBash struct {
	actool.CoreTool
	backend CommandSandbox
	taskID  int64
}

func (t *sandboxBash) Prompt() string {
	return "Executes Bash inside this run's container. Commands are synchronous with a timeout (default 120 seconds, max 600). Background execution is unavailable in this mode. Write scripts and evidence in the working directory; files there are shared with Read/Write/Edit."
}
func (t *sandboxBash) InputSchema() map[string]any {
	return map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}, "timeout_ms": map[string]any{"type": "integer"}}, "required": []any{"command"}}
}
func (t *sandboxBash) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var input struct {
		Command    string `json:"command"`
		Timeout    int    `json:"timeout_ms"`
		Background bool   `json:"run_in_background"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if strings.TrimSpace(input.Command) == "" {
		return actool.Errorf("command is required"), nil
	}
	if input.Background {
		return actool.Errorf("background execution is unavailable in container mode; use a synchronous command"), nil
	}
	if tc == nil || tc.WorkingDir == "" {
		return actool.Errorf("sandbox requires a working directory"), nil
	}
	duration := 120 * time.Second
	if input.Timeout > 0 {
		duration = time.Duration(min(input.Timeout, 600000)) * time.Millisecond
	}
	out, err := t.backend.Execute(ctx, t.taskID, tc.WorkingDir, input.Command, duration, nil)
	text := actool.Capture(tc, string(out))
	if err != nil {
		return actool.Errorf(fmt.Sprintf("%s\n[container command failed: %v]", text, err)), nil
	}
	return actool.Text(text), nil
}
func sandboxWorkerTools(base []actool.CoreTool, backend CommandSandbox, id int64) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(base))
	for _, tool := range base {
		if tool.Name() == "Bash" {
			out = append(out, &sandboxBash{CoreTool: tool, backend: backend, taskID: id})
		} else {
			out = append(out, tool)
		}
	}
	return out
}

// Preserve agent visibility, skill gating and deferred MCP metadata. The
// sandbox only changes the Bash execution tool; other tool transports retain
// their configured behavior and remain covered by the degraded isolation status.
func assembleWorkerTools(ctx context.Context, base, external []actool.CoreTool, backend CommandSandbox, id int64) ([]actool.CoreTool, DeferredInfo, func()) {
	all := append(base, external...)
	tools, def, cleanup := AugmentTools(ctx, "worker", all)
	if backend != nil {
		tools = sandboxWorkerTools(tools, backend, id)
	}
	return tools, def, cleanup
}
func assembleTaskTools(ctx context.Context, kind string, base []actool.CoreTool, backend CommandSandbox, id int64) ([]actool.CoreTool, DeferredInfo, func()) {
	tools, def, cleanup := AugmentTools(ctx, kind, base)
	if backend != nil {
		tools = sandboxWorkerTools(tools, backend, id)
	}
	return tools, def, cleanup
}
