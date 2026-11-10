package mcpserver

import "sync"

// metrics accumulates per-tool MCP telemetry. It is guarded by a mutex because
// the per-tool maps grow lazily and several transports may call concurrently.
type metrics struct {
	mu         sync.Mutex
	requests   int64
	errors     int64
	toolCalls  map[string]int64
	toolErrors map[string]int64
}

// Snapshot is the server's cumulative telemetry, surfaced to Prometheus via the
// metrics bridge and to the admin info endpoint.
type Snapshot struct {
	// Requests is the total number of JSON-RPC requests dispatched (excluding
	// notifications).
	Requests int64 `json:"requests"`
	// Errors is the total number of requests that produced a JSON-RPC error or a
	// tool result flagged isError.
	Errors int64 `json:"errors"`
	// ToolCalls counts tools/call invocations per tool name.
	ToolCalls map[string]int64 `json:"toolCalls"`
	// ToolErrors counts tools/call invocations per tool name that returned a tool
	// error (isError) or failed argument validation.
	ToolErrors map[string]int64 `json:"toolErrors"`
}

func (m *metrics) recordRequest(isErr bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	if isErr {
		m.errors++
	}
}

func (m *metrics) recordTool(name string, isErr bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.toolCalls == nil {
		m.toolCalls = map[string]int64{}
		m.toolErrors = map[string]int64{}
	}
	m.toolCalls[name]++
	if isErr {
		m.toolErrors[name]++
	}
}

func (m *metrics) snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := make(map[string]int64, len(m.toolCalls))
	for k, v := range m.toolCalls {
		calls[k] = v
	}
	errs := make(map[string]int64, len(m.toolErrors))
	for k, v := range m.toolErrors {
		errs[k] = v
	}
	return Snapshot{
		Requests:   m.requests,
		Errors:     m.errors,
		ToolCalls:  calls,
		ToolErrors: errs,
	}
}
