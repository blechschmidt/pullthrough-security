package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
)

// JSON-RPC 2.0 error codes (subset used by this server).
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// rpcRequest is an incoming JSON-RPC 2.0 message. A message with no ID is a
// notification and produces no response.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether the message is a notification (no id present).
func (r *rpcRequest) isNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// rpcResponse is an outgoing JSON-RPC 2.0 message. Exactly one of Result/Error
// is set.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError is a JSON-RPC 2.0 error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func resultResponse(id json.RawMessage, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func errorResponse(id json.RawMessage, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// initializeParams is the subset of the MCP initialize request we read.
type initializeParams struct {
	ProtocolVersion string          `json:"protocolVersion"`
	ClientInfo      json.RawMessage `json:"clientInfo,omitempty"`
}

// toolsCallParams names the tool to invoke and carries its arguments.
type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// dispatch routes a single JSON-RPC request to its handler, scoped to tenant. It
// returns the response and whether a response should be sent (notifications
// produce none). It records request-level telemetry.
func (s *Server) dispatch(ctx context.Context, tenant string, req rpcRequest) (*rpcResponse, bool) {
	// Notifications (initialized, cancelled, ...) are acknowledged silently.
	if req.isNotification() {
		return nil, false
	}

	switch req.Method {
	case "initialize":
		s.metrics.recordRequest(false)
		return s.handleInitialize(req), true
	case "ping":
		s.metrics.recordRequest(false)
		return resultResponse(req.ID, map[string]any{}), true
	case "tools/list":
		s.metrics.recordRequest(false)
		return resultResponse(req.ID, map[string]any{"tools": s.toolDescriptors()}), true
	case "tools/call":
		return s.handleToolsCall(ctx, tenant, req), true
	default:
		s.metrics.recordRequest(true)
		return errorResponse(req.ID, codeMethodNotFound, "unknown method: "+req.Method), true
	}
}

// handleInitialize answers the MCP handshake. It negotiates the protocol version
// (echoing the client's when supplied) and advertises the tools capability.
func (s *Server) handleInitialize(req rpcRequest) *rpcResponse {
	version := supportedProtocolVersion
	if len(req.Params) > 0 {
		var p initializeParams
		if err := json.Unmarshal(req.Params, &p); err == nil {
			if v := strings.TrimSpace(p.ProtocolVersion); v != "" {
				version = v
			}
		}
	}
	result := map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    serverName,
			"version": s.version,
		},
		"instructions": "Read-only supply-chain security context for package coordinates. " +
			"Use get_risk_verdict for an authoritative safe-to-add verdict, get_vulnerabilities " +
			"and get_findings for details, get_provenance for source-commit/attestation provenance, " +
			"get_timeline for incident history, and run_query for ad-hoc questions over the security " +
			"data model. Every tool is hard-scoped to your tenant.",
	}
	return resultResponse(req.ID, result)
}

// handleToolsCall validates and invokes a tool, mapping the outcome into the MCP
// tools/call result shape (content + structuredContent + isError). Tool
// execution errors are reported as a normal result with isError=true (per the
// MCP spec), reserving JSON-RPC errors for protocol-level problems.
func (s *Server) handleToolsCall(ctx context.Context, tenant string, req rpcRequest) *rpcResponse {
	var p toolsCallParams
	if len(req.Params) == 0 || json.Unmarshal(req.Params, &p) != nil {
		s.metrics.recordRequest(true)
		return errorResponse(req.ID, codeInvalidParams, "tools/call requires params with a tool name")
	}
	name := strings.TrimSpace(p.Name)
	t, ok := s.byName[name]
	if !ok {
		s.metrics.recordRequest(true)
		s.metrics.recordTool(name, true)
		return resultResponse(req.ID, toolError("unknown tool: "+name))
	}

	structured, err := t.Handler(ctx, tenant, p.Arguments)
	if err != nil {
		s.metrics.recordRequest(true)
		s.metrics.recordTool(name, true)
		return resultResponse(req.ID, toolError(err.Error()))
	}
	s.metrics.recordRequest(false)
	s.metrics.recordTool(name, false)
	return resultResponse(req.ID, toolResult(structured))
}

// toolResult renders a successful tool outcome: the structured object plus a
// text rendering (indented JSON) so both structured-aware and text-only agents
// can consume it.
func toolResult(structured any) map[string]any {
	text := "{}"
	if b, err := json.MarshalIndent(structured, "", "  "); err == nil {
		text = string(b)
	}
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": text}},
		"structuredContent": structured,
		"isError":           false,
	}
}

// toolError renders a failed tool outcome as an isError result.
func toolError(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}
