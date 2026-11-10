package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
)

// MaxRequestBody bounds an accepted JSON-RPC message (or batch) so a hostile
// client cannot stream an unbounded body into the decoder.
const MaxRequestBody = 1 << 20 // 1 MiB

// ServeMessage handles one MCP HTTP exchange: it parses a JSON-RPC message (or a
// batch array) from body, dispatches each scoped to tenant, and returns the
// marshaled response with the HTTP status to send. A notification-only payload
// produces an empty body with 202 Accepted. A malformed payload yields a
// JSON-RPC parse error with 400.
//
// The caller (the admin handler) is responsible for authentication, the CapRead
// check, and deriving tenant from the authenticated identity before calling
// this. ServeMessage performs no auth itself; it only enforces tenant scope by
// threading tenant into every dispatch.
func (s *Server) ServeMessage(ctx context.Context, tenant string, body []byte) ([]byte, int) {
	if !s.Enabled() {
		resp := errorResponse(nil, codeInternalError, "the MCP server is not enabled")
		out, _ := json.Marshal(resp)
		return out, http.StatusServiceUnavailable
	}

	trimmed := skipSpace(body)
	if len(trimmed) == 0 {
		resp := errorResponse(nil, codeParseError, "empty request body")
		out, _ := json.Marshal(resp)
		return out, http.StatusBadRequest
	}

	// Batch: a JSON array of requests.
	if trimmed[0] == '[' {
		var batch []rpcRequest
		if err := json.Unmarshal(body, &batch); err != nil {
			resp := errorResponse(nil, codeParseError, "invalid JSON-RPC batch: "+err.Error())
			out, _ := json.Marshal(resp)
			return out, http.StatusBadRequest
		}
		responses := make([]*rpcResponse, 0, len(batch))
		for _, req := range batch {
			if resp, send := s.dispatch(ctx, tenant, req); send {
				responses = append(responses, resp)
			}
		}
		if len(responses) == 0 {
			return nil, http.StatusAccepted
		}
		out, _ := json.Marshal(responses)
		return out, http.StatusOK
	}

	// Single message.
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		resp := errorResponse(nil, codeParseError, "invalid JSON-RPC request: "+err.Error())
		out, _ := json.Marshal(resp)
		return out, http.StatusBadRequest
	}
	resp, send := s.dispatch(ctx, tenant, req)
	if !send {
		return nil, http.StatusAccepted
	}
	out, _ := json.Marshal(resp)
	return out, http.StatusOK
}

// ServerInfo is the human-facing description of the MCP surface returned by the
// admin GET /api/mcp endpoint: the server identity, the negotiated protocol
// version, the tool catalog, and the cumulative telemetry.
type ServerInfo struct {
	Name            string           `json:"name"`
	Version         string           `json:"version"`
	ProtocolVersion string           `json:"protocolVersion"`
	Tools           []toolDescriptor `json:"tools"`
	Metrics         Snapshot         `json:"metrics"`
}

// Info returns the tool catalog and server metadata for the GET endpoint.
func (s *Server) Info() ServerInfo {
	if !s.Enabled() {
		return ServerInfo{Name: serverName, ProtocolVersion: supportedProtocolVersion}
	}
	return ServerInfo{
		Name:            serverName,
		Version:         s.version,
		ProtocolVersion: supportedProtocolVersion,
		Tools:           s.toolDescriptors(),
		Metrics:         s.metrics.snapshot(),
	}
}

// skipSpace returns b with leading JSON whitespace removed.
func skipSpace(b []byte) []byte {
	for len(b) > 0 {
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			b = b[1:]
		default:
			return b
		}
	}
	return b
}
