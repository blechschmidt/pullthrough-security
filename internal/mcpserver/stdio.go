package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// stdioMaxLine bounds a single newline-delimited JSON-RPC message read from
// stdin so a malformed stream cannot exhaust memory.
const stdioMaxLine = 1 << 20 // 1 MiB

// ServeStdio runs the MCP server over a newline-delimited JSON-RPC stream (the
// stdio transport): it reads one JSON-RPC message per line from in, dispatches
// it scoped to tenant, and writes each response as a single line to out.
// Notifications produce no output line. It returns when in reaches EOF or ctx is
// cancelled.
//
// tenant is the fixed hard scope for the whole session: a stdio MCP server is
// launched per developer/agent, so the tenant is established once (by the
// launching process) rather than per request.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer, tenant string) error {
	if !s.Enabled() {
		return fmt.Errorf("mcpserver: server is not enabled")
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64<<10), stdioMaxLine)
	enc := json.NewEncoder(out)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := skipSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			if encErr := enc.Encode(errorResponse(nil, codeParseError, "invalid JSON-RPC request: "+err.Error())); encErr != nil {
				return encErr
			}
			continue
		}
		resp, send := s.dispatch(ctx, tenant, req)
		if !send {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}
