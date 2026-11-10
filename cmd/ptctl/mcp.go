package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// runMCP drives the proxy's read-only Model Context Protocol endpoint (Task 79).
//
// In the default (smoke-test) mode it performs the MCP handshake against the
// proxy's admin /api/mcp endpoint, lists the exposed tools, and — when --call is
// given — invokes one tool for a coordinate and prints its result. This both
// onboards an operator and serves as a connectivity/auth/tool self-test.
//
// In --stdio mode it turns ptctl into a thin stdio↔HTTP bridge so an IDE agent
// (Claude Desktop, a Codex/Cursor MCP client) can speak newline-delimited
// JSON-RPC on stdin/stdout while ptctl forwards each message to the proxy's MCP
// HTTP endpoint, scoped to --tenant. Configure the agent to run:
//
//	ptctl mcp --stdio --url https://proxy.example.com --tenant acme --token $TOKEN
func runMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	stdio := fs.Bool("stdio", false, "run as a stdio↔HTTP MCP bridge (for IDE agents) instead of the smoke test")
	call := fs.String("call", "", "in smoke-test mode, invoke this tool (e.g. get_risk_verdict) after listing")
	name := fs.String("name", "", "package name for --call")
	ecosystem := fs.String("ecosystem", "", "package ecosystem for --call (optional)")
	pkgVersion := fs.String("version", "", "package version for --call (optional)")
	asJSON := fs.Bool("json", false, "print raw JSON results")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl mcp [--stdio] [--call <tool> --name <pkg>] [flags]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Query the proxy's read-only MCP security endpoint, or bridge stdio↔HTTP for IDE agents.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	if *stdio {
		return mcpStdioBridge(c)
	}
	return mcpSmokeTest(c, *call, *name, *ecosystem, *pkgVersion, *asJSON)
}

// jsonrpcRequest is a JSON-RPC 2.0 request envelope.
type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// jsonrpcResponse is a JSON-RPC 2.0 response envelope.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// mcpURL returns the proxy's MCP endpoint, carrying the tenant scope.
func (c *client) mcpURL() string {
	return c.adminURL("api/mcp", map[string]string{"tenant": c.tenant})
}

// mcpCall sends one JSON-RPC request and returns the decoded response.
func (c *client) mcpCall(method string, params any) (*jsonrpcResponse, error) {
	req := jsonrpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params}
	var resp jsonrpcResponse
	if err := c.postJSON(c.mcpURL(), req, &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return &resp, fmt.Errorf("MCP error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	return &resp, nil
}

// mcpSmokeTest exercises the MCP endpoint end to end.
func mcpSmokeTest(c *client, call, name, ecosystem, pkgVersion string, asJSON bool) error {
	// 1) initialize handshake.
	initResp, err := c.mcpCall("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"clientInfo":      map[string]any{"name": "ptctl", "version": version},
		"capabilities":    map[string]any{},
	})
	if err != nil {
		return fmt.Errorf("MCP initialize failed: %w", err)
	}
	var initResult struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	_ = json.Unmarshal(initResp.Result, &initResult)
	fmt.Printf("Connected to MCP server %q (version %s, protocol %s)\n",
		initResult.ServerInfo.Name, initResult.ServerInfo.Version, initResult.ProtocolVersion)

	// 2) tools/list.
	listResp, err := c.mcpCall("tools/list", map[string]any{})
	if err != nil {
		return fmt.Errorf("MCP tools/list failed: %w", err)
	}
	var listResult struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(listResp.Result, &listResult)
	fmt.Printf("\nExposed tools (%d):\n", len(listResult.Tools))
	for _, t := range listResult.Tools {
		fmt.Printf("  - %-20s %s\n", t.Name, firstSentence(t.Description))
	}

	if strings.TrimSpace(call) == "" {
		fmt.Println("\nSmoke test OK. Pass --call <tool> --name <pkg> to invoke a tool.")
		return nil
	}

	// 3) tools/call.
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("--call requires --name <package>")
	}
	args := map[string]any{"name": name}
	if ecosystem != "" {
		args["ecosystem"] = ecosystem
	}
	if pkgVersion != "" {
		args["version"] = pkgVersion
	}
	callResp, err := c.mcpCall("tools/call", map[string]any{"name": call, "arguments": args})
	if err != nil {
		return fmt.Errorf("MCP tools/call %q failed: %w", call, err)
	}
	var callResult struct {
		IsError           bool            `json:"isError"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		Content           []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(callResp.Result, &callResult)
	fmt.Printf("\nResult of %s(%s):\n", call, name)
	if asJSON && len(callResult.StructuredContent) > 0 {
		var buf bytes.Buffer
		_ = json.Indent(&buf, callResult.StructuredContent, "", "  ")
		fmt.Println(buf.String())
	} else if len(callResult.Content) > 0 {
		fmt.Println(callResult.Content[0].Text)
	}
	if callResult.IsError {
		return fmt.Errorf("tool reported an error (see output above)")
	}
	return nil
}

// mcpStdioBridge forwards newline-delimited JSON-RPC messages between stdin/stdout
// and the proxy's MCP HTTP endpoint, scoped to the configured tenant.
func mcpStdioBridge(c *client) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		respBody, status, err := c.mcpForward(line)
		if err != nil {
			return err
		}
		// 202 (notification) yields no response line.
		if status == http.StatusAccepted || len(bytes.TrimSpace(respBody)) == 0 {
			continue
		}
		if _, err := out.Write(respBody); err != nil {
			return err
		}
		if err := out.WriteByte('\n'); err != nil {
			return err
		}
		if err := out.Flush(); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// mcpForward POSTs a raw JSON-RPC message body to the MCP endpoint and returns
// the response body and status.
func (c *client) mcpForward(body []byte) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, c.mcpURL(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting to %s: %w", c.mcpURL(), err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return respBody, resp.StatusCode, nil
}

// firstSentence trims a description to its first sentence for compact listings.
func firstSentence(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i+1]
	}
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
