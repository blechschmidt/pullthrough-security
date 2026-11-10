package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	connect "connectrpc.com/connect"

	securityv1 "github.com/blechschmidt/pullthrough-security/internal/grpcapi/gen/securityv1"
	"github.com/blechschmidt/pullthrough-security/internal/grpcapi/gen/securityv1/securityv1connect"
)

// runGRPC drives the proxy's read-only gRPC/Connect security API (Task 159). It
// doubles as an example client: it shows how to construct the generated Connect
// client against the admin-mounted endpoint, attach the bearer credential, and
// call both a unary and a server-streaming RPC.
//
//	ptctl grpc                      smoke test: compliance scorecard + a streamed query
//	ptctl grpc --rpc risk --name left-pad --ecosystem npm
//	ptctl grpc --rpc findings --name log4j-core --ecosystem maven --version 2.14.1
//	ptctl grpc --rpc provenance --name express --ecosystem npm --version 4.18.2
//	ptctl grpc --rpc dossier --name left-pad --ecosystem npm
//	ptctl grpc --rpc compliance [--refresh]
//	ptctl grpc --rpc query  --select coordinate,riskScore --where '{"field":"riskBlock","op":"eq","value":true}'
//	ptctl grpc --rpc stream --select coordinate,riskScore --limit 25
func runGRPC(args []string) error {
	fs := flag.NewFlagSet("grpc", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	rpc := fs.String("rpc", "", "RPC to call: risk|findings|provenance|dossier|compliance|query|stream (default: smoke test)")
	name := fs.String("name", "", "package name (for risk/findings/provenance/dossier)")
	ecosystem := fs.String("ecosystem", "", "package ecosystem (optional)")
	pkgVersion := fs.String("version", "", "package version (optional)")
	coordinate := fs.String("coordinate", "", "package coordinate name[@version] (for dossier)")
	selectFields := fs.String("select", "", "comma-separated fields to project (for query/stream)")
	whereJSON := fs.String("where", "", "where predicate as a JSON object (for query/stream)")
	limit := fs.Int("limit", 0, "page size (for query/stream)")
	offset := fs.Int("offset", 0, "pagination offset (for query/stream)")
	refresh := fs.Bool("refresh", false, "recompute the compliance scorecard from live posture (for compliance)")
	asJSON := fs.Bool("json", false, "print raw JSON results")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl grpc [--rpc <name>] [flags]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Query the proxy's read-only gRPC/Connect security API (Task 159).")
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
	cli := c.grpcClient()
	ctx := context.Background()

	switch strings.TrimSpace(*rpc) {
	case "":
		return grpcSmokeTest(ctx, cli, c.tenant)
	case "risk":
		return grpcRisk(ctx, cli, c.tenant, *ecosystem, *name, *pkgVersion, *asJSON)
	case "findings":
		return grpcFindings(ctx, cli, c.tenant, *ecosystem, *name, *pkgVersion, *asJSON)
	case "provenance":
		return grpcProvenance(ctx, cli, c.tenant, *ecosystem, *name, *pkgVersion, *asJSON)
	case "dossier":
		return grpcDossier(ctx, cli, c.tenant, *ecosystem, *coordinate, *name, *pkgVersion, *asJSON)
	case "compliance":
		return grpcCompliance(ctx, cli, *refresh, *asJSON)
	case "query":
		return grpcQuery(ctx, cli, c.tenant, splitCSV(*selectFields), *whereJSON, *limit, *offset, *asJSON)
	case "stream":
		return grpcStream(ctx, cli, c.tenant, splitCSV(*selectFields), *whereJSON, *limit, *offset, *asJSON)
	default:
		return fmt.Errorf("unknown --rpc %q (want risk|findings|provenance|dossier|compliance|query|stream)", *rpc)
	}
}

// grpcClient constructs the generated Connect client pointed at the proxy's
// admin-mounted gRPC endpoint, injecting the bearer credential on every request
// (unary and streaming) via a transport wrapper. It speaks the Connect protocol
// over HTTP/1.1 so it works against the plain admin listener.
func (c *client) grpcClient() securityv1connect.SecurityQueryServiceClient {
	base := c.baseURL + c.adminPrefix + "/api/grpc"
	httpClient := &http.Client{
		Timeout:   c.http.Timeout,
		Transport: &bearerTransport{token: c.token, base: c.http.Transport},
	}
	return securityv1connect.NewSecurityQueryServiceClient(httpClient, base)
}

// bearerTransport attaches the proxy access token to every request. Wrapping the
// transport (rather than using a Connect interceptor) covers unary and streaming
// calls uniformly.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.token != "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	return base.RoundTrip(req)
}

// grpcErr renders a Connect error with its code so onboarding failures (auth,
// not-found) are legible.
func grpcErr(action string, err error) error {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return fmt.Errorf("%s: %s: %s", action, ce.Code(), ce.Message())
	}
	return fmt.Errorf("%s: %w", action, err)
}

func grpcSmokeTest(ctx context.Context, cli securityv1connect.SecurityQueryServiceClient, tenant string) error {
	// 1) a unary RPC: the compliance scorecard.
	cardResp, err := cli.GetComplianceScorecard(ctx, connect.NewRequest(&securityv1.ComplianceScorecardRequest{}))
	if err != nil {
		return grpcErr("GetComplianceScorecard", err)
	}
	card := cardResp.Msg
	if card.GetEnabled() {
		fmt.Printf("Connected. Compliance scorecard: grade %s (score %.2f), status %s, SLSA %s.\n",
			card.GetGrade(), card.GetScore(), card.GetStatus(), card.GetSlsa().GetTrack())
	} else {
		fmt.Println("Connected. Compliance scorecard is not enabled on this proxy.")
	}

	// 2) a server-streaming RPC: a small corpus query.
	req := connect.NewRequest(&securityv1.QueryRequest{Tenant: tenant, Limit: 5})
	stream, err := cli.StreamQueryCorpus(ctx, req)
	if err != nil {
		return grpcErr("StreamQueryCorpus", err)
	}
	rows := 0
	for stream.Receive() {
		if _, ok := stream.Msg().GetKind().(*securityv1.QueryRowOrSummary_Summary); ok {
			break
		}
		rows++
	}
	if err := stream.Err(); err != nil {
		return grpcErr("StreamQueryCorpus", err)
	}
	fmt.Printf("Streamed %d row(s) from the federated security corpus.\n", rows)
	fmt.Println("\nSmoke test OK. Pass --rpc <name> to call a specific RPC.")
	return nil
}

func grpcRisk(ctx context.Context, cli securityv1connect.SecurityQueryServiceClient, tenant, eco, name, ver string, asJSON bool) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("--rpc risk requires --name")
	}
	resp, err := cli.GetRiskVerdict(ctx, connect.NewRequest(&securityv1.CoordinateRequest{
		Tenant: tenant, Ecosystem: eco, Name: name, Version: ver,
	}))
	if err != nil {
		return grpcErr("GetRiskVerdict", err)
	}
	v := resp.Msg
	if asJSON {
		return printProtoJSON(v)
	}
	fmt.Printf("%s — verdict %s, band %s, score %d (found=%t)\n",
		orDash(v.GetCoordinate()), v.GetVerdict(), orDash(v.GetBand()), v.GetScore(), v.GetFound())
	fmt.Println(v.GetSummary())
	for _, ct := range v.GetContributions() {
		fmt.Printf("  - %-20s %+.1f pts  %s\n", ct.GetSignal(), ct.GetPoints(), ct.GetDetail())
	}
	return nil
}

func grpcFindings(ctx context.Context, cli securityv1connect.SecurityQueryServiceClient, tenant, eco, name, ver string, asJSON bool) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("--rpc findings requires --name")
	}
	resp, err := cli.GetFindings(ctx, connect.NewRequest(&securityv1.CoordinateRequest{
		Tenant: tenant, Ecosystem: eco, Name: name, Version: ver,
	}))
	if err != nil {
		return grpcErr("GetFindings", err)
	}
	f := resp.Msg
	if asJSON {
		return printProtoJSON(f)
	}
	fmt.Printf("%s — %d finding(s), %d blocking, worst=%s\n",
		orDash(f.GetCoordinate()), f.GetTotal(), f.GetBlocking(), orDash(f.GetWorstSeverity()))
	for _, it := range f.GetFindings() {
		sup := ""
		if it.GetSuppressed() {
			sup = " (suppressed)"
		}
		fmt.Printf("  - [%s/%s] %s %s%s\n", it.GetGate(), it.GetSeverity(), orDash(it.GetIdentifier()), it.GetTitle(), sup)
	}
	return nil
}

func grpcProvenance(ctx context.Context, cli securityv1connect.SecurityQueryServiceClient, tenant, eco, name, ver string, asJSON bool) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("--rpc provenance requires --name")
	}
	resp, err := cli.GetProvenance(ctx, connect.NewRequest(&securityv1.CoordinateRequest{
		Tenant: tenant, Ecosystem: eco, Name: name, Version: ver,
	}))
	if err != nil {
		return grpcErr("GetProvenance", err)
	}
	p := resp.Msg
	if asJSON {
		return printProtoJSON(p)
	}
	fmt.Printf("%s — %d direct dependents, %d downstream paths\n",
		orDash(p.GetCoordinate()), p.GetDirectDependents(), p.GetDownstreamPaths())
	if sc := p.GetSourceCommit(); sc.GetFound() {
		fmt.Printf("  source commit: %s %s\n", orDash(sc.GetCommitSha()), orDash(sc.GetCommitId()))
	}
	if rd := p.GetReverseDependencies(); rd.GetFound() {
		fmt.Printf("  reverse deps: %d total (%d direct)\n", rd.GetTotal(), rd.GetDirect())
	}
	if a := p.GetAttestation(); a != nil {
		fmt.Printf("  attestation present: %t\n", a.GetPresent())
	}
	return nil
}

func grpcDossier(ctx context.Context, cli securityv1connect.SecurityQueryServiceClient, tenant, eco, coordinate, name, ver string, asJSON bool) error {
	if strings.TrimSpace(coordinate) == "" && strings.TrimSpace(name) == "" {
		return fmt.Errorf("--rpc dossier requires --coordinate or --name")
	}
	resp, err := cli.GetDossier(ctx, connect.NewRequest(&securityv1.GetDossierRequest{
		Tenant: tenant, Ecosystem: eco, Coordinate: coordinate, Name: name, Version: ver,
	}))
	if err != nil {
		return grpcErr("GetDossier", err)
	}
	d := resp.Msg
	if asJSON {
		return printProtoJSON(d)
	}
	h := d.GetHeadline()
	fmt.Printf("%s — verdict %s (risk %d %s)%s\n",
		orDash(d.GetCoordinate()), h.GetVerdict(), h.GetRiskScore(), orDash(h.GetRiskBand()),
		partialTag(d.GetPartial()))
	fmt.Println(h.GetSummary())
	for _, r := range h.GetReasons() {
		fmt.Printf("  - %s\n", r)
	}
	for _, s := range d.GetSources() {
		fmt.Printf("  source %-14s %s %s\n", s.GetSource(), s.GetStatus(), s.GetDetail())
	}
	return nil
}

func grpcCompliance(ctx context.Context, cli securityv1connect.SecurityQueryServiceClient, refresh, asJSON bool) error {
	resp, err := cli.GetComplianceScorecard(ctx, connect.NewRequest(&securityv1.ComplianceScorecardRequest{Refresh: refresh}))
	if err != nil {
		return grpcErr("GetComplianceScorecard", err)
	}
	card := resp.Msg
	if asJSON {
		return printProtoJSON(card)
	}
	if !card.GetEnabled() {
		fmt.Println("compliance scorecard is not enabled on this proxy")
		return nil
	}
	fmt.Printf("Compliance: grade %s (score %.2f), status %s\n", card.GetGrade(), card.GetScore(), card.GetStatus())
	fmt.Printf("SLSA: %s — %s\n", card.GetSlsa().GetTrack(), card.GetSlsa().GetRationale())
	sum := card.GetSummary()
	fmt.Printf("Controls: %d pass, %d warn, %d fail, %d n/a\n", sum.GetPass(), sum.GetWarn(), sum.GetFail(), sum.GetNa())
	for _, ctl := range card.GetControls() {
		fmt.Printf("  [%-4s] %-28s %s\n", ctl.GetStatus(), ctl.GetId(), ctl.GetDetail())
	}
	return nil
}

func grpcQuery(ctx context.Context, cli securityv1connect.SecurityQueryServiceClient, tenant string, sel []string, whereJSON string, limit, offset int, asJSON bool) error {
	resp, err := cli.QueryCorpus(ctx, connect.NewRequest(&securityv1.QueryRequest{
		Tenant: tenant, Select: sel, WhereJson: whereJSON, Limit: int32(limit), Offset: int32(offset),
	}))
	if err != nil {
		return grpcErr("QueryCorpus", err)
	}
	r := resp.Msg
	if asJSON {
		return printProtoJSON(r)
	}
	fmt.Printf("%d row(s) of %d (scanned %d, cost %d, truncated=%t)\n",
		r.GetReturned(), r.GetTotal(), r.GetScanned(), r.GetCost(), r.GetTruncated())
	for _, row := range r.GetRows() {
		fmt.Printf("  %s\n", compactStruct(row.AsMap()))
	}
	return nil
}

func grpcStream(ctx context.Context, cli securityv1connect.SecurityQueryServiceClient, tenant string, sel []string, whereJSON string, limit, offset int, asJSON bool) error {
	stream, err := cli.StreamQueryCorpus(ctx, connect.NewRequest(&securityv1.QueryRequest{
		Tenant: tenant, Select: sel, WhereJson: whereJSON, Limit: int32(limit), Offset: int32(offset),
	}))
	if err != nil {
		return grpcErr("StreamQueryCorpus", err)
	}
	rows := 0
	for stream.Receive() {
		msg := stream.Msg()
		switch k := msg.GetKind().(type) {
		case *securityv1.QueryRowOrSummary_Row:
			rows++
			if asJSON {
				if err := printProtoJSON(msg); err != nil {
					return err
				}
			} else {
				fmt.Printf("  %s\n", compactStruct(k.Row.AsMap()))
			}
		case *securityv1.QueryRowOrSummary_Summary:
			s := k.Summary
			fmt.Printf("-- streamed %d row(s); total %d, scanned %d, cost %d, truncated=%t\n",
				rows, s.GetTotal(), s.GetScanned(), s.GetCost(), s.GetTruncated())
		}
	}
	if err := stream.Err(); err != nil {
		return grpcErr("StreamQueryCorpus", err)
	}
	return nil
}

// printProtoJSON prints a proto message as indented JSON. The generated messages
// carry JSON tags, so the stdlib encoder renders a faithful, dependency-light
// view without pulling in protojson.
func printProtoJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// compactStruct renders a query row map as a stable, compact key=value list.
func compactStruct(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return strings.Join(parts, " ")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func partialTag(partial bool) string {
	if partial {
		return " [partial]"
	}
	return ""
}
