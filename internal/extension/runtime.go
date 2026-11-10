package extension

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// sandbox is the wazero-backed execution environment for a single module. It owns
// one runtime (pure-Go interpreter, no cgo) and one compiled module, both built
// once at load. Each invocation instantiates a fresh module instance so memory
// never carries state between requests, then closes it. wazero supports
// concurrent instantiation, so a sandbox is safe to invoke concurrently.
type sandbox struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	limits   Limits
}

// errFuelExhausted is the cancellation cause used when the fuel meter aborts a
// module. It is distinguishable from a wall-clock deadline (context.Cause is
// errFuelExhausted rather than context.DeadlineExceeded), so the two budgets map
// to distinct outcomes and metrics.
var errFuelExhausted = errors.New("extension: fuel budget exhausted")

// newSandbox compiles wasm under the given limits, wiring a sealed WASI surface
// (no filesystem, no stdio, no sockets) and, when fuel metering is enabled, the
// function-call meter. It verifies the module exports the ABI and reports a
// compatible ABI version, failing fast at load otherwise.
func newSandbox(ctx context.Context, wasm []byte, limits Limits) (*sandbox, error) {
	limits = limits.withDefaults()

	cfg := wazero.NewRuntimeConfigInterpreter().
		// Periodically check the call's context during execution and close the
		// module when it is done — this is what enforces the wall-clock timeout and
		// the fuel cancellation.
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(limits.memoryPages())

	// The compile-time context carries the fuel-meter listener factory (when fuel
	// metering is on). Installing it at compile time attaches the listener to the
	// module's functions; the per-call meter is supplied via the call context.
	compileCtx := ctx
	if limits.Fuel > 0 {
		compileCtx = experimental.WithFunctionListenerFactory(ctx, fuelFactory{})
	}

	rt := wazero.NewRuntimeWithConfig(compileCtx, cfg)
	// Instantiate a sealed WASI so language runtimes that import it can initialize.
	// The default ModuleConfig (used per-call below) grants no fs/stdio/sockets, so
	// WASI provides no host access.
	if _, err := wasi_snapshot_preview1.Instantiate(compileCtx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("extension: instantiate wasi: %w", err)
	}

	compiled, err := rt.CompileModule(compileCtx, wasm)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("extension: compile module: %w", err)
	}

	sb := &sandbox{runtime: rt, compiled: compiled, limits: limits}
	if err := sb.verifyABI(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	return sb, nil
}

// verifyABI instantiates the module once and checks it exports the required ABI
// functions and reports a supported ABI version.
func (s *sandbox) verifyABI(ctx context.Context) error {
	vctx, cancel := context.WithTimeout(ctx, maxDuration(s.limits.Timeout, 5*time.Second))
	defer cancel()
	mod, err := s.instantiate(vctx)
	if err != nil {
		return fmt.Errorf("extension: instantiate for abi check: %w", err)
	}
	defer mod.Close(ctx)

	for _, name := range []string{ExportABIVersion, ExportAlloc, ExportEval} {
		if mod.ExportedFunction(name) == nil {
			return fmt.Errorf("extension: module is missing required export %q", name)
		}
	}
	if mod.Memory() == nil {
		return fmt.Errorf("extension: module does not export %q", ExportMemory)
	}
	res, err := mod.ExportedFunction(ExportABIVersion).Call(vctx)
	if err != nil {
		return fmt.Errorf("extension: calling %s: %w", ExportABIVersion, err)
	}
	if len(res) != 1 {
		return fmt.Errorf("extension: %s returned %d values, want 1", ExportABIVersion, len(res))
	}
	if got := int32(res[0]); got != ABIVersion {
		return fmt.Errorf("extension: module reports ABI version %d, host supports %d", got, ABIVersion)
	}
	return nil
}

// instantiate creates a fresh module instance with a sealed config. The instance
// is anonymous (empty name) so many can coexist on one runtime, and its WASI
// reactor initializer (_initialize) runs at instantiation when present.
func (s *sandbox) instantiate(ctx context.Context) (api.Module, error) {
	cfg := wazero.NewModuleConfig().
		WithName("").
		WithStartFunctions(exportInitialize)
	return s.runtime.InstantiateModule(ctx, s.compiled, cfg)
}

// invoke runs one evaluation: it instantiates a fresh instance, writes the input
// JSON into guest memory via the guest allocator, calls pt_eval, reads the packed
// verdict back, and classifies any termination. It always returns a populated
// Outcome; verdict is meaningful only when outcome is allow/warn/block.
func (s *sandbox) invoke(ctx context.Context, input []byte) (verdict Verdict, outcome Outcome, err error) {
	mod, err := s.instantiate(ctx)
	if err != nil {
		return Verdict{}, OutcomeError, fmt.Errorf("instantiate: %w", err)
	}
	defer mod.Close(ctx)

	// Per-invocation budget context: a wall-clock deadline (CPU/time bound) plus a
	// cancel cause used by the fuel meter. WithCloseOnContextDone makes the runtime
	// observe both.
	callCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var meter *fuelMeter
	if s.limits.Fuel > 0 {
		meter = &fuelMeter{budget: s.limits.Fuel, cancel: cancel}
		callCtx = context.WithValue(callCtx, fuelMeterKey{}, meter)
	}
	deadlineCtx, dcancel := context.WithTimeout(callCtx, s.limits.Timeout)
	defer dcancel()

	alloc := mod.ExportedFunction(ExportAlloc)
	eval := mod.ExportedFunction(ExportEval)
	mem := mod.Memory()

	// Ask the guest to allocate room for the input, then copy it in.
	allocRes, err := alloc.Call(deadlineCtx, uint64(len(input)))
	if err != nil {
		return Verdict{}, classify(deadlineCtx, callCtx, err), fmt.Errorf("alloc: %w", err)
	}
	if len(allocRes) != 1 || allocRes[0] == 0 {
		return Verdict{}, OutcomeError, errors.New("module returned a null allocation for the input")
	}
	inPtr := uint32(allocRes[0])
	if !mem.Write(inPtr, input) {
		return Verdict{}, OutcomeError, fmt.Errorf("input of %d bytes does not fit module memory at offset %d", len(input), inPtr)
	}

	evalRes, err := eval.Call(deadlineCtx, uint64(inPtr), uint64(len(input)))
	if err != nil {
		return Verdict{}, classify(deadlineCtx, callCtx, err), fmt.Errorf("eval: %w", err)
	}
	// Best-effort free of the input buffer.
	s.free(deadlineCtx, mod, inPtr)

	if len(evalRes) != 1 || evalRes[0] == 0 {
		return Verdict{}, OutcomeError, errors.New("module returned a null result from pt_eval")
	}
	outPtr, outLen := unpackResult(int64(evalRes[0]))
	if int(outLen) > s.limits.MaxOutputBytes {
		return Verdict{}, OutcomeError, fmt.Errorf("verdict of %d bytes exceeds the %d-byte output limit", outLen, s.limits.MaxOutputBytes)
	}
	raw, ok := mem.Read(outPtr, outLen)
	if !ok {
		return Verdict{}, OutcomeError, fmt.Errorf("verdict region [%d,%d) is out of bounds", outPtr, outPtr+outLen)
	}
	// Copy out before the instance (and its memory) is closed.
	out := make([]byte, len(raw))
	copy(out, raw)
	s.free(deadlineCtx, mod, outPtr)

	v, perr := ParseVerdict(out)
	if perr != nil {
		return Verdict{}, OutcomeError, perr
	}
	return v, decisionFor(v.Decision), nil
}

// free invokes the optional pt_free export, ignoring errors (the instance is
// discarded after the call regardless).
func (s *sandbox) free(ctx context.Context, mod api.Module, ptr uint32) {
	if f := mod.ExportedFunction(ExportFree); f != nil {
		_, _ = f.Call(ctx, uint64(ptr))
	}
}

// close releases the runtime and its compiled module.
func (s *sandbox) close(ctx context.Context) error {
	if s == nil || s.runtime == nil {
		return nil
	}
	return s.runtime.Close(ctx)
}

// classify maps a wazero call error to an Outcome by inspecting why execution
// stopped: a fuel cancellation (cause on the budget context), a wall-clock
// deadline, or any other trap/error.
func classify(deadlineCtx, budgetCtx context.Context, err error) Outcome {
	if err == nil {
		return OutcomeAllow
	}
	// Fuel exhaustion cancels the budget context with errFuelExhausted; check it
	// first because the deadline context derives from the budget context.
	if errors.Is(context.Cause(budgetCtx), errFuelExhausted) {
		return OutcomeFuel
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(deadlineCtx.Err(), context.DeadlineExceeded) {
		return OutcomeTimeout
	}
	// A clean guest proc_exit surfaces as a sys.ExitError; treat it (and any other
	// trap) as a module error.
	var exit *sys.ExitError
	if errors.As(err, &exit) {
		return OutcomeError
	}
	return OutcomeError
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// --- fuel metering -----------------------------------------------------------

// fuelMeterKey is the context key under which a per-invocation fuelMeter is
// stashed, so the shared listener can find it.
type fuelMeterKey struct{}

// fuelMeter counts wasm function calls for one invocation and cancels the budget
// context once the call count exceeds the configured budget.
type fuelMeter struct {
	count  atomic.Int64
	budget int64
	cancel context.CancelCauseFunc
}

// fuelFactory returns the shared fuel listener for every function definition. The
// listener reads the per-call meter from the call context, so one factory serves
// all invocations.
type fuelFactory struct{}

func (fuelFactory) NewFunctionListener(api.FunctionDefinition) experimental.FunctionListener {
	return fuelListener{}
}

// fuelListener increments the per-call meter on each function entry and trips the
// budget context's cancel when the count exceeds the budget.
type fuelListener struct{}

func (fuelListener) Before(ctx context.Context, _ api.Module, _ api.FunctionDefinition, _ []uint64, _ experimental.StackIterator) {
	m, _ := ctx.Value(fuelMeterKey{}).(*fuelMeter)
	if m == nil {
		return
	}
	if m.count.Add(1) > m.budget && m.cancel != nil {
		m.cancel(errFuelExhausted)
	}
}

func (fuelListener) After(context.Context, api.Module, api.FunctionDefinition, []uint64) {}

func (fuelListener) Abort(context.Context, api.Module, api.FunctionDefinition, error) {}
