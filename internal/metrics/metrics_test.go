package metrics

import (
	"strings"
	"testing"
)

func render(t *testing.T, r *Registry) string {
	t.Helper()
	var sb strings.Builder
	if err := r.WritePrometheus(&sb); err != nil {
		t.Fatalf("WritePrometheus: %v", err)
	}
	return sb.String()
}

func TestCounterAndGauge(t *testing.T) {
	r := New()
	c := r.NewCounter("requests_total", "total requests")
	c.Inc()
	c.Add(4)
	g := r.NewGauge("queue_depth", "items queued")
	g.Set(7)
	g.Dec()

	out := render(t, r)
	for _, want := range []string{
		"# HELP requests_total total requests",
		"# TYPE requests_total counter",
		"requests_total 5",
		"# TYPE queue_depth gauge",
		"queue_depth 6",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestCounterVecLabels(t *testing.T) {
	r := New()
	v := r.NewCounterVec("http_requests_total", "by backend and status", []string{"backend", "status"})
	v.With("npm", "200").Add(3)
	v.With("npm", "404").Inc()

	out := render(t, r)
	if !strings.Contains(out, `http_requests_total{backend="npm",status="200"} 3`) {
		t.Errorf("missing 200 series:\n%s", out)
	}
	if !strings.Contains(out, `http_requests_total{backend="npm",status="404"} 1`) {
		t.Errorf("missing 404 series:\n%s", out)
	}
}

func TestHistogram(t *testing.T) {
	r := New()
	h := r.NewHistogram("latency_seconds", "request latency", []float64{0.1, 0.5, 1})
	h.Observe(0.05) // bucket 0.1
	h.Observe(0.2)  // bucket 0.5
	h.Observe(2)    // only +Inf

	out := render(t, r)
	for _, want := range []string{
		"# TYPE latency_seconds histogram",
		`latency_seconds_bucket{le="0.1"} 1`,
		`latency_seconds_bucket{le="0.5"} 2`,
		`latency_seconds_bucket{le="1"} 2`,
		`latency_seconds_bucket{le="+Inf"} 3`,
		"latency_seconds_count 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
	// Sum should be 0.05+0.2+2 = 2.25
	if !strings.Contains(out, "latency_seconds_sum 2.25") {
		t.Errorf("missing sum:\n%s", out)
	}
}

func TestRegisterFunc(t *testing.T) {
	r := New()
	val := 42.0
	r.RegisterFunc("cache_hits_total", "cache hits", "counter", func() float64 { return val })
	out := render(t, r)
	if !strings.Contains(out, "# TYPE cache_hits_total counter") || !strings.Contains(out, "cache_hits_total 42") {
		t.Errorf("func collector not rendered:\n%s", out)
	}
}

func TestRegisterFuncVec(t *testing.T) {
	r := New()
	r.RegisterFuncVec("notifications_sent_total", "by sink", "counter", []string{"sink"},
		func() []LabeledValue {
			return []LabeledValue{
				{Labels: []string{"slack"}, Value: 3},
				{Labels: []string{"hook"}, Value: 7},
				{Labels: []string{"too", "many"}, Value: 99}, // mismatched arity: skipped
			}
		})
	out := render(t, r)
	if !strings.Contains(out, "# TYPE notifications_sent_total counter") {
		t.Errorf("type line missing:\n%s", out)
	}
	if !strings.Contains(out, `notifications_sent_total{sink="slack"} 3`) {
		t.Errorf("slack series missing:\n%s", out)
	}
	if !strings.Contains(out, `notifications_sent_total{sink="hook"} 7`) {
		t.Errorf("hook series missing:\n%s", out)
	}
	if strings.Contains(out, "99") {
		t.Errorf("mismatched-arity sample should have been skipped:\n%s", out)
	}
}

func TestLabelEscaping(t *testing.T) {
	r := New()
	v := r.NewGaugeVec("thing", "", []string{"path"})
	v.With(`a"b\c`).Set(1)
	out := render(t, r)
	if !strings.Contains(out, `thing{path="a\"b\\c"} 1`) {
		t.Errorf("label not escaped:\n%s", out)
	}
}

func TestDuplicatePanics(t *testing.T) {
	r := New()
	r.NewCounter("dup", "")
	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate metric name")
		}
	}()
	r.NewGauge("dup", "")
}
