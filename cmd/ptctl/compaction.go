package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// runCompaction reports the proxy's transparent cache compression +
// deduplication space savings (Task 125). It fetches the admin
// /api/cache/compaction endpoint and renders a human-readable report (default)
// or raw JSON.
func runCompaction(args []string) error {
	fs := flag.NewFlagSet("compaction", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	format := fs.String("format", "table", "output format: table|json")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl compaction [flags]")
		fmt.Fprintln(os.Stderr, "\nReport cache compression & cross-artifact deduplication space savings (Task 125).")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	var st cache.CompactionStats
	if err := c.getJSON(c.adminURL("api/cache/compaction", nil), &st); err != nil {
		return err
	}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	if !st.Enabled {
		fmt.Println("Cache compaction layer: disabled")
		fmt.Println("Enable it with cache.compression.enabled: true (codec zstd; optional dedup on the filesystem backend).")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "Cache compaction layer\t")
	fmt.Fprintf(tw, "  Codec\t%s (level %d)\n", st.Codec, st.Level)
	fmt.Fprintf(tw, "  Dedup\t%s\n", enabledWord(st.DedupEnabled))
	fmt.Fprintf(tw, "  Min compress size\t%s\n", humanBytes(st.MinSizeBytes))
	fmt.Fprintln(tw, "\t")
	fmt.Fprintf(tw, "  Entries compressed\t%d\n", st.EntriesCompressed)
	fmt.Fprintf(tw, "  Entries stored raw\t%d\n", st.EntriesStoredRaw)
	fmt.Fprintln(tw, "\t")
	fmt.Fprintf(tw, "  Logical bytes\t%s\n", humanBytes(st.LogicalBytes))
	fmt.Fprintf(tw, "  Physical bytes\t%s\n", humanBytes(st.PhysicalBytes))
	fmt.Fprintf(tw, "  Saved\t%s (%.1f%%)\n", humanBytes(st.SavedBytes), savedPercent(st.LogicalBytes, st.PhysicalBytes))
	fmt.Fprintf(tw, "  Compression ratio\t%.2fx\n", st.CompressionRatio)
	if st.DedupEnabled {
		fmt.Fprintln(tw, "\t")
		fmt.Fprintf(tw, "  Unique chunks\t%d\n", st.UniqueChunks)
		fmt.Fprintf(tw, "  Chunks written\t%d\n", st.DedupChunksWritten)
		fmt.Fprintf(tw, "  Chunks reused\t%d\n", st.DedupChunksReused)
		fmt.Fprintf(tw, "  Dedup savings\t%s\n", humanBytes(st.DedupSavingsBytes))
	}
	return tw.Flush()
}

func enabledWord(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

func savedPercent(logical, physical int64) float64 {
	if logical <= 0 {
		return 0
	}
	return 100 * float64(logical-physical) / float64(logical)
}

// humanBytes renders a byte count with a binary unit suffix.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
