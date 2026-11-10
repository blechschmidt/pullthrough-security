package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// runCacheEncryption reports the proxy's at-rest cache-encryption status or
// triggers a key-encryption-key rotation (Task 141). It is a thin client over
// the admin /api/cache/encryption surface:
//
//	ptctl cache-encryption status   # default
//	ptctl cache-encryption rotate
func runCacheEncryption(args []string) error {
	fs := flag.NewFlagSet("cache-encryption", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	format := fs.String("format", "table", "output format: table|json")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl cache-encryption [status|rotate] [flags]")
		fmt.Fprintln(os.Stderr, "\nReport at-rest cache-encryption status, or rotate the key-encryption key (Task 141).")
		fmt.Fprintln(os.Stderr, "\nSubcommands:")
		fmt.Fprintln(os.Stderr, "  status   show encryption status and cumulative statistics (default)")
		fmt.Fprintln(os.Stderr, "  rotate   re-wrap every object's data key to the active KEK (payloads are not rewritten)")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	// Accept an optional leading subcommand before the flags (status|rotate).
	sub := "status"
	if len(args) > 0 && (args[0] == "status" || args[0] == "rotate") {
		sub = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "table" && *format != "json" {
		return fmt.Errorf("unknown --format %q (want table or json)", *format)
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	switch sub {
	case "status":
		return encryptionStatus(c, *format)
	case "rotate":
		return encryptionRotate(c, *format)
	default:
		fs.Usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

func encryptionStatus(c *client, format string) error {
	var st cache.EncryptionStats
	if err := c.getJSON(c.adminURL("api/cache/encryption", nil), &st); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(st)
	}
	if !st.Enabled {
		fmt.Println("At-rest cache encryption: disabled")
		fmt.Println("Enable it with cache.encryption.enabled: true (keyId + keyRef; AES-256-GCM envelope).")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "At-rest cache encryption\t")
	fmt.Fprintf(tw, "  Algorithm\t%s\n", st.Algorithm)
	fmt.Fprintf(tw, "  Key wrapping\t%s\n", st.KeyDerivation)
	fmt.Fprintf(tw, "  Primary KEK\t%s\n", st.PrimaryKeyID)
	fmt.Fprintf(tw, "  Known KEKs\t%s\n", strings.Join(st.KnownKeyIDs, ", "))
	fmt.Fprintf(tw, "  FIPS mode\t%s\n", enabledWord(st.FIPS))
	fmt.Fprintf(tw, "  Frame size\t%s\n", humanBytes(int64(st.FrameSizeBytes)))
	fmt.Fprintln(tw, "\t")
	fmt.Fprintf(tw, "  Objects encrypted\t%d\n", st.ObjectsEncrypted)
	fmt.Fprintf(tw, "  Objects decrypted\t%d\n", st.ObjectsDecrypted)
	fmt.Fprintf(tw, "  Bytes encrypted\t%s\n", humanBytes(st.BytesEncrypted))
	fmt.Fprintf(tw, "  Bytes decrypted\t%s\n", humanBytes(st.BytesDecrypted))
	fmt.Fprintf(tw, "  DEKs wrapped\t%d\n", st.DEKsWrapped)
	fmt.Fprintf(tw, "  Decrypt failures\t%d\n", st.DecryptFailures)
	fmt.Fprintln(tw, "\t")
	fmt.Fprintf(tw, "  Rotations\t%d\n", st.Rotations)
	fmt.Fprintf(tw, "  Re-wrapped objects\t%d\n", st.RewrappedObjects)
	if !st.LastRotation.IsZero() {
		fmt.Fprintf(tw, "  Last rotation\t%s\n", st.LastRotation.Format("2006-01-02 15:04:05 MST"))
	}
	return tw.Flush()
}

func encryptionRotate(c *client, format string) error {
	var rep cache.KEKRotationReport
	if err := c.postJSON(c.adminURL("api/cache/encryption/rotate", nil), struct{}{}, &rep); err != nil {
		return err
	}
	if format == "json" {
		return printJSON(rep)
	}
	if rep.Unsupported {
		fmt.Println("Key rotation is not supported on this cache backend (the store cannot update metadata in place).")
		fmt.Println("Re-wrapping without re-encrypting payloads requires a metadata-updatable store (the filesystem backend).")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "KEK rotation complete\t")
	fmt.Fprintf(tw, "  Primary KEK\t%s\n", rep.PrimaryKeyID)
	fmt.Fprintf(tw, "  Duration\t%s\n", rep.Duration)
	fmt.Fprintln(tw, "\t")
	fmt.Fprintf(tw, "  Scanned\t%d\n", rep.Scanned)
	fmt.Fprintf(tw, "  Re-wrapped\t%d\n", rep.Rewrapped)
	fmt.Fprintf(tw, "  Already current\t%d\n", rep.AlreadyCurrent)
	fmt.Fprintf(tw, "  Skipped\t%d\n", rep.Skipped)
	fmt.Fprintf(tw, "  Errors\t%d\n", rep.Errors)
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(rep.SampleErrors) > 0 {
		fmt.Println("\nSample errors:")
		for _, e := range rep.SampleErrors {
			fmt.Printf("  - %s\n", e)
		}
	}
	if rep.Errors > 0 {
		fmt.Println("\nObjects wrapped by a KEK that is no longer configured could not be re-wrapped.")
		fmt.Println("Add the old key under cache.encryption.previousKeys and rotate again.")
	}
	return nil
}
