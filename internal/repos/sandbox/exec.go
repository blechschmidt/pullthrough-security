package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// ExecMain is the in-container half of a job, run as "<binary> sandbox-exec
// <spec>": it starts the forwarder — an HTTP relay from the loopback address
// the tool is configured with to the proxy's unix socket, adding the session
// token — and then runs the job's commands in order. It returns the process's
// exit status: the first failing command's, or 0.
func ExecMain(specPath string) int {
	data, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: reading the job: %v\n", err)
		return 125
	}
	var sp spec
	if err := json.Unmarshal(data, &sp); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: reading the job: %v\n", err)
		return 125
	}
	// Whatever the commands leave belongs to this container's user; the
	// proxy's user, which is not this one, reads the results and removes
	// the rest once the container is gone.
	if sp.Release != "" {
		defer release(sp.Release)
	}
	if len(sp.Commands) == 0 {
		return 0
	}
	if home := os.Getenv("HOME"); home != "" {
		_ = os.MkdirAll(home, 0o755)
	}
	ln, err := net.Listen("tcp", sp.Listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: the forwarder cannot listen on %s: %v\n", sp.Listen, err)
		return 125
	}
	srv := &http.Server{Handler: relay(sp.Socket, sp.Token), ReadHeaderTimeout: time.Minute}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	if err := limitFileSize(maxFileBytes); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: limiting file sizes: %v\n", err)
		return 125
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	env := append(os.Environ(), sp.Env...)
	for _, argv := range sp.Commands {
		if len(argv) == 0 {
			continue
		}
		fmt.Fprintf(os.Stdout, "sandbox: running %q\n", argv)
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Dir = sp.Dir
		cmd.Env = env
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() > 0 {
				return exit.ExitCode()
			}
			fmt.Fprintf(os.Stderr, "sandbox: %v\n", err)
			return 126
		}
	}
	return 0
}

// release opens up the tree below dir to every user: directories 0777, files
// 0666. What this container's user created is otherwise private to it, and the
// proxy's user, outside, could neither read a result written 0600 nor remove a
// directory made 0755. Entries another user owns are left alone, and symbolic
// links are not followed.
func release(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		mode := fs.FileMode(0o666)
		if d.IsDir() {
			mode = 0o777
		}
		_ = os.Chmod(p, mode)
		return nil
	})
}

// relay forwards every request to the proxy's socket with the session token.
// The tool cannot reach anything else: the container has no network.
func relay(socket, token string) http.Handler {
	target := &url.URL{Scheme: "http", Host: "proxy"}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		ResponseHeaderTimeout: 15 * time.Minute,
	}
	base := rp.Director
	rp.Director = func(r *http.Request) {
		base(r)
		r.Header.Set(TokenHeader, token)
	}
	return rp
}
