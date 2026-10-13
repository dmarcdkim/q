package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/log"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/util"
)

// Loopback only: the daemon speaks for whoever can reach it, so it must not
// be exposed beyond the host it serves.
const defaultDaemonAddr = "127.0.0.1:8053"

const (
	daemonShort = "Serve lookups over HTTP"
	daemonLong  = "Serve lookups over HTTP on addr, a loopback host:port or a Unix socket path. " +
		"The other flags are read once and apply to every lookup; a request overrides name, type, server and timeout. ~/.qrc is not read."
)

// daemonCommand is `q daemon [addr]`. A request carries only name, type,
// server and timeout, so the flags that shape the process, such as the -b
// bootstrap resolver, are given on the command line and applied once before
// serving; the parsed flags are the base of every request.
type daemonCommand struct {
	Args struct {
		Addr string `positional-arg-name:"addr" description:"host:port or Unix socket path (default 127.0.0.1:8053)"`
	} `positional-args:"yes"`
}

// runDaemon serves DNS queries over HTTP until SIGINT/SIGTERM. addr is a
// host:port, or a filesystem path for a Unix socket.
func runDaemon(addr string, base cli.Flags) error {
	network := "tcp"
	if strings.Contains(addr, "/") {
		network = "unix"
		if err := removeStaleSocket(addr); err != nil {
			return err
		}
	}
	listener, err := net.Listen(network, addr)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: daemonMux(base), ReadHeaderTimeout: 5 * time.Second}
	drained := make(chan error, 1)
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		drained <- server.Shutdown(ctx)
	}()

	log.Infof("q daemon listening on %s", listener.Addr())
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// Serve returns as soon as Shutdown starts: wait for the in-flight requests.
	return <-drained
}

// removeStaleSocket clears the socket a previous daemon left at path. It
// refuses a path that is not a socket, and a socket that still answers.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = conn.Close()
		return fmt.Errorf("%s is in use by another process", path)
	}
	return os.Remove(path)
}

func daemonMux(base cli.Flags) *http.ServeMux {
	// Requests always print JSON, so the color global is never written again
	// once the server is up.
	util.UseColor = false
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /query", func(w http.ResponseWriter, r *http.Request) { queryHandler(base, w, r) })
	return mux
}

// queryHandler answers GET /query?name=example.com&type=TXT&type=MX&server=1.1.1.1&timeout=3s
// with the same JSON the CLI prints for `q @1.1.1.1 TXT MX example.com --timeout=3s --format=json`.
// type and server may be repeated or comma-separated. A failed lookup is a 502
// whose body is the CLI's error message.
func queryHandler(base cli.Flags, w http.ResponseWriter, r *http.Request) {
	opts, err := queryOpts(base, r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var buf bytes.Buffer
	if err := query(&opts, nil, &buf); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
}

// queryOpts lays a request over the base flags. name, type and server are set
// on the flags directly, never parsed as arguments, so a value can neither be
// read as an option nor infer a different target. Slices are replaced, never
// appended to, so concurrent requests share nothing with base.
func queryOpts(base cli.Flags, query url.Values) (cli.Flags, error) {
	opts := base
	opts.Format = "json"

	opts.Name = query.Get("name")
	if opts.Name == "" || strings.HasPrefix(opts.Name, "-") || strings.ContainsAny(opts.Name, " \t@/") {
		return opts, fmt.Errorf("name parameter is required and must be a DNS name")
	}
	if types := splitList(query["type"]); len(types) > 0 {
		opts.Types = types
	}
	if _, err := cli.ParseRRTypes(opts.Types); err != nil {
		return opts, err
	}
	if servers := splitList(query["server"]); len(servers) > 0 {
		opts.Server = nil
		for _, server := range servers {
			opts.Server = append(opts.Server, strings.TrimPrefix(server, "@"))
		}
	}
	if timeout := query.Get("timeout"); timeout != "" {
		d, err := time.ParseDuration(timeout)
		if err != nil {
			return opts, fmt.Errorf("invalid timeout %q", timeout)
		}
		opts.Timeout = d
	}
	return opts, nil
}

func splitList(values []string) []string {
	var out []string
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, item)
			}
		}
	}
	return out
}
