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

// runDaemon serves DNS queries over HTTP until SIGINT/SIGTERM. addr is a
// host:port, or a filesystem path for a Unix socket.
func runDaemon(addr string) error {
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

	server := &http.Server{Handler: daemonMux(), ReadHeaderTimeout: 5 * time.Second}
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

func daemonMux() *http.ServeMux {
	// Requests always print JSON, so the color global is never written again
	// once the server is up.
	util.UseColor = false
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /query", queryHandler)
	return mux
}

// queryHandler answers GET /query?name=example.com&type=TXT&type=MX&server=1.1.1.1&timeout=3s
// with the same JSON the CLI prints for `q @1.1.1.1 TXT MX example.com --timeout=3s --format=json`.
// type and server may be repeated or comma-separated. A failed lookup is a 502
// whose body is the CLI's error message.
func queryHandler(w http.ResponseWriter, r *http.Request) {
	opts, args, err := queryOpts(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var buf bytes.Buffer
	if err := driver(&opts, args, &buf); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
}

// queryOpts maps a request onto the CLI flags. name, type and server are set
// on the flags directly, never passed as arguments, so the CLI parser can
// neither read them as options nor infer a different target from them.
func queryOpts(query url.Values) (cli.Flags, []string, error) {
	opts := newOpts()
	opts.Color = false

	opts.Name = query.Get("name")
	if opts.Name == "" || strings.HasPrefix(opts.Name, "-") || strings.ContainsAny(opts.Name, " \t@/") {
		return opts, nil, fmt.Errorf("name parameter is required and must be a DNS name")
	}
	opts.Types = splitList(query["type"])
	if _, err := cli.ParseRRTypes(opts.Types); err != nil {
		return opts, nil, err
	}
	for _, server := range splitList(query["server"]) {
		opts.Server = append(opts.Server, strings.TrimPrefix(server, "@"))
	}

	args := []string{"--format=json"}
	if timeout := query.Get("timeout"); timeout != "" {
		if _, err := time.ParseDuration(timeout); err != nil {
			return opts, nil, fmt.Errorf("invalid timeout %q", timeout)
		}
		args = append(args, "--timeout="+timeout)
	}
	return opts, args, nil
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
