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
		_ = os.Remove(addr)
	}
	listener, err := net.Listen(network, addr)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: daemonMux(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Infof("q daemon listening on %s", listener.Addr())
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
	args, err := queryArgs(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	opts := newOpts()
	opts.Color = false
	var buf bytes.Buffer
	if err := driver(&opts, args, &buf); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
}

func queryArgs(query url.Values) ([]string, error) {
	name := query.Get("name")
	if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, " \t@/") {
		return nil, fmt.Errorf("name parameter is required and must be a DNS name")
	}

	var args []string
	for _, server := range splitList(query["server"]) {
		args = append(args, "@"+strings.TrimPrefix(server, "@"))
	}
	for _, rrType := range splitList(query["type"]) {
		if strings.HasPrefix(rrType, "-") {
			return nil, fmt.Errorf("invalid type %q", rrType)
		}
		args = append(args, rrType)
	}
	args = append(args, name)
	if timeout := query.Get("timeout"); timeout != "" {
		if _, err := time.ParseDuration(timeout); err != nil {
			return nil, fmt.Errorf("invalid timeout %q", timeout)
		}
		args = append(args, "--timeout="+timeout)
	}
	return append(args, "--format=json"), nil
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
