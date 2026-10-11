// Command httpserver is a small HTTP target for the inbound eBPF tracer.
// It intentionally closes each connection after one request so application
// request records can be paired with kernel connection records by endpoints.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type connectionInfo struct {
	local      string
	remote     string
	acceptedNS uint64
}

type requestLog struct {
	Event              string `json:"event"`
	RequestID          uint64 `json:"request_id,omitempty"`
	Local              string `json:"local"`
	Remote             string `json:"remote"`
	TimestampNS        uint64 `json:"timestamp_ns"`
	AcceptedAtNS       uint64 `json:"accepted_at_ns,omitempty"`
	HandlerStartedNS   uint64 `json:"handler_started_ns,omitempty"`
	FirstResponseWrite uint64 `json:"first_response_write_ns,omitempty"`
	HandlerCompletedNS uint64 `json:"handler_completed_ns,omitempty"`
	AcceptToHandlerNS  uint64 `json:"accept_to_handler_ns,omitempty"`
	HandlerDurationNS  uint64 `json:"handler_duration_ns,omitempty"`
	Status             int    `json:"status,omitempty"`
	ResponseBytes      int    `json:"response_bytes,omitempty"`
}

type responseWriter struct {
	http.ResponseWriter
	status       int
	bytes        int
	firstWriteNS uint64
}

func (w *responseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
	if w.firstWriteNS == 0 {
		w.firstWriteNS = monotonicNS()
	}
}

func (w *responseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
		w.ResponseWriter.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(body)
	if w.firstWriteNS == 0 {
		w.firstWriteNS = monotonicNS()
	}
	w.bytes += n
	return n, err
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	flag.Parse()

	logger := log.New(os.Stdout, "", 0)
	var logMu sync.Mutex
	var requestID atomic.Uint64
	emit := func(record requestLog) {
		logMu.Lock()
		defer logMu.Unlock()
		_ = json.NewEncoder(logger.Writer()).Encode(record)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("hello from the traced Go server\n"))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This marks when Go begins processing the parsed HTTP request.
		info, _ := r.Context().Value(connectionContextKey{}).(*connectionInfo)
		started := monotonicNS()
		id := requestID.Add(1)
		tracked := &responseWriter{ResponseWriter: w}
		w.Header().Set("Connection", "close")
		mux.ServeHTTP(tracked, r)
		completed := monotonicNS()
		if tracked.status == 0 {
			tracked.status = http.StatusOK
		}
		record := requestLog{
			Event: "request_complete", RequestID: id,
			HandlerStartedNS: started, FirstResponseWrite: tracked.firstWriteNS,
			HandlerCompletedNS: completed, HandlerDurationNS: completed - started,
			Status: tracked.status, ResponseBytes: tracked.bytes,
		}
		if info != nil {
			record.Local, record.Remote, record.AcceptedAtNS = info.local, info.remote, info.acceptedNS
			record.TimestampNS = completed
			record.AcceptToHandlerNS = started - info.acceptedNS
		}
		emit(record)
	})

	server := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			// ConnContext runs after Accept returns, giving us the app-side accept time.
			info := &connectionInfo{
				local: conn.LocalAddr().String(), remote: conn.RemoteAddr().String(),
				acceptedNS: monotonicNS(),
			}
			emit(requestLog{Event: "accepted", Local: info.local, Remote: info.remote,
				TimestampNS: info.acceptedNS})
			return context.WithValue(ctx, connectionContextKey{}, info)
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.New(os.Stderr, "", log.LstdFlags).Printf("listening on %s", *addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

type connectionContextKey struct{}

func monotonicNS() uint64 {
	// CLOCK_MONOTONIC shares its time base with bpf_ktime_get_ns on Linux.
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		log.Fatal(err)
	}
	return uint64(now.Nano())
}
