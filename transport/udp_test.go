package transport

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// udpServer is a loopback DNS server that records the source port of every query.
type udpServer struct {
	addr  string
	mu    sync.Mutex
	ports map[string]int
}

func serveUDP(t *testing.T, handler dns.HandlerFunc) *udpServer {
	return serveUDPOn(t, "127.0.0.1:0", handler)
}

func serveUDPOn(t *testing.T, listen string, handler dns.HandlerFunc) *udpServer {
	conn, err := net.ListenPacket("udp", listen)
	if err != nil {
		t.Skipf("cannot listen on %s: %s", listen, err)
	}
	s := &udpServer{addr: conn.LocalAddr().String(), ports: map[string]int{}}
	srv := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.mu.Lock()
		s.ports[port(w.RemoteAddr())]++
		s.mu.Unlock()
		handler(w, r)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return s
}

func (s *udpServer) queriesFrom(p string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ports[p]
}

func (s *udpServer) sourcePorts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ports := make([]string, 0, len(s.ports))
	for p := range s.ports {
		ports = append(ports, p)
	}
	return ports
}

func port(addr net.Addr) string {
	_, p, _ := net.SplitHostPort(addr.String())
	return p
}

// answer is a reply to r with one A record for its question.
func answer(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg).SetReply(r)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(127, 0, 0, 1),
	}}
	return m
}

func answering(w dns.ResponseWriter, r *dns.Msg) {
	_ = w.WriteMsg(answer(r))
}

func question(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func newSocket(t *testing.T) *UDPSocket {
	s, err := NewUDPSocket()
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// settledGoroutines waits for the goroutines the test started to end and
// returns the count left. assert.Eventually would run the check in a goroutine
// of its own and count it.
func settledGoroutines(baseline int) int {
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

// inflight is how many queries hold a key, which must be zero between queries.
func (s *UDPSocket) inflight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.waiting)
}

// Concurrent queries through one Plain leave from one port, and each gets its
// own reply back.
func TestUDPSocketSharesOneSourcePort(t *testing.T) {
	server := serveUDP(t, answering)
	socket := newSocket(t)
	tp := &Plain{Common: Common{Server: server.addr}, EDNS: true, UDPBuffer: 1232, Timeout: 2 * time.Second, Socket: socket}

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := question(fmt.Sprintf("host%d.example", i))
			q.Id = dns.Id()
			reply, err := tp.Exchange(q)
			if err != nil {
				errs <- err
				return
			}
			if reply.Id != q.Id || reply.Question[0].Name != q.Question[0].Name || len(reply.Answer) != 1 {
				errs <- fmt.Errorf("wrong reply for %s: %s", q.Question[0].Name, reply)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, []string{port(socket.LocalAddr())}, server.sourcePorts())
	assert.Equal(t, 0, socket.inflight())
}

// An IPv4 peer shows up as an IPv4-mapped address on the dual-stack socket,
// and an IPv6 peer as itself: replies from both find their query.
func TestUDPSocketReachesIPv6(t *testing.T) {
	server := serveUDPOn(t, "[::1]:0", answering)
	socket := newSocket(t)
	reply, err := socket.Exchange(question("six.example"), server.addr, 2*time.Second)
	require.NoError(t, err)
	assert.Len(t, reply.Answer, 1)
	assert.Equal(t, []string{port(socket.LocalAddr())}, server.sourcePorts())
	assert.Equal(t, 0, socket.inflight())
}

// Two queries to one server under one ID cannot share the socket: the second
// is renumbered, and both get their own answer.
func TestUDPSocketRenumbersAnIDInFlight(t *testing.T) {
	server := serveUDP(t, func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(200 * time.Millisecond)
		answering(w, r)
	})
	socket := newSocket(t)
	queries := []*dns.Msg{question("first.example"), question("second.example")}
	queries[0].Id, queries[1].Id = 7, 7

	var wg sync.WaitGroup
	replies := make([]*dns.Msg, 2)
	errs := make([]error, 2)
	for i, q := range queries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replies[i], errs[i] = socket.Exchange(q, server.addr, 2*time.Second)
		}()
	}
	wg.Wait()
	for i, q := range queries {
		require.NoError(t, errs[i])
		assert.Equal(t, q.Id, replies[i].Id)
		assert.Equal(t, q.Question[0].Name, replies[i].Question[0].Name)
	}
	assert.NotEqual(t, queries[0].Id, queries[1].Id)
	assert.True(t, queries[0].Id == 7 || queries[1].Id == 7, "the first query keeps its ID")
	assert.Equal(t, 0, socket.inflight())
}

// A query that times out releases its key at once and reports the same
// timeout a dns.Client would. Its reply, arriving later, is dropped and the
// socket goes on serving.
func TestUDPSocketTimeoutReleasesTheQuery(t *testing.T) {
	late := serveUDP(t, func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(300 * time.Millisecond)
		answering(w, r)
	})
	prompt := serveUDP(t, answering)
	socket := newSocket(t)

	q := question("slow.example")
	start := time.Now()
	reply, err := socket.Exchange(q, late.addr, 100*time.Millisecond)
	assert.Nil(t, reply)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout())
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	assert.Contains(t, err.Error(), "i/o timeout")
	assert.Less(t, time.Since(start), time.Second)
	assert.Equal(t, 0, socket.inflight())

	time.Sleep(400 * time.Millisecond)
	retry := question("slow.example")
	retry.Id = q.Id
	reply, err = socket.Exchange(retry, prompt.addr, time.Second)
	require.NoError(t, err)
	assert.Equal(t, retry.Id, reply.Id)
	assert.Equal(t, 1, late.queriesFrom(port(socket.LocalAddr())), "the late server saw the one query")
	assert.Equal(t, 0, socket.inflight())
}

// Only a reply under the query's ID that echoes its question is the answer.
// A packet that does not unpack, one under another ID and one to another
// question are dropped while the query keeps waiting.
func TestUDPSocketDropsRepliesToOtherQueries(t *testing.T) {
	server := serveUDP(t, func(w dns.ResponseWriter, r *dns.Msg) {
		_, _ = w.Write([]byte{byte(r.Id >> 8), byte(r.Id), 0x81, 0x80})
		otherID := answer(r)
		otherID.Id++
		_ = w.WriteMsg(otherID)
		otherQuestion := answer(r)
		otherQuestion.Question[0].Name = "other.example."
		_ = w.WriteMsg(otherQuestion)
		answering(w, r)
	})
	socket := newSocket(t)
	q := question("mine.example")
	reply, err := socket.Exchange(q, server.addr, 2*time.Second)
	require.NoError(t, err)
	assert.Equal(t, q.Id, reply.Id)
	assert.Equal(t, "mine.example.", reply.Question[0].Name)
	assert.Equal(t, "mine.example.", reply.Answer[0].Header().Name)
	assert.Equal(t, 0, socket.inflight())
}

// An error reply without a question section is still the answer.
func TestUDPSocketAcceptsReplyWithoutQuestion(t *testing.T) {
	server := serveUDP(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := &dns.Msg{MsgHdr: dns.MsgHdr{Id: r.Id, Response: true, Rcode: dns.RcodeRefused}}
		_ = w.WriteMsg(m)
	})
	socket := newSocket(t)
	reply, err := socket.Exchange(question("refused.example"), server.addr, 2*time.Second)
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeRefused, reply.Rcode)
	assert.Equal(t, 0, socket.inflight())
}

// Close fails the queries in flight at once, refuses new ones, stops the
// reader and gives the port back. A second Close is harmless.
func TestUDPSocketCloseReleasesEverything(t *testing.T) {
	arrived := make(chan struct{}, 1)
	server := serveUDP(t, func(w dns.ResponseWriter, r *dns.Msg) {
		arrived <- struct{}{}
		time.Sleep(500 * time.Millisecond)
		answering(w, r)
	})
	goroutines := runtime.NumGoroutine()
	socket, err := NewUDPSocket()
	require.NoError(t, err)
	local := socket.LocalAddr().String()

	result := make(chan error, 1)
	go func() {
		_, err := socket.Exchange(question("hang.example"), server.addr, 5*time.Second)
		result <- err
	}()
	<-arrived
	assert.Equal(t, 1, socket.inflight())

	start := time.Now()
	assert.NoError(t, socket.Close())
	assert.ErrorIs(t, <-result, errUDPSocketClosed)
	assert.Less(t, time.Since(start), time.Second, "Exchange waited for its timeout after Close")
	assert.Equal(t, 0, socket.inflight())

	_, err = socket.Exchange(question("after.example"), server.addr, time.Second)
	assert.ErrorIs(t, err, errUDPSocketClosed)
	assert.NoError(t, socket.Close())

	conn, err := net.ListenPacket("udp", local)
	require.NoError(t, err, "the port is still held")
	_ = conn.Close()
	assert.LessOrEqual(t, settledGoroutines(goroutines), goroutines, "the reader is still running")
}

// A truncated UDP reply is retried over TCP, which has its own connection, and
// the UDP query still leaves from the shared socket.
func TestPlainSocketFallsBackToTCPWhenTruncated(t *testing.T) {
	server := serveUDP(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	listener, err := net.Listen("tcp", server.addr)
	require.NoError(t, err)
	tcp := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(answering)}
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() { _ = tcp.Shutdown() })

	socket := newSocket(t)
	tp := &Plain{Common: Common{Server: server.addr}, UDPBuffer: 1232, Timeout: 2 * time.Second, Socket: socket}
	reply, err := tp.Exchange(question("big.example"))
	require.NoError(t, err)
	assert.False(t, reply.Truncated)
	assert.Len(t, reply.Answer, 1)
	assert.Equal(t, []string{port(socket.LocalAddr())}, server.sourcePorts())
	assert.Equal(t, 0, socket.inflight())
}
