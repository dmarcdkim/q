package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/miekg/dns"
)

// UDPSocket is one unconnected UDP socket shared by every plain query of a
// process. A dns.Client dials a socket per query, and a NAT between the
// process and the servers keeps an entry per source port for minutes after
// the reply, so a resident process that asks thousands of questions runs out
// of entries. On a shared socket every query to one server leaves from the
// same port, and the entries count servers, not questions.
//
// Replies come back on the one socket and are handed to the query that sent
// them by the pair (server address, message ID). An ID still in flight to the
// same server is renumbered before the query leaves. A reply whose question
// differs from the query's is dropped and the query keeps waiting: the fixed
// source port is what a forger guesses first, and the question is the cheap
// second check.
type UDPSocket struct {
	conn      net.PacketConn
	mu        sync.Mutex
	waiting   map[udpKey]chan []byte
	closed    bool
	done      chan struct{} // closed once the reader has stopped
	closeOnce sync.Once
	closeErr  error
}

type udpKey struct {
	server netip.AddrPort
	id     uint16
}

// defaultUDPTimeout is what dns.Client uses for a zero timeout.
const defaultUDPTimeout = 2 * time.Second

// udpReplyBacklog is how many replies the reader keeps for a query that has
// not taken them yet. The reader never blocks on a query: past this a reply
// is dropped. A query takes its reply at once, so only a second packet under
// the same key, a duplicate or a forgery, ever queues.
const udpReplyBacklog = 4

var errUDPSocketClosed = errors.New("udp socket closed")

// NewUDPSocket opens the socket and starts its reader.
func NewUDPSocket() (*UDPSocket, error) {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	// Every reply of the process lands on this socket, so ask for a larger
	// kernel buffer where the kernel allows it (Linux caps at rmem_max).
	if udpConn, ok := conn.(*net.UDPConn); ok {
		_ = udpConn.SetReadBuffer(1 << 20)
	}
	s := &UDPSocket{conn: conn, waiting: make(map[udpKey]chan []byte), done: make(chan struct{})}
	go s.read()
	return s, nil
}

// LocalAddr is the address every query leaves from.
func (s *UDPSocket) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// Exchange sends m to server and returns the reply, or a timeout error once
// timeout has passed (zero means the dns.Client default). m.Id changes when
// another query to server is in flight under it.
func (s *UDPSocket) Exchange(m *dns.Msg, server string, timeout time.Duration) (*dns.Msg, error) {
	if timeout <= 0 {
		timeout = defaultUDPTimeout
	}
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	key, replies, err := s.register(m, addr)
	if err != nil {
		return nil, err
	}
	defer s.release(key)

	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	if _, err := s.conn.WriteTo(packed, addr); err != nil {
		return nil, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case packet, ok := <-replies:
			if !ok {
				return nil, errUDPSocketClosed
			}
			reply := new(dns.Msg)
			if err := reply.Unpack(packet); err != nil {
				log.Debugf("Dropping reply from %s that does not unpack: %s", server, err)
				continue
			}
			if !sameQuestion(m, reply) {
				log.Debugf("Dropping reply from %s to another question: %s", server, reply.Question[0].String())
				continue
			}
			return reply, nil
		case <-timer.C:
			return nil, &net.OpError{Op: "read", Net: "udp", Source: s.conn.LocalAddr(), Addr: addr, Err: os.ErrDeadlineExceeded}
		}
	}
}

// Close stops the reader and fails the queries in flight. It returns once the
// reader has stopped, so nothing of the socket outlives the call.
func (s *UDPSocket) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.conn.Close() })
	<-s.done
	return s.closeErr
}

// register claims the (server, ID) pair for m, renumbering m while another
// query to server holds its ID, and returns the channel its reply arrives on.
func (s *UDPSocket) register(m *dns.Msg, addr *net.UDPAddr) (udpKey, chan []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return udpKey{}, nil, errUDPSocketClosed
	}
	key := udpKey{server: addrPort(addr), id: m.Id}
	for tries := 0; ; tries++ {
		if _, taken := s.waiting[key]; !taken {
			break
		}
		// Eight random misses in a row means nearly every ID is in flight
		// to this server, and one more query would not get an answer anyway.
		if tries == 8 {
			return udpKey{}, nil, fmt.Errorf("no free query ID for %s", addr)
		}
		key.id = dns.Id()
	}
	m.Id = key.id
	replies := make(chan []byte, udpReplyBacklog)
	s.waiting[key] = replies
	return key, replies, nil
}

func (s *UDPSocket) release(key udpKey) {
	s.mu.Lock()
	delete(s.waiting, key)
	s.mu.Unlock()
}

// read hands every packet to the query waiting under its source and ID and
// drops the rest: late replies, duplicates and packets nobody asked for. It
// stops when the socket is closed and fails the queries still waiting.
func (s *UDPSocket) read() {
	defer close(s.done)
	buf := make([]byte, dns.MaxMsgSize)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.failWaiting()
				return
			}
			log.Warnf("udp socket read: %s", err)
			continue
		}
		fromUDP, ok := from.(*net.UDPAddr)
		if !ok || n < 2 {
			continue
		}
		key := udpKey{server: addrPort(fromUDP), id: binary.BigEndian.Uint16(buf[:2])}
		s.mu.Lock()
		replies := s.waiting[key]
		s.mu.Unlock()
		if replies == nil {
			continue
		}
		select {
		case replies <- bytes.Clone(buf[:n]):
		default:
		}
	}
}

func (s *UDPSocket) failWaiting() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for key, replies := range s.waiting {
		close(replies)
		delete(s.waiting, key)
	}
}

// addrPort is the key form of addr: a dual-stack socket reports an IPv4 peer
// as an IPv4-mapped IPv6 address, which must match the IPv4 it was sent to.
func addrPort(addr *net.UDPAddr) netip.AddrPort {
	ap := addr.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// sameQuestion reports whether reply echoes the question of m. A reply with
// no question section, which some servers send for an error code, passes.
func sameQuestion(m, reply *dns.Msg) bool {
	if len(m.Question) == 0 || len(reply.Question) == 0 {
		return true
	}
	q, r := m.Question[0], reply.Question[0]
	return q.Qtype == r.Qtype && q.Qclass == r.Qclass && strings.EqualFold(q.Name, r.Name)
}
