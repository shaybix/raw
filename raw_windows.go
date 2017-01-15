// +build windows

package raw

import (
	"net"
	"sync"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/context"
)

var (
	_ net.PacketConn = &packetConn{}
)

type packetConn struct {
	ifi *net.Interface
	s   socket

	sleeper sleeper

	// Timeouts set via Set{Read,}Deadline, guarded by mutex
	timeoutMu   sync.RWMutex
	nonblocking bool
	rtimeout    time.Time
}

// socket is an interface which enables swapping out socket syscalls for
// testing.
type socket interface {
	Bind(syscall.Sockaddr) error
	Close() error
	FD() int
	Recvfrom([]byte, int) (int, syscall.Sockaddr, error)
	Sendto([]byte, int, syscall.Sockaddr) error
	SetNonblock(bool) error
	SetSockopt(level, name int, v unsafe.Pointer, l uint32) error
}

type sleeper interface {
	Sleep(time.Duration)
}

func listenPacket(ifi *net.Interface, proto Protocol) (*packetConn, error) {

	// Convert proto to big endian
	pbe := htons(uint16(proto))

	// Open a packet socket using specified socket and protocol types
	fd, err := syscall.Socket(syscall.AF_UNSPEC, syscall.SOCK_RAW, int(pbe))
	if err != nil {
		return nil, err
	}

	return newPacketConn(
		ifi,
		&sysSocket{
			fd: fd,
		},
		pbe,
		&timeSleeper{},
	)

}

func newPacketConn(ifi *net.Interface, s socket, pbe int, sleeper sleeper) (*packetConn, error) {

	if err := s.Bind(s.fd, &syscall.RawSockAddr, unsafe.Sizeof(&syscall.RawSockAddr)); err != nil {
		return nil, err
	}

	return &packetConn{
		ifi:     ifi,
		s:       s,
		sleeper: sleeper,
	}, err

}

// Readfrom implements the net.PackConn.ReadFrom method
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {

	// Set up deadline context if needed, if a read timeout is set
	ctx, cancel := context.TODO(), func() {}
	p.timeoutMu.RLock()
	if p.rtimeout.After(time.Now()) {
		ctx, cancel = context.WithDeadline(context.Background(), p.rtimeout)
	}

	p.timeoutMu.RUnlock()

	//  Information returned by syscall.Recvfrom
	var n int
	var addr syscall.RawSockaddr
	var err error

	for {

		// Continue looping, or if deadline is set and has expired, return an error
		select {

		case <-ctx.Done():
			// We only know how to handle deadline exceeded, so return any
			// other errors for the caller to deal with
			if err := ctx.Err(); err != context.DeadlineExceeded {
				return n, nil, err
			}

			// Return standard net.OpError so caller can detect timeouts and retry
			return n, nil, &net.OpError{
				Op:   "read",
				Net:  "raw",
				Addr: nil,
				Err:  &timeoutError{},
			}

		default:

			// Not timed out, keep trying
		}

		// Attempt to receive on socket
		// TODO(shaybix): need to implement syscall.Recvfrom()
		n, addr, err = p.s.Recvfrom(b, 0)
		if err != nil {
			n = 0

			// TODO(shaybix): check if particular error is of type WSAEINPROGRESS
			// if so then sleep and try again.

			return n, nil, err
		}

		cancel()
		break

	}

	// Retrieve hardware address and other information
	// TODO(shaybix): Not sure whether link layer could be accessed
	// in windows.

}

// WriteTo implements the net.PackConn.WriteTo method.
func (p *packetConn) WriteTo(b []byte, _ net.Addr) (int, error) {}

// Close closes the connection
func (p *packetConn) Close() error {}

// LocalAddr returns the local network address.
func (p *packetConn) LocalAddr() net.Addr {}

// SetDeadline implements the net.PacketConn.SetDeadline method.
func (p *packetConn) SetDeadline(t time.Time) error {}

// SetReadDeadline implements the net.PacketConn.SetReadDeadline method.
func (p *packetConn) SetReadDeadline(t time.Time) error {}

// SetWriteDeadline implements the net.PacketConn.SetWriteDeadline method.
func (p *packetConn) SetWriteDeadline(t time.Time) error {}

// SetBPF attqchws an assembled BPF program to a raw net.PacketConn.
func (p *packetConn) SetBPF(filter []bpf.RawInstruction) error {}

type sysSocket struct {
	fd int
}

func (s *sysSocket) Bind(sa syscall.Sockaddr) error { return syscall.Bind(s.fd, sa) }

func (s *sysSocket) Close() error { return syscall.Close(s.fd) }

func (s *sysSocket) FD() int { return s.fd }

func (s *sysSocket) Recvfrom(p []byte, flags int) (int, syscall.Sockaddr, error) {
	return syscall.Recvfrom(s.fd, p, flags)
}

func (s *sysSocket) Sendto(p []byte, flags int, to syscall.Sockaddr) error {
	return syscall.Sendto(s.fd, p, flags, to)
}

func (s *sysSocket) SetNonblock(nonblocking bool) error {
	return syscall.SetNonblock(s.fd, nonblocking)
}

func (s *sysSocket) SetSockopt(level, name int, v unsafe.Pointer, l uint32) error {
	return setsockopt(s.fd, level, name, v, l)
}

type timeSleeper struct{}

func (_ timeSleeper) Sleep(d time.Duration) {
	time.Sleep(d)
}
