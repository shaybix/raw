// +build !darwin,!dragonfly,!freebsd,!linux,!netbsd,!openbsd, !windows

package raw

import (
	"net"
	"time"

	"golang.org/x/net/bpf"
)

var (
	// Must implement net.PacketConn at compile-time.
	_ net.PacketConn = &packetConn{}
)

// packetConn is the generic implementation of net.PacketConn for this package.
type packetConn struct{}

// listenPacket is not currently implemented on this platform.
func listenPacket(ifi *net.Interface, proto Protocol) (*packetConn, error) {
	return nil, ErrNotImplemented
}

// ReadFrom is not currently implemented on this platform.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return 0, nil, ErrNotImplemented
}

// WriteTo is not currently implemented on this platform.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return 0, ErrNotImplemented
}

// Close is not currently implemented on this platform.
func (p *packetConn) Close() error {
	return ErrNotImplemented
}

// LocalAddr is not currently implemented on this platform.
func (p *packetConn) LocalAddr() net.Addr {
	return nil
}

// SetDeadline is not currently implemented on this platform.
func (p *packetConn) SetDeadline(t time.Time) error {
	return ErrNotImplemented
}

// SetReadDeadline is not currently implemented on this platform.
func (p *packetConn) SetReadDeadline(t time.Time) error {
	return ErrNotImplemented
}

// SetWriteDeadline is not currently implemented on this platform.
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return ErrNotImplemented
}

// SetBPF is not currently implemented on this platform.
func (p *packetConn) SetBPF(filter []bpf.RawInstruction) error {
	return ErrNotImplemented
}
