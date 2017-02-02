// +build windows

package raw

import (
	"net"
	"sync"
	"time"
	"unsafe"

	"syscall"

	"fmt"

	"golang.org/x/net/bpf"
	"golang.org/x/net/context"
)

// Windows sockets error codes
const (
	wsaINVALIDHANDLE    syscall.Errno = 6
	wsaNOTENOUGHMEMORY  syscall.Errno = 8
	wsaINVALIDPARAMETER syscall.Errno = 87

	wsaOPERATIONABORTED syscall.Errno = 995
	wsaIOINCOMPLETE     syscall.Errno = 996
	wsaIOPENDING        syscall.Errno = 997

	wsaEINTR syscall.Errno = 10004
	wsaEBADF syscall.Errno = 10009

	wsaEACCES syscall.Errno = 10013
	wsaEFAULT syscall.Errno = 10014

	wsaEINVAL syscall.Errno = 10022
	wsaEMFILE syscall.Errno = 10024

	wsaEWOULDBLOCK     syscall.Errno = 10035
	wsaEINPROGRESS     syscall.Errno = 10036
	wsaEALREADY        syscall.Errno = 10037
	wsaENOTSOCK        syscall.Errno = 10038
	wsaEDESTADDRREQ    syscall.Errno = 10039
	wsaEMSGSIZE        syscall.Errno = 10040
	wsaEPROTOTYPE      syscall.Errno = 10041
	wsaENOPROTOOPT     syscall.Errno = 10042
	wsaEPROTONOSUPPORT syscall.Errno = 10043
	wsaESOCKTNOSUPPORT syscall.Errno = 10044
	wsaEOPNOTSUPP      syscall.Errno = 10045
	wsaEPFNOSUPPORT    syscall.Errno = 10046
	wsaEAFNOSUPPORT    syscall.Errno = 10047
	wsaEADDRINUSE      syscall.Errno = 10048
	wsaEADDRNOTAVAIL   syscall.Errno = 10049
	wsaENETDOWN        syscall.Errno = 10050
	wsaENETUNREACH     syscall.Errno = 10051
	wsaENETRESET       syscall.Errno = 10052
	wsaECONNABORTED    syscall.Errno = 10053
	wsaECONNRESET      syscall.Errno = 10054
	wsaENOBUFS         syscall.Errno = 10055
	wsaEISCONN         syscall.Errno = 10056
	wsaENOTCONN        syscall.Errno = 10057
	wsaESHUTDOWN       syscall.Errno = 10058
	wsaETOOMANYREFS    syscall.Errno = 10059
	wsaETIMEDOUT       syscall.Errno = 10060
	wsaECONNREFUSED    syscall.Errno = 10061
	wsaELOOP           syscall.Errno = 10062
	wsaENAMETOOLONG    syscall.Errno = 10063
	wsaEHOSTDOWN       syscall.Errno = 10064
	wsaEHOSTUNREACH    syscall.Errno = 10065
	wsaENOTEMPTY       syscall.Errno = 10066
	wsaEPROCLIM        syscall.Errno = 10067
	wsaEUSERS          syscall.Errno = 10068
	wsaEDQUOT          syscall.Errno = 10069
	wsaESTALE          syscall.Errno = 10070
	wsaEREMOTE         syscall.Errno = 10071

	wsaSYSNOTREADY     syscall.Errno = 10091
	wsaVERNOTSUPPORTED syscall.Errno = 10092
	wsaNOTINITIALISED  syscall.Errno = 10093

	wsaEDISCON             syscall.Errno = 10101
	wsaENOMORE             syscall.Errno = 10102
	wsaECANCELLED          syscall.Errno = 10103
	wsaEINVALIDPROCTABLE   syscall.Errno = 10104
	wsaEINVALIDPROVIDER    syscall.Errno = 10105
	wsaEPROVIDERFAILEDINIT syscall.Errno = 10106
	wsaSYSCALLFAILURE      syscall.Errno = 10107
	wsaSERVICENOTFOUND     syscall.Errno = 10108
	wsaTYPENOTFOUND        syscall.Errno = 10109
	wsaENOMORE2            syscall.Errno = 10110
	wsaECANCELLED2         syscall.Errno = 10111
	wsaEREFUSED            syscall.Errno = 10112

	wsaHOSTNOTFOUND        syscall.Errno = 11001
	wsaTRYAGAIN            syscall.Errno = 11002
	wsaNORECOVERY          syscall.Errno = 11003
	wsaNODATA              syscall.Errno = 11004
	wsaQOSRECEIVERS        syscall.Errno = 11005
	wsaQOSSENDERS          syscall.Errno = 11006
	wsaQOSNOSENDERS        syscall.Errno = 11007
	wsaQOSNORECEIVERS      syscall.Errno = 11008
	wsaQOSREQUESTCONFIRMED syscall.Errno = 11009
	wsaQOSADMISSIONFAILURE syscall.Errno = 11010
	wsaQOSPOLICYFAILURE    syscall.Errno = 11011
	wsaQOSBADSTYLE         syscall.Errno = 11012
	wsaQOSBADOBJECT        syscall.Errno = 11013
	wsaQOSTRAFFICCTRLERROR syscall.Errno = 11014
	wsaQOSGENERICERROR     syscall.Errno = 11015
	wsaQOSESERVICETYPE     syscall.Errno = 11016
	wsaQOSEFLOWSPEC        syscall.Errno = 11017
	wsaQOSEPROVSPECBUF     syscall.Errno = 11018
	wsaQOSEFILTERSTYLE     syscall.Errno = 11019
	wsaQOSEFILTERTYPE      syscall.Errno = 11020
	wsaQOSEFILTERCOUNT     syscall.Errno = 11021
	wsaQOSEOBJLENGTH       syscall.Errno = 11022
	wsaQOSEFLOWCOUNT       syscall.Errno = 11023
	wsaQOSEUNKOWNPSOBJ     syscall.Errno = 11024
	wsaQOSEPOLICYOBJ       syscall.Errno = 11025
	wsaQOSEFLOWDESC        syscall.Errno = 11026
	wsaQOSEPSFLOWSPEC      syscall.Errno = 11027
	wsaQOSEPSFILTERSPEC    syscall.Errno = 11028
	wsaQOSESDMODEOBJ       syscall.Errno = 11029
	wsaQOSESHAPERATEOBJ    syscall.Errno = 11030
	wsaQOSRESERVEDPETYPE   syscall.Errno = 11031
)

var (
	_ net.PacketConn = &packetConn{}

	// Loading recvfrom function from ws2_32.DLL library.
	ws232        = syscall.NewLazyDLL("ws2_32.dll")
	procRecvfrom = ws232.NewProc("recvfrom")
	procSendto   = ws232.NewProc("sendto")
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

func newPacketConn(ifi *net.Interface, s socket, pbe uint16, sleeper sleeper) (*packetConn, error) {

	SockaddrINET4 := syscall.SockaddrInet4{}
	var err error
	if err = s.Bind(&SockaddrINET4); err != nil {
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
	var addr syscall.Sockaddr
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

	return n, nil, nil
}

// WriteTo implements the net.PackConn.WriteTo method.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {

	// Ensure correct Addr type
	a, ok := addr.(*Addr)
	if !ok || len(a.HardwareAddr) < 6 {
		return 0, syscall.EINVAL
	}

	var baddr [8]byte
	copy(baddr[:], a.HardwareAddr)

	err := p.s.Sendto(b, 0, &syscall.SockaddrInet4{})

	return len(b), err
}

// Close closes the connection
func (p *packetConn) Close() error {
	return p.s.Close()
}

// LocalAddr returns the local network address.
func (p *packetConn) LocalAddr() net.Addr {
	return &Addr{
		HardwareAddr: p.ifi.HardwareAddr,
	}
}

// SetDeadline implements the net.PacketConn.SetDeadline method.
func (p *packetConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements the net.PacketConn.SetReadDeadline method.
func (p *packetConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements the net.PacketConn.SetWriteDeadline method.
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// SetBPF attqchws an assembled BPF program to a raw net.PacketConn.
func (p *packetConn) SetBPF(filter []bpf.RawInstruction) error {
	return nil
}

type sysSocket struct {
	fd syscall.Handle
}

func (s *sysSocket) Bind(sa syscall.Sockaddr) error { return syscall.Bind(s.fd, sa) }

func (s *sysSocket) Close() error { return syscall.Close(s.fd) }

func (s *sysSocket) FD() int { return int(s.fd) }

func (s *sysSocket) Recvfrom(p []byte, flags int) (int, syscall.Sockaddr, error) {

	var sockaddrInet4 = syscall.SockaddrInet4{}
	var nLen uint32

	n, err := recvfrom(s.fd, p, &sockaddrInet4, &nLen)
	if err != nil {
		// TODO(shaybix): handle error
		return n, nil, err
	}

	return n, &sockaddrInet4, nil
}

func (s *sysSocket) Sendto(p []byte, flags int, to syscall.Sockaddr) error {
	return sendto(s.fd, p, flags, to)
}

func (s *sysSocket) SetNonblock(nonblocking bool) error {
	return syscall.SetNonblock(s.fd, nonblocking)
}

func (s *sysSocket) SetSockopt(level, name int, v unsafe.Pointer, l uint32) error {
	return setsockopt(s.fd, level, name, v, l)
}

type timeSleeper struct{}

func (t timeSleeper) Sleep(d time.Duration) {
	time.Sleep(d)
}

// recvfrom is an implementation for windows function recvfrom which wasn't implemented in the standard library.
//
// see: https://github.com/golang/sys/blob/master/windows/syscall_windows.go#L812
func recvfrom(fd syscall.Handle, p []byte, from syscall.Sockaddr, fromlen *uint32) (n int, err error) {

	// TODO(shaybix): consider swapping out syscall.LazyProc.Call() for syscall.Syscall() as it is used
	// in the standard library. Perhaps better?

	bytePtr, err := syscall.BytePtrFromString(string(p))
	if err != nil {
		return n, err
	}

	rt, _, _ := procRecvfrom.Call(
		uintptr(fd),
		uintptr(unsafe.Pointer(bytePtr)),
		0,
		0,
		uintptr(unsafe.Pointer(&from)),
		uintptr(unsafe.Pointer(&fromlen)))

	n = int(rt)
	if n == -1 {

		//TODO(shaybix): check for errors
		return n, nil
	}

	return n, nil

}

// sendto is an implementation of windows function sendto() which wasn't implemented in the standard library.
//
//see: https://github.com/golang/sys/blob/master/windows/syscall_windows.go#L815
func sendto(fd syscall.Handle, p []byte, flags int, to syscall.Sockaddr) (err error) {

	bytePtr, err := syscall.BytePtrFromString(string(p))
	if err != nil {
		return err
	}

	rt, _, _ := procSendto.Call(
		uintptr(fd),
		uintptr(unsafe.Pointer(bytePtr)),
		uintptr(len(p)),
		uintptr(flags),
		uintptr(unsafe.Pointer(&to)))

	if int(rt) == -1 {
		//TODO(shaybix): check for errors
		return fmt.Errorf("Could not send data, Error code: %d", int(rt))
	}

	return err
}
