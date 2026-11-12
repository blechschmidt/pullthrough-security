//go:build linux

package intercept

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// soOriginalDst is SO_ORIGINAL_DST (netfilter, IPv4) and IP6T_SO_ORIGINAL_DST
// (IPv6): both are 80.
const soOriginalDst = 80

// originalDestination returns the address a connection was originally sent to
// before a netfilter NAT rule (iptables/nftables REDIRECT or DNAT) redirected it
// to this proxy, as recorded in the connection-tracking table. A connection that
// was not redirected reports its own local address (or an error when
// connection tracking is not loaded).
func originalDestination(conn net.Conn) (net.Addr, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("intercept: connection does not expose a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}
	tcp, _ := conn.LocalAddr().(*net.TCPAddr)
	v6 := tcp != nil && tcp.IP.To4() == nil

	var addr net.Addr
	var opErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		if v6 {
			// sockaddr_in6 (28 bytes) — IPv6MTUInfo is large enough to hold it.
			info, err := unix.GetsockoptIPv6MTUInfo(int(fd), unix.SOL_IPV6, soOriginalDst)
			if err != nil {
				opErr = err
				return
			}
			raw := (*[unsafe.Sizeof(*info)]byte)(unsafe.Pointer(info))
			port := binary.BigEndian.Uint16(raw[2:4])
			ip := make(net.IP, net.IPv6len)
			copy(ip, raw[8:24])
			addr = &net.TCPAddr{IP: ip, Port: int(port)}
			return
		}
		// sockaddr_in (16 bytes) — returned in the IPv6Mreq structure.
		mreq, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, soOriginalDst)
		if err != nil {
			opErr = err
			return
		}
		raw := mreq.Multiaddr
		port := binary.BigEndian.Uint16(raw[2:4])
		addr = &net.TCPAddr{IP: net.IPv4(raw[4], raw[5], raw[6], raw[7]), Port: int(port)}
	})
	if ctrlErr != nil {
		return nil, ctrlErr
	}
	if opErr != nil {
		return nil, fmt.Errorf("intercept: reading the original destination: %w", opErr)
	}
	return addr, nil
}
