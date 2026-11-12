//go:build !linux

package intercept

import (
	"errors"
	"net"
)

// originalDestination is only known on Linux, where netfilter records it.
func originalDestination(net.Conn) (net.Addr, error) {
	return nil, errors.New("intercept: the original destination of a redirected connection is only available on Linux")
}
