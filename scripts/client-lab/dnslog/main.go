// Command dnslog is the name server of the client lab (scripts/client-lab).
//
// A lab client runs on a network where the proxy is the only host it can
// reach. That proves an install needs nothing but the proxy — it does not show
// whether the client TRIED to go elsewhere: a package manager that asks the
// public registry first and shrugs when it does not answer looks exactly like
// one that never asked. On a network with a way out, that client talks to the
// registry directly.
//
// dnslog makes the attempt visible. It is the only resolver the client has; it
// answers the proxy's name with the proxy's address, answers every other name
// "no such domain", and prints one line per question:
//
//	query registry.npmjs.org A
//
// lab.sh reads those lines after a run: the names a client looked up besides
// the proxy's are the hosts it would have contacted.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	listen := flag.String("listen", ":53", "UDP address to serve on")
	name := flag.String("name", "proxy.example.com", "the one name that resolves")
	addr := flag.String("addr", "", "the IPv4 address it resolves to")
	flag.Parse()

	ip := net.ParseIP(*addr).To4()
	if ip == nil {
		log.Fatalf("dnslog: -addr %q is not an IPv4 address", *addr)
	}
	conn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatalf("dnslog: %v", err)
	}
	fmt.Fprintf(os.Stdout, "serving %s -> %s on %s\n", *name, ip, *listen)

	buf := make([]byte, 4096)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		reply, q, err := answer(buf[:n], *name, ip)
		if err != nil {
			continue // not a question we can read; a resolver retries or gives up
		}
		fmt.Fprintf(os.Stdout, "query %s %s\n", q.name, typeName(q.qtype))
		_, _ = conn.WriteTo(reply, peer)
	}
}

// question is the first question of a DNS query.
type question struct {
	name  string // lower case, without the trailing dot
	qtype uint16
	// end is the offset just past the question in the message.
	end int
}

const (
	typeA    = 1
	typeAAAA = 28

	rcodeNameError = 3
)

// parseQuestion reads the header and the first question of a DNS query.
func parseQuestion(msg []byte) (question, error) {
	var q question
	if len(msg) < 12 {
		return q, errors.New("short message")
	}
	if msg[2]&0x80 != 0 {
		return q, errors.New("not a query")
	}
	if qdcount := int(msg[4])<<8 | int(msg[5]); qdcount < 1 {
		return q, errors.New("no question")
	}
	var labels []string
	i := 12
	for {
		if i >= len(msg) {
			return q, errors.New("truncated name")
		}
		l := int(msg[i])
		i++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			return q, errors.New("compressed name in a question")
		}
		if i+l > len(msg) {
			return q, errors.New("truncated label")
		}
		labels = append(labels, string(msg[i:i+l]))
		i += l
		if len(labels) > 127 {
			return q, errors.New("too many labels")
		}
	}
	if i+4 > len(msg) {
		return q, errors.New("truncated question")
	}
	q.name = strings.ToLower(strings.Join(labels, "."))
	q.qtype = uint16(msg[i])<<8 | uint16(msg[i+1])
	q.end = i + 4
	return q, nil
}

// answer builds the reply to a query: the address for an A question about
// name, an empty answer for any other question about it, and "no such domain"
// for every other name.
func answer(msg []byte, name string, ip net.IP) ([]byte, question, error) {
	q, err := parseQuestion(msg)
	if err != nil {
		return nil, q, err
	}
	// Header and question are echoed; everything after the first question (more
	// questions, EDNS) is dropped and the counts say so.
	reply := append([]byte(nil), msg[:q.end]...)
	reply[2] = 0x80 | (msg[2] & 0x01) // response, recursion desired as asked
	reply[3] = 0x80                   // recursion available
	reply[4], reply[5] = 0, 1         // one question
	for i := 6; i < 12; i++ {
		reply[i] = 0
	}
	switch {
	case !strings.EqualFold(q.name, strings.TrimSuffix(name, ".")):
		reply[3] |= rcodeNameError
	case q.qtype == typeA:
		reply[7] = 1 // one answer
		reply = append(reply,
			0xC0, 0x0C, // the name: a pointer to the question
			0, typeA, 0, 1, // type A, class IN
			0, 0, 0, 5, // TTL
			0, 4, // address length
		)
		reply = append(reply, ip.To4()...)
	}
	return reply, q, nil
}

func typeName(t uint16) string {
	switch t {
	case typeA:
		return "A"
	case typeAAAA:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	}
	return fmt.Sprintf("TYPE%d", t)
}
