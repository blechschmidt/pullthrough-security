package main

import (
	"bytes"
	"net"
	"testing"
)

// query builds a DNS query for one name and type.
func query(id uint16, name string, qtype uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range bytes.Split([]byte(name), []byte(".")) {
		if len(label) == 0 {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return msg
}

func TestAnswer(t *testing.T) {
	ip := net.ParseIP("172.20.0.2")
	for name, tc := range map[string]struct {
		qname     string
		qtype     uint16
		wantRcode byte
		wantAddr  net.IP
	}{
		"the proxy's name resolves":        {"proxy.example.com", typeA, 0, ip},
		"case does not matter":             {"Proxy.Example.COM", typeA, 0, ip},
		"no IPv6 address, but the name is": {"proxy.example.com", typeAAAA, 0, nil},
		"any other name does not exist":    {"registry.npmjs.org", typeA, rcodeNameError, nil},
		"nor does a subdomain":             {"x.proxy.example.com", typeA, rcodeNameError, nil},
		"nor a parent":                     {"example.com", typeA, rcodeNameError, nil},
	} {
		t.Run(name, func(t *testing.T) {
			msg := query(0xBEEF, tc.qname, tc.qtype)
			// A resolver may append an EDNS record; it is not echoed.
			msg[11] = 1
			msg = append(msg, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)

			reply, q, err := answer(msg, "proxy.example.com", ip)
			if err != nil {
				t.Fatalf("answer: %v", err)
			}
			if got := reply[0:2]; got[0] != 0xBE || got[1] != 0xEF {
				t.Errorf("id = %x", got)
			}
			if reply[2]&0x80 == 0 {
				t.Error("not marked as a response")
			}
			if got := reply[3] & 0x0F; got != tc.wantRcode {
				t.Errorf("rcode = %d, want %d", got, tc.wantRcode)
			}
			if reply[11] != 0 {
				t.Error("the additional count of the query was echoed")
			}
			answers := int(reply[6])<<8 | int(reply[7])
			if tc.wantAddr == nil {
				if answers != 0 {
					t.Errorf("%d answers, want none", answers)
				}
				if len(reply) != q.end {
					t.Errorf("reply is %d bytes, want the header and question only (%d)", len(reply), q.end)
				}
				return
			}
			if answers != 1 {
				t.Fatalf("%d answers, want 1", answers)
			}
			if got := net.IP(reply[len(reply)-4:]); !got.Equal(tc.wantAddr) {
				t.Errorf("address = %s, want %s", got, tc.wantAddr)
			}
		})
	}
}

func TestParseQuestionRejectsWhatItCannotRead(t *testing.T) {
	good := query(1, "a.example", typeA)
	response := append([]byte(nil), good...)
	response[2] |= 0x80
	noQuestion := append([]byte(nil), good...)
	noQuestion[5] = 0
	compressed := append(append([]byte(nil), good[:12]...), 0xC0, 0x0C, 0, 1, 0, 1)

	for name, msg := range map[string][]byte{
		"empty":             nil,
		"short header":      good[:11],
		"a response":        response,
		"no question":       noQuestion,
		"name cut off":      good[:14],
		"label cut off":     good[:13],
		"question cut off":  good[:len(good)-2],
		"compressed name":   compressed,
		"unterminated name": append(append([]byte(nil), good[:12]...), 1, 'a'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseQuestion(msg); err == nil {
				t.Error("accepted")
			}
			if _, _, err := answer(msg, "proxy.example.com", net.ParseIP("10.0.0.1")); err == nil {
				t.Error("answered")
			}
		})
	}

	q, err := parseQuestion(good)
	if err != nil || q.name != "a.example" || q.qtype != typeA || q.end != len(good) {
		t.Errorf("parseQuestion(good) = %+v, %v", q, err)
	}
}

func TestTypeName(t *testing.T) {
	for typ, want := range map[uint16]string{1: "A", 28: "AAAA", 65: "HTTPS", 99: "TYPE99"} {
		if got := typeName(typ); got != want {
			t.Errorf("typeName(%d) = %q, want %q", typ, got, want)
		}
	}
}
