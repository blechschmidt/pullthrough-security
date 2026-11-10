package egress

import "net"

// The cloud-metadata service IPs. 169.254.169.254 is used by AWS (IMDS), GCP,
// Azure, OpenStack, DigitalOcean, and others; fd00:ec2::254 is the AWS IMDSv6
// address. These are the single highest-value SSRF targets, so they earn a
// dedicated, escalated reason even though they also fall inside the link-local /
// unique-local ranges.
var (
	metadataV4 = net.ParseIP("169.254.169.254")
	metadataV6 = net.ParseIP("fd00:ec2::254")
)

// cgnatNet is the RFC 6598 carrier-grade-NAT shared address space, which is not
// classified private by net.IP.IsPrivate but is just as unsafe a destination.
var cgnatNet = mustCIDR("100.64.0.0/10")

// nat64Prefix is the RFC 6052 well-known NAT64 prefix; the embedded IPv4 lives in
// the last four bytes.
var nat64Prefix = mustCIDR("64:ff9b::/96")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("egress: bad builtin CIDR " + s + ": " + err.Error())
	}
	return n
}

// classifyIP returns the block reason for ip and whether it must be blocked when
// BlockPrivateNetworks is enabled. A nil ip is treated as a resolve error.
//
// IPv4-mapped, 6to4, and NAT64 IPv6 forms are normalized to their embedded IPv4
// and re-classified so a transition address cannot smuggle an internal v4 target
// past the v4 checks.
func classifyIP(ip net.IP) (Reason, bool) {
	if ip == nil {
		return ReasonResolveError, true
	}
	if v4 := ip.To4(); v4 != nil {
		return classifyV4(v4)
	}
	return classifyV6(ip)
}

// classifyV4 classifies a 4-byte IPv4 address.
func classifyV4(ip net.IP) (Reason, bool) {
	switch {
	case ip.Equal(metadataV4):
		return ReasonMetadata, true
	case ip.IsLoopback(): // 127.0.0.0/8
		return ReasonLoopback, true
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast(): // 169.254.0.0/16
		return ReasonLinkLocal, true
	case ip.IsPrivate(): // 10/8, 172.16/12, 192.168/16
		return ReasonPrivateNetwork, true
	case cgnatNet.Contains(ip): // 100.64.0.0/10
		return ReasonCGNAT, true
	case ip.IsUnspecified() || ip[0] == 0: // 0.0.0.0 and the 0.0.0.0/8 "this network"
		return ReasonUnspecified, true
	case ip.IsMulticast(): // 224.0.0.0/4
		return ReasonMulticast, true
	}
	return "", false
}

// classifyV6 classifies a 16-byte IPv6 address.
func classifyV6(ip net.IP) (Reason, bool) {
	switch {
	case ip.IsLoopback(): // ::1
		return ReasonLoopback, true
	case ip.Equal(metadataV6):
		return ReasonMetadata, true
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast(): // fe80::/10
		return ReasonLinkLocal, true
	case ip.IsPrivate(): // fc00::/7 unique-local
		return ReasonUniqueLocal, true
	case ip.IsUnspecified(): // ::
		return ReasonUnspecified, true
	case ip.IsMulticast(): // ff00::/8
		return ReasonMulticast, true
	}
	// Transition addresses that embed an IPv4 target: re-classify the inner v4 so
	// e.g. 6to4 2002:0a00:0001:: (-> 10.0.0.1) cannot reach an internal host.
	if v4 := embeddedV4(ip); v4 != nil {
		return classifyV4(v4)
	}
	return "", false
}

// embeddedV4 extracts the IPv4 address embedded in a 6to4 (2002::/16) or NAT64
// (64:ff9b::/96) IPv6 address, or nil if none is present.
func embeddedV4(ip net.IP) net.IP {
	if len(ip) != net.IPv6len {
		return nil
	}
	// 6to4: 2002:WWXX:YYZZ::/16 carries the IPv4 in bytes 2..5.
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4()
	}
	// NAT64 well-known prefix 64:ff9b::/96 carries the IPv4 in the last 4 bytes.
	if nat64Prefix.Contains(ip) {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	}
	return nil
}
