package acl

import (
	"net"
	"strings"
)

// BuiltinCIDR 使用内置的函数实现
type BuiltinCIDR struct {
	cidrs  []net.IPNet
	enable bool
}

func (b *BuiltinCIDR) ParseAclNode(line string) {
	if !strings.Contains(line, "/") {
		parsedIP := net.ParseIP(line)

		if ipv4 := parsedIP.To4(); ipv4 != nil {
			// return ip in a 4-byte representation
			parsedIP = ipv4
		}
		if parsedIP != nil {
			switch len(parsedIP) {
			case net.IPv4len:
				line += "/32"
			case net.IPv6len:
				line += "/128"
			}
		}
	}
	_, cidrNet, err := net.ParseCIDR(line)
	if err == nil {
		b.cidrs = append(b.cidrs, *cidrNet)
	}
}

func (b *BuiltinCIDR) AclCheck(ip string) bool {
	for _, cidr := range b.cidrs {
		remoteIP := net.ParseIP(ip)
		if cidr.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func (b *BuiltinCIDR) Enable() {
	b.enable = true
}

func (b *BuiltinCIDR) IsEnable() bool {
	return b.enable
}
