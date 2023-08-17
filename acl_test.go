package acl

import (
	"fmt"
	"net"
	"testing"
)

func TestAcl(t *testing.T) {

	s := &SourceAddressControl{
		aclNodes: make([]aclNode, 0),
	}

	s.ParseAclNode("2001:db8::/96")
	s.ParseAclNode("192.168.1.0/28")
	s.ParseAclNode("::1")
	s.ParseAclNode("127.0.0.1")

	ips := []string{
		"2001:dB8::0",
		"2001:dB8::1",
		"2001:db8::4",
		"2001:0db8::11",
		"2001:0db8::ff",
		"2001:0db8::fff",
		"2001:0db8::123",
		"2001:0db8::1fff",
		"2001:0db8::1:fff",
		"2001:0db8::1:1:fff",
		"2001:0db8::0:1:fff",
		"2001:0db8:0:0:0:0:0:fff",
		"::ffff:127.0.0.1",
		"::ffff:c0a8:590",
		"::1",
		"2001::",
		"2001:db8::",
		"192.168.1.10",
		"192.168.1.16",
		"192.168.1.254",
		"192.168.0.254",
	}
	for _, ip := range ips {
		fmt.Printf("%-30s %v\n", ip, s.AclCheck(ip))
	}
}

func TestIPNet(t *testing.T) {
	acl := &BuiltinCIDR{
		cidrs: make([]net.IPNet, 0),
	}
	acl.ParseAclNode("2001:db8::/96")
	acl.ParseAclNode("192.168.1.0/28")
	acl.ParseAclNode("::1")
	acl.ParseAclNode("127.0.0.1")

	ips := []string{
		"2001:dB8::0",
		"2001:dB8::1",
		"2001:db8::4",
		"2001:0db8::11",
		"2001:0db8::ff",
		"2001:0db8::fff",
		"2001:0db8::123",
		"2001:0db8::1fff",
		"2001:0db8::1:fff",
		"2001:0db8::1:1:fff",
		"2001:0db8::0:1:fff",
		"2001:0db8:0:0:0:0:0:fff",
		"::ffff:127.0.0.1",
		"::ffff:c0a8:590",
		"::1",
		"2001::",
		"2001:db8::",
		"192.168.1.10",
		"192.168.1.16",
		"192.168.1.254",
		"192.168.0.254",
	}
	for _, ip := range ips {
		fmt.Printf("%-30s %v\n", ip, acl.AclCheck(ip))
	}
}
