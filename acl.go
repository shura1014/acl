package acl

import "net"

// Acl 受信任的IP控制器
// 普通方式实现
// 标准库内置函数实现
type Acl interface {
	ParseAclNode(line string)
	AclCheck(ip string) bool
	IsEnable() bool
	Enable()
}

func Default() Acl {
	acl := &SourceAddressControl{
		aclNodes: make([]aclNode, 0),
	}
	return acl
}

func BuiltinAcl() Acl {
	acl := &BuiltinCIDR{
		cidrs: make([]net.IPNet, 0),
	}
	return acl
}
