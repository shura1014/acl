package acl

import (
	"log"
	"net/netip"
	"strconv"
	"strings"
)

// 普通方式实现

type i128 [2]int64

var one64 = int64(0x1)

type aclNode struct {
	high    int64
	low     int64
	highLen int
	lowLen  int
	ipv6    bool
}

type SourceAddressControl struct {
	aclNodes []aclNode
	enable   bool
}

func (s *SourceAddressControl) putNode(node aclNode) {
	s.aclNodes = append(s.aclNodes, node)
}

func (s *SourceAddressControl) Enable() {
	s.enable = true
}

func (s *SourceAddressControl) IsEnable() bool {
	return s.enable
}

func (s *SourceAddressControl) ParseAclNode(line string) {
	index := strings.Index(line, ":")
	if index == -1 {
		s.parseAclNodeIpv4(line)
		return
	}
	s.parseAclNodeIpv6(line)
}

func (s *SourceAddressControl) parseAclNodeIpv4(line string) {
	i := strings.Index(line, "/")
	addr := line
	mask := "32"
	if -1 != i {
		addr = line[0:i]
		mask = line[i+1:]
	}

	slice := strings.Split(addr, ".")
	net := 0
	for _, s := range slice {
		i, _ := strconv.Atoi(s)
		net = (net << 8) + i
	}

	imask, _ := strconv.Atoi(mask)
	rtn := 0
	for i := 31; i >= (32 - imask); i-- {
		rtn += 0x1 << i
	}

	net = net & rtn

	node := aclNode{
		low:    int64(net),
		lowLen: imask,
		ipv6:   false,
	}

	s.putNode(node)

}

func (s *SourceAddressControl) parseAclNodeIpv6(line string) {
	i := strings.Index(line, "/")
	addr := line
	mask := "128"
	if -1 != i {
		addr = line[0:i]
		mask = line[i+1:]
	}

	addr = s.expandIpv6(addr)

	slice := strings.Split(addr, ":")

	highSlice := slice[0:4]
	lowSlice := slice[4:]
	rtn := i128{int64(0), int64(0)}
	for _, s := range highSlice {
		i, _ := strconv.ParseInt(s, 16, 64)
		rtn[0] = (rtn[0] << 16) + i
	}

	for _, s := range lowSlice {
		i, _ := strconv.ParseInt(s, 16, 64)
		rtn[1] = (rtn[1] << 16) + i
	}
	imask, _ := strconv.Atoi(mask)

	highLen := 64
	lowLen := 0
	if 64-imask > 0 {
		highLen = 64 - imask
	}

	if imask-64 > 0 {
		lowLen = imask - 64
	}

	highN := int64(0)
	for i := 63; i >= (64 - highLen); i-- {
		highN += one64 << i
	}

	lowN := int64(0)
	for i := 63; i >= (64 - lowLen); i-- {
		lowN += one64 << i
	}

	node := aclNode{
		high:    rtn[0] & highN,
		low:     rtn[1] & lowN,
		highLen: highLen,
		lowLen:  lowLen,
		ipv6:    true,
	}

	s.putNode(node)

}

func (s *SourceAddressControl) AclCheck(ip string) bool {
	//fmt.Printf("check ip %s\n", ip)
	index := strings.Index(ip, ":")
	if index == -1 {
		return s.aclCheckIpv4(ip)
	}

	return s.aclCheckIpv6(ip)
}

func (s *SourceAddressControl) aclCheckIpv4(strIp string) bool {
	if strings.TrimSpace(strIp) == "" {
		return false
	}
	slice := strings.Split(strIp, ".")
	if 4 != len(slice) {
		log.Panicf("invalid ip: %s", strIp)
	}

	net := 0
	for _, s := range slice {
		i, _ := strconv.Atoi(s)
		net = (net << 8) + i
	}
	n := int64(0)
	for _, s := range slice {
		i, _ := strconv.ParseInt(s, 10, 64)
		n = (n << 8) + i
	}

	for _, node := range s.aclNodes {
		if node.ipv6 {
			continue
		}
		lowLen := 32 - node.lowLen
		k := 31

		for ; k >= lowLen; k-- {
			if ((0x1 << k) & node.low) != ((0x1 << k) & n) {
				break
			}
		}

		if k == (lowLen - 1) {
			return true
		}
	}

	return false
}

func (s *SourceAddressControl) aclCheckIpv6(strIp string) bool {
	strIp = s.expandIpv6(strIp)
	slice := strings.Split(strIp, ":")
	if 8 != len(slice) {
		log.Panicf("invalid ip: %s", strIp)
	}

	rtn := i128{int64(0), int64(0)}
	highSlice := slice[0:4]
	lowSlice := slice[4:]
	for _, s := range highSlice {
		i, _ := strconv.ParseInt(s, 16, 64)
		rtn[0] = (rtn[0] << 16) + i
	}

	for _, s := range lowSlice {
		i, _ := strconv.ParseInt(s, 16, 64)
		rtn[1] = (rtn[1] << 16) + i
	}

	for _, node := range s.aclNodes {
		if !node.ipv6 {
			continue
		}

		highLen := 64 - node.highLen
		lowLen := 64 - node.lowLen
		highK := 63
		lowK := 63

		for ; highK >= highLen; highK-- {
			if ((one64 << highK) & node.high) != ((one64 << highK) & rtn[0]) {
				break
			}
		}

		for ; lowK >= lowLen; lowK-- {
			if ((one64 << lowK) & node.low) != ((one64 << lowK) & rtn[1]) {
				break
			}
		}

		if highK == (highLen-1) && lowK == (lowLen-1) {
			return true
		}
	}

	return false
}
func (s *SourceAddressControl) expandIpv6(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return addr.StringExpanded()
}
