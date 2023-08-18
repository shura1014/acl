# acl

App应用级防火墙（IP黑白名单），支持ipv4与ipv6

# 快速使用

go get -u -v github.com/shura1014/acl
### api使用
```go
func TestIPNet(t *testing.T) {
	acl := BuiltinAcl()
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
```
```text
=== RUN   TestIPNet
2001:dB8::0                    true
2001:dB8::1                    true
2001:db8::4                    true
2001:0db8::11                  true
2001:0db8::ff                  true
2001:0db8::fff                 true
2001:0db8::123                 true
2001:0db8::1fff                true
2001:0db8::1:fff               true
2001:0db8::1:1:fff             false
2001:0db8::0:1:fff             true
2001:0db8:0:0:0:0:0:fff        true
::ffff:127.0.0.1               true
::ffff:c0a8:590                false
::1                            true
2001::                         false
2001:db8::                     true
192.168.1.10                   true
192.168.1.16                   false
192.168.1.254                  false
192.168.0.254                  false
--- PASS: TestIPNet (0.00s)
PASS
```


### 指定acl文件
适合于web框架针对于ip做黑白名单使用
acl.conf
::1
127.0.0.1

解析文件
acl.ParseAclNode(line)

校验
acl.AclCheck(ip)