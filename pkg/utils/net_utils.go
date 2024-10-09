package utils

import (
	"net"
	"regexp"

	log "github.com/sirupsen/logrus"
)

var IsWord = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9\-]{1,49}$`).MatchString

func ParseSize(ipMask string) int {
	ip := net.ParseIP(ipMask)
	mask := net.IPMask(ip.To4())
	size, _ := mask.Size()
	if size == 0 {
		log.Errorf("invalid mask %v", ipMask)
		return 0
	}
	log.Infof("parse ip mask %v -> %v", ipMask, size)
	return size

}

func NextIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

func CIDR2IPNet(cidr string) (*net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return &net.IPNet{
		IP:   ip,
		Mask: ipNet.Mask,
	}, nil
}

func IPNet2CIDR(ipNet *net.IPNet) string {
	return ipNet.String()
}
