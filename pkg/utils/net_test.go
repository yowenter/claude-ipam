package utils

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskConvert(t *testing.T) {

	_, clusterNet, _ := net.ParseCIDR("172.10.0.0/16")

	assert.Equal(t, net.IPMask([]byte(clusterNet.Mask)).String(), clusterNet.Mask.String())
	assert.Equal(t, ParseSize(net.IP(clusterNet.Mask).To4().String()), 16)

}

func TestIPRes(t *testing.T) {

	ip, ipnet, _ := net.ParseCIDR("172.10.0.192/16")
	rip := net.IPNet{
		IP:   ip,
		Mask: ipnet.Mask,
	}
	assert.Equal(t, rip.String(), "172.10.0.192/16")
	assert.Equal(t, ipnet.String(), "172.10.0.0/16")

}

func TestIPNet26(t *testing.T) {
	ip, ipnet, _ := net.ParseCIDR("172.10.1.192/26")
	rip := net.IPNet{
		IP:   ip,
		Mask: ipnet.Mask,
	}
	assert.Equal(t, rip.String(), "172.10.1.192/26")
	assert.Equal(t, ipnet.String(), "172.10.1.192/26")
	fmt.Println(GetFirstAndLastIP(*ipnet))

	// 172.10.4.65

	ip, ipnet, _ = net.ParseCIDR("172.10.4.65/26")
	rip = net.IPNet{
		IP:   ip,
		Mask: ipnet.Mask,
	}
	assert.Equal(t, rip.String(), "172.10.4.65/26")
	assert.Equal(t, ipnet.String(), "172.10.4.64/26")
	fmt.Println(GetFirstAndLastIP(*ipnet))
	fmt.Println(GetFirstAndLastIP(rip))
}

func TestCIDRConvert(t *testing.T) {
	ipnet := &net.IPNet{
		IP:   net.ParseIP("172.10.4.65"),
		Mask: net.CIDRMask(24, 32),
	}
	assert.Equal(t, IPNet2CIDR(ipnet), "172.10.4.65/24")
	newIpnet, err := CIDR2IPNet("172.10.4.65/24")
	if err != nil {
		panic(err)
	}
	assert.Equal(t, newIpnet.String(), "172.10.4.65/24")

}
