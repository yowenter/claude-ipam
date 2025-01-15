package utils

import "net"

func GetFirstAndLastIP(sub net.IPNet) (net.IP, net.IP) {
	// 获取子网的第一个 IP（网络地址）
	ip := make(net.IP, len(sub.IP.To4()))
	mask := make(net.IPMask, len(sub.Mask))
	copy(ip, sub.IP.To4())
	copy(mask, sub.Mask)

	subnet := net.IPNet{
		IP:   ip,
		Mask: mask,
	}
	firstIP := subnet.IP.To4()
	// 将最后一位设置为 1
	for i := len(firstIP) - 1; i >= 0; i-- {
		if firstIP[i] < 255 {
			firstIP[i]++
			break
		}
		firstIP[i] = 0
	}

	// 获取子网的最后一个 IP（广播地址）
	lastIP := make(net.IP, len(subnet.IP.To4()))
	copy(lastIP, subnet.IP.To4())
	m := subnet.Mask
	for i := 0; i < len(lastIP); i++ {
		lastIP[i] |= ^m[i]
	}

	return firstIP, lastIP
}

func IncrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}
