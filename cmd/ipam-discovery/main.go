package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/ipam"
)

func pingIpamServer(ip string) (bool, error) {
	client := http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:8080/ping", ip), &bytes.Buffer{})
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("ping ipam server ip %s failed ", ip)
	}
	return true, nil
}

func main() {

	ipamConf, err := ipam.LoadIpamConfigFromHost()
	if err != nil {
		log.Errorf("load ipam conf failed %v!", err)
		os.Exit(1)
		return
	}

	var ipamServerIp string
	ips, _ := net.LookupIP("claude-ipam-svc.kube-system")
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			logrus.Infof("check IPv4: %s", ipv4)
			ok, err := pingIpamServer(ipv4.String())
			if err != nil {
				logrus.Errorf("ping ipam server %s failed %v", ipv4.String(), err)
				continue
			}
			if ok {
				ipamServerIp = ipv4.String()
				break
			}

		}
	}

	if ipamServerIp == "" {
		log.Errorf("no available ipam server ip")
		os.Exit(1)
	}
	if ipamConf.IpamServerSvc != ipamServerIp {
		log.Infof("ipam server ip changed %s -> %s", ipamConf.IpamServerSvc, ipamServerIp)
		ipamConf.IpamServerSvc = ipamServerIp
		if err := ipam.SaveIpamConfig(ipamConf, true); err != nil {
			log.Errorf("sync ipam server ip failed %v", err)
			os.Exit(1)
		}
	}
}
