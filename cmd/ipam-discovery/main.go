package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/ipam"
)

func pingIpamServer(svc string) (bool, error) {
	client := http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/ping", svc), &bytes.Buffer{})
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("ping ipam server  %s failed ", svc)
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

	ipam_svc := os.Getenv("CLAUDE_IPAM_SVC_PORT")
	if ipam_svc == "" {
		log.Errorf("CLAUDE_IPAM_SVC_PORT env not set")
		os.Exit(1)
		return
	}
	ipam_svc = strings.Replace(ipam_svc, "tcp", "http", -1)

	ok, err := pingIpamServer(ipam_svc)
	if err != nil || !ok {
		logrus.Errorf("ping ipam server %s failed %v", ipam_svc, err)
		os.Exit(1)
		return
	}

	if ipamConf.IpamServerSvc != ipam_svc {
		log.Infof("ipam server ip changed %s -> %s", ipamConf.IpamServerSvc, ipam_svc)
		ipamConf.IpamServerSvc = ipam_svc
		if err := ipam.SaveIpamConfig(ipamConf, true); err != nil {
			log.Errorf("sync ipam server svc failed %v", err)
			os.Exit(1)
		}
	}
}
