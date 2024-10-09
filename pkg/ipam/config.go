package ipam

import (
	"os"

	"github.com/yowenter/claude-ipam/pkg/store/etcd"
	"github.com/yowenter/claude-ipam/pkg/types"
	"gopkg.in/yaml.v3"
)

const (
	allocatingExpire   = 180
	claudeConfig       = "/etc/cni/net.d/claude/ipam.yaml"
	claudeServerConfig = "/data/claude-server.yaml"
)

type IPAMConfig struct {
	Etcd *etcd.EtcdConfig
}

func LoadIpamConfig() (*types.IpamConfiguration, error) {
	data, err := os.ReadFile(claudeConfig)
	if err != nil {
		return nil, err
	}
	var conf types.IpamConfiguration
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
}

func LoadIpamServerConfig() (*types.IpamServerConfiguration, error) {
	data, err := os.ReadFile(claudeServerConfig)
	if err != nil {
		return nil, err
	}
	var conf types.IpamServerConfiguration
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	return &conf, nil

}
