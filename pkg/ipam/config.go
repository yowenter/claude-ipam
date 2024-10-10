package ipam

import (
	"os"
	"path/filepath"

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

func SaveIpamConfig(conf *types.IpamConfiguration, toHost bool) error {
	data, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}
	fname := claudeConfig
	if toHost {
		fname = filepath.Join("/host/", fname)
	}
	return os.WriteFile(fname, data, 0644)
}

func LoadIpamConfigFromHost() (*types.IpamConfiguration, error) {
	data, err := os.ReadFile(filepath.Join("/host/", claudeConfig))
	if err != nil {
		return nil, err
	}
	var conf types.IpamConfiguration
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
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
