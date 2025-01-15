package types

import (
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
)

type IPAMEnvArgs struct {
	cnitypes.CommonArgs
	IP                         cnitypes.UnmarshallableString `json:"ip,omitempty"`
	GATEWAY                    cnitypes.UnmarshallableString `json:"gateway,omitempty"`
	K8S_POD_NAME               cnitypes.UnmarshallableString //revive:disable-line
	K8S_POD_NAMESPACE          cnitypes.UnmarshallableString //revive:disable-line
	K8S_POD_INFRA_CONTAINER_ID cnitypes.UnmarshallableString //revive:disable-line
}

type IpamConfiguration struct {
	IpamServerSvc string `yaml:"ipamServerSvc"`
	StaticSvc     bool   `json:"staticSvc"`
	BasicUser     string `yaml:"basicUser"`
	BasicPass     string `yaml:"basicPass"`
}

type ElectionOption struct {
	Name          string        `yaml:"name,omitempty"`
	Namespace     string        `yaml:"namespace,omitempty"`
	LeaseDuration time.Duration `yaml:"lease_duration,omitempty"`
}

type IpamServerConfiguration struct {
	BasicUser string `yaml:"basicUser"`
	BasicPass string `yaml:"basicPass"`
	AdminPass string `yaml:"adminPass"`
	Debug     bool   `json:"debug"`

	PodCidr               string `yaml:"podCidr"`
	AutoAssignNodeIPBlock bool   `yaml:"autoAssignNodeIPBlock"`
	SubnetSize            int    `yaml:"subnetSize"`
	// 单网段 gateway
	Gateway string `yaml:"gateway"`

	EtcdEndpoints  string `yaml:"etcdEndpoints"`
	EtcdUsername   string `yaml:"etcdUsername" envconfig:"ETCD_USERNAME"`
	EtcdPassword   string `yaml:"etcdPassword" envconfig:"ETCD_PASSWORD"`
	EtcdKeyFile    string `yaml:"etcdKeyFile" envconfig:"ETCD_KEY_FILE"`
	EtcdCertFile   string `yaml:"etcdCertFile" envconfig:"ETCD_CERT_FILE"`
	EtcdCACertFile string `yaml:"etcdCACertFile" envconfig:"ETCD_CA_CERT_FILE"`
	// These config file parameters are to support inline certificates, keys and CA / Trusted certificate.
	// There are no corresponding environment variables to avoid accidental exposure.
	EtcdKey    string `yaml:"etcdKey" ignored:"true"`
	EtcdCert   string `yaml:"etcdCert" ignored:"true"`
	EtcdCACert string `yaml:"etcdCACert" ignored:"true"`

	// 多网段
	MultiNets []*NetworkConf `yaml:"multiNets"`
	NetMode   string         `yaml:"netMode"`
}

type NetworkConf struct {
	ID           string        `json:"id" yaml:"id"`
	Name         string        `json:"name" yaml:"name"`
	CIDR         string        `json:"cidr" yaml:"cidr"`
	RangeStart   string        `json:"rangeStart,omitempty" yaml:"rangeStart"`
	RangeEnd     string        `json:"rangeEnd,omitempty" yaml:"rangeEnd"`
	Gateway      string        `json:"gateway,omitempty" yaml:"gateway"`
	NodeSelector *NodeSelector `json:"nodeSelector" yaml:"nodeSelector"`
}

type NodeSelector struct {
	NodeNames     []string `json:"nodeNames" yaml:"nodeNames"`
	NodeNameRegex string   `json:"nodeNameRegex" yaml:"nodeNameRegex"`
	NodeMethod    string   `json:"nodeMethod" yaml:"nodeMethod"`

	IfaceRegex  string `json:"ifaceRegex" yaml:"ifaceRegex"`
	IfaceName   string `json:"ifaceName" yaml:"ifaceName"`
	IfaceMethod string `json:"ifaceMethod" yaml:"ifaceMethod"` // regex, name
}

type ClaudeNetConf struct {
	cnitypes.NetConf

	// https://github.com/containernetworking/plugins/blob/abfac4a938866b6184441d02ad49544d10931fe1/plugins/main/macvlan/macvlan.go#L39
	Master string `json:"master"`

	// https://github.com/k8snetworkplumbingwg/sriov-cni/blob/ae8ffa4ef830aa80dfc71986e4f1ae041e600c75/pkg/types/types.go#L61
	DeviceID string `json:"deviceID"` // PCI address of a VF in valid sysfs format

}
