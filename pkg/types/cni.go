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

	PodCidr               string `yaml:"podCidr"`
	AutoAssignNodeIPBlock bool   `yaml:"autoAssignNodeIPBlock"`
	SubnetSize            int    `yaml:"subnetSize"`
	Gateway               string `yaml:"gateway"`

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
}
