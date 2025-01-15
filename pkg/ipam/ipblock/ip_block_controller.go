package ipblock

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/utils"
)

type IPBlockAllocator struct {
	clusterNet        *net.IPNet
	subnetSize        int
	allocatedNets     *utils.SafeNetMap
	hostAllocatedNets *utils.SafeMap
	mask              net.IPMask
	gateway           string
}

// Maybe we should learn from calico ipam block..
func NewIPBlockAllocator(podCidr string, subnetSize int, gateway string) (*IPBlockAllocator, error) {
	_, clusterNet, err := net.ParseCIDR(podCidr)
	if err != nil {
		return nil, err
	}
	log.Infof("ipblock cluster net %v, mask %v, subnetsize %v, gateway %v", clusterNet, clusterNet.Mask.String(), subnetSize, gateway)
	return &IPBlockAllocator{
		clusterNet:        clusterNet,
		subnetSize:        subnetSize,
		allocatedNets:     utils.NewSafeNetMap(),
		hostAllocatedNets: utils.NewSafeMap(),
		mask:              clusterNet.Mask,
		gateway:           gateway,
	}, nil
}

func (a *IPBlockAllocator) UpdateAllocated(subnet *net.IPNet) {
	a.allocatedNets.Set(utils.IPNet2CIDR(subnet), subnet)
}

func (a *IPBlockAllocator) UpdateHostSubnet(nodeName string, subnet *net.IPNet) {
	a.hostAllocatedNets.Set(nodeName, utils.IPNet2CIDR(subnet))
	a.UpdateAllocated(subnet)
}

func (a *IPBlockAllocator) Gateway() string {
	return a.gateway
}

func (a *IPBlockAllocator) NetMask() string {
	return net.IP(a.mask).To4().String()
}

func (a *IPBlockAllocator) NodeAlreadyAssigned(nodeName string) bool {
	_, ok := a.hostAllocatedNets.Get(nodeName)
	return ok
}

// Allocate 分配一个小网段
// TODO performance issue, allocate more than 200 ipam block
func (a *IPBlockAllocator) Allocate(nodeName string) (*net.IPNet, error) {
	if network, ok := a.hostAllocatedNets.Get(nodeName); ok {
		net, ok := a.allocatedNets.Get(network)
		if !ok {
			return nil, fmt.Errorf("allocated network %v not found ", network)
		}
		return net, nil
	}
	for ip := a.clusterNet.IP.Mask(a.clusterNet.Mask); a.clusterNet.Contains(ip); utils.IncrementIP(ip) {
		subnet := &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(a.subnetSize, 32),
		}
		if !a.isAllocated(subnet) {
			a.UpdateHostSubnet(nodeName, subnet)
			return subnet, nil
		}
	}
	return nil, fmt.Errorf("no available subnet")
}

// isAllocated 检查小网段是否已经被分配
func (a *IPBlockAllocator) isAllocated(subnet *net.IPNet) bool {
	for _, allocated := range a.allocatedNets.Range() {
		if subnet.Contains(allocated.IP) || allocated.Contains(subnet.IP) {
			return true
		}
	}
	return false
}
