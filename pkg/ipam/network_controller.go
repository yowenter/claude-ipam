package ipam

import (
	"context"
	"fmt"
	"net"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/types"
	"github.com/yowenter/claude-ipam/pkg/utils"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type IPBlockAllocator struct {
	clusterNet    *net.IPNet
	subnetSize    int
	allocated     map[string]*net.IPNet
	hostAllocated map[string]string
	mask          net.IPMask
	gateway       string
}

// Maybe we should learn from calico ipam block..
func NewIPBlockAllocator(podCidr string, subnetSize int, gateway string) (*IPBlockAllocator, error) {
	_, clusterNet, err := net.ParseCIDR(podCidr)
	if err != nil {
		return nil, err
	}
	log.Infof("cluster net %v, mask %v, subnetsize %v", clusterNet, clusterNet.Mask.String(), subnetSize)
	return &IPBlockAllocator{
		clusterNet:    clusterNet,
		subnetSize:    subnetSize,
		allocated:     make(map[string]*net.IPNet),
		hostAllocated: make(map[string]string),
		mask:          clusterNet.Mask,
		gateway:       gateway,
	}, nil
}

func (a *IPBlockAllocator) UpdateAllocated(subnet *net.IPNet) {
	a.allocated[utils.IPNet2CIDR(subnet)] = subnet
}

func (a *IPBlockAllocator) UpdateHostSubnet(nodeName string, subnet *net.IPNet) {
	a.hostAllocated[nodeName] = utils.IPNet2CIDR(subnet)
	a.UpdateAllocated(subnet)
}

func (a *IPBlockAllocator) Gateway() string {
	return a.gateway
}

func (a *IPBlockAllocator) NetMask() string {
	return net.IP(a.mask).To4().String()
}

func (a *IPBlockAllocator) NodeAlreadyAssigned(nodeName string) bool {
	return a.hostAllocated[nodeName] != ""
}

// Allocate 分配一个小网段
func (a *IPBlockAllocator) Allocate(nodeName string) (*net.IPNet, error) {
	if network, ok := a.hostAllocated[nodeName]; ok {
		return a.allocated[network], nil
	}
	for ip := a.clusterNet.IP.Mask(a.clusterNet.Mask); a.clusterNet.Contains(ip); incrementIP(ip) {
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
	for _, allocated := range a.allocated {
		if subnet.Contains(allocated.IP) || allocated.Contains(subnet.IP) {
			return true
		}
	}
	return false
}

// incrementIP 增加 IP 地址
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func (ic *IpamController) SyncNetwork() error {
	ctx := context.TODO()
	ne := &types.NetworkInfo{}
	networksKv, err := ic.store.List(ctx, ne.ParentKey(), "")
	if err != nil {
		log.Error("list network err. try again in 10 seconds ", err)
		return err
	}

	for _, nkv := range networksKv.KVPairs {
		ne, err = types.DeSerializeNetworkInfo(nkv)
		if err != nil {
			log.Error("DeSerializeNetworkInfo err", nkv, err)
			continue
		}
		ipNet, err := utils.CIDR2IPNet(ne.CIDR)
		if err != nil {
			log.Errorf("parse cidr %v failed %v", ne.CIDR, err)
			continue
		}
		ic.ipBlockAllocator.UpdateAllocated(ipNet)
	}

	for nodename := range ic.hostNetworkIds {
		network, err := ic.findNodeNetwork(ctx, nodename)
		if err != nil {
			log.Errorf("find network by node %v failed %v", nodename, err)
			continue
		}
		ipNet, err := utils.CIDR2IPNet(network.CIDR)
		if err != nil {
			log.Errorf("parse cidr %v failed %v", ne.CIDR, err)
			continue
		}
		ic.ipBlockAllocator.UpdateHostSubnet(nodename, ipNet)
	}

	return nil

}

func (ic *IpamController) AssignNodeIpamBlocks() error {
	// 自动将 pod cidr 地址 切分成小网段给 主机。
	ctx := context.TODO()
	nodesList, err := ic.k8sclient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, node := range nodesList.Items {
		if ic.ipBlockAllocator.NodeAlreadyAssigned(node.Name) {
			continue
		}
		nodeNet, err := ic.ipBlockAllocator.Allocate(node.Name)
		if err != nil {
			return err
		}
		ipamblock, err := ic.CreateNetwork(ctx, &types.NetworkInfo{
			ID:   uuid.NewString(),
			Name: fmt.Sprintf("node-%s-block", node.Name),
			Idc:  "",
			CIDR: utils.IPNet2CIDR(nodeNet),
		})
		if err != nil {
			return err
		}
		_, err = ic.CreateNode(ctx, &types.Node{
			HostName:  node.Name,
			NetworkID: ipamblock.ID,
		})
		if err != nil {
			if _, e := ic.store.Delete(ctx, ipamblock.Key(), ipamblock.Revision); e != nil {
				log.Errorf("delete network %v failed %v", ipamblock, err)
			}
			return err
		}

		ipStart, ipEnd := utils.GetFirstAndLastIP(*nodeNet)
		mask := ic.ipBlockAllocator.NetMask()
		log.Infof("net %v ip start %v, ip end %v, mask %v", nodeNet, ipStart, ipEnd, mask)
		ips, err := ic.CreateIPRange(ctx, &types.IPRangeReq{
			RangeStart: ipStart.String(),
			RangeEnd:   ipEnd.String(),
			Subnet:     utils.IPNet2CIDR(nodeNet),
			Gateway:    ic.ipBlockAllocator.Gateway(),
			Mask:       mask,
			NetworkID:  ipamblock.ID,
		})
		if err != nil {
			log.Errorf("create ip range failed %v", err)
			return err
		}
		log.Infof("node %s network %s created, ips cnt %v", node.Name, ipamblock.CIDR, len(ips))
	}

	return nil

}
