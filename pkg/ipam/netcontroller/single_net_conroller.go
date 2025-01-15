package netcontroller

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/ipam/dao"
	"github.com/yowenter/claude-ipam/pkg/ipam/ipblock"
	"github.com/yowenter/claude-ipam/pkg/store"
	"github.com/yowenter/claude-ipam/pkg/types"
	"github.com/yowenter/claude-ipam/pkg/utils"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type SingleNetController struct {
	ipBlockAllocator *ipblock.IPBlockAllocator
	dao              *dao.NetDao
	store            store.Store
	k8sclient        *kubernetes.Clientset

	hostNetworkIds *utils.SafeMap
}

func NewSingleNetController(dao *dao.NetDao, store store.Store, k8s *kubernetes.Clientset, ippblockAllocator *ipblock.IPBlockAllocator) *SingleNetController {
	sc := &SingleNetController{
		hostNetworkIds:   utils.NewSafeMap(),
		dao:              dao,
		store:            store,
		k8sclient:        k8s,
		ipBlockAllocator: ippblockAllocator,
	}
	go sc.reloadNodeNetworks()
	return sc
}

func (sc *SingleNetController) FindNodeNetwork(nodeName string, masterIf string) (string, bool) {
	if nId, ok := sc.hostNetworkIds.Get(nodeName); ok {
		return nId, ok
	}
	return "", false
}

func (sc *SingleNetController) Watch() {
	for {
		if err := sc.WaitForSyncNetwork(); err != nil {
			time.Sleep(time.Second * 10)
			log.Errorf("wait for sync network failed %v", err)
			continue
		}
		if err := sc.AssignNodeIpamBlocks(); err != nil {
			time.Sleep(time.Second * 10)
			log.Errorf("assign node ipam blocks failed %v", err)
			continue
		}
		time.Sleep(120 * time.Second)
	}

}

func (sc *SingleNetController) reloadNodeNetworks() {
	ctx := context.Background()
	log.Infof("loop reloading node networks started...")
	for {
		nodes, err := sc.dao.ListNode(ctx)
		if err != nil {
			log.Errorf("list node failed %v", err)
			time.Sleep(time.Second * 10)
			continue
		}
		for _, node := range nodes {
			sc.hostNetworkIds.Set(node.HostName, node.NetworkID)
		}
		time.Sleep(time.Second * 180)
	}
}

func (sc *SingleNetController) WaitForSyncNetwork() error {
	ctx := context.TODO()

	if sc.ipBlockAllocator == nil {
		return nil
	}
	networks, err := sc.dao.ListNetwork(ctx)
	if err != nil {
		return err
	}

	for _, net := range networks {
		ipNet, err := utils.CIDR2IPNet(net.CIDR)
		if err != nil {
			log.Errorf("parse cidr %v failed %v", net.CIDR, err)
			continue
		}
		sc.ipBlockAllocator.UpdateAllocated(ipNet)
	}

	nodes, err := sc.dao.ListNode(ctx)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		sc.hostNetworkIds.Set(node.HostName, node.NetworkID)
	}

	if sc.ipBlockAllocator == nil {
		log.Info("ip block allocator nil, skipped")
		return nil
	}

	for _, node := range nodes {
		network, err := sc.dao.GetNetwork(ctx, node.NetworkID)
		if err != nil {
			log.Errorf("get network %v failed %v", node.NetworkID, err)
			continue
		}
		ipNet, err := utils.CIDR2IPNet(network.CIDR)
		if err != nil {
			log.Errorf("parse cidr %v failed %v", network.CIDR, err)
			continue
		}
		sc.ipBlockAllocator.UpdateHostSubnet(node.HostName, ipNet)
	}
	log.Info("sync single network ok")

	return nil

}

func (sc *SingleNetController) AssignNodeIpamBlocks() error {
	// 自动将 pod cidr 地址 切分成小网段给 主机。
	if sc.ipBlockAllocator == nil {
		return nil
	}
	ctx := context.TODO()
	nodesList, err := sc.k8sclient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, node := range nodesList.Items {
		if sc.ipBlockAllocator.NodeAlreadyAssigned(node.Name) {
			continue
		}
		nodeNet, err := sc.ipBlockAllocator.Allocate(node.Name)
		if err != nil {
			return err
		}
		ipamblock, err := sc.dao.CreateNetwork(ctx, &types.NetworkInfo{
			ID:   uuid.NewString(),
			Name: fmt.Sprintf("node-%s-block", node.Name),
			Idc:  "",
			CIDR: utils.IPNet2CIDR(nodeNet),
		})
		if err != nil {
			return err
		}
		_, err = sc.dao.CreateNode(ctx, &types.Node{
			HostName:  node.Name,
			NetworkID: ipamblock.ID,
		})
		if err != nil {
			if _, e := sc.store.Delete(ctx, ipamblock.Key(), ipamblock.Revision); e != nil {
				log.Errorf("delete network %v failed %v", ipamblock, err)
			}
			return err
		}

		ipStart, ipEnd := utils.GetFirstAndLastIP(*nodeNet)
		mask := sc.ipBlockAllocator.NetMask()
		log.Infof("net %v ip start %v, ip end %v, mask %v", nodeNet, ipStart, ipEnd, mask)
		ips, err := sc.dao.CreateIPRange(ctx, &types.IPRangeReq{
			RangeStart: ipStart.String(),
			RangeEnd:   ipEnd.String(),
			Subnet:     utils.IPNet2CIDR(nodeNet),
			Gateway:    sc.ipBlockAllocator.Gateway(),
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
