package ipam

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/yowenter/claude-ipam/pkg/store"
	"github.com/yowenter/claude-ipam/pkg/store/etcd"
	"github.com/yowenter/claude-ipam/pkg/types"
	"github.com/yowenter/claude-ipam/pkg/utils"
)

type IpamController struct {
	store store.Store

	ipBlockAllocator *IPBlockAllocator
	gateway          string

	k8sclient *kubernetes.Clientset

	hostNetworkIds map[string]string
}

func NewIpamController(cfg *types.IpamServerConfiguration, etcdcfg *etcd.EtcdConfig) (*IpamController, error) {
	etcdClient, err := etcd.NewEtcdV3Client(etcdcfg)
	if err != nil {
		return nil, err
	}
	var ipblockAllocator *IPBlockAllocator
	if cfg.AutoAssignNodeIPBlock {
		ipblockAllocator, err = NewIPBlockAllocator(cfg.PodCidr, cfg.SubnetSize, cfg.Gateway)
		if err != nil {
			return nil, err
		}
	}
	k8sclient, err := utils.NewK8sClient(utils.InCluster())
	if err != nil {
		return nil, err
	}

	return &IpamController{
		store:            etcdClient,
		hostNetworkIds:   map[string]string{},
		ipBlockAllocator: ipblockAllocator,
		gateway:          cfg.Gateway,
		k8sclient:        k8sclient,
	}, nil
}

func (ic *IpamController) RequireIP(ctx context.Context, req *types.IPReq) (*types.IPResData, error) {
	if req.Hostname == "" || req.ContainerID == "" {
		return nil, errors.New("hostName and containerId are both required")
	}
	req.Hostname = strings.ToLower(req.Hostname)
	p := &types.IpRecordInfo{ContainerId: req.ContainerID, Host: req.Hostname, IfName: req.IfName}
	oldIprecordKV, _ := ic.store.Get(ctx, p.Key(), "")
	if oldIprecordKV != nil {
		// already exists ip
		ipRecord, err := types.DeSerializeIpRecord(oldIprecordKV)
		if err != nil {
			log.Error("DeSerializeIpRecord err", oldIprecordKV, err)
			return nil, err
		}
		log.Infof("ip record exists %v", ipRecord)
		size := utils.ParseSize(ipRecord.Mask)
		return &types.IPResData{
			Ip:      fmt.Sprintf("%v/%v", ipRecord.Ip, size),
			Gateway: ipRecord.Gateway,
		}, nil
	}

	network, err := ic.findNodeNetwork(ctx, req.Hostname)
	if err != nil {
		log.Error("findNetworkByHostname err", err)
		return nil, err
	}

	ipPool, err := ic.listIPByNetworkID(ctx, network.ID, types.STATUS_AVAILABLE)
	if err != nil {
		log.Error("listIPByNetworkID err", err)
		return nil, err
	}
	ip, err := ic.pickIp(ctx, network.ID, ipPool, req.PolicyId)
	if err != nil {
		log.Error("pickIp err: ", err)
		return nil, err
	}
	ipRecord, err := ic.assignIp(ctx, ip, req.PodName, req.PodNamespace, req.ContainerID, req.Hostname, req.IfName)
	if err != nil {
		log.Error("assignIp err", err)
		return nil, err
	}

	size := utils.ParseSize(ip.Mask)
	data := &types.IPResData{
		Ip:      fmt.Sprintf("%v/%v", ipRecord.Ip, size),
		Gateway: ip.Gateway,
	}
	log.Infof("require ip resp %v", data)

	return data, nil
}

func (ic *IpamController) ReleaseIP(ctx context.Context, req *types.IPReq) (*types.IPResData, error) {
	//log.Infof("ReleaseIP req %v", req)
	if req.Hostname == "" || req.ContainerID == "" {
		return nil, errors.New("hostName and containerId required")
	}

	req.Hostname = strings.ToLower(req.Hostname)

	p := &types.IpRecordInfo{
		Host:        req.Hostname,
		ContainerId: req.ContainerID,
		IfName:      req.IfName,
	}

	ipRecordKV, err := ic.store.Get(ctx, p.Key(), "")
	if err != nil {
		log.Errorf("fetch ipRecord %v err %v ", p.Key(), err)
		return &types.IPResData{}, nil
	}
	if ipRecordKV == nil {
		return &types.IPResData{}, nil
	}

	matched, err := types.DeSerializeIpRecord(ipRecordKV)
	if err != nil {
		log.Errorf("DeSerializeIpRecord failed %v", err)
		return nil, err
	}
	if matched == nil {
		return &types.IPResData{}, nil
	}

	pi := &types.IpInfo{
		Ip:        matched.Ip,
		NetworkID: matched.NetworkID,
	}
	ipInfoKV, err := ic.store.Get(ctx, pi.Key(), "")
	if err != nil {
		log.Errorf("fetch ip %v err %v ", pi, err)
		return nil, err
	}
	ipInfo, err := types.DeSerializeIpInfo(ipInfoKV)
	if err != nil {
		log.Errorf("deserialize ip %v err %v ", ipInfoKV, err)
		return nil, err
	}
	// 先删记录，再更新 IP 状态
	_, err = ic.store.Delete(ctx, matched.Key(), matched.Revision)
	if err != nil {
		log.Errorf("ip record %v delete failure ", matched)
		return nil, err
	}

	if ipInfo.Status == types.STATUS_AVAILABLE {
		log.Warningf("ip already released. %v", ipInfo)
	} else {
		_ = ic.gcIP(ctx, ipInfo, types.ACTION_RELEASE)
	}

	return &types.IPResData{
		Ip:      ipInfo.Ip,
		Gateway: ipInfo.Gateway,
	}, nil
}

func (ic *IpamController) FindNodeNetworkCIDR(ctx context.Context, hostname string) ([]*types.NetworkCIDR, error) {
	network, err := ic.findNodeNetwork(ctx, hostname)
	if err != nil {
		log.Error("findNetworkByHostname err", hostname, err)
		return nil, err
	}
	ips, e := ic.listIPByNetworkID(ctx, network.ID, "")
	if e != nil {
		log.Error("listIPByNetworkID err", network, e)
		return nil, err
	}
	nets := map[string]*types.IpInfo{}
	for i, ip := range ips {
		if _, ok := nets[ip.Gateway+ip.Mask]; !ok {
			nets[ip.Gateway+ip.Mask] = ips[i]
		}
	}
	var networkCIDRs []*types.NetworkCIDR
	for _, ne := range nets {
		ip := net.ParseIP(ne.Ip)
		mask := net.ParseIP(ne.Mask)
		if mask == nil || ip == nil {
			log.Warnf("invalid ip %v", ne)
			continue
		}
		var subnet []byte
		for i := range ip {
			subnet = append(subnet, ip[i]&mask[i])
		}
		subnetIp := net.IP(subnet)
		size := utils.ParseSize(ne.Mask)

		networkCIDRs = append(networkCIDRs, &types.NetworkCIDR{
			NetworkID: network.ID,
			Idc:       network.Idc,
			Name:      network.Name,
			Mask:      ne.Mask,
			Network:   fmt.Sprintf("%s/%v", subnetIp.String(), size),
		})
	}
	return networkCIDRs, nil
}

func (ic *IpamController) findNodeNetwork(ctx context.Context, nodeName string) (*types.NetworkInfo, error) {
	nId, ok := ic.hostNetworkIds[nodeName]
	if !ok {
		return nil, errors.New("not found")
	}
	if nId == "" {
		return nil, errors.New("not found")
	}
	ne := &types.NetworkInfo{ID: nId}
	data, err := ic.store.Get(ctx, ne.Key(), "")
	if err != nil {
		return nil, err
	}
	ne, err = types.DeSerializeNetworkInfo(data)
	if err != nil {
		return nil, err
	}

	return ne, nil
}

func (ic *IpamController) listIPByNetworkID(ctx context.Context, networkID string, status string) ([]*types.IpInfo, error) {
	n := &types.IpInfo{NetworkID: networkID}
	kvs, err := ic.store.List(ctx, n.ParentKey(), "")
	if err != nil {
		return nil, err
	}

	ips := make([]*types.IpInfo, 0, len(kvs.KVPairs))
	for _, kv := range kvs.KVPairs {
		ip, err := types.DeSerializeIpInfo(kv)
		if err != nil {
			log.Error("DeSerializeIpInfo err", kv.Value, err)
			continue
		}
		if status != "" {
			if status == ip.Status {
				ips = append(ips, ip)
			}
		} else {
			ips = append(ips, ip)
		}
	}

	return ips, nil
}

func (ic *IpamController) pickIp(ctx context.Context, networkId string, ipPool []*types.IpInfo, policyId string) (*types.IpInfo, error) {

	if len(ipPool) < 1 {
		return nil, fmt.Errorf("ip pool has no available ips")
	}

	reservedIps := make([]*types.IpInfo, 0, len(ipPool))
	unreservedIps := make([]*types.IpInfo, 0, len(ipPool))

	availableIps := make([]*types.IpInfo, 0, len(ipPool))

	for _, ip := range ipPool {
		if ip.Reserved {
			reservedIps = append(reservedIps, ip)
		} else {
			iip := net.ParseIP(ip.Ip).To4()
			// 结尾为 255 或者 0 的 ip 为保留 ip，不分配。
			if iip[3] == 255 || iip[3] == 0 {
				continue
			}
			unreservedIps = append(unreservedIps, ip)
		}
	}

	if policyId != "" {
		t := &types.IPReservePolicy{
			NetworkID: networkId,
			PolicyId:  policyId,
		}
		ipReserveKv, err := ic.store.Get(ctx, t.Key(), "")
		if err != nil {
			log.Errorf("IPReservePolicy %v fetch err %v", t.Key(), err)
			return nil, fmt.Errorf("IPReservePolicy %v fetch err %v", t.Key(), err)
		}
		ipReserve, err := types.DeSerializeIPReservePolicy(ipReserveKv)
		if err != nil {
			log.Errorf("DeSerializeIPReservePolicy %v err %v", ipReserveKv, err)
			return nil, fmt.Errorf("DeSerializeIPReservePolicy %v err %v", ipReserveKv, err)
		}
		if len(ipReserve.ReserveIps) < 1 {
			log.Errorf("IPReservePolicy %v has no reserved ips", ipReserve)
			return nil, fmt.Errorf("IPReservePolicy %v has no reserved ips", ipReserve)
		}

		for _, ip := range reservedIps {
			for _, iip := range ipReserve.ReserveIps {
				if ip.Ip == iip {
					availableIps = append(availableIps, ip)
					break
				}
			}
		}
		log.Infof("policy %v: reservedIps: %v, available ips %v ", policyId, ipReserve.ReserveIps, availableIps)

	} else {

		availableIps = unreservedIps
	}

	if len(availableIps) < 1 {
		return nil, errors.New("no available ip in pool")
	}

	var ipKv *types.KVPair
	var err error
	triedCnt := 0
	for {
		triedCnt += 1
		if triedCnt > int(math.Min(3, float64(len(availableIps)))) {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("assign ip max retried")
		}
		idx := rand.Intn(len(availableIps))
		ip := availableIps[idx]

		ip.Status = types.STATUS_ALLOCATING
		ipKv, err = ic.store.Save(ctx, ip)
		if err != nil {
			log.Errorf("allocating ip %v failure %v, will try again later", ip, err)
			time.Sleep(time.Second * 3)
			continue
		}

		break
	}

	ip, err := types.DeSerializeIpInfo(ipKv)
	if err != nil {
		log.Errorf("DeSerializeIpInfo ip %v err %v", ipKv, err)
		return nil, err
	}

	return ip, nil
}

func (ic *IpamController) assignIp(ctx context.Context, ip *types.IpInfo, podName, podNamespace, containerId, hostname, ifName string) (*types.IpRecordInfo, error) {

	id := hostname + "-" + containerId + "-" + ifName

	ipRecord := &types.IpRecordInfo{
		ID:           id,
		Ip:           ip.Ip,
		Host:         hostname,
		PodName:      podName,
		PodNamespace: podNamespace,
		ContainerId:  containerId,
		NetworkID:    ip.NetworkID,
		Gateway:      ip.Gateway,
		Mask:         ip.Mask,
		IfName:       ifName,
	}

	ip.Status = types.STATUS_INUSE
	ip.PodName = podName
	newIpKv, err := ic.store.Save(ctx, ip)
	if err != nil {
		log.Error("update ip status failure", ip, err)
		return nil, err
	}
	savedIpRecord, err := ic.store.Save(ctx, ipRecord)
	if err != nil {
		// 保存 ip 记录出错，回收 IP
		newIp, e := types.DeSerializeIpInfo(newIpKv)
		if e != nil {
			log.Error("DeSerializeIpInfo err", newIpKv)
			return nil, e
		}
		_ = ic.gcIP(ctx, newIp, types.ACTION_DEASIGN)
		return nil, err
	}

	return types.DeSerializeIpRecord(savedIpRecord)

}

func (ic *IpamController) CreateNetwork(ctx context.Context, info *types.NetworkInfo) (*types.NetworkInfo, error) {
	data, err := ic.store.Save(ctx, info)
	if err != nil {
		log.Error("Save network err", info, err)
		return nil, err
	}
	return types.DeSerializeNetworkInfo(data)

}

func (ic *IpamController) CreateNode(ctx context.Context, node *types.Node) (*types.Node, error) {
	ne := &types.NetworkInfo{
		ID: node.NetworkID,
	}
	_, err := ic.store.Get(ctx, ne.Key(), "")
	if err != nil {
		log.Errorf("get network %s err %v", ne.Key(), err)
		return nil, fmt.Errorf("find network err: %v", err)
	}
	data, err := ic.store.Save(ctx, node)
	if err != nil {
		log.Error("Save node err ", node, err)
		return nil, err
	}
	return types.DeSerializeNodeInfo(data)
}

func (ic *IpamController) CreateIPRange(ctx context.Context, ipRange *types.IPRangeReq) ([]*types.IpInfo, error) {
	log.Infof("creating ip range: %v", ipRange)
	subNet, err := utils.CIDR2IPNet(ipRange.Subnet)
	if err != nil {
		return nil, err
	}
	start := net.ParseIP(ipRange.RangeStart)
	end := net.ParseIP(ipRange.RangeEnd)
	var ips []net.IP
	if bytes.Compare(end, start) < 1 {
		return nil, fmt.Errorf("ip end %v less than start %v", end, start)
	}

	s := start
	cnt := 0
	for {
		if bytes.Compare(end, s) < 0 {
			break
		}
		if subNet.Contains(s) {
			ips = append(ips, s)
			cnt += 1
		} else {
			break
		}

		s = utils.NextIP(s, 1)

	}
	if ipRange.Mask == "" {
		ipRange.Mask = net.IP(subNet.Mask).To4().String()
	}
	log.Infof("creating iprange %v, cnt %v", ipRange, len(ips))
	ipInfos := make([]*types.IpInfo, 0, len(ips))
	for _, ip := range ips {
		ipInfos = append(ipInfos, &types.IpInfo{
			Ip:        ip.String(),
			Mask:      ipRange.Mask,
			Gateway:   ipRange.Gateway,
			Status:    types.STATUS_AVAILABLE,
			NetworkID: ipRange.NetworkID,
		})
	}

	var succeedIps []*types.IpInfo
	for _, ip := range ipInfos {
		_, err := ic.store.Save(ctx, ip)
		if err != nil {
			log.Error("save ip error", ip)
			continue
		}
		succeedIps = append(succeedIps, ip)

	}
	if len(succeedIps) < 1 {
		return nil, errors.New("no ip create success")
	}

	return succeedIps, nil

}

func (ic *IpamController) GCAllocatingExpiredIps() {
	ctx := context.Background()
	log.Infof("IPGarbageCollect started.")
	for {
		time.Sleep(time.Second * 180)
		var expireAllocatingIps []*types.IpInfo
		ne := &types.NetworkInfo{}
		networksKv, err := ic.store.List(ctx, ne.ParentKey(), "")
		if err != nil {
			log.Error("list network err. try again in 10 seconds ", err)
			time.Sleep(time.Second * 10)
			continue
		}
		for _, nkv := range networksKv.KVPairs {
			ne, err = types.DeSerializeNetworkInfo(nkv)
			if err != nil {
				log.Error("DeSerializeNetworkInfo err", nkv, err)
				continue
			}
			ip := &types.IpInfo{
				NetworkID: ne.ID,
			}
			ipKvs, err := ic.store.List(ctx, ip.ParentKey(), "")
			if err != nil {
				log.Error("list network ips err", ip.ParentKey(), err)
				continue
			}
			for _, ipKv := range ipKvs.KVPairs {
				ip, err := types.DeSerializeIpInfo(ipKv)
				if err != nil {
					log.Error("DeSerializeIpInfo err", ipKv, err)
					continue

				}
				if (ip.Status == types.STATUS_ALLOCATING || ip.Status == types.STATUS_WAIT_GC) && time.Now().Unix() > ip.UpdateAt+allocatingExpire {
					expireAllocatingIps = append(expireAllocatingIps, ip)
				}

			}

		}
		log.Debugf("expired IPs cnt %v", len(expireAllocatingIps))
		for _, ip := range expireAllocatingIps {
			_ = ic.gcIP(ctx, ip, types.ACTION_GC)
		}

	}

}

func (ic *IpamController) gcIP(ctx context.Context, ip *types.IpInfo, action string) error {
	ipGcCounter.WithLabelValues(ip.NetworkID, action, "TOTAL").Inc()
	ip.Status = types.STATUS_AVAILABLE
	ip.PodName = "" // 将 Pod name 设置为空
	_, err := ic.store.Save(ctx, ip)
	if err != nil {
		ipGcCounter.WithLabelValues(ip.NetworkID, action, "FAILURE").Inc()
		log.Errorf("gc ip %v failure, err: %v", ip, err)
	} else {
		ipGcCounter.WithLabelValues(ip.NetworkID, action, "SUCCESS").Inc()
		log.Infof("ip %v gc success", ip)
	}
	return err
}

func (ic *IpamController) SyncNodeNetworks(ctx context.Context) error {
	n := &types.Node{}
	nlist, err := ic.store.List(ctx, n.ParentKey(), "")
	if err != nil || nlist == nil {
		log.Error("node list err", err)
		return err
	}

	nodes := make([]*types.Node, 0, len(nlist.KVPairs))
	for _, kv := range nlist.KVPairs {
		node, err := types.DeSerializeNodeInfo(kv)
		if err != nil {
			log.Warning("DeSerializeNodeInfo node err", kv, err)
			continue
		}
		nodes = append(nodes, node)
	}
	log.Debugf("nodes count %v", len(nodes))

	hostNetworks := map[string]string{}

	for _, n := range nodes {
		if n.NetworkID == "" {
			continue
		}
		if _, exist := hostNetworks[n.HostName]; !exist {
			hostNetworks[n.HostName] = n.NetworkID
		}
	}

	if len(ic.hostNetworkIds) != len(hostNetworks) {
		log.Infof("hostNetwork changed %v -> %v ", ic.hostNetworkIds, hostNetworks)

	}
	ic.hostNetworkIds = hostNetworks
	return nil

}

func (ic *IpamController) EnsureNodesNetwork() {
	ctx := context.Background()
	for {

		if err := ic.SyncNodeNetworks(ctx); err != nil {
			log.Errorf("sync node network failed %v", err)
			time.Sleep(time.Second * 10)
			continue
		}
		if err := ic.SyncNetwork(); err != nil {
			log.Errorf("sync node network failed %v", err)
			time.Sleep(time.Second * 10)
			continue
		}
		if err := ic.AssignNodeIpamBlocks(); err != nil {
			log.Errorf("assign node ipam blocks failed %v", err)
			time.Sleep(time.Second * 10)
			continue
		}
		time.Sleep(time.Second * 60)
	}
}