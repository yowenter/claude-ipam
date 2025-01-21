package dao

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/store"
	"github.com/yowenter/claude-ipam/pkg/types"
	"github.com/yowenter/claude-ipam/pkg/utils"
)

type NetDao struct {
	store store.Store
}

func NewDao(store store.Store) *NetDao {
	return &NetDao{
		store: store,
	}
}

func (d *NetDao) CreateNetwork(ctx context.Context, info *types.NetworkInfo) (*types.NetworkInfo, error) {
	data, err := d.store.Save(ctx, info)
	if err != nil {
		log.Error("Save network err", info, err)
		return nil, err
	}
	return types.DeSerializeNetworkInfo(data)
}

func (d *NetDao) ListNode(ctx context.Context) ([]*types.Node, error) {
	ne := &types.Node{}
	nodesKv, err := d.store.List(ctx, ne.ParentKey(), "")
	if err != nil {
		log.Errorf("list network err %v", err)
		return nil, err
	}
	nodes := make([]*types.Node, 0, len(nodesKv.KVPairs))

	for _, nkv := range nodesKv.KVPairs {
		ne, err = types.DeSerializeNodeInfo(nkv)
		if err != nil {
			log.Error("DeSerializeNetworkInfo err", nkv, err)
			continue
		}
		nodes = append(nodes, ne)

	}
	return nodes, nil
}

func (d *NetDao) ListNetwork(ctx context.Context) ([]*types.NetworkInfo, error) {
	ne := &types.NetworkInfo{}
	networksKv, err := d.store.List(ctx, ne.ParentKey(), "")
	if err != nil {
		log.Errorf("list network err %v", err)
		return nil, err
	}
	networks := make([]*types.NetworkInfo, 0, len(networksKv.KVPairs))

	for _, nkv := range networksKv.KVPairs {
		ne, err = types.DeSerializeNetworkInfo(nkv)
		if err != nil {
			log.Error("DeSerializeNetworkInfo err", nkv, err)
			continue
		}
		networks = append(networks, ne)

	}
	return networks, nil
}

func (d *NetDao) GetNetwork(ctx context.Context, nId string) (*types.NetworkInfo, error) {
	ne := &types.NetworkInfo{ID: nId}
	data, err := d.store.Get(ctx, ne.Key(), "")
	if err != nil {
		return nil, err
	}
	ne, err = types.DeSerializeNetworkInfo(data)
	if err != nil {
		return nil, err
	}
	return ne, nil
}

func (d *NetDao) CreateNode(ctx context.Context, node *types.Node) (*types.Node, error) {
	ne := &types.NetworkInfo{
		ID: node.NetworkID,
	}
	_, err := d.store.Get(ctx, ne.Key(), "")
	if err != nil {
		log.Errorf("get network %s err %v", ne.Key(), err)
		return nil, fmt.Errorf("find network err: %v", err)
	}
	data, err := d.store.Save(ctx, node)
	if err != nil {
		log.Error("Save node err ", node, err)
		return nil, err
	}
	return types.DeSerializeNodeInfo(data)
}

func (d *NetDao) CreateIPRange(ctx context.Context, ipRange *types.IPRangeReq) ([]*types.IpInfo, error) {
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
		_, err := d.store.Save(ctx, ip)
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
