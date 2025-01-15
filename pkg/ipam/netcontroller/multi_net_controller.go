package netcontroller

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/yowenter/claude-ipam/pkg/ipam/dao"
	"github.com/yowenter/claude-ipam/pkg/store"
	"github.com/yowenter/claude-ipam/pkg/types"
	"github.com/yowenter/claude-ipam/pkg/utils"

	log "github.com/sirupsen/logrus"
)

type MultiNetController struct {
	multiNets []*types.NetworkConf
	dao       *dao.NetDao
	store     store.Store
}

const (
	IFACE_MATCH_METHOD_REGEX = "regex"
	IFACE_MATCH_METHOD_NAME  = "name"
	IFACE_MATCH_METHOD_ANY   = "any"

	NODE_MATCH_METHOD_REGEX = "regex"
	NODE_MATCH_METHOD_NAME  = "name"
	NODE_MATCH_METHOD_ANY   = "any"
)

func NewMultiNetController(
	multiNets []*types.NetworkConf, da *dao.NetDao, store store.Store) *MultiNetController {
	log.Info("loading net configurations...")
	for _, n := range multiNets {
		log.Infof("%++v, NodeSelector: %+v", n, n.NodeSelector)
	}
	return &MultiNetController{
		multiNets: multiNets,
		dao:       da,
		store:     store,
	}
}

func (m *MultiNetController) FindNodeNetwork(nodeName string, masterIf string) (string, bool) {
	var targetNet string
	for _, net := range m.multiNets {
		if net.NodeSelector == nil {
			continue
		}
		if match, e := NodeSlectorMatch(net.NodeSelector, nodeName, masterIf); e == nil {
			if match {
				targetNet = net.ID
				break
			}
		} else {
			log.Errorf("nodeselector %v match node %v-%v failed %v", net.NodeSelector, nodeName, masterIf, e)
		}

	}
	if targetNet != "" {
		log.Infof("node %v-%v match network %v", nodeName, masterIf, targetNet)
		return targetNet, true
	}
	return "", false

}

func NodeSlectorMatch(ns *types.NodeSelector, nodeName, masterIf string) (bool, error) {
	ifaceMatch := false
	nodeMatch := false

	switch ns.IfaceMethod {
	case IFACE_MATCH_METHOD_NAME:
		if masterIf == ns.IfaceName {
			ifaceMatch = true
		}

	case IFACE_MATCH_METHOD_REGEX:
		if match, err := regexp.Match(ns.IfaceRegex, []byte(masterIf)); err == nil {
			if match {
				ifaceMatch = true
			}
		} else {
			return false, err
		}

	case IFACE_MATCH_METHOD_ANY:

		if masterIf == ns.IfaceName {
			ifaceMatch = true
		}
		if !ifaceMatch && ns.IfaceRegex != "" {
			regexM, _ := regexp.Match(ns.IfaceRegex, []byte(masterIf))
			ifaceMatch = regexM
		}
	}

	/////////////////////////////
	switch ns.NodeMethod {
	case NODE_MATCH_METHOD_REGEX:
		if match, err := regexp.Match(ns.NodeNameRegex, []byte(nodeName)); err == nil {
			if match {
				nodeMatch = true
			}
		} else {
			return false, err
		}

	case NODE_MATCH_METHOD_NAME:
		for _, n := range ns.NodeNames {
			exnodes, err := utils.ExpandNodeName(n)
			if err != nil {
				continue
			}

			for _, nn := range exnodes {
				if nn == nodeName {
					nodeMatch = true
					break
				}
			}
		}

	case NODE_MATCH_METHOD_ANY:
		for _, n := range ns.NodeNames {
			exnodes, err := utils.ExpandNodeName(n)
			if err != nil {
				continue
			}

			for _, nn := range exnodes {
				if nn == nodeName {
					nodeMatch = true
					break
				}
			}
		}

		if !nodeMatch && ns.NodeNameRegex != "" {
			if match, err := regexp.Match(ns.NodeNameRegex, []byte(nodeName)); err == nil {
				if match {
					nodeMatch = true
				}
			} else {
				return false, err
			}
		}
	}
	return ifaceMatch && nodeMatch, nil

}

func (m *MultiNetController) Watch() {
	for {
		m.SyncNetworks()
		time.Sleep(time.Second * 120)
	}
}

func (m *MultiNetController) SyncNetworks() {
	ctx := context.TODO()
	log.Infof("multinet controller loading network configuration started... ")
	for _, nnet := range m.multiNets {
		if nnet.ID == "" {
			log.Warnf("network %v id not specified, creating skipped", nnet)
			continue
		}

		needCreate := false
		netW, err := m.dao.GetNetwork(ctx, nnet.ID)
		if err != nil {
			if strings.Contains(err.Error(), "NOT FOUND") {
				needCreate = true
			} else {
				log.Warnf("get network %v failed %v", nnet.ID, err)
				continue
			}
		} else {
			log.Infof("network %v exists, creating using conf %v skipped.", netW, nnet)
			continue
		}
		if !needCreate {
			continue
		}
		ipnet, err := utils.CIDR2IPNet(nnet.CIDR)
		if err != nil {
			log.Errorf("CIDR2IPNet %v failed %v", nnet.CIDR, err)
			continue
		}

		newNet := types.NetworkInfo{
			ID:   nnet.ID,
			Name: nnet.Name,
			CIDR: nnet.CIDR,
		}
		_, err = m.dao.CreateNetwork(ctx, &newNet)
		if err != nil {
			log.Errorf("create network %v failed %v", newNet, err)
			continue
		}

		ips, err := m.dao.CreateIPRange(ctx, &types.IPRangeReq{
			RangeStart: nnet.RangeStart,
			RangeEnd:   nnet.RangeEnd,
			Subnet:     nnet.CIDR,
			Gateway:    nnet.Gateway,
			Mask:       net.IP(ipnet.Mask).To4().String(),
			NetworkID:  nnet.ID,
		})
		if err != nil {
			log.Errorf("create iprange %v failed %v", nnet, err)
			continue
		}
		log.Infof("network %v created ips cnt %v", nnet, len(ips))
	}

}
