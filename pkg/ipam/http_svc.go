package ipam

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/types"
)

func (ic *IpamController) CreateNetworkHandler(c *gin.Context) {
	var req []*types.NetworkInfo
	if err := c.BindJSON(&req); err != nil {
		c.JSON(422, gin.H{"error": err.Error()})
		return
	}
	ctx := context.TODO()
	var nets []*types.NetworkInfo
	for _, net := range req {
		net.ID = strings.ReplaceAll(net.Idc+"-"+net.Name, "/", "-")
		n, e := ic.CreateNetwork(ctx, net)
		if e != nil {
			log.Error("create network err", net, e)
			c.JSON(http.StatusBadRequest, gin.H{"error": e.Error()})
			return
		}
		nets = append(nets, n)

	}
	c.JSON(http.StatusCreated, nets)
}

func (ic *IpamController) CreateIPRangeHandler(c *gin.Context) {
	var req []*types.IPRangeReq
	if err := c.BindJSON(&req); err != nil {
		c.JSON(422, gin.H{"error": err.Error()})
		return
	}
	ctx := context.TODO()
	var resultIps []*types.IpInfo
	for _, iprange := range req {
		n := &types.NetworkInfo{
			ID: iprange.NetworkID,
		}
		ne, e := ic.store.Get(ctx, n.Key(), "")
		if e != nil || ne == nil {
			log.Error("fetch network info err", e)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("fetch network failure %v", e)})
			return
		}

		ips, e := ic.CreateIPRange(ctx, iprange)
		if e != nil {
			log.Error("create network err", iprange, e)
			c.JSON(http.StatusBadRequest, gin.H{"error": e.Error()})
			return
		}

		resultIps = append(resultIps, ips...)

	}
	c.JSON(http.StatusCreated, resultIps)
}

func (ic *IpamController) CreateNodeHandler(c *gin.Context) {
	var req []*types.Node
	if err := c.BindJSON(&req); err != nil {
		c.JSON(422, gin.H{"error": err.Error()})
		return
	}
	ctx := context.TODO()
	var nodes []*types.Node
	for _, node := range req {
		n, e := ic.CreateNode(ctx, node)
		if e != nil {
			log.Error("create node err", node, e)
			c.JSON(http.StatusBadRequest, gin.H{"error": e.Error()})
			return
		}
		nodes = append(nodes, n)

	}
	c.JSON(http.StatusCreated, nodes)
}

func (ic *IpamController) ReleaseIPHandler(c *gin.Context) {
	var req types.IPReq
	if err := c.BindJSON(&req); err != nil {
		c.JSON(422, gin.H{"error": err.Error()})
		return
	}
	ctx := context.TODO()
	data, err := ic.ReleaseIP(ctx, &req)
	if err != nil {
		log.Errorf("ReleaseIP %v err %v", req, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Infof("ReleaseIP req %v, resp %v", req, data)
	c.JSON(http.StatusOK, types.CommonResp{
		Code:    0,
		Message: "OK",
		Data:    data,
	})
}

func (ic *IpamController) RequireIPHandler(c *gin.Context) {
	var req types.IPReq
	if err := c.BindJSON(&req); err != nil {
		c.JSON(422, gin.H{"error": err.Error()})
		return
	}
	ctx := context.TODO()
	log.Infof("require ip req: %v", req)
	data, err := ic.RequireIP(ctx, &req)
	if err != nil {
		log.Errorf("RequireIP %v err %v", req, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, &types.CommonResp{
		Code:    0,
		Message: "OK",
		Data:    data,
	})
}

func (ic *IpamController) NodeNetworkHandler(c *gin.Context) {
	ctx := context.TODO()
	var req types.HostNetReq
	if err := c.BindJSON(&req); err != nil {
		c.JSON(422, gin.H{"error": err.Error()})
		return
	}
	if req.Hostname == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostIp not provided"})
		return
	}

	data, err := ic.FindNodeNetworkCIDR(ctx, req.Hostname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, &types.CommonResp{
		Code:    0,
		Message: "OK",
		Data:    data,
	})
}
