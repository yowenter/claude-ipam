package types

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type IPReq struct {
	Hostname     string `json:"hostName"`
	ContainerID  string `json:"containerId"`
	PodName      string `json:"podName"`
	PolicyId     string `json:"policyId,omitempty"`
	PodNamespace string `json:"podNamespace"`
	IfName       string `json:"ifName"`
}

type IPReserveReq struct {
	IpCnt      int    `json:"ipCnt"`
	PolicyId   string `json:"policyId"`
	PolicyName string `json:"policyName"`
	NetworkId  string `json:"networkId"`
}

type HostNetReq struct {
	Region   string `json:"region"`
	Idc      string `json:"idc"`
	Hostname string `json:"hostname"`
}

type IPReserveDetail struct {
	Idc        string   `json:"idc"`
	NetworkID  string   `json:"networkId"`
	ReserveIps []string `json:"reserveIps"`
	PolicyId   string   `json:"policyId"`
	PolicyName string   `json:"policyName"`

	IpRecords []*IpBriefInfo `json:"ipRecords"`
}

const (
	STATUS_ALLOCATING = "ALLOCATING"
	STATUS_INUSE      = "IN_USE"
	STATUS_AVAILABLE  = "AVAILABLE"
	STATUS_WAIT_GC    = "WAIT_GC"

	IP_RESERVED = "RESERVED"

	ACTION_REQUIRE = "REQUIRE"
	ACTION_RELEASE = "RELEASE"
	ACTION_DEASIGN = "DE_ASIGN"
	ACTION_GC      = "GC"
	ACTION_MARK_GC = "MARK_GC"
)

type CommonResp struct {
	Code    int32       `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

type IPResData struct {
	Ip      string `json:"ip"`
	Gateway string `json:"gateway"`
}

type IPRangeReq struct {
	RangeStart string `json:"rangeStart,omitempty"`
	RangeEnd   string `json:"rangeEnd,omitempty"`
	Subnet     string `json:"subnet"`
	Mask       string `json:"mask"`
	Gateway    string `json:"gateway,omitempty"`
	NetworkID  string `json:"networkId"`
}

type Node struct {
	HostName string `json:"hostname"`

	NetworkID string `json:"networkId"`
	UpdateAt  int64  `json:"update_at"`
	Revision  string `json:"-"`
}

type IPReservePolicy struct {
	Idc        string   `json:"idc"`
	NetworkID  string   `json:"networkId"`
	ReserveIps []string `json:"reserveIps"`
	PolicyId   string   `json:"policyId"`
	PolicyName string   `json:"policyName"`

	UpdateAt int64  `json:"update_at"`
	Revision string `json:"-"`
}

func (key *IPReservePolicy) Key() string {
	k := fmt.Sprintf("/claude-ipam/v1/ip-reserve/%s", key.PolicyId)
	return k
}

func (key *IPReservePolicy) ParentKey() string {
	return "/claude-ipam/v1/ip-reserve"
}

func (key *IPReservePolicy) UpdateTs() {
	key.UpdateAt = time.Now().Unix()
}

func (key *IPReservePolicy) Serialize() (*KVPair, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &KVPair{
		Key:      key.Key(),
		Value:    string(data),
		Revision: key.Revision,
	}, nil

}

func (key *Node) Key() string {
	k := strings.ToLower(fmt.Sprintf("/claude-ipam/v1/node/%s-%s", key.NetworkID, key.HostName))
	return k
}

func (key *Node) ParentKey() string {
	return "/claude-ipam/v1/node/"
}

func (key *Node) UpdateTs() {
	key.UpdateAt = time.Now().Unix()
}

func (key *Node) Serialize() (*KVPair, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &KVPair{
		Key:      key.Key(),
		Value:    string(data),
		Revision: key.Revision,
	}, nil

}

type IpBriefInfo struct {
	Ip      string `json:"ip"`
	PodName string `json:"podName"`
	Status  string `json:"status"` // USED, UNUSED, ALLOCATING, ABNORMAL, DISABLED
}

type IpInfo struct {
	Ip        string `json:"ip"`
	Mask      string `json:"mask"`
	Gateway   string `json:"gateway"`
	Status    string `json:"status"` // USED, UNUSED, ALLOCATING, ABNORMAL, DISABLED
	NetworkID string `json:"network_id"`
	Revision  string `json:"-"`
	UpdateAt  int64  `json:"update_at"`
	Reserved  bool   `json:"reserved"` // 是否被预留。

	PodName string `json:"pod_name"`
}

type IpStat struct {
	Ip          string `json:"ip"`
	Mask        string `json:"mask"`
	Gateway     string `json:"gateway"`
	PodName     string `json:"pod_name"`
	Host        string `json:"host"`
	ContainerId string `json:"container_id"`
	Status      string `json:"status"` // USED, UNUSED, RESERVED, ALLOCATING, ABNORMAL, DISABLED
	NetworkID   string `json:"network_id"`
	Reserved    bool   `json:"reserved"`
	PolicyId    string `json:"policyId"`
}

func (key *IpInfo) Key() string {
	k := fmt.Sprintf("/claude-ipam/v1/ip/%s/%s", key.NetworkID, key.Ip)
	return k
}

func (key *IpInfo) ParentKey() string {
	k := fmt.Sprintf("/claude-ipam/v1/ip/%s/", key.NetworkID)
	return k
}

func (key *IpInfo) UpdateTs() {
	key.UpdateAt = time.Now().Unix()
}

func (key IpInfo) Serialize() (*KVPair, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &KVPair{
		Key:      key.Key(),
		Value:    string(data),
		Revision: key.Revision,
	}, nil

}

// 容器 IP 使用记录。
type IpRecordInfo struct {
	ID           string `json:"id"`
	Ip           string `json:"ip"`
	Host         string `json:"host"`
	PodName      string `json:"pod_name"`
	PodNamespace string `json:"pod_namespace"`
	ContainerId  string `json:"container_id"`
	Revision     string `json:"-"`
	NetworkID    string `json:"network_id"`
	Gateway      string `json:"gateway"`
	Mask         string `json:"mask"`
	UpdateAt     int64  `json:"update_at"`
	IfName       string `json:"ifName"`
}

func (key *IpRecordInfo) UpdateTs() {
	key.UpdateAt = time.Now().Unix()
}

func (key *IpRecordInfo) ParentKey() string {
	return "/claude-ipam/v1/ip-records"
}

func (key *IpRecordInfo) Key() string {
	k := strings.ToLower(fmt.Sprintf("/claude-ipam/v1/ip-records/%s", key.Host+"-"+key.ContainerId+"-"+key.IfName))
	return k
}

func (key *IpRecordInfo) Serialize() (*KVPair, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &KVPair{
		Key:      key.Key(),
		Value:    string(data),
		Revision: key.Revision,
	}, nil

}

type NetworkInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	CIDR string `json:"cidr"`

	Idc      string `json:"idc"`
	Revision string `json:"-"`
	UpdateAt int64  `json:"update_at"`
}

type NetworkCIDR struct {
	NetworkID string `json:"network_id"`
	Idc       string `json:"idc"`
	Name      string `json:"name"`
	Mask      string `json:"mask"`
	Network   string `json:"network"`
}

func (key *NetworkInfo) Key() string {
	k := "/claude-ipam/v1/network/" + key.ID
	return k
}

func (key *NetworkInfo) ParentKey() string {
	k := "/claude-ipam/v1/network/"
	return k
}

func (key *NetworkInfo) UpdateTs() {
	key.UpdateAt = time.Now().Unix()
}

func (key *NetworkInfo) Serialize() (*KVPair, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &KVPair{
		Key:      key.Key(),
		Value:    string(data),
		Revision: key.Revision,
	}, nil
}

func DeSerializeIpInfo(pair *KVPair) (*IpInfo, error) {
	var ip IpInfo
	err := json.Unmarshal([]byte(pair.Value), &ip)
	if err != nil {
		return nil, err
	}
	ip.Revision = pair.Revision
	return &ip, nil

}

func DeSerializeNetworkInfo(pair *KVPair) (*NetworkInfo, error) {
	var ne NetworkInfo
	err := json.Unmarshal([]byte(pair.Value), &ne)
	if err != nil {
		return nil, err
	}
	ne.Revision = pair.Revision
	return &ne, nil
}

func DeSerializeIpRecord(pair *KVPair) (*IpRecordInfo, error) {
	var ip IpRecordInfo
	err := json.Unmarshal([]byte(pair.Value), &ip)
	if err != nil {
		return nil, err
	}
	ip.Revision = pair.Revision
	return &ip, nil
}

func DeSerializeNodeInfo(pair *KVPair) (*Node, error) {
	var ne Node
	err := json.Unmarshal([]byte(pair.Value), &ne)
	if err != nil {
		return nil, err
	}
	ne.Revision = pair.Revision
	return &ne, nil
}

func DeSerializeIPReservePolicy(pair *KVPair) (*IPReservePolicy, error) {
	var ne IPReservePolicy
	err := json.Unmarshal([]byte(pair.Value), &ne)
	if err != nil {
		return nil, err
	}
	ne.Revision = pair.Revision
	return &ne, nil
}
