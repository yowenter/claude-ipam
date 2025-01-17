package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniversion "github.com/containernetworking/cni/pkg/version"
	types "github.com/yowenter/claude-ipam/pkg/types"

	"github.com/yowenter/claude-ipam/pkg/ipam"
)

var buildtime string
var version string

var logPath = "/var/log/claude/cni/cni.log"

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{})
	if err := os.MkdirAll(filepath.Dir(logPath), os.ModeDir); err != nil {
		logrus.Fatal(err)
		return
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.Fatal("Error opening log file:", err)
	}
	defer logFile.Close()

	logrus.SetOutput(logFile)
	skel.PluginMain(
		func(args *skel.CmdArgs) error {
			conf, err := parseNetConf(args.StdinData)
			if err != nil {
				logrus.Errorf("parse net stdindata %v err %v", args.StdinData, err)
				return err
			}
			ipamEnv, err := parseIPamEnv(args.Args)
			if err != nil {
				logrus.Errorf("parse ipam env %v failed %v", args.Args, err)
				return err
			}
			ipamConf, err := ipam.LoadIpamConfig()
			if err != nil {
				logrus.Errorf("load ipam config failed %v", err)
				return err
			}
			logrus.Infof("cmdAdd net conf %++v, ipam env %v", conf, ipamEnv)
			return cmdAdd(args, ipamEnv, ipamConf, conf.Master, conf.CNIVersion)
		},
		func(args *skel.CmdArgs) error {
			return fmt.Errorf("CNI CHECK method is not implemented")
		},
		func(args *skel.CmdArgs) error {
			ipamEnv, err := parseIPamEnv(args.Args)
			if err != nil {
				return err
			}
			ipamConf, err := ipam.LoadIpamConfig()
			if err != nil {
				return err
			}

			return cmdDel(args, ipamEnv, ipamConf)
		},
		cniversion.All,
		fmt.Sprintf("calude ipam version: %s, buildtime: %s", version, buildtime),
	)
}

func parseNetConf(bytes []byte) (*types.ClaudeNetConf, error) {
	conf := &types.ClaudeNetConf{}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}
	//TODO get masterif
	return conf, nil
}

func parseIPamEnv(envArgs string) (*types.IPAMEnvArgs, error) {
	args := types.IPAMEnvArgs{}
	if err := cnitypes.LoadArgs(envArgs, &args); err != nil {
		return nil, fmt.Errorf("LoadArgs - CNI Args Parsing Error: %s", err)
	}
	return &args, nil
}

func cmdAdd(args *skel.CmdArgs, ipamEnv *types.IPAMEnvArgs, ipamConf *types.IpamConfiguration, masterIf string, cniVersion string) error {
	nodeName, err := os.Hostname()
	if err != nil {
		return err
	}
	ipamClient := &http.Client{}
	// TODO ADD key verification

	ipreqData := types.IPReq{
		Hostname:     nodeName,
		ContainerID:  string(args.ContainerID),
		PodName:      string(ipamEnv.K8S_POD_NAME),
		PodNamespace: string(ipamEnv.K8S_POD_NAMESPACE),
		PolicyId:     "",
		IfName:       args.IfName,
		MasterIf:     masterIf,
	}

	ipReqJson, err := json.Marshal(ipreqData)
	if err != nil {
		logrus.Errorf("marshal ipreq data %v err %v", ipreqData, err)
		return err
	}

	logrus.Infof("require ip %v", ipreqData)
	ipReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/ip/require", ipamConf.IpamServerSvc), bytes.NewBuffer(ipReqJson))
	if err != nil {
		logrus.Errorf("new require ip request failed %v", err)
		return err
	}
	ipReq.SetBasicAuth(ipamConf.BasicUser, ipamConf.BasicPass)
	resp, err := ipamClient.Do(ipReq)
	if err != nil {
		logrus.Errorf("require ip do request err %v", err)
		return err
	}
	if resp.StatusCode > 299 {
		logrus.Errorf("resp code not 2xx")
		return fmt.Errorf("resp not ok")
	}
	defer resp.Body.Close()
	ipresJson, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("read resp body failed %v", err)
		return err
	}

	type IpRequireResp struct {
		Code    int32           `json:"code"`
		Message string          `json:"msg"`
		Data    types.IPResData `json:"data"`
	}

	var ipRes IpRequireResp
	if err := json.Unmarshal(ipresJson, &ipRes); err != nil {
		logrus.Errorf("json unmarshal failed %v", err)
		return err
	}
	if ipRes.Code != 0 {
		logrus.Errorf("ipreq resp code %v msg %v", ipRes.Code, ipRes.Message)
		return fmt.Errorf("ip require failed, code: %v, msg: %v", ipRes.Code, ipRes.Message)
	}

	ip, ipNet, err := net.ParseCIDR(ipRes.Data.Ip)
	if err != nil {
		logrus.Errorf("parse ip %v failed %v", ipRes.Data, err)
		return err
	}

	result := &current.Result{}
	gw := net.ParseIP(ipRes.Data.Gateway)
	result.IPs = append(result.IPs, &current.IPConfig{
		Version: "4",
		Address: net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
		Gateway: gw,
	})
	result.Routes = []*cnitypes.Route{
		{
			Dst: *ipNet,
			GW:  gw,
		},
	}
	logrus.Infof("require ip result %v", result)

	return cnitypes.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs, ipamEnv *types.IPAMEnvArgs, ipamConf *types.IpamConfiguration) error {
	nodeName, err := os.Hostname()
	if err != nil {
		return err
	}
	ipamClient := &http.Client{}
	// TODO ADD key verification

	ipreqData := types.IPReq{
		Hostname:     nodeName,
		ContainerID:  string(args.ContainerID),
		PodName:      string(ipamEnv.K8S_POD_NAME),
		PodNamespace: string(ipamEnv.K8S_POD_NAMESPACE),
		PolicyId:     "",
		IfName:       args.IfName,
	}

	ipReqJson, err := json.Marshal(ipreqData)
	if err != nil {
		logrus.Errorf("json marshal %v failed %v", ipreqData, err)
		return err
	}
	logrus.Infof("release ip %v", ipreqData)
	ipReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/ip/release", ipamConf.IpamServerSvc), bytes.NewBuffer(ipReqJson))
	if err != nil {
		logrus.Errorf("new release request failed %v", err)
		return err
	}
	ipReq.SetBasicAuth(ipamConf.BasicUser, ipamConf.BasicPass)
	resp, err := ipamClient.Do(ipReq)
	if err != nil {
		logrus.Errorf("do release request failed %v", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		logrus.Errorf("resp code not 2xx")
		return fmt.Errorf("resp not ok")
	}
	ipresJson, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("read resp failed %v", err)
		return err
	}

	var ipRes types.CommonResp
	if err := json.Unmarshal(ipresJson, &ipRes); err != nil {
		return err
	}
	if ipRes.Code != 0 {
		logrus.Errorf("ip release failed, code %v msg: %v", ipRes.Code, ipRes.Message)
		return fmt.Errorf("ip release failed, code: %v, msg: %v", ipRes.Code, ipRes.Message)
	}

	return nil
}
