package ipam

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/types"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ic *IpamController) GcIpTask(ctx context.Context) error {
	if !ic.enableGcIP {
		return nil
	}

	nodesList, err := ic.k8s.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, n := range nodesList.Items {
		records, err := ic.dao.ListIpRecords(ctx, "/"+n.Name)
		if err != nil {
			log.Errorf("list node %v ip records failed %v", n.Name, err)
			continue
		}

		for _, rc := range records {
			// ip record 创建于 7 天内，不处理
			if rc.UpdateAt > time.Now().Unix()-int64(time.Second*86400*7) {
				continue
			}
			ip, err := ic.dao.GetIp(ctx, &types.IpInfo{
				Ip:        rc.Ip,
				NetworkID: rc.NetworkID,
			})
			if err != nil {
				log.Errorf("get ip by record %v failed %v", rc, err)
				continue
			}
			_, err = ic.k8s.CoreV1().Pods(rc.PodNamespace).Get(ctx, rc.PodName, metav1.GetOptions{})
			if err != nil && errors.IsNotFound(err) {
				if err := ic.gcIP(ctx, ip, types.ACTION_GC); err != nil {
					log.Errorf("gc ip %v, record %v, failed %v", ip, rc, err)
				} else {
					log.Infof("ip record %v pod not found, gc ip %v ok", rc, ip)
				}
			}

		}
	}

	return nil

}

func (ic *IpamController) LoopGcIPs() {
	if !ic.enableGcIP {
		return
	}
	log.Infof("GC IP task started...")
	ctx := context.Background()
	for {
		time.Sleep(time.Second * 180)
		if err := ic.GcIpTask(ctx); err != nil {
			log.Errorf("gc ip task failed %v", err)
		}
	}

}
