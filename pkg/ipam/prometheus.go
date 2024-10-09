package ipam

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/types"
)

var ipUsageGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "network_ip_usage",
	Help: "network ip usage",
}, []string{"network", "ip_status"})

var ipRecordsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "ip_records",
	Help: "ip records ",
}, []string{"status"})

var ipGcCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "ip_gc_counter",
	Help: "ip gc",
}, []string{"network", "action", "gc_result"})

func (ic *IpamController) MetrcisCollector() {
	log.Infof("Sync IP Metrics started.")
	ctx := context.Background()
	for {
		time.Sleep(time.Second * 60)

		networks := map[string]bool{}
		for _, n := range ic.hostNetworkIds {
			if _, ok := networks[n]; !ok {
				networks[n] = true
			}

		}
		var totalIPUsed float64
		for netId := range networks {
			ips, err := ic.listIPByNetworkID(ctx, netId, "")
			if err != nil {
				log.Error("listIPByNetworkID err", netId, err)
				continue
			}
			var ipTotal, ipUsed, ipUnused, ipAllocating, ipReserved, ipWaitGC float64
			ipTotal = float64(len(ips))

			for _, ip := range ips {
				if ip.Reserved {
					ipReserved += 1
				}
				switch ip.Status {
				case types.STATUS_INUSE:
					ipUsed += 1
				case types.STATUS_AVAILABLE:
					ipUnused += 1
				case types.STATUS_ALLOCATING:
					ipAllocating += 1

				case types.STATUS_WAIT_GC:
					ipWaitGC += 1
				}

			}
			ipUsageGauge.WithLabelValues(netId, "TOTAL").Set(ipTotal)

			ipUsageGauge.WithLabelValues(netId, types.STATUS_AVAILABLE).Set(ipUnused)

			ipUsageGauge.WithLabelValues(netId, types.STATUS_INUSE).Set(ipUsed)

			ipUsageGauge.WithLabelValues(netId, types.STATUS_ALLOCATING).Set(ipAllocating)

			ipUsageGauge.WithLabelValues(netId, types.IP_RESERVED).Set(ipReserved)

			ipUsageGauge.WithLabelValues(netId, types.STATUS_WAIT_GC).Set(ipWaitGC)

			totalIPUsed += ipUsed
			log.Debugf("network %v total ips %v, unused %v, used %v, allocating %v, reserved %v, wait_gc %v",
				netId, ipTotal, ipUnused, ipUsed, ipAllocating, ipReserved, ipWaitGC)
			time.Sleep(time.Second)

		}

	}
}

func InitPrometheus() {
	log.Info("register ip usage metric")
	prometheus.MustRegister(ipUsageGauge)
	prometheus.MustRegister(ipRecordsGauge)
	prometheus.MustRegister(ipGcCounter)
}
