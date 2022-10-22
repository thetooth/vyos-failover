package statistics

import (
	"math"

	"github.com/thetooth/vyos-failover/config"
	"github.com/thetooth/vyos-failover/decision"
)

type Statistics []RouteStat

type RouteStat struct {
	Name        string        `json:"name"`
	Operational bool          `json:"operational"`
	Multipath   bool          `json:"multipath"`
	NextHops    []NextHopStat `json:"next_hops"`
}

type NextHopStat struct {
	Gateway string       `json:"gateway"`
	Check   config.Check `json:"check"`

	Interface  string `json:"interface"`
	SourceAddr string `json:"source"`
	Metric     int    `json:"metric"`

	Operational  bool `json:"operational"`
	LastChange   int  `json:"last_change"`
	FailCount    int  `json:"fail_count"`
	SuccessCount int  `json:"success_count"`

	PacketsRecv           int             `json:"packets_recv"`
	PacketsSent           int             `json:"packets_sent"`
	PacketsRecvDuplicates int             `json:"packets_recv_dup"`
	PacketLoss            float64         `json:"packet_loss"`
	MinRtt                config.Interval `json:"min_rtt"`
	MaxRtt                config.Interval `json:"max_rtt"`
	AvgRtt                config.Interval `json:"avg_rtt"`
	StdDevRtt             config.Interval `json:"std_dev_rtt"`
	LastRTT               config.Interval `json:"last_rtt"`
}

func Build(routes []*decision.Route) (stats Statistics) {
	for _, route := range routes {
		route.RLock()
		s := RouteStat{
			Name:      route.Name,
			Multipath: route.Cfg.Multipath,
		}

		var totalFailures int
		for _, nexthop := range route.Nexthops {
			// Check loss is not NaN
			loss := nexthop.Statistics.PacketLoss
			if math.IsNaN(loss) {
				loss = 0
			}
			n := NextHopStat{
				Gateway: nexthop.Name,
				Check:   nexthop.Cfg.Check,

				Operational:  nexthop.Operational,
				LastChange:   int(nexthop.LastChange.Unix()),
				SuccessCount: nexthop.SuccessCount,
				FailCount:    nexthop.FailCount,

				Interface:  nexthop.Cfg.Interface,
				SourceAddr: nexthop.Monitor.Source,
				Metric:     nexthop.Cfg.Metric + nexthop.Cfg.Weight, // One of the two

				PacketsRecv:           nexthop.Statistics.PacketsRecv,
				PacketsSent:           nexthop.Statistics.PacketsSent,
				PacketsRecvDuplicates: nexthop.Statistics.PacketsRecvDuplicates,
				PacketLoss:            loss,
				MinRtt:                config.Interval{Duration: nexthop.Statistics.MinRtt},
				MaxRtt:                config.Interval{Duration: nexthop.Statistics.MaxRtt},
				AvgRtt:                config.Interval{Duration: nexthop.Statistics.AvgRtt},
				StdDevRtt:             config.Interval{Duration: nexthop.Statistics.StdDevRtt},
				LastRTT:               config.Interval{Duration: nexthop.LastRTT},
			}
			if !nexthop.Operational {
				totalFailures++
			}
			s.NextHops = append(s.NextHops, n)
		}

		if totalFailures < len(route.Nexthops) {
			s.Operational = true
		}
		route.RUnlock()

		stats = append(stats, s)
	}

	return
}
