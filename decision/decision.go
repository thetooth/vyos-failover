package decision

import (
	"fmt"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/thetooth/vyos-failover/util"
)

func Compute(routes []*Route) (err error) {
	for _, route := range routes {
		route.Lock()

		op := []string{}

		if route.Cfg.Multipath {
			availableNexthops := 0
			bestWeight := 0

			op = append(op, fmt.Sprintf("route replace %v proto failover table %v", route.Name, route.Cfg.Table))

			for _, nexthop := range route.Nexthops {
				if nexthop.IsUp(route.Name) {
					availableNexthops++
					if route.Cfg.DropLowerWeight && bestWeight != 0 && nexthop.Cfg.Weight < bestWeight {
						continue
					}
					bestWeight = nexthop.Cfg.Weight
					op[0] += fmt.Sprintf(" nexthop via %v", nexthop.Name)
					if nexthop.Cfg.Interface != "" {
						op[0] += fmt.Sprintf(" dev %v", nexthop.Cfg.Interface)
					}
					op[0] += fmt.Sprintf(" weight %v", nexthop.Cfg.Weight)
				}
			}

			if availableNexthops < 1 {
				op[0] = fmt.Sprintf("route del %v protocol failover table %v", route.Name, route.Cfg.Table)
			}
		} else {
			for opIdx, nexthop := range route.Nexthops {
				op = append(op, fmt.Sprintf("route replace %v proto failover table %v", route.Name, route.Cfg.Table))
				if nexthop.IsUp(route.Name) {
					op[opIdx] += fmt.Sprintf(" via %v", nexthop.Name)
					if nexthop.Cfg.Interface != "" {
						op[opIdx] += fmt.Sprintf(" dev %v", nexthop.Cfg.Interface)
					}
					op[opIdx] += fmt.Sprintf(" metric %v", nexthop.Cfg.Metric)
				} else {
					op[opIdx] = fmt.Sprintf("route del %v proto failover table %v", route.Name, route.Cfg.Table)
					op[opIdx] += fmt.Sprintf(" metric %v", nexthop.Cfg.Metric)
				}
			}
		}

		// If no changes occurred then skip
		if reflect.DeepEqual(op, route.lastOp) {
			route.Unlock()
			continue
		}

		logrus.Info("[ ROUTE_UPDATE ] route: ", route.Name)
		for _, arg := range op {
			var stderr string
			_, stderr, err = util.Exec("ip", arg)
			if err != nil {
				logrus.Trace("Failed to update route, check configuration for errors")
				logrus.Trace(stderr)
			}
		}

		route.lastOp = op
		route.Unlock()
	}

	return
}

func (n *NextHop) IsUp(route string) bool {
	if err := n.Respawn(); err != nil {
		if n.Operational {
			logrus.Warn("[ TARGET_FAIL ] No address")
			n.LastChange = time.Now()
			n.FailCount++
		}
		n.Operational = false
		return false
	}
	if n.Statistics.PacketLoss > n.Cfg.Check.LossThreshold || n.Statistics.AvgRtt > n.Cfg.Check.RTTThreshold.Duration {
		if n.Operational {
			logrus.Warn("[ TARGET_FAIL ] route: ", route, " nexthop: ", n.Name, " target: ", n.Cfg.Check.Target)
			n.LastChange = time.Now()
			n.FailCount++
		}
		n.Operational = false
		return false
	}

	if !n.Operational {
		logrus.Info("[ TARGET_SUCCESS ] route: ", route, " nexthop: ", n.Name, " target: ", n.Cfg.Check.Target)
		n.LastChange = time.Now()
		n.SuccessCount++
	}
	n.Operational = true

	return true
}
