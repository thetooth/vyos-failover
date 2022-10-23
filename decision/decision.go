package decision

import (
	"fmt"
	"reflect"

	"github.com/sirupsen/logrus"
	"github.com/thetooth/vyos-failover/util"
)

// Evaluate compares each routes next-hop, if none are passing the route is removed
func Evaluate(routes []*Route) (err error) {
	for _, route := range routes {
		route.Lock()

		op := []string{}

		// When multipath is enabled build a single replace command with all of the available targets.
		// If DropLowerWeight is also enabled then next-hops with weights less than the first operational
		// target are not included.
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

			// If none of the targets are alive we will delete the route entry
			if availableNexthops < 1 {
				op[0] = fmt.Sprintf("route del %v protocol failover table %v", route.Name, route.Cfg.Table)
			}
		} else {
			// For regular metric driven next-hops, append a replace command for each next-hop, replacing
			// with delete when a given target is down
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

		// If no changes occurred then skip actually executing the command
		if reflect.DeepEqual(op, route.lastOp) {
			route.Unlock()
			continue
		}

		logrus.Info("[ ROUTE_UPDATE ] route: ", route.Name)
		for _, arg := range op {
			var stderr string
			_, stderr, err = util.Exec("ip", arg)
			if err != nil {
				logrus.Debug("Failed to update route: ", stderr)
			}
		}

		route.lastOp = op
		route.Unlock()
	}

	return
}
