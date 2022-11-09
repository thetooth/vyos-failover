package decision

import (
	"bytes"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/thetooth/vyos-failover/check"
	"github.com/thetooth/vyos-failover/config"
)

// Route is a composite type containing configuration and current runtime states
type Route struct {
	*sync.RWMutex
	Cfg config.Route

	Name string

	Nexthops []*NextHop
	lastOp   []string
}

// BuildRoutes takes in the unmarshalled configuration and initializes and sorts a list of routes for control
func BuildRoutes(cfg *config.Config) (routes []*Route) {
	for routeName, routeConfig := range cfg.Route {
		if routeConfig.VRF == "" {
			routeConfig.VRF = "default"
		}
		if routeConfig.Table == "" {
			routeConfig.Table = "main"
		}
		newRoute := Route{Cfg: routeConfig, Name: routeName, RWMutex: &sync.RWMutex{}}

		// Build runtime nexthops table
		for nexthopName, nexthopConfig := range routeConfig.NextHop {
			newNextHop := NextHop{Cfg: nexthopConfig, Name: nexthopName, LastChange: time.Now(), Operational: true}

			// Set up monitor
			switch newNextHop.Cfg.Check.Kind {
			case "icmp", "udp":
				pinger, err := check.NewPinger(newNextHop.Cfg.Check.Target)
				if err != nil {
					logrus.Fatal("Unable to load configuration: ", err)
				}
				newNextHop.Check = pinger
				pinger.RecordRtts = false
				// Needs privileged mode due to VyOS not allowing user mode UDP sockets,
				// but ICMP mode won't work if multiple checks have the same target...
				if newNextHop.Cfg.Check.Kind == "icmp" {
					// pinger.SetPrivileged(true)
				}
				pinger.Interval = newNextHop.Cfg.Check.Interval.Duration
			case "tcp":
				tcper, err := check.NewTCPer(newNextHop.Cfg.Check.Target)
				if err != nil {
					logrus.Fatal("Unable to load configuration: ", err)
				}
				newNextHop.Check = tcper
				tcper.Interval = newNextHop.Cfg.Check.Interval.Duration
			case "http":
				httper, err := check.NewHTTPer(newNextHop.Cfg.Check.Target)
				if err != nil {
					logrus.Fatal("Unable to load configuration: ", err)
				}
				newNextHop.Check = httper
				httper.Interval = newNextHop.Cfg.Check.Interval.Duration
			default:
				logrus.Fatal("Unsupported check type: ", newNextHop.Cfg.Check.Kind)
			}

			newRoute.Nexthops = append(newRoute.Nexthops, &newNextHop)
		}

		// Sort nexthops by metric, then by IP
		sort.Slice(newRoute.Nexthops, func(i, j int) bool {
			im := newRoute.Nexthops[i].Cfg.Metric + newRoute.Nexthops[i].Cfg.Weight
			jm := newRoute.Nexthops[j].Cfg.Metric + newRoute.Nexthops[j].Cfg.Weight
			if im != jm {
				in := net.ParseIP(newRoute.Nexthops[i].Name)
				jn := net.ParseIP(newRoute.Nexthops[j].Name)
				return bytes.Compare(in, jn) < 0
			}
			return im < jm
		})

		routes = append(routes, &newRoute)
	}

	// Sort routes by IP
	sort.Slice(routes, func(i, j int) bool {
		in := net.ParseIP(routes[i].Name)
		jn := net.ParseIP(routes[j].Name)
		return bytes.Compare(in, jn) < 0
	})

	return
}
