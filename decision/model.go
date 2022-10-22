package decision

import (
	"bytes"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/thetooth/vyos-failover/config"
	"github.com/thetooth/vyos-failover/ping"
	"github.com/thetooth/vyos-failover/util"
)

func New(cfg *config.Config) (routes []*Route) {
	for routeName, routeConfig := range cfg.Route {
		newRoute := Route{Cfg: routeConfig, Name: routeName, RWMutex: &sync.RWMutex{}}

		// Build runtime nexthops table
		for nexthopName, nexthopConfig := range routeConfig.NextHop {
			newNextHop := NextHop{Cfg: nexthopConfig, Name: nexthopName, LastChange: time.Now()}

			// Setup monitor
			pinger, err := ping.NewPinger(newNextHop.Cfg.Check.Target)
			if err != nil {
				logrus.Panic(err)
			}
			newNextHop.Monitor = pinger
			pinger.RecordRtts = false
			// Needs privileged mode due to VyOS not allowing user mode UDP sockets
			// pinger.SetPrivileged(true)
			pinger.Interval = newNextHop.Cfg.Check.Interval.Duration

			// Collect statistics every time a packet is sent
			pinger.OnSend = func(pkt *ping.Packet) {
				newRoute.Lock()
				newNextHop.Statistics = *pinger.Statistics()
				newRoute.Unlock()
			}
			pinger.OnRecv = func(pkt *ping.Packet) {
				newRoute.Lock()
				newNextHop.LastRTT = pkt.Rtt
				newRoute.Unlock()
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

type Route struct {
	*sync.RWMutex
	Cfg config.Route

	Name string

	Nexthops []*NextHop
	lastOp   []string
}

type NextHop struct {
	Cfg config.NextHop

	Name       string
	Statistics ping.Statistics
	Monitor    *ping.Pinger

	Operational  bool
	FailCount    int
	SuccessCount int
	LastChange   time.Time
	LastRTT      time.Duration
}

func (n *NextHop) Respawn() (err error) {
	nSrc, err := util.BindIface(n.Cfg.Interface, util.IsIPv6(n.Cfg.Check.Target))
	if err != nil {
		n.Monitor.Stop()
		n.Monitor.Source = "???"
		return
	}
	if n.Monitor.Source != nSrc {
		n.Monitor.Stop()
		n.Monitor.Source = nSrc
		go func() {
			err = n.Monitor.Run()
			if err != nil {
				logrus.Panic(err)
			}
		}()
	}

	return
}
