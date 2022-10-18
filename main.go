package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ping/ping"
	"github.com/sirupsen/logrus"
	"github.com/thetooth/vyos-failover/config"
)

var (
	debug, trace bool
	path         string
	statPath     string
	statChange   chan StatEvent
)

type Route struct {
	mu  *sync.RWMutex
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

type KV struct {
	Key   string
	Value config.NextHop
}

func main() {
	flag.BoolVar(&debug, "debug", false, "Show additional output")
	flag.BoolVar(&trace, "trace", false, "Show A LOT of output")
	flag.StringVar(&path, "config", "/run/vyos-failover.conf", "Path to protocols failover configuration")
	flag.StringVar(&statPath, "socket", "/tmp/vyos-failover", "Path to statstics socket")
	flag.Parse()

	if trace {
		logrus.SetLevel(logrus.TraceLevel)
		logrus.SetReportCaller(true)
	} else if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// Attempt configuration file load
	cfg, err := config.Load(path)
	if err != nil {
		logrus.Panic(err)
	}

	// Control signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	statChange = make(chan StatEvent, 1)
	flap := time.NewTicker(cfg.FlapRate.Duration)

	// Build runtime route table
	routes := buildRuntime(cfg)

	for {
		select {
		case <-c: // Clean up and quit
			execute("ip", "route flush proto failover")
			return
		case <-statChange: // Update stats every time a check completes
			buildStatistics(routes)
		case <-flap.C: // Compute next routing table update
			for _, route := range routes {
				route.mu.Lock()
				availableNexthops := 0
				bestWeight := 0
				op := []string{}

				for nIdx, nexthop := range route.Nexthops {
					opID := nIdx
					// When adding a multipath route do it in a single command, opID is always zero and we prefix
					// with `route replace` on the first hop defined.
					if route.Cfg.Multipath {
						if nIdx == 0 {
							op = append(op, fmt.Sprintf("route replace %v proto failover table %v", route.Name, route.Cfg.Table))
						}
						opID = 0
					} else {
						op = append(op, fmt.Sprintf("route add %v proto failover table %v", route.Name, route.Cfg.Table))
					}

					s := nexthop.Statistics

					// Consider target failed when thresholds exceeded or no packets have been sent due to misconfiguration
					if s.PacketLoss > nexthop.Cfg.Check.LossThreshold ||
						s.PacketsSent == 0 || s.AvgRtt > nexthop.Cfg.Check.RTTThreshold.Duration {
						if nexthop.Operational {
							logrus.Warn("[ TARGET_FAIL ] route:", route.Name, "nexthop:", nexthop.Name, "target:", nexthop.Cfg.Check.Target)
							nexthop.LastChange = time.Now()
							nexthop.FailCount++
						}
						nexthop.Operational = false
					} else {
						availableNexthops++
						if !nexthop.Operational {
							logrus.Info("[ TARGET_SUCCESS ] route:", route.Name, "nexthop:", nexthop.Name, "target:", nexthop.Cfg.Check.Target)
							nexthop.LastChange = time.Now()
							nexthop.SuccessCount++
						}
						nexthop.Operational = true

						if route.Cfg.Multipath {
							if route.Cfg.DropLowerWeight && bestWeight != 0 && nexthop.Cfg.Weight < bestWeight {
								continue
							}
							bestWeight = nexthop.Cfg.Weight
							op[opID] += fmt.Sprintf(" nexthop via %v", nexthop.Name)
							if nexthop.Cfg.Interface != "" {
								op[opID] += fmt.Sprintf(" dev %v", nexthop.Cfg.Interface)
							}
							op[opID] += fmt.Sprintf(" weight %v", nexthop.Cfg.Weight)
						} else {
							op[opID] += fmt.Sprintf(" via %v", nexthop.Name)
							if nexthop.Cfg.Interface != "" {
								op[opID] += fmt.Sprintf(" dev %v", nexthop.Cfg.Interface)
							}
							op[opID] += fmt.Sprintf(" metric %v", nexthop.Cfg.Metric)
						}
					}
				}

				// If no changes occurred then skip
				if reflect.DeepEqual(op, route.lastOp) {
					route.mu.Unlock()
					continue
				}

				if availableNexthops < 1 {
					logrus.Warn("[ ROUTE_FAIL ] route:", route.Name)
					var stderr string
					_, stderr, err = execute("ip", fmt.Sprintf("route del %v protocol failover table %v", route.Name, route.Cfg.Table))
					if err != nil {
						logrus.Error("Failed to destroy route, check configuration for errors")
						logrus.Debug(stderr)
					}
				} else {
					logrus.Info("[ ROUTE_UPDATE ] route:", route.Name)
					for _, arg := range op {
						var stderr string
						_, stderr, err = execute("ip", arg)
						// On fault retry, usually means bad parameters from the user but, the link takes time to
						// settle which can cause a bad gateway message that will be corrected in due time.
						// Not doing this results in routes being incorrect until the next state change.
						if err != nil {
							logrus.Error("Failed to update route, check configuration for errors")
							logrus.Debug(stderr)
							break
						}
					}
				}
				if err != nil {
					logrus.Debug("Did not apply last route, will retry in ", cfg.FlapRate)
				} else {
					logrus.Trace("Sync FSM")
					route.lastOp = op
				}

				route.mu.Unlock()
			}
		}
	}
}

func buildRuntime(cfg *config.Config) (routes []*Route) {
	routeKeys := []string{}
	for k := range cfg.Route {
		routeKeys = append(routeKeys, k)
	}
	sort.Strings(routeKeys)

	for _, routeName := range routeKeys {
		newRoute := Route{Cfg: cfg.Route[routeName], Name: routeName, mu: &sync.RWMutex{}}

		// Sort nexthops by metric, then by IP
		nexthopKeys := make([]KV, 0, len(cfg.Route[routeName].NextHop))
		for key, value := range cfg.Route[routeName].NextHop {
			nexthopKeys = append(nexthopKeys, KV{key, value})
		}
		sort.Slice(nexthopKeys, func(i, j int) bool {
			im := nexthopKeys[i].Value.Metric + nexthopKeys[i].Value.Weight
			jm := nexthopKeys[j].Value.Metric + nexthopKeys[j].Value.Weight
			if im != jm {
				in := net.ParseIP(nexthopKeys[i].Key)
				jn := net.ParseIP(nexthopKeys[j].Key)
				return bytes.Compare(in, jn) < 0
			}
			return im < jm
		})

		// Build runtime nexthops table
		for _, nexthopKV := range nexthopKeys {
			newNextHop := NextHop{Cfg: cfg.Route[routeName].NextHop[nexthopKV.Key], Name: nexthopKV.Key, LastChange: time.Now()}

			// Setup monitor
			pinger, err := ping.NewPinger(newNextHop.Cfg.Check.Target)
			if err != nil {
				logrus.Panic(err)
			}
			newNextHop.Monitor = pinger
			if !trace {
				pinger.SetLogger(ping.NoopLogger{})
			}
			pinger.RecordRtts = false
			// Needs privileged mode due to VyOS not allowing user mode UDP sockets
			pinger.SetPrivileged(true)
			if newNextHop.Cfg.Interface != "" {
				pinger.Source, err = bindIface(newNextHop.Cfg.Interface, IsIPv6(newNextHop.Cfg.Check.Target))
				if err != nil {
					logrus.Panic(err)
				}
			}
			pinger.Interval = newNextHop.Cfg.Check.Interval.Duration

			// Emit event and collect statistics every time a packet is sent
			pinger.OnSend = func(pkt *ping.Packet) {
				newRoute.mu.Lock()
				newNextHop.Statistics = *pinger.Statistics()
				newRoute.mu.Unlock()
				statChange <- StatEvent{}
			}
			pinger.OnRecv = func(pkt *ping.Packet) {
				newRoute.mu.Lock()
				newNextHop.LastRTT = pkt.Rtt
				newRoute.mu.Unlock()
			}

			go func() {
				err = pinger.Run()
				if err != nil {
					logrus.Panic(err)
				}
			}()

			newRoute.Nexthops = append(newRoute.Nexthops, &newNextHop)
		}

		routes = append(routes, &newRoute)
	}

	return
}

type StatEvent struct{}

type Statistics []RouteStat

type RouteStat struct {
	Route       string        `json:"route"`
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

func buildStatistics(routes []*Route) (stats Statistics) {
	for _, route := range routes {
		route.mu.RLock()
		s := RouteStat{
			Route:     route.Name,
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
				Check:   *nexthop.Cfg.Check,

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
		route.mu.RUnlock()

		stats = append(stats, s)
	}

	b, err := json.Marshal(stats)
	if err != nil {
		logrus.Panic(err)
	}

	ioutil.WriteFile(statPath, b, 0644)

	return
}

func bindIface(ifaceName string, ipv6 bool) (addr string, err error) {
	inet := "inet"
	if ipv6 {
		inet = "inet6"
	}
	t, _, err := execute("ip", fmt.Sprintf("--json -f %v addr show %v", inet, ifaceName))
	if err != nil {
		return
	}
	res := []struct {
		AddressInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}{}
	err = json.Unmarshal([]byte(t), &res)
	if err != nil {
		return
	}

	if len(res) < 1 || len(res[0].AddressInfo) < 1 {
		err = errors.New(fmt.Sprintf("interface %s don't have an IP address\n", ifaceName))
		return
	}

	for _, addrInfo := range res[0].AddressInfo {
		addr = addrInfo.Local
		if strings.HasPrefix(addr, "fe80::") { // Prefer global addresses
			continue
		}
		break
	}

	return
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func execute(command string, args string) (stdout, stderr string, err error) {
	logrus.Tracef("EXEC: %v %v", command, args)

	cmd := exec.Command(command, strings.Split(args, " ")...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err = cmd.Run()
	stdout = outb.String()
	stderr = errb.String()

	return
}
