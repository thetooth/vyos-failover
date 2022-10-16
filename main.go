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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ping/ping"
	"github.com/thetooth/vyos-failover/config"
)

var (
	path       string
	statPath   string
	statChange chan StatEvent
)

type Route struct {
	Cfg config.Route

	Name string

	Nexthops []*NextHop
	lastArg  string
	mu       *sync.RWMutex
}

type NextHop struct {
	Cfg config.NextHop

	Name       string
	Statistics ping.Statistics
	Monitor    *ping.Pinger
	Failed     bool
}

type KV struct {
	Key   string
	Value config.NextHop
}

type StatEvent struct{}

type Statistics []RouteStat

type RouteStat struct {
	Route        string        `json:"route"`
	Failed       bool          `json:"failed"`
	SuccessCount int           `json:"success_count"`
	FailCount    int           `json:"fail_count"`
	NextHops     []NextHopStat `json:"next_hops"`
}

type NextHopStat struct {
	Gateway string       `json:"gateway"`
	Check   config.Check `json:"check"`

	PacketsRecv           int             `json:"packets_recv"`
	PacketsSent           int             `json:"packets_sent"`
	PacketsRecvDuplicates int             `json:"packets_recv_dup"`
	PacketLoss            float64         `json:"packet_loss"`
	MinRtt                config.Interval `json:"min_rtt"`
	MaxRtt                config.Interval `json:"max_rtt"`
	AvgRtt                config.Interval `json:"avg_rtt"`
	StdDevRtt             config.Interval `json:"std_dev_rtt"`
}

func main() {
	flag.StringVar(&path, "config", "/run/vyos-failover.conf", "Path to protocols failover configuration")
	flag.StringVar(&statPath, "socket", "/tmp/vyos-failover", "Path to statstics socket")
	flag.Parse()

	// Attempt configuration file load
	cfg, err := config.Load(path)
	if err != nil {
		panic(err)
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
			for routeName, route := range cfg.Route {
				fmt.Println("[ EXIT_CLEANUP ] route:", routeName)

				arg := fmt.Sprintf("route del %v proto failover table %v", routeName, route.Table)
				execute("ip", arg)
			}
			return
		case <-statChange: // Update stats everytime a check completes
			buildStatistics(routes)
		case <-flap.C: // Compute next routing table update
			for _, route := range routes {
				route.mu.Lock()
				availableNexthops := 0
				arg := fmt.Sprintf("route replace %v proto failover table %v", route.Name, route.Cfg.Table)

				for _, nexthop := range route.Nexthops {
					s := nexthop.Statistics

					// Consider target failed when thresholds exceeded or no packets have been sent due to misconfiguration
					if s.PacketLoss > nexthop.Cfg.Check.LossThreshold ||
						s.PacketsSent == 0 || s.AvgRtt > nexthop.Cfg.Check.RTTThreshold.Duration {
						if !nexthop.Failed {
							fmt.Println("[ TARGET_FAIL ] route:", route.Name, "nexthop:", nexthop.Name, "target:", nexthop.Cfg.Check.Target)
						}
						nexthop.Failed = true
					} else {
						availableNexthops++
						if nexthop.Failed {
							fmt.Println("[ TARGET_SUCCESS ] route:", route.Name, "nexthop:", nexthop.Name, "target:", nexthop.Cfg.Check.Target)
						}
						nexthop.Failed = false

						// When more than 1 nexthop is given assume the user wants to setup multipathing.
						// In this case the metric becomes the weight so it's meaning is inverted.
						if len(route.Nexthops) > 1 {
							arg += fmt.Sprintf(" nexthop via %v", nexthop.Name)
							if nexthop.Cfg.Interface != "" {
								arg += fmt.Sprintf(" dev %v", nexthop.Cfg.Interface)
							}
							arg += fmt.Sprintf(" weight %v", nexthop.Cfg.Metric)
						} else {
							arg += fmt.Sprintf(" via %v", nexthop.Name)
							if nexthop.Cfg.Interface != "" {
								arg += fmt.Sprintf(" dev %v", nexthop.Cfg.Interface)
							}
							arg += fmt.Sprintf(" metric %v", nexthop.Cfg.Metric)
						}
					}
				}

				// If no changes occured then skip
				if arg == route.lastArg {
					route.mu.Unlock()
					continue
				}

				if availableNexthops < 1 {
					fmt.Println("[ ROUTE_FAIL ] route:", route.Name)
					execute("ip", fmt.Sprintf("route del %v protocol failover table %v", route.Name, route.Cfg.Table))
				} else {
					fmt.Println("[ ROUTE_UPDATE ] route:", route.Name)
					_, _, err = execute("ip", arg)
					// On fault retry, usually means bad parameters from the user but, the link takes time to
					// settle which can cause a bad gateway message that will be corrected in due time.
					// Not doing this results in routes being incorrect until the next state change.
					if err != nil {
						route.mu.Unlock()
						continue
					}
				}
				route.lastArg = arg

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
			if nexthopKeys[i].Value.Metric == nexthopKeys[j].Value.Metric {
				a := net.ParseIP(nexthopKeys[i].Key)
				b := net.ParseIP(nexthopKeys[j].Key)
				return bytes.Compare(a, b) < 0
			}
			return nexthopKeys[i].Value.Metric < nexthopKeys[j].Value.Metric
		})

		// Build runtime nexthops table
		for _, nexthopKV := range nexthopKeys {
			newNextHop := NextHop{Cfg: cfg.Route[routeName].NextHop[nexthopKV.Key], Name: nexthopKV.Key}

			// Setup monitor
			pinger, err := ping.NewPinger(newNextHop.Cfg.Check.Target)
			if err != nil {
				panic(err)
			}
			newNextHop.Monitor = pinger
			pinger.SetLogger(ping.NoopLogger{})
			pinger.RecordRtts = false
			// Needs privileged mode due to VyOS not allowing user mode UDP sockets
			pinger.SetPrivileged(true)
			if newNextHop.Cfg.Interface != "" {
				pinger.Source, err = bindIface(newNextHop.Cfg.Interface, IsIPv6(newNextHop.Cfg.Check.Target))
				if err != nil {
					panic(err)
				}
			}
			pinger.Interval = newNextHop.Cfg.Check.Interval.Duration

			// Emit event and collect statistics everytime a packet is sent
			pinger.OnSend = func(pkt *ping.Packet) {
				newRoute.mu.Lock()
				newNextHop.Statistics = *pinger.Statistics()
				newRoute.mu.Unlock()
				statChange <- StatEvent{}
			}

			go func() {
				err = pinger.Run()
				if err != nil {
					panic(err)
				}
			}()

			newRoute.Nexthops = append(newRoute.Nexthops, &newNextHop)
		}

		routes = append(routes, &newRoute)
	}

	return
}

func buildStatistics(routes []*Route) (stats Statistics) {
	for _, route := range routes {
		route.mu.RLock()
		s := RouteStat{
			Route: route.Name,
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

				PacketsRecv:           nexthop.Statistics.PacketsRecv,
				PacketsSent:           nexthop.Statistics.PacketsSent,
				PacketsRecvDuplicates: nexthop.Statistics.PacketsRecvDuplicates,
				PacketLoss:            loss,
				MinRtt:                config.Interval{Duration: nexthop.Statistics.MinRtt},
				MaxRtt:                config.Interval{Duration: nexthop.Statistics.MaxRtt},
				AvgRtt:                config.Interval{Duration: nexthop.Statistics.AvgRtt},
				StdDevRtt:             config.Interval{Duration: nexthop.Statistics.StdDevRtt},
			}
			if nexthop.Failed {
				s.FailCount++
				totalFailures++
			} else {
				s.SuccessCount++
			}
			s.NextHops = append(s.NextHops, n)
		}

		if totalFailures >= len(route.Nexthops) {
			s.Failed = true
		}
		route.mu.RUnlock()

		stats = append(stats, s)
	}

	b, err := json.Marshal(stats)
	if err != nil {
		panic(err)
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
	cmd := exec.Command(command, strings.Split(args, " ")...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err = cmd.Run()
	stdout = outb.String()
	stderr = errb.String()

	return
}
