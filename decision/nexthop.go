package decision

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/thetooth/vyos-failover/check"
	"github.com/thetooth/vyos-failover/config"
	"github.com/thetooth/vyos-failover/util"
)

// NextHop is a composite type building off the ICMP pinger and configuration
type NextHop struct {
	Cfg config.NextHop

	Name         string
	Operational  bool
	FailCount    int
	SuccessCount int
	LastChange   time.Time
	Check        check.Check
	CheckFault   string

	checkRunning bool
}

// IsUp ensures that a target has a valid source address, and it's packet loss and average RTT is below
// the configured threshold
func (n *NextHop) IsUp(route string) bool {
	if err := n.Bind(); err != nil {
		n.CheckFault = fmt.Sprintf("Could not bind address on %v: %v", n.Cfg.Interface, err)
		if n.Operational {
			logrus.Warn("[ TARGET_FAIL ] ", err, ", route: ", route, " nexthop: ", n.Name, " target: ", n.Cfg.Check.Target)
			n.LastChange = time.Now()
			n.FailCount++
		}
		n.Operational = false
		return false
	}

	if !n.checkRunning {
		if n.Operational {
			logrus.Warn("[ TARGET_FAIL ] Check is not running, route: ", route, " nexthop: ", n.Name, " target: ", n.Cfg.Check.Target)
			n.LastChange = time.Now()
			n.FailCount++
		}
		n.Operational = false
		return false
	}

	s := n.Check.Statistics()
	if s.PacketLoss > n.Cfg.Check.LossThreshold || s.AvgRtt > n.Cfg.Check.RTTThreshold.Duration {
		if s.PacketLoss > n.Cfg.Check.LossThreshold {
			n.CheckFault = "Packet loss exceeds threshold"
		} else if s.AvgRtt > n.Cfg.Check.RTTThreshold.Duration {
			n.CheckFault = "Average RTT exceeds threshold"
		}
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

// Bind wraps Pinger.Run and tries to ensure a valid address is always available before starting
func (n *NextHop) Bind() (err error) {
	nSrc, err := util.BindIface(n.Cfg.Interface, util.IsIPv6(n.Cfg.Check.Target))
	if err != nil {
		n.Check.Stop()
		n.Check.SetSource("???")
		return
	}

	if n.Check.Source() != nSrc || !n.checkRunning {
		n.Check.Stop()
		err = n.Check.SetSource(nSrc)
		if err != nil {
			logrus.Panic(err)
		}
		go func() {
			n.checkRunning = true
			defer func() { n.checkRunning = false }()

			// Introduce clock skew to evaluation, this helps prevent errantly reporting loss of in flight packets that
			// otherwise succeed. The issue here is that all checks are started at roughly the same time, so they are
			// all sending at the point of evaluation.
			// The skew is chosen to avoid landing on multiples 1s, since that's the most likely set of values humans
			// will go for.
			min := float64(n.Cfg.Check.Interval.Duration/2) * 0.1337
			max := rand.Float64() * float64(n.Cfg.Check.Interval.Duration/2) * 0.1337
			time.Sleep(time.Duration(min) + time.Duration(max))

			err = n.Check.Run()
			if err != nil {
				if n.Operational {
					logrus.Warn("[ CHECK_FAIL ] ", err, " nexthop: ", n.Name, " target: ", n.Cfg.Check.Target)
				}
				n.CheckFault = err.Error()
			}
		}()
	}

	return
}
