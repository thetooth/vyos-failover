package decision

import (
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
	LastRTT      time.Duration
	Check        check.Check
}

// IsUp ensures that a target has a valid source address, and it's packet loss and average RTT is below
// the configured threshold
func (n *NextHop) IsUp(route string) bool {
	if err := n.Bind(); err != nil {
		if n.Operational {
			logrus.Warn("[ TARGET_FAIL ] No address, is the interface up?")
			n.LastChange = time.Now()
			n.FailCount++
		}
		n.Operational = false
		return false
	}

	s := n.Check.Statistics()
	if s.PacketLoss > n.Cfg.Check.LossThreshold || s.AvgRtt > n.Cfg.Check.RTTThreshold.Duration {
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
		n.Check.SetTarget("???")
		return
	}

	if n.Check.Target() != nSrc {
		n.Check.Stop()
		n.Check.SetTarget(nSrc)
		go func() {
			err = n.Check.Run()
			if err != nil {
				logrus.Panic(err)
			}
		}()
	}

	return
}
