package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/thetooth/vyos-failover/config"
	"github.com/thetooth/vyos-failover/decision"
	"github.com/thetooth/vyos-failover/statistics"
	"github.com/thetooth/vyos-failover/util"
)

var (
	debug, trace bool
	path         string
	statPath     string
)

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
	flap := time.NewTicker(cfg.FlapRate.Duration)

	// Build runtime route table
	routes := decision.BuildRoutes(cfg)

	for {
		select {
		case <-c: // Clean up and quit
			for routeName, route := range cfg.Route {
				fmt.Println("[ EXIT_CLEANUP ] route: ", routeName)

				arg := fmt.Sprintf("route del %v proto failover table %v", routeName, route.Table)
				util.Exec("ip", arg)
			}
			return
		case <-flap.C:
			// Compute next routing table
			err = decision.Evaluate(routes)
			if err != nil {
				logrus.Debug("Issue computing routes: ", err)
			}

			// Update and output statistics
			stats := statistics.Build(routes)
			b, err := json.Marshal(stats)
			if err != nil {
				logrus.Panic(err)
			}

			err = ioutil.WriteFile(statPath, b, 0644)
			if err != nil {
				logrus.Panic(err)
			}
		}
	}
}
