package config

import (
	"encoding/json"
	"io/ioutil"
	"time"
)

func Load(path string) (cfg *Config, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return
	}

	return
}

type Config struct {
	Route    map[string]Route `json:"route"`
	FlapRate Interval         `json:"flap_rate"`
}

type Route struct {
	Table           string             `json:"table"`
	VRF             string             `json:"vrf"`
	Multipath       bool               `json:"multipath"`
	DropLowerWeight bool               `json:"drop_lower_weight"`
	NextHop         map[string]NextHop `json:"next_hop"`
}

type NextHop struct {
	Interface string `json:"interface"`
	Metric    int    `json:"metric"`
	Weight    int    `json:"weight"`
	Check     Check  `json:"check"`
}

type Check struct {
	Target        string   `json:"target"`
	Interval      Interval `json:"interval"`
	RTTThreshold  Interval `json:"rtt_threshold"`
	LossThreshold float64  `json:"loss_threshold"`
}

type Interval struct {
	time.Duration
}

func (d *Interval) UnmarshalJSON(data []byte) (err error) {
	var pstr string
	err = json.Unmarshal(data, &pstr)
	if err != nil {
		return err
	}
	d.Duration, err = time.ParseDuration(pstr)
	return
}

func (d *Interval) MarshalJSON() (data []byte, err error) {
	s := d.Duration.String()
	data, err = json.Marshal(s)
	return
}
