package config_test

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/thetooth/vyos-failover/config"
)

func TestInterval(t *testing.T) {
	expectedInterval := config.Interval{Duration: 1 * time.Second}
	expected := []byte(`"1s"`)

	b, err := expectedInterval.MarshalJSON()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(b, expected) {
		t.Error("Encoded interval does not match expected value")
	}

	n := config.Interval{}
	err = n.UnmarshalJSON(expected)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(n, expectedInterval) {
		t.Error("Decoded interval does not match expected value")
	}
}

func TestLoad(t *testing.T) {
	expectedConfig := config.Config{
		Route: map[string]config.Route{
			"203.0.113.0/24": {
				Table:           "main",
				VRF:             "default",
				UCMP:            true,
				DropLowerWeight: true,
				NextHop: map[string]config.NextHop{
					"10.0.16.1": {
						Check: config.Check{
							Target:        "1.1.1.1",
							Interval:      config.Interval{Duration: 1 * time.Second},
							RTTThreshold:  config.Interval{Duration: 250 * time.Millisecond},
							LossThreshold: 5,
						},
						Interface: "eth0",
						Weight:    10,
					},
				},
			},
		},
		FlapRate: config.Interval{Duration: 1 * time.Second},
	}
	cfg, err := config.Load("test.conf")
	if err != nil {
		t.Error(err)
	}

	if cfg.FlapRate != expectedConfig.FlapRate {
		t.Error("Loaded configuration does not match expected")
	}
	for routeName, route := range expectedConfig.Route {
		if !reflect.DeepEqual(cfg.Route[routeName], route) {
			t.Error("Loaded configuration does not match expected")
		}
	}
}
