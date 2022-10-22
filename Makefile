.PHONY: build

all: build

build:
	CGO_ENABLED=0 go build -o vyos-failover main.go

test-stats:
	watch -n 1 'cat /tmp/vyos-failover | jq'

test-routes:
	watch -n 0.5 'ip route list protocol failover && ip route list protocol failover table 10 && ip -6 route list protocol failover && ip -6 route list protocol failover table 10'

test-deploy:
	scp vyos-failover vyos@10.0.16.1:vyos-failover
	scp vyos-test.json vyos@10.0.16.1:vyos-test.json
	scp show_failover.py vyos@10.0.16.1:show_failover.py
