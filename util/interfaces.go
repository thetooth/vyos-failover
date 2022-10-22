package util

import (
	"errors"
	"net"
	"strings"
)

func BindIface(ifaceName string, ipv6 bool) (addr string, err error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return
	}
	if !IsUp(iface) {
		err = errors.New("Interface is down")
		return
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		if ipv6 && !IsIPv6(ip.String()) {
			continue
		}
		addr = ip.String()
		if strings.HasPrefix(addr, "fe80::") { // Prefer global addresses
			continue
		}
		break
	}
	if addr == "" {
		err = errors.New("Interface has no addresses")
	}

	return
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func IsUp(nif *net.Interface) bool { return nif.Flags&net.FlagUp != 0 }
