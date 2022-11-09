package check

import (
	"context"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

func NewHTTPer(addr string) (*HTTPer, error) {
	t := &HTTPer{
		done: make(chan interface{}),
		lock: sync.Mutex{},
	}
	t.SetTarget(addr)
	return t, t.Resolve()
}

type HTTPer struct {
	Interval    time.Duration
	PacketsSent int
	PacketsRecv int

	done chan interface{}
	lock sync.Mutex

	addr       string
	srcAddr    string
	tcpSrcAddr *net.TCPAddr

	// Round trip time statistics
	LatestRTT time.Duration
	minRtt    time.Duration
	maxRtt    time.Duration
	avgRtt    time.Duration
	stdDevRtt time.Duration
	stddevm2  time.Duration
	statsMu   sync.RWMutex
}

func (p *HTTPer) Run() (err error) {
	var g errgroup.Group

	g.Go(func() error {
		defer p.Stop()
		return p.runLoop()
	})

	p.done = make(chan interface{})
	return g.Wait()
}

func (t *HTTPer) runLoop() (err error) {
	interval := time.NewTicker(t.Interval)
	defer func() {
		interval.Stop()
	}()

	for {
		select {
		case <-t.done:
			err = nil
			return

		case <-interval.C:
			t.statsMu.Lock()
			t.PacketsSent++
			t.statsMu.Unlock()
			var receiveTime time.Time
			start := time.Now()

			dialer := &net.Dialer{LocalAddr: t.tcpSrcAddr}

			dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialer.Dial(network, addr)
				return conn, err
			}

			transport := &http.Transport{DialContext: dialContext}
			client := http.Client{
				Transport: transport,
				Timeout:   t.Interval,
			}

			resp, err := client.Get(t.addr)
			if err != nil {
				return err
			}
			resp.Body.Close()
			receiveTime = time.Now()
			rtt := receiveTime.Sub(start)
			if rtt < 0 {
				continue
			}
			t.updateStatistics(rtt)
		}
	}
}

func (p *HTTPer) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()

	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

func (p *HTTPer) Statistics() *Statistics {
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()
	sent := p.PacketsSent
	loss := float64(sent-p.PacketsRecv) / float64(sent) * 100
	s := Statistics{
		PacketsSent: sent,
		PacketsRecv: p.PacketsRecv,
		PacketLoss:  loss,
		Addr:        p.addr,
		LatestRTT:   p.LatestRTT,
		MaxRtt:      p.maxRtt,
		MinRtt:      p.minRtt,
		AvgRtt:      p.avgRtt,
		StdDevRtt:   p.stdDevRtt,
	}
	return &s
}

func (p *HTTPer) updateStatistics(rtt time.Duration) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()

	p.LatestRTT = rtt
	p.PacketsRecv++

	if p.PacketsRecv == 1 || rtt < p.minRtt {
		p.minRtt = rtt
	}

	if rtt > p.maxRtt {
		p.maxRtt = rtt
	}

	pktCount := time.Duration(p.PacketsRecv)
	// welford's online method for stddev
	// https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
	delta := rtt - p.avgRtt
	p.avgRtt += delta / pktCount
	delta2 := rtt - p.avgRtt
	p.stddevm2 += delta * delta2

	p.stdDevRtt = time.Duration(math.Sqrt(float64(p.stddevm2 / pktCount)))
}

func (t *HTTPer) Resolve() (err error) {
	t.tcpSrcAddr, err = net.ResolveTCPAddr("tcp", t.srcAddr+":0") // Sneak in the random port here
	if err != nil {
		return
	}

	return
}

func (p *HTTPer) SetTarget(addr string) error {
	p.addr = addr
	return nil
}

// Addr returns the string ip address of the target host.
func (p *HTTPer) Target() string {
	return p.addr
}

func (p *HTTPer) SetSource(addr string) error {
	oldAddr := p.srcAddr
	p.srcAddr = addr
	err := p.Resolve()
	if err != nil {
		p.srcAddr = oldAddr
		return err
	}

	return nil
}

func (p *HTTPer) Source() string {
	return p.srcAddr
}
