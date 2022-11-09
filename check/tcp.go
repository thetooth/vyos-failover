package check

import (
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

func NewTCPer(addr string) (*TCPer, error) {
	t := &TCPer{
		done: make(chan interface{}),
		lock: sync.Mutex{},
	}
	t.SetTarget(addr)
	return t, t.Resolve()
}

type TCPer struct {
	Interval    time.Duration
	PacketsSent int
	PacketsRecv int

	done chan interface{}
	lock sync.Mutex

	addr       string
	srcAddr    string
	tcpAddr    *net.TCPAddr
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

func (p *TCPer) Run() (err error) {
	var g errgroup.Group

	g.Go(func() error {
		defer p.Stop()
		return p.runLoop()
	})

	p.done = make(chan interface{})
	return g.Wait()
}

func (t *TCPer) runLoop() (err error) {
	var conn *net.TCPConn
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
			if conn == nil {
				conn, err = net.DialTCP("tcp", nil, t.tcpAddr)
				if err != nil {
					return
				}
			}

			err = t.sendTCP(conn)
			if err != nil {
				if err != io.EOF {
					logrus.Trace("Could not send TCP: ", err)
				}
				conn.Close()
				return
			}
		}
	}
}

func (t *TCPer) sendTCP(conn *net.TCPConn) (err error) {
	if conn == nil {
		return
	}

	t.statsMu.Lock()
	t.PacketsSent++
	t.statsMu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)

	var receiveTime time.Time

	go func() {
		defer wg.Done()

		buf := make([]byte, 1024)
		for {
			conn.SetDeadline(time.Now().Add(t.Interval))
			var n int
			n, err = conn.Read(buf)
			if err != nil || n > 0 {
				if err != nil && err != io.EOF {
					logrus.Error(err)
					return
				}
				receiveTime = time.Now()
				return
			}
		}
	}()

	start := time.Now()
	conn.SetWriteDeadline(time.Now().Add(t.Interval))
	_, err = conn.Write([]byte(`GET / HTTP/1.1\r\n`))
	if err != nil {
		logrus.Error(err)
		return
	}

	wg.Wait()

	if err == nil || err == io.EOF {
		rtt := receiveTime.Sub(start)
		if rtt < 0 {
			return
		}
		t.updateStatistics(rtt)
	}

	return
}

func (p *TCPer) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()

	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

func (p *TCPer) Statistics() *Statistics {
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

func (p *TCPer) updateStatistics(rtt time.Duration) {
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

func (t *TCPer) Resolve() (err error) {
	t.tcpAddr, err = net.ResolveTCPAddr("tcp", t.addr)
	if err != nil {
		return
	}
	t.tcpSrcAddr, err = net.ResolveTCPAddr("tcp", t.srcAddr+":0") // Sneak in the random port here
	if err != nil {
		return
	}

	return
}

// SetTarget resolves and sets the ip address of the target host, addr can be a
// DNS name like "www.google.com" or IP like "127.0.0.1".
func (p *TCPer) SetTarget(addr string) error {
	oldAddr := p.addr
	p.addr = addr
	err := p.Resolve()
	if err != nil {
		p.addr = oldAddr
		return err
	}
	return nil
}

// Addr returns the string ip address of the target host.
func (p *TCPer) Target() string {
	return p.addr
}

func (p *TCPer) SetSource(addr string) error {
	oldAddr := p.srcAddr
	p.srcAddr = addr
	err := p.Resolve()
	if err != nil {
		p.srcAddr = oldAddr
		return err
	}

	return nil
}

func (p *TCPer) Source() string {
	return p.srcAddr
}
