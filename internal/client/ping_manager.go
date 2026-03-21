package client

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

const (
	pingAggressiveInterval = 300 * time.Millisecond
	pingLazyInterval       = 1 * time.Second
	pingCoolDownInterval   = 3 * time.Second
	pingColdInterval       = 30 * time.Second
	pingWarmThreshold      = 5 * time.Second
	pingCoolThreshold      = 10 * time.Second
	pingColdThreshold      = 20 * time.Second
	pingPongFreshWindow    = 2 * time.Second
)

type PingManager struct {
	client                 *Client
	lastMeaningfulActivity atomic.Int64
	lastPingSentAt         atomic.Int64
	lastPongReceivedAt     atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	wakeCh chan struct{}
}

func newPingManager(client *Client) *PingManager {
	now := time.Now().UnixNano()
	p := &PingManager{
		client: client,
		wakeCh: make(chan struct{}, 1),
	}
	p.lastMeaningfulActivity.Store(now)
	p.lastPingSentAt.Store(now)
	p.lastPongReceivedAt.Store(now)
	return p
}

// Start starts the autonomous ping loop.
func (p *PingManager) Start(parentCtx context.Context) {
	p.Stop() // Ensure old one is stopped

	p.ctx, p.cancel = context.WithCancel(parentCtx)
	p.wg.Add(1)
	go p.pingLoop()
}

// Stop stops the ping loop.
func (p *PingManager) Stop() {
	if p.cancel != nil {
		p.cancel()
		p.wg.Wait()
		p.cancel = nil
	}
}

func (p *PingManager) NotifyMeaningfulActivity() {
	if p == nil {
		return
	}
	p.lastMeaningfulActivity.Store(time.Now().UnixNano())
	select {
	case p.wakeCh <- struct{}{}:
	default:
	}
}

func (p *PingManager) NotifyPingSent() {
	if p == nil {
		return
	}
	p.lastPingSentAt.Store(time.Now().UnixNano())
}

func (p *PingManager) NotifyPongReceived() {
	if p == nil {
		return
	}
	p.lastPongReceivedAt.Store(time.Now().UnixNano())
}

func (p *PingManager) onlyPingPongActive(now time.Time, meaningfulAt time.Time) bool {
	lastPing := time.Unix(0, p.lastPingSentAt.Load())
	lastPong := time.Unix(0, p.lastPongReceivedAt.Load())
	if lastPing.Before(meaningfulAt) || lastPong.Before(meaningfulAt) {
		return false
	}
	if now.Sub(lastPing) > pingPongFreshWindow || now.Sub(lastPong) > pingPongFreshWindow {
		return false
	}
	return true
}

func (p *PingManager) nextInterval(now time.Time) time.Duration {
	meaningfulAt := time.Unix(0, p.lastMeaningfulActivity.Load())
	if !p.onlyPingPongActive(now, meaningfulAt) {
		return pingAggressiveInterval
	}

	idleTime := now.Sub(meaningfulAt)
	switch {
	case idleTime < pingWarmThreshold:
		return pingAggressiveInterval
	case idleTime < pingCoolThreshold:
		return pingLazyInterval
	case idleTime < pingColdThreshold:
		return pingCoolDownInterval
	default:
		return pingColdInterval
	}
}

func (p *PingManager) pingLoop() {
	defer p.wg.Done()

	p.client.log.Debugf("\U0001F3D3 <cyan>Ping Manager loop started</cyan>")
	timer := time.NewTimer(pingAggressiveInterval)
	defer timer.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.wakeCh:
			// Woken up by data activity! Re-evaluate immediately.
		case <-timer.C:
			// Timer fired.
		}

		now := time.Now()
		interval := p.nextInterval(now)
		lastPing := time.Unix(0, p.lastPingSentAt.Load())
		if now.Sub(lastPing) >= interval {
			if p.client.SessionReady() {
				payload, err := buildClientPingPayload()
				if err == nil {
					p.client.QueueControlPacket(Enums.PACKET_PING, payload)
					p.NotifyPingSent()
				}
			}
		}

		checkInterval := interval / 2
		if checkInterval < 100*time.Millisecond {
			checkInterval = 100 * time.Millisecond
		}
		if checkInterval > 1*time.Second {
			checkInterval = 1 * time.Second
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(checkInterval)
	}
}
