// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"net"
)

type DNSListener struct {
	client   *Client
	conn     *net.UDPConn
	stopChan chan struct{}
}

func NewDNSListener(c *Client) *DNSListener {
	return &DNSListener{
		client:   c,
		stopChan: make(chan struct{}),
	}
}

func (l *DNSListener) Start(ctx context.Context, ip string, port int) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	l.conn = conn

	l.client.log.Infof("🚀 <green>DNS server is listening on <cyan>%s:%d</cyan></green>", ip, port)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, peerAddr, err := l.conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-l.stopChan:
					return
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			// Copy data for the handler to prevent overwrite race condition
			dataCopy := make([]byte, n)
			copy(dataCopy, buf[:n])
			go l.handleQuery(ctx, dataCopy, peerAddr)
		}
	}()

	return nil
}

func (l *DNSListener) Stop() {
	close(l.stopChan)
	if l.conn != nil {
		_ = l.conn.Close()
	}
}

// handleQuery is an empty placeholder for future DNS query management.
func (l *DNSListener) handleQuery(ctx context.Context, data []byte, addr *net.UDPAddr) {
	// Placeholder: Do nothing yet, will implement DNS response logic later.
}
