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

type TCPListener struct {
	client       *Client
	protocolType string
	listener     net.Listener
	stopChan     chan struct{}
}

func NewTCPListener(c *Client, protocolType string) *TCPListener {
	return &TCPListener{
		client:       c,
		protocolType: protocolType,
		stopChan:     make(chan struct{}),
	}
}

func (l *TCPListener) Start(ctx context.Context, ip string, port int) error {
	addr := fmt.Sprintf("%s:%d", ip, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	l.listener = listener

	l.client.log.Infof("🚀 <green>%s Proxy server is listening on <cyan>%s</cyan></green>", l.protocolType, addr)

	go func() {
		for {
			conn, err := l.listener.Accept()
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
			go l.handleConnection(ctx, conn, l.protocolType)
		}
	}()

	return nil
}

func (l *TCPListener) Stop() {
	close(l.stopChan)
	if l.listener != nil {
		_ = l.listener.Close()
	}
}

// handleConnection is an empty placeholder for future protocol management.
func (l *TCPListener) handleConnection(ctx context.Context, conn net.Conn, protocolType string) {
	// Placeholder: Do nothing yet, will implement SOCKS5/TCP logic later.
	// l.client.log.Debugf("New %s connection accepted from %v", protocolType, conn.RemoteAddr())
	_ = conn.Close() // Temporarily close to prevent leaks until implemented
}
