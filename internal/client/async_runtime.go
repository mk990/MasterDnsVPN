package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
)

// StopAsyncRuntime stops all running workers (Readers, Writers, Processors).
// It ensures the UDP socket is closed and all goroutines exit.
func (c *Client) StopAsyncRuntime() {
	if c.asyncCancel != nil {
		c.log.Debugf("\U0001F6D1 <yellow>Stopping High-Performance Async Runtime...</yellow>")
		c.asyncCancel()
		c.asyncWG.Wait()
		c.asyncCancel = nil

		// Final drain to return all buffers to the pool and prevent memory leaks.
		c.drainQueues()
		c.log.Debugf("\U0001F232 <green>Async Runtime stopped cleanly.</green>")
	}

	if c.tunnelConn != nil {
		_ = c.tunnelConn.Close()
		c.tunnelConn = nil
	}

	if c.pingManager != nil {
		c.pingManager.Stop()
	}
}

// StartAsyncRuntime initializes the parallel system for tunnel I/O and processing.
func (c *Client) StartAsyncRuntime(parentCtx context.Context) error {
	// 1. Ensure any previous instance is completely stopped.
	c.StopAsyncRuntime()

	// 2. Setup session context.
	runtimeCtx, cancel := context.WithCancel(parentCtx)
	c.asyncCancel = cancel

	// 3. Open shared UDP socket.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		cancel()
		c.asyncCancel = nil
		return fmt.Errorf("failed to open high-performance tunnel socket: %w", err)
	}
	c.tunnelConn = conn

	c.log.Infof("\U0001F4E1 <cyan>Async Runtime Initialized: <green>%d Writes</green>, <green>%d Reads</green>, <green>%d Processors</green></cyan>",
		c.tunnelWriterWorkers, c.tunnelReaderWorkers, c.tunnelProcessWorkers)

	// 4. Initialize Virtual Stream 0 (Control Channel)
	c.initVirtualStream0()

	// 5. Start support runtimes (DNS Cache, Health Monitor)
	c.StartSupportRuntimes(runtimeCtx)

	// 6. Spawn Reader Workers (High-speed ingestion)
	for i := 0; i < c.tunnelReaderWorkers; i++ {
		c.asyncWG.Add(1)
		go c.asyncReaderWorker(runtimeCtx, i, conn)
	}

	// 5. Spawn Processor Workers (Parallel data analysis)
	for i := 0; i < c.tunnelProcessWorkers; i++ {
		c.asyncWG.Add(1)
		go c.asyncProcessorWorker(runtimeCtx, i)
	}

	// 6. Spawn Writer Workers (Burst transmission)
	for i := 0; i < c.tunnelWriterWorkers; i++ {
		c.asyncWG.Add(1)
		go c.asyncWriterWorker(runtimeCtx, i, conn)
	}

	// 7. Lifecycle cleanup.
	c.asyncWG.Add(1)
	go func() {
		defer c.asyncWG.Done()
		<-runtimeCtx.Done()
		conn.Close()
	}()

	// 8. Start Ping Manager (Autonomous adaptive pinging)
	c.pingManager.Start(runtimeCtx)

	return nil
}

// drainQueues removes any stale packets from TX and RX channels.
// Buffers from the RX channel are returned to the pool to prevent leaks.
func (c *Client) drainQueues() {
	// Drain TX
	for {
		select {
		case <-c.txChannel:
		default:
			goto drainRX
		}
	}
drainRX:
	// Drain RX and return buffers to pool
	for {
		select {
		case pkt := <-c.rxChannel:
			if pkt.data != nil {
				c.udpBufferPool.Put(pkt.data[:cap(pkt.data)])
			}
		default:
			return
		}
	}
}

// asyncWriterWorker fires packets from txChannel at the destination.
func (c *Client) asyncWriterWorker(ctx context.Context, id int, conn *net.UDPConn) {
	defer c.asyncWG.Done()
	c.log.Debugf("\U0001F680 <green>Writer Worker <cyan>#%d</cyan> started</green>", id)
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-c.txChannel:
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", pkt.conn.Resolver, pkt.conn.ResolverPort))
			if err != nil {
				continue
			}

			if c.tunnelPacketTimeout > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(c.tunnelPacketTimeout))
			}

			_, _ = conn.WriteToUDP(pkt.payload, addr)
		}
	}
}

// asyncReaderWorker reads raw UDP data and pushes to the rxChannel (Internal Queue).
func (c *Client) asyncReaderWorker(ctx context.Context, id int, conn *net.UDPConn) {
	defer c.asyncWG.Done()
	c.log.Debugf("\U0001F442 <green>Reader Worker <cyan>#%d</cyan> started</green>", id)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buf := c.udpBufferPool.Get().([]byte)
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				c.udpBufferPool.Put(buf)
				if ctx.Err() != nil {
					return
				}
				continue
			}

			if n < 12 { // Basic DNS header length
				c.udpBufferPool.Put(buf)
				continue
			}

			// Shallow check: DNS Response bit (QR=1)
			// DNS Header: ID(2), Flags(2)... Flags first byte bit 7 is QR.
			if (buf[2] & 0x80) == 0 {
				// Not a response, we are a client, we only care about responses.
				c.udpBufferPool.Put(buf)
				continue
			}

			packetData := buf[:n]

			select {
			case c.rxChannel <- asyncReadPacket{data: packetData, addr: addr}:
			default:
				// Queue full! Drop packet and RECYCLE buffer.
				c.udpBufferPool.Put(buf)
			}
		}
	}
}

// asyncProcessorWorker pulls from rxChannel and performs the actual packet handling.
func (c *Client) asyncProcessorWorker(ctx context.Context, id int) {
	defer c.asyncWG.Done()
	c.log.Debugf("\U0001F3D7  <green>Processor Worker <cyan>#%d</cyan> started</green>", id)
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-c.rxChannel:
			c.handleInboundPacket(pkt.data, pkt.addr)

			// RECYCLE buffer back to the pool.
			c.udpBufferPool.Put(pkt.data[:cap(pkt.data)])
		}
	}
}

// handleInboundPacket is the central entry point for all received tunnel packets.
func (c *Client) handleInboundPacket(data []byte, addr *net.UDPAddr) {
	c.log.Debugf("Inbound packet from %v (%d bytes)", addr, len(data))

	// 1. Extract VPN Packet from DNS Response
	vpnPacket, err := DnsParser.ExtractVPNResponse(data, c.responseMode == mtuProbeBase64Reply)
	if err != nil {
		return
	}

	// 2. Security Validation
	if !c.validateServerPacket(vpnPacket) {
		return
	}

	if vpnPacket.PacketType == Enums.PACKET_PONG {
		c.pingManager.NotifyPongReceived()
	} else {
		c.pingManager.NotifyMeaningfulActivity()
	}

	// 4. Dispatch to Session/Stream handler
	dispatch, err := c.dispatchServerPacket(vpnPacket, time.Second, nil)
	if err != nil {
		if !errors.Is(err, ErrSessionDropped) {
			c.log.Debugf("\U0001F9F9 <yellow>Packet Dispatch Error: <cyan>%v</cyan></yellow>", err)
		}
		return
	}

	// 5. Follow-up handling (e.g. multi-packet responses)
	if dispatch.hasNext {
		if err := c.handleFollowUpServerPacket(dispatch.next, time.Second); err != nil {
			c.log.Debugf("\U0001F9F9 <yellow>Follow-up Packet Handling Failed: <cyan>%v</cyan></yellow>", err)
		}
	}
}

// SendBurstPacket adds a packet to the transmission queue.
func (c *Client) SendBurstPacket(conn Connection, payload []byte, packetType uint8) {
	if packetType != Enums.PACKET_PING {
		c.pingManager.NotifyMeaningfulActivity()
	}
	select {
	case c.txChannel <- asyncPacket{conn: conn, payload: payload, packetType: packetType}:
	default:
	}
}
