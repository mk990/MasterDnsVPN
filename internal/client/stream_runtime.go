// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"errors"
	"io"
	"net"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const maxClientStreamFollowUps = 16
const streamTXInitialRetryDelay = 350 * time.Millisecond
const streamTXMaxRetryDelay = 2 * time.Second

var ErrClientStreamClosed = errors.New("client stream closed")

func (c *Client) createStream(streamID uint16, conn net.Conn) *clientStream {
	stream := &clientStream{
		ID:             streamID,
		Conn:           conn,
		NextSequence:   2,
		LastActivityAt: time.Now(),
		TXQueue:        make([]clientStreamTXPacket, 0, 8),
		TXInFlight:     make([]clientStreamTXPacket, 0, c.effectiveStreamTXWindow()),
		TXWake:         make(chan struct{}, 1),
		StopCh:         make(chan struct{}),
	}
	c.storeStream(stream)
	if c.stream0Runtime != nil {
		c.stream0Runtime.NotifyDNSActivity()
	}
	go c.runClientStreamTXLoop(stream, 5*time.Second)
	return stream
}

func (c *Client) nextClientStreamSequence(stream *clientStream) uint16 {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.NextSequence++
	if stream.NextSequence == 0 {
		stream.NextSequence = 1
	}
	stream.LastActivityAt = time.Now()
	return stream.NextSequence
}

func (c *Client) sendStreamData(stream *clientStream, payload []byte, timeout time.Duration) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	packet, err := c.exchangeStreamControlPacket(
		Enums.PACKET_STREAM_DATA,
		stream.ID,
		c.nextClientStreamSequence(stream),
		payload,
		timeout,
	)
	if err != nil {
		return err
	}
	return c.handleFollowUpServerPacket(packet, timeout)
}

func (c *Client) sendStreamFIN(stream *clientStream, timeout time.Duration) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	stream.mu.Lock()
	if stream.LocalFinSent || stream.Closed {
		stream.mu.Unlock()
		return nil
	}
	stream.LocalFinSent = true
	stream.mu.Unlock()

	packet, err := c.exchangeStreamControlPacket(
		Enums.PACKET_STREAM_FIN,
		stream.ID,
		c.nextClientStreamSequence(stream),
		nil,
		timeout,
	)
	if err != nil {
		return err
	}
	return c.handleFollowUpServerPacket(packet, timeout)
}

func (c *Client) sendStreamRST(stream *clientStream, timeout time.Duration) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	stream.mu.Lock()
	if stream.ResetSent || stream.Closed {
		stream.mu.Unlock()
		return nil
	}
	stream.ResetSent = true
	stream.mu.Unlock()

	packet, err := c.exchangeStreamControlPacket(
		Enums.PACKET_STREAM_RST,
		stream.ID,
		c.nextClientStreamSequence(stream),
		nil,
		timeout,
	)
	if err != nil {
		return err
	}
	return c.handleFollowUpServerPacket(packet, timeout)
}

func (c *Client) handleFollowUpServerPacket(packet VpnProto.Packet, timeout time.Duration) error {
	current := packet
	for range maxClientStreamFollowUps {
		switch current.PacketType {
		case 0, Enums.PACKET_PONG, Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_SYN_ACK, Enums.PACKET_SOCKS5_SYN_ACK:
			return nil
		case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_FIN, Enums.PACKET_STREAM_RST:
			nextPacket, err := c.handleInboundStreamPacket(current, timeout)
			if err != nil {
				return err
			}
			current = nextPacket
		default:
			if isSOCKS5ErrorPacket(current.PacketType) {
				return errors.New(Enums.PacketTypeName(current.PacketType))
			}
			return nil
		}
	}
	return nil
}

func (c *Client) handleInboundStreamPacket(packet VpnProto.Packet, timeout time.Duration) (VpnProto.Packet, error) {
	stream, ok := c.getStream(packet.StreamID)
	if !ok || stream == nil {
		return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_RST, packet.StreamID, packet.SequenceNum, nil, timeout)
	}

	stream.mu.Lock()
	stream.LastActivityAt = time.Now()
	stream.mu.Unlock()

	switch packet.PacketType {
	case Enums.PACKET_STREAM_DATA:
		stream.mu.Lock()
		if stream.InboundDataSet && sequenceSeenOrOlder(stream.InboundDataSeq, packet.SequenceNum) {
			stream.mu.Unlock()
			return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_DATA_ACK, stream.ID, packet.SequenceNum, nil, timeout)
		}
		stream.InboundDataSeq = packet.SequenceNum
		stream.InboundDataSet = true
		stream.mu.Unlock()
		if len(packet.Payload) != 0 {
			if _, err := stream.Conn.Write(packet.Payload); err != nil {
				stream.mu.Lock()
				stream.Closed = true
				stream.mu.Unlock()
				c.deleteStream(stream.ID)
				return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_RST, stream.ID, packet.SequenceNum, nil, timeout)
			}
		}
		return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_DATA_ACK, stream.ID, packet.SequenceNum, nil, timeout)
	case Enums.PACKET_STREAM_FIN:
		stream.mu.Lock()
		if stream.RemoteFinSet && stream.RemoteFinSeq == packet.SequenceNum {
			stream.mu.Unlock()
			return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_FIN_ACK, stream.ID, packet.SequenceNum, nil, timeout)
		}
		stream.RemoteFinSeq = packet.SequenceNum
		stream.RemoteFinSet = true
		stream.RemoteFinRecv = true
		stream.mu.Unlock()
		closeWriteConn(stream.Conn)
		if streamFinished(stream) {
			c.deleteStream(stream.ID)
		}
		return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_FIN_ACK, stream.ID, packet.SequenceNum, nil, timeout)
	case Enums.PACKET_STREAM_RST:
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		c.deleteStream(stream.ID)
		return c.exchangeStreamControlPacket(Enums.PACKET_STREAM_RST_ACK, stream.ID, packet.SequenceNum, nil, timeout)
	default:
		return VpnProto.Packet{}, nil
	}
}

func (c *Client) queueStreamPacket(stream *clientStream, packetType uint8, payload []byte) error {
	if c == nil || stream == nil {
		return ErrClientStreamClosed
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.Closed {
		return ErrClientStreamClosed
	}
	if packetType == Enums.PACKET_STREAM_FIN && stream.LocalFinSent {
		return nil
	}
	if packetType == Enums.PACKET_STREAM_RST && stream.ResetSent {
		return nil
	}

	stream.NextSequence++
	if stream.NextSequence == 0 {
		stream.NextSequence = 1
	}
	sequenceNum := stream.NextSequence
	stream.LastActivityAt = time.Now()
	if packetType == Enums.PACKET_STREAM_FIN {
		stream.LocalFinSent = true
	}
	if packetType == Enums.PACKET_STREAM_RST {
		stream.ResetSent = true
		clearClientStreamDataLocked(stream)
	}
	packet := clientStreamTXPacket{
		PacketType:  packetType,
		SequenceNum: sequenceNum,
		Payload:     append([]byte(nil), payload...),
		RetryDelay:  streamTXInitialRetryDelay,
	}
	if packetType == Enums.PACKET_STREAM_RST {
		stream.TXQueue = append(stream.TXQueue, clientStreamTXPacket{})
		copy(stream.TXQueue[1:], stream.TXQueue[:len(stream.TXQueue)-1])
		stream.TXQueue[0] = packet
	} else {
		stream.TXQueue = append(stream.TXQueue, packet)
	}
	notifyStreamWake(stream)
	return nil
}

func (c *Client) runClientStreamTXLoop(stream *clientStream, timeout time.Duration) {
	if c == nil || stream == nil {
		return
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	for {
		packet, waitFor, shouldStop := nextClientStreamTX(stream, c.effectiveStreamTXWindow())
		if shouldStop {
			return
		}
		if packet == nil {
			select {
			case <-stream.TXWake:
				continue
			case <-stream.StopCh:
				return
			}
		}
		if waitFor > 0 {
			timer := time.NewTimer(waitFor)
			select {
			case <-timer.C:
			case <-stream.TXWake:
				timer.Stop()
				continue
			case <-stream.StopCh:
				timer.Stop()
				return
			}
		}

		response, err := c.exchangeStreamControlPacket(packet.PacketType, stream.ID, packet.SequenceNum, packet.Payload, timeout)
		if err != nil {
			rescheduleClientStreamTX(stream, packet.SequenceNum)
			continue
		}
		acked := ackClientStreamTXByResponse(stream, packet.PacketType, response)
		if err := c.handleFollowUpServerPacket(response, timeout); err != nil {
			if !acked {
				rescheduleClientStreamTX(stream, packet.SequenceNum)
			}
			continue
		}
		if !acked {
			rescheduleClientStreamTX(stream, packet.SequenceNum)
		}
		if streamFinished(stream) {
			c.deleteStream(stream.ID)
			return
		}
	}
}

func nextClientStreamTX(stream *clientStream, windowSize int) (*clientStreamTXPacket, time.Duration, bool) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.Closed {
		return nil, 0, true
	}
	if windowSize < 1 {
		windowSize = 1
	}
	now := time.Now()
	for len(stream.TXInFlight) < windowSize && len(stream.TXQueue) != 0 {
		packet := stream.TXQueue[0]
		stream.TXQueue[0] = clientStreamTXPacket{}
		stream.TXQueue = stream.TXQueue[1:]
		if packet.RetryDelay <= 0 {
			packet.RetryDelay = streamTXInitialRetryDelay
		}
		packet.RetryAt = now
		stream.TXInFlight = append(stream.TXInFlight, packet)
	}
	if len(stream.TXInFlight) == 0 {
		return nil, 0, false
	}

	selectedIdx := -1
	minWait := time.Duration(-1)
	for idx := range stream.TXInFlight {
		waitFor := time.Until(stream.TXInFlight[idx].RetryAt)
		if waitFor <= 0 {
			selectedIdx = idx
			minWait = 0
			break
		}
		if minWait < 0 || waitFor < minWait {
			minWait = waitFor
		}
	}
	if selectedIdx < 0 {
		return nil, minWait, false
	}
	packet := stream.TXInFlight[selectedIdx]
	return &packet, minWait, false
}

func rescheduleClientStreamTX(stream *clientStream, sequenceNum uint16) {
	if stream == nil {
		return
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for idx := range stream.TXInFlight {
		if stream.TXInFlight[idx].SequenceNum != sequenceNum {
			continue
		}
		delay := stream.TXInFlight[idx].RetryDelay
		if delay <= 0 {
			delay = streamTXInitialRetryDelay
		}
		stream.TXInFlight[idx].RetryAt = time.Now().Add(delay)
		delay *= 2
		if delay > streamTXMaxRetryDelay {
			delay = streamTXMaxRetryDelay
		}
		stream.TXInFlight[idx].RetryDelay = delay
		return
	}
}

func ackClientStreamTX(stream *clientStream, sequenceNum uint16) {
	if stream == nil {
		return
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for idx := range stream.TXInFlight {
		if stream.TXInFlight[idx].SequenceNum != sequenceNum {
			continue
		}
		copy(stream.TXInFlight[idx:], stream.TXInFlight[idx+1:])
		lastIdx := len(stream.TXInFlight) - 1
		stream.TXInFlight[lastIdx] = clientStreamTXPacket{}
		stream.TXInFlight = stream.TXInFlight[:lastIdx]
		return
	}
}

func ackClientStreamTXByResponse(stream *clientStream, sentPacketType uint8, response VpnProto.Packet) bool {
	if stream == nil {
		return false
	}
	if !matchesClientStreamAck(sentPacketType, response.PacketType) {
		return false
	}
	if response.StreamID != stream.ID {
		return false
	}
	ackClientStreamTX(stream, response.SequenceNum)
	return true
}

func notifyStreamWake(stream *clientStream) {
	if stream == nil {
		return
	}
	select {
	case stream.TXWake <- struct{}{}:
	default:
	}
}

func (c *Client) runLocalStreamReadLoop(stream *clientStream, timeout time.Duration) {
	defer func() {
		stream.mu.Lock()
		closed := stream.Closed
		stream.mu.Unlock()
		if !closed {
			_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_FIN, nil)
		}
		if streamFinished(stream) {
			c.deleteStream(stream.ID)
		}
	}()

	readSize := c.maxMainStreamFragmentPayload(c.cfg.Domains[0], Enums.PACKET_STREAM_DATA)
	if readSize < 256 {
		readSize = 256
	}
	buffer := make([]byte, readSize)
	for {
		n, err := stream.Conn.Read(buffer)
		if n > 0 {
			if sendErr := c.queueStreamPacket(stream, Enums.PACKET_STREAM_DATA, buffer[:n]); sendErr != nil {
				_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_RST, nil)
				return
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return
		}
		_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_RST, nil)
		return
	}
}

func streamFinished(stream *clientStream) bool {
	if stream == nil {
		return true
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.Closed || (stream.LocalFinSent && stream.RemoteFinRecv)
}

func closeWriteConn(conn net.Conn) {
	if conn == nil {
		return
	}
	type closeWriter interface {
		CloseWrite() error
	}
	if writer, ok := conn.(closeWriter); ok {
		_ = writer.CloseWrite()
		return
	}
	_ = conn.Close()
}

func sequenceSeenOrOlder(last uint16, current uint16) bool {
	diff := uint16(current - last)
	return diff == 0 || diff >= 0x8000
}

func matchesClientStreamAck(sentType uint8, ackType uint8) bool {
	switch sentType {
	case Enums.PACKET_STREAM_DATA:
		return ackType == Enums.PACKET_STREAM_DATA_ACK
	case Enums.PACKET_STREAM_FIN:
		return ackType == Enums.PACKET_STREAM_FIN_ACK
	case Enums.PACKET_STREAM_RST:
		return ackType == Enums.PACKET_STREAM_RST_ACK
	default:
		return false
	}
}

func (c *Client) effectiveStreamTXWindow() int {
	if c == nil || c.streamTXWindow < 1 {
		return 1
	}
	if c.streamTXWindow > 32 {
		return 32
	}
	return c.streamTXWindow
}

func clearClientStreamDataLocked(stream *clientStream) {
	if stream == nil {
		return
	}
	if len(stream.TXQueue) != 0 {
		filteredQueue := stream.TXQueue[:0]
		for _, packet := range stream.TXQueue {
			if packet.PacketType == Enums.PACKET_STREAM_RST {
				filteredQueue = append(filteredQueue, packet)
			}
		}
		for idx := len(filteredQueue); idx < len(stream.TXQueue); idx++ {
			stream.TXQueue[idx] = clientStreamTXPacket{}
		}
		stream.TXQueue = filteredQueue
	}
	if len(stream.TXInFlight) != 0 {
		filteredInFlight := stream.TXInFlight[:0]
		for _, packet := range stream.TXInFlight {
			if packet.PacketType == Enums.PACKET_STREAM_RST {
				filteredInFlight = append(filteredInFlight, packet)
			}
		}
		for idx := len(filteredInFlight); idx < len(stream.TXInFlight); idx++ {
			stream.TXInFlight[idx] = clientStreamTXPacket{}
		}
		stream.TXInFlight = filteredInFlight
	}
}
