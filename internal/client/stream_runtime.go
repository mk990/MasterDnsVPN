package client

import (
	"errors"
	"io"
	"net"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/streamutil"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const maxClientStreamFollowUps = 16

var ErrClientStreamClosed = errors.New("client stream closed")
var ErrClientStreamBackpressure = errors.New("client stream send queue full")

func (c *Client) createStream(streamID uint16, conn net.Conn) *clientStream {
	now := time.Now()
	stream := &clientStream{
		ID:             streamID,
		Conn:           conn,
		NextSequence:   2,
		LastActivityAt: now,
		TXQueue:        make([]clientStreamTXPacket, 0, 8),
		TXWake:         make(chan struct{}, 1),
		StopCh:         make(chan struct{}),
		arqWindowSize:  c.arqWindowSize,
		log:            c.log,
	}
	if preferred, ok := c.GetBestConnection(); ok && preferred.Key != "" {
		stream.PreferredServerKey = preferred.Key
		stream.LastResolverFailover = now
	}
	c.storeStream(stream)
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
	return c.sendStreamProtocolOneWay(
		Enums.PACKET_STREAM_DATA,
		stream.ID,
		c.nextClientStreamSequence(stream),
		payload,
		timeout,
	)
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

	return c.sendStreamProtocolOneWay(
		Enums.PACKET_STREAM_FIN,
		stream.ID,
		c.nextClientStreamSequence(stream),
		nil,
		timeout,
	)
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

	return c.sendStreamProtocolOneWay(
		Enums.PACKET_STREAM_RST,
		stream.ID,
		c.nextClientStreamSequence(stream),
		nil,
		timeout,
	)
}

func (c *Client) handleFollowUpServerPacket(packet VpnProto.Packet, timeout time.Duration) error {
	current := packet
	for range maxClientStreamFollowUps {
		dispatch, err := c.dispatchServerPacket(current, timeout, nil)
		if err != nil {
			return err
		}
		if dispatch.stop || !dispatch.hasNext {
			return nil
		}
		current = dispatch.next
	}
	return nil
}

func (c *Client) handlePackedServerControlBlocks(payload []byte, timeout time.Duration) error {
	_, err := c.handlePackedServerControlBlocksForQueuedPacket(payload, timeout, nil)
	return err
}

func (c *Client) handlePackedServerControlBlocksForQueuedPacket(payload []byte, timeout time.Duration, sent *arq.QueuedPacket) (bool, error) {
	if len(payload) < arq.PackedControlBlockSize {
		return false, nil
	}
	c.cachePackedStreamControlReplies(payload)
	var firstErr error
	ackedSent := false
	arq.ForEachPackedControlBlock(payload, func(packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
		if packetType == Enums.PACKET_PACKED_CONTROL_BLOCKS {
			return true
		}
		packet := VpnProto.Packet{
			PacketType:     packetType,
			StreamID:       streamID,
			HasStreamID:    streamID != 0,
			SequenceNum:    sequenceNum,
			HasSequenceNum: sequenceNum != 0,
			FragmentID:     fragmentID,
			TotalFragments: totalFragments,
		}
		dispatch, err := c.dispatchServerPacket(packet, timeout, sent)
		if dispatch.ackedQueued {
			ackedSent = true
		}
		if err != nil && firstErr == nil {
			firstErr = err
			return false
		}
		if dispatch.hasNext {
			if err := c.handleFollowUpServerPacket(dispatch.next, timeout); err != nil && firstErr == nil {
				firstErr = err
				return false
			}
		}
		return true
	})
	return ackedSent, firstErr
}

func matchesQueuedPacketAck(sent arq.QueuedPacket, packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
	if sent.StreamID != 0 {
		if sent.StreamID != streamID || sent.SequenceNum != sequenceNum {
			return false
		}
		return matchesClientStreamAck(sent.PacketType, packetType)
	}
	if sent.PacketType != Enums.PACKET_DNS_QUERY_REQ || packetType != Enums.PACKET_DNS_QUERY_REQ_ACK {
		return false
	}
	if sent.SequenceNum != sequenceNum || sent.FragmentID != fragmentID {
		return false
	}
	expectedTotal := sent.TotalFragments
	if expectedTotal == 0 {
		expectedTotal = 1
	}
	if totalFragments == 0 {
		totalFragments = 1
	}
	return expectedTotal == totalFragments
}

func (c *Client) handleInboundStreamPacket(packet VpnProto.Packet, timeout time.Duration) (VpnProto.Packet, error) {
	stream, ok := c.getStream(packet.StreamID)
	if !ok || stream == nil {
		if closedResponse, handled, err := c.handleClosedStreamPacket(packet, timeout); handled {
			return closedResponse, err
		}
		if err := c.sendStreamProtocolOneWay(Enums.PACKET_STREAM_RST, packet.StreamID, packet.SequenceNum, nil, timeout); err != nil {
			return VpnProto.Packet{}, err
		}
		return VpnProto.Packet{}, nil
	}

	stream.mu.Lock()
	stream.LastActivityAt = time.Now()
	stream.mu.Unlock()

	switch packet.PacketType {
	case Enums.PACKET_STREAM_DATA:
		if c.log != nil && len(packet.Payload) != 0 {
			c.log.Debugf(
				"📥 <blue>Inbound Stream Data, Stream ID: <cyan>%d</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan></blue>",
				stream.ID,
				packet.SequenceNum,
				len(packet.Payload),
			)
		}
		c.noteStreamProgress(stream.ID)
		assembled, ready, completed := c.collectInboundStreamDataFragments(packet)
		if completed {
			return c.sendStreamAckOneWay(Enums.PACKET_STREAM_DATA_ACK, stream.ID, packet.SequenceNum)
		}
		if !ready {
			return VpnProto.Packet{}, nil
		}
		if len(assembled) != 0 {
			if _, err := stream.Conn.Write(assembled); err != nil {
				if c.log != nil {
					c.log.Warnf(
						"🧦 <yellow>Local Stream Write Failed, Stream ID: <cyan>%d</cyan> | Error: <cyan>%v</cyan></yellow>",
						stream.ID,
						err,
					)
				}
				stream.mu.Lock()
				stream.Closed = true
				stream.mu.Unlock()
				c.deleteStream(stream.ID)
				if err := c.sendStreamProtocolOneWay(Enums.PACKET_STREAM_RST, stream.ID, packet.SequenceNum, nil, timeout); err != nil {
					return VpnProto.Packet{}, err
				}
				return VpnProto.Packet{}, nil
			}
		}
		stream.mu.Lock()
		stream.InboundDataSeq = packet.SequenceNum
		stream.InboundDataSet = true
		stream.mu.Unlock()
		return c.sendStreamAckOneWay(Enums.PACKET_STREAM_DATA_ACK, stream.ID, packet.SequenceNum)
	case Enums.PACKET_STREAM_FIN:
		c.noteStreamProgress(stream.ID)
		stream.mu.Lock()
		if stream.RemoteFinSet && stream.RemoteFinSeq == packet.SequenceNum {
			stream.mu.Unlock()
			return c.sendStreamAckOneWay(Enums.PACKET_STREAM_FIN_ACK, stream.ID, packet.SequenceNum)
		}
		stream.RemoteFinSeq = packet.SequenceNum
		stream.RemoteFinSet = true
		stream.RemoteFinRecv = true
		stream.mu.Unlock()
		streamutil.CloseWrite(stream.Conn)
		if streamFinished(stream) {
			c.deleteStream(stream.ID)
		}
		return c.sendStreamAckOneWay(Enums.PACKET_STREAM_FIN_ACK, stream.ID, packet.SequenceNum)
	case Enums.PACKET_STREAM_RST:
		c.noteStreamProgress(stream.ID)
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		c.deleteStream(stream.ID)
		return c.sendStreamAckOneWay(Enums.PACKET_STREAM_RST_ACK, stream.ID, packet.SequenceNum)
	default:
		return VpnProto.Packet{}, nil
	}
}

func (c *Client) sendStreamAckOneWay(packetType uint8, streamID uint16, sequenceNum uint16) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrClientStreamClosed
	}
	if c.log != nil {
		c.log.Debugf(
			"📨 <blue>Sending Stream ACK</blue> <magenta>|</magenta> <blue>Stream ID</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Packet</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
			streamID,
			Enums.PacketTypeName(packetType),
			sequenceNum,
		)
	}
	err := c.sendStreamProtocolOneWay(packetType, streamID, sequenceNum, nil, defaultRuntimeTimeout)
	return VpnProto.Packet{}, err
}

func (c *Client) sendStreamProtocolOneWay(packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, timeout time.Duration) error {
	if c == nil {
		return ErrClientStreamClosed
	}
	if !c.SessionReady() {
		return ErrTunnelDNSDispatchFailed
	}

	connections, err := c.selectTargetConnectionsForPacket(packetType, streamID)
	if err != nil {
		return err
	}

	packet := arq.QueuedPacket{
		PacketType:  packetType,
		StreamID:    streamID,
		SequenceNum: sequenceNum,
		Payload:     payload,
		Priority:    arq.DefaultPriorityForPacket(packetType),
	}
	deadline := time.Now().Add(normalizeTimeout(timeout, defaultRuntimeTimeout))
	return sendRuntimeQueuedPacketParallel(connections, ErrTunnelDNSDispatchFailed, func(connection Connection) error {
		return c.sendQueuedRuntimePacketWithConnection(connection, packet, deadline)
	})
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
	if packetType == Enums.PACKET_STREAM_DATA && c.effectiveStreamTXQueueLimit() > 0 && len(stream.TXQueue) >= c.effectiveStreamTXQueueLimit() {
		return ErrClientStreamBackpressure
	}

	stream.NextSequence++
	if stream.NextSequence == 0 {
		stream.NextSequence = 1
	}
	sequenceNum := stream.NextSequence
	stream.LastActivityAt = time.Now()
	if packetType == Enums.PACKET_STREAM_FIN {
		stream.LocalFinSent = true
		stream.LocalFinSeq = sequenceNum
	}
	if packetType == Enums.PACKET_STREAM_RST {
		stream.ResetSent = true
		clearClientStreamDataLocked(stream)
		stream.Closed = true
	}

	packet := clientStreamTXPacket{
		PacketType:  packetType,
		SequenceNum: sequenceNum,
		Payload:     arq.AllocPayload(payload),
		CreatedAt:   stream.LastActivityAt,
	}
	stream.TXQueue = append(stream.TXQueue, packet)
	queueLen := len(stream.TXQueue)
	notifyStreamWake(stream)
	if c.log != nil {
		c.log.Debugf(
			"📤 <blue>Queued Stream Packet, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan> | Queue: <cyan>%d</cyan></blue>",
			stream.ID,
			Enums.PacketTypeName(packetType),
			sequenceNum,
			len(payload),
			queueLen,
		)
	}
	return nil
}

func (c *Client) runClientStreamTXLoop(stream *clientStream, timeout time.Duration) {
	if c == nil || stream == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if c.log != nil {
				c.log.Errorf(
					"💥 <red>Client Stream TX Loop Panic: <cyan>%v</cyan> (Stream ID: <cyan>%d</cyan>)</red>",
					recovered,
					stream.ID,
				)
			}
			_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_RST, nil)
			c.deleteStream(stream.ID)
		}
	}()
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)

	waitTimer := time.NewTimer(time.Hour)
	if !waitTimer.Stop() {
		select {
		case <-waitTimer.C:
		default:
		}
	}
	defer waitTimer.Stop()

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
			waitTimer.Reset(waitFor)
			select {
			case <-waitTimer.C:
			case <-stream.TXWake:
				if !waitTimer.Stop() {
					select {
					case <-waitTimer.C:
					default:
					}
				}
				continue
			case <-stream.StopCh:
				return
			}
		}
		packetType := packet.PacketType
		if c.log != nil {
			c.log.Debugf(
				"🚀 <blue>Dispatching Stream Packet, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan></blue>",
				stream.ID,
				Enums.PacketTypeName(packetType),
				packet.SequenceNum,
				len(packet.Payload),
			)
		}
		if err := c.sendStreamProtocolOneWay(packetType, stream.ID, packet.SequenceNum, packet.Payload, timeout); err != nil {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		if packet.Payload != nil {
			arq.FreePayload(packet.Payload)
		}
		if stream.ID != 0 && streamFinished(stream) {
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
	_ = windowSize
	if len(stream.TXQueue) == 0 {
		return nil, 0, false
	}
	packet := stream.TXQueue[0]
	stream.TXQueue[0] = clientStreamTXPacket{}
	stream.TXQueue = stream.TXQueue[1:]
	return &packet, 0, false
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
	if stream == nil || stream.ID == 0 {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if c.log != nil {
				c.log.Errorf(
					"💥 <red>Client Stream Read Loop Panic: <cyan>%v</cyan> (Stream ID: <cyan>%d</cyan>)</red>",
					recovered,
					stream.ID,
				)
			}
			_ = c.queueStreamPacket(stream, Enums.PACKET_STREAM_RST, nil)
		}
	}()
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
			if c.log != nil {
				c.log.Debugf(
					"📂 <blue>Local Stream Read, Stream ID: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan></blue>",
					stream.ID,
					n,
				)
			}
			if sendErr := c.queueStreamPacket(stream, Enums.PACKET_STREAM_DATA, buffer[:n]); sendErr != nil {
				if c.log != nil {
					c.log.Warnf(
						"📂 <yellow>Local Stream Queue Failed, Stream ID: <cyan>%d</cyan> | Error: <cyan>%v</cyan></yellow>",
						stream.ID,
						sendErr,
					)
				}
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
	if stream.Closed {
		return true
	}
	if stream.ResetSent {
		return false
	}
	if stream == nil || stream.ID == 0 {
		return false
	}
	if !stream.LocalFinSent || !stream.RemoteFinRecv {
		return false
	}
	return len(stream.TXQueue) == 0
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

func (c *Client) effectiveStreamTXQueueLimit() int {
	if c == nil || c.streamTXQueueLimit < 1 {
		return 128
	}
	if c.streamTXQueueLimit > 4096 {
		return 4096
	}
	return c.streamTXQueueLimit
}

func (c *Client) effectiveStreamTXMaxRetries() int {
	if c == nil || c.streamTXMaxRetries < 1 {
		return 24
	}
	if c.streamTXMaxRetries > 512 {
		return 512
	}
	return c.streamTXMaxRetries
}

func (c *Client) effectiveStreamTXTTL() time.Duration {
	if c == nil || c.streamTXTTL <= 0 {
		return 120 * time.Second
	}
	return c.streamTXTTL
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
			} else if packet.Payload != nil {
				arq.FreePayload(packet.Payload)
			}
		}
		for idx := len(filteredQueue); idx < len(stream.TXQueue); idx++ {
			stream.TXQueue[idx] = clientStreamTXPacket{}
		}
		stream.TXQueue = filteredQueue
	}
}
