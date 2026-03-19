// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"sync"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const streamOutboundInitialRetryDelay = 350 * time.Millisecond
const streamOutboundMaxRetryDelay = 2 * time.Second

type streamOutboundStore struct {
	mu       sync.Mutex
	sessions map[uint8]*streamOutboundSession
	window   int
}

type outboundPendingPacket struct {
	Packet     VpnProto.Packet
	RetryAt    time.Time
	RetryDelay time.Duration
}

type streamOutboundSession struct {
	queue   []VpnProto.Packet
	pending []outboundPendingPacket
}

func newStreamOutboundStore(windowSize int) *streamOutboundStore {
	if windowSize < 1 {
		windowSize = 1
	}
	if windowSize > 32 {
		windowSize = 32
	}
	return &streamOutboundStore{
		sessions: make(map[uint8]*streamOutboundSession, 32),
		window:   windowSize,
	}
}

func (s *streamOutboundStore) Enqueue(sessionID uint8, packet VpnProto.Packet) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		session = &streamOutboundSession{
			queue:   make([]VpnProto.Packet, 0, 8),
			pending: make([]outboundPendingPacket, 0, s.effectiveWindow()),
		}
		s.sessions[sessionID] = session
	}
	packet.Payload = append([]byte(nil), packet.Payload...)
	if packet.PacketType == Enums.PACKET_STREAM_RST {
		pruneOutboundStreamPackets(session, packet.StreamID)
		prependOutboundPacket(&session.queue, packet)
		return
	}
	session.queue = append(session.queue, packet)
}

func (s *streamOutboundStore) Next(sessionID uint8, now time.Time) (VpnProto.Packet, bool) {
	if s == nil {
		return VpnProto.Packet{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		return VpnProto.Packet{}, false
	}
	if len(session.pending) < s.effectiveWindow() && len(session.queue) != 0 {
		packet := session.queue[0]
		session.queue[0] = VpnProto.Packet{}
		session.queue = session.queue[1:]
		session.pending = append(session.pending, outboundPendingPacket{
			Packet:     packet,
			RetryAt:    now.Add(streamOutboundInitialRetryDelay),
			RetryDelay: streamOutboundInitialRetryDelay,
		})
		return cloneOutboundPacket(packet), true
	}
	selectedIdx := -1
	for idx := range session.pending {
		if !session.pending[idx].RetryAt.After(now) {
			selectedIdx = idx
			break
		}
	}
	if selectedIdx < 0 {
		return VpnProto.Packet{}, false
	}
	packet := session.pending[selectedIdx].Packet
	delay := session.pending[selectedIdx].RetryDelay
	if delay <= 0 {
		delay = streamOutboundInitialRetryDelay
	}
	session.pending[selectedIdx].RetryAt = now.Add(delay)
	delay *= 2
	if delay > streamOutboundMaxRetryDelay {
		delay = streamOutboundMaxRetryDelay
	}
	session.pending[selectedIdx].RetryDelay = delay
	return cloneOutboundPacket(packet), true
}

func (s *streamOutboundStore) Ack(sessionID uint8, packetType uint8, streamID uint16, sequenceNum uint16) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil || len(session.pending) == 0 {
		return false
	}
	for idx := range session.pending {
		pending := session.pending[idx]
		if !matchesStreamOutboundAck(pending.Packet.PacketType, packetType) {
			continue
		}
		if pending.Packet.StreamID != streamID || pending.Packet.SequenceNum != sequenceNum {
			continue
		}
		copy(session.pending[idx:], session.pending[idx+1:])
		lastIdx := len(session.pending) - 1
		session.pending[lastIdx] = outboundPendingPacket{}
		session.pending = session.pending[:lastIdx]
		if len(session.pending) == 0 && len(session.queue) == 0 {
			delete(s.sessions, sessionID)
		}
		return true
	}
	return false
}

func (s *streamOutboundStore) ClearStream(sessionID uint8, streamID uint16) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		return
	}
	if len(session.pending) != 0 {
		filteredPending := session.pending[:0]
		for _, pending := range session.pending {
			if pending.Packet.StreamID != streamID {
				filteredPending = append(filteredPending, pending)
			}
		}
		for idx := len(filteredPending); idx < len(session.pending); idx++ {
			session.pending[idx] = outboundPendingPacket{}
		}
		session.pending = filteredPending
	}
	if len(session.queue) != 0 {
		filtered := session.queue[:0]
		for _, packet := range session.queue {
			if packet.StreamID != streamID {
				filtered = append(filtered, packet)
			}
		}
		session.queue = filtered
	}
	if len(session.pending) == 0 && len(session.queue) == 0 {
		delete(s.sessions, sessionID)
	}
}

func (s *streamOutboundStore) RemoveSession(sessionID uint8) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
}

func matchesStreamOutboundAck(pendingType uint8, ackType uint8) bool {
	switch pendingType {
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

func cloneOutboundPacket(packet VpnProto.Packet) VpnProto.Packet {
	packet.Payload = append([]byte(nil), packet.Payload...)
	return packet
}

func pruneOutboundStreamPackets(session *streamOutboundSession, streamID uint16) {
	if session == nil {
		return
	}
	if len(session.queue) != 0 {
		filteredQueue := session.queue[:0]
		for _, packet := range session.queue {
			if packet.StreamID != streamID {
				filteredQueue = append(filteredQueue, packet)
			}
		}
		for idx := len(filteredQueue); idx < len(session.queue); idx++ {
			session.queue[idx] = VpnProto.Packet{}
		}
		session.queue = filteredQueue
	}
	if len(session.pending) != 0 {
		filteredPending := session.pending[:0]
		for _, pending := range session.pending {
			if pending.Packet.StreamID != streamID {
				filteredPending = append(filteredPending, pending)
			}
		}
		for idx := len(filteredPending); idx < len(session.pending); idx++ {
			session.pending[idx] = outboundPendingPacket{}
		}
		session.pending = filteredPending
	}
}

func prependOutboundPacket(queue *[]VpnProto.Packet, packet VpnProto.Packet) {
	if queue == nil {
		return
	}
	*queue = append(*queue, VpnProto.Packet{})
	copy((*queue)[1:], (*queue)[:len(*queue)-1])
	(*queue)[0] = packet
}

func (s *streamOutboundStore) effectiveWindow() int {
	if s == nil || s.window < 1 {
		return 1
	}
	if s.window > 32 {
		return 32
	}
	return s.window
}
