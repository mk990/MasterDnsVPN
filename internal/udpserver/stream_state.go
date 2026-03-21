// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"net"
	"sync"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/streamutil"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	serverClosedStreamRecordTTL = 45 * time.Second
	serverClosedStreamRecordCap = 1000
	serverInboundReorderWindow  = 64
)

type streamStateRecord struct {
	SessionID      uint8
	StreamID       uint16
	State          uint8
	TargetHost     string
	TargetPort     uint16
	UpstreamConn   net.Conn
	Connected      bool
	CreatedAt      time.Time
	LastActivityAt time.Time
	LastSequence   uint16
	OutboundSeq    uint16
	InboundNextSeq uint16
	InboundNextSet bool
	InboundPending map[uint16][]byte
	RemoteFinSeq   uint16
	RemoteFinSet   bool
}

type inboundDataDecision struct {
	Ack          bool
	ReadyPayload [][]byte
}

type streamStateStore struct {
	mu       sync.Mutex
	sessions map[uint8]map[uint16]*streamStateRecord
	closed   map[uint8]map[uint16]int64
}

func newStreamStateStore() *streamStateStore {
	return &streamStateStore{
		sessions: make(map[uint8]map[uint16]*streamStateRecord, 32),
		closed:   make(map[uint8]map[uint16]int64, 32),
	}
}

func (s *streamStateStore) EnsureOpen(sessionID uint8, streamID uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	streams := s.sessions[sessionID]
	if streams == nil {
		streams = make(map[uint16]*streamStateRecord, 8)
		s.sessions[sessionID] = streams
	}

	if record := streams[streamID]; record != nil {
		record.LastActivityAt = now
		return cloneStreamStateRecord(record), false
	}

	record := &streamStateRecord{
		SessionID:      sessionID,
		StreamID:       streamID,
		State:          Enums.STREAM_STATE_OPEN,
		CreatedAt:      now,
		LastActivityAt: now,
	}
	streams[streamID] = record
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) BindTarget(sessionID uint8, streamID uint16, host string, port uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	if record.TargetHost != "" && (record.TargetHost != host || record.TargetPort != port) {
		return nil, false
	}
	record.TargetHost = host
	record.TargetPort = port
	record.LastActivityAt = now
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) AttachUpstream(sessionID uint8, streamID uint16, host string, port uint16, conn net.Conn, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		streamutil.SafeClose(conn)
		return nil, false
	}
	if record.UpstreamConn != nil && record.UpstreamConn != conn {
		streamutil.SafeClose(conn)
		return nil, false
	}
	record.TargetHost = host
	record.TargetPort = port
	record.UpstreamConn = conn
	record.Connected = conn != nil
	record.LastActivityAt = now
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) Touch(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) MarkRemoteFin(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	record.RemoteFinSeq = sequenceNum
	record.RemoteFinSet = true
	streamutil.CloseWrite(record.UpstreamConn)
	switch record.State {
	case Enums.STREAM_STATE_HALF_CLOSED_LOCAL:
		record.State = Enums.STREAM_STATE_DRAINING
	case Enums.STREAM_STATE_OPEN:
		record.State = Enums.STREAM_STATE_HALF_CLOSED_REMOTE
	}
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) ReceiveInboundData(sessionID uint8, streamID uint16, sequenceNum uint16, payload []byte, now time.Time) (*streamStateRecord, inboundDataDecision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, inboundDataDecision{}, false
	}
	prevSequence := record.LastSequence
	record.LastActivityAt = now
	record.LastSequence = sequenceNum

	if !record.InboundNextSet {
		nextSeq := prevSequence + 1
		if nextSeq == 0 {
			nextSeq = 1
		}
		record.InboundNextSeq = nextSeq
		record.InboundNextSet = true
	}

	lastDelivered := record.InboundNextSeq - 1
	if record.InboundNextSeq == 0 {
		lastDelivered = 0xFFFF
	}
	if streamutil.SequenceSeenOrOlder(lastDelivered, sequenceNum) {
		return cloneStreamStateRecord(record), inboundDataDecision{Ack: true}, true
	}

	diff := uint16(sequenceNum - record.InboundNextSeq)
	if diff > serverInboundReorderWindow {
		return cloneStreamStateRecord(record), inboundDataDecision{}, true
	}

	if record.InboundPending == nil {
		record.InboundPending = make(map[uint16][]byte, 8)
	}
	if _, exists := record.InboundPending[sequenceNum]; !exists {
		record.InboundPending[sequenceNum] = append([]byte(nil), payload...)
	}

	decision := inboundDataDecision{Ack: true}
	for {
		chunk, ok := record.InboundPending[record.InboundNextSeq]
		if !ok {
			break
		}
		decision.ReadyPayload = append(decision.ReadyPayload, chunk)
		delete(record.InboundPending, record.InboundNextSeq)
		record.InboundNextSeq++
		if record.InboundNextSeq == 0 {
			record.InboundNextSeq = 1
		}
	}

	return cloneStreamStateRecord(record), decision, true
}

func (s *streamStateStore) IsDuplicateRemoteFin(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	if record.RemoteFinSet && record.RemoteFinSeq == sequenceNum {
		return cloneStreamStateRecord(record), true, true
	}
	return cloneStreamStateRecord(record), true, false
}

func (s *streamStateStore) MarkLocalFin(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	switch record.State {
	case Enums.STREAM_STATE_HALF_CLOSED_REMOTE:
		record.State = Enums.STREAM_STATE_DRAINING
	case Enums.STREAM_STATE_OPEN:
		record.State = Enums.STREAM_STATE_HALF_CLOSED_LOCAL
	}
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) NextOutboundSequence(sessionID uint8, streamID uint16, now time.Time) (uint16, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return 0, false
	}
	record.LastActivityAt = now
	nextSeq := record.OutboundSeq + 1
	if nextSeq == 0 {
		nextSeq = 1
	}
	record.OutboundSeq = nextSeq
	return nextSeq, true
}

func (s *streamStateStore) ResetWithNextOutboundSequence(sessionID uint8, streamID uint16, now time.Time) (uint16, bool) {
	s.mu.Lock()
	streams := s.sessions[sessionID]
	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		s.mu.Unlock()
		return 0, false
	}

	nextSeq := record.OutboundSeq + 1
	if nextSeq == 0 {
		nextSeq = 1
	}
	record.OutboundSeq = nextSeq

	conn := record.UpstreamConn
	record.UpstreamConn = nil
	record.Connected = false
	record.LastActivityAt = now
	record.LastSequence = nextSeq
	record.State = Enums.STREAM_STATE_RESET
	s.noteClosedLocked(sessionID, streamID, now.UnixNano())
	delete(streams, streamID)
	if len(streams) == 0 {
		delete(s.sessions, sessionID)
	}
	s.mu.Unlock()

	streamutil.SafeClose(conn)
	return nextSeq, true
}

func (s *streamStateStore) MarkReset(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) bool {
	s.mu.Lock()
	streams := s.sessions[sessionID]
	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		s.mu.Unlock()
		return false
	}
	conn := record.UpstreamConn
	record.UpstreamConn = nil
	record.Connected = false
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	record.State = Enums.STREAM_STATE_RESET
	s.noteClosedLocked(sessionID, streamID, now.UnixNano())
	delete(streams, streamID)
	if len(streams) == 0 {
		delete(s.sessions, sessionID)
	}
	s.mu.Unlock()

	streamutil.SafeClose(conn)
	return true
}

func (s *streamStateStore) Lookup(sessionID uint8, streamID uint16) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) Exists(sessionID uint8, streamID uint16) bool {
	if s == nil || streamID == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookupLocked(sessionID, streamID) != nil
}

func (s *streamStateStore) RemoveSession(sessionID uint8) {
	s.mu.Lock()
	streams := s.sessions[sessionID]
	delete(s.sessions, sessionID)
	delete(s.closed, sessionID)
	s.mu.Unlock()
	for _, record := range streams {
		if record != nil {
			streamutil.SafeClose(record.UpstreamConn)
		}
	}
}

func (s *streamStateStore) HandleClosedPacket(sessionID uint8, streamID uint16, packetType uint8, sequenceNum uint16, now time.Time) (VpnProto.Packet, bool) {
	if s == nil || streamID == 0 {
		return VpnProto.Packet{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRecentlyClosedLocked(sessionID, streamID, now.UnixNano()) {
		return VpnProto.Packet{}, false
	}

	packet := VpnProto.Packet{
		StreamID:    streamID,
		SequenceNum: sequenceNum,
	}
	switch packetType {
	case Enums.PACKET_STREAM_FIN:
		packet.PacketType = Enums.PACKET_STREAM_FIN_ACK
		return packet, true
	case Enums.PACKET_STREAM_RST:
		packet.PacketType = Enums.PACKET_STREAM_RST_ACK
		return packet, true
	case Enums.PACKET_SOCKS5_SYN:
		packet.PacketType = Enums.PACKET_SOCKS5_CONNECT_FAIL
		packet.SequenceNum = 0
		return packet, true
	case Enums.PACKET_STREAM_SYN, Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND, Enums.PACKET_STREAM_DATA_ACK:
		packet.PacketType = Enums.PACKET_STREAM_RST
		packet.SequenceNum = 0
		return packet, true
	default:
		return VpnProto.Packet{}, false
	}
}

func (s *streamStateStore) lookupLocked(sessionID uint8, streamID uint16) *streamStateRecord {
	if streams, ok := s.sessions[sessionID]; ok {
		return streams[streamID]
	}
	return nil
}

func (s *streamStateStore) noteClosedLocked(sessionID uint8, streamID uint16, nowUnix int64) {
	if streamID == 0 {
		return
	}
	closed := s.closed[sessionID]
	if closed == nil {
		closed = make(map[uint16]int64, 8)
		s.closed[sessionID] = closed
	}
	expiredBefore := nowUnix - serverClosedStreamRecordTTL.Nanoseconds()
	for closedID, closedAt := range closed {
		if closedAt < expiredBefore {
			delete(closed, closedID)
		}
	}
	closed[streamID] = nowUnix
	if len(closed) <= serverClosedStreamRecordCap {
		return
	}

	var oldestID uint16
	var oldestAt int64
	first := true
	for closedID, closedAt := range closed {
		if first || closedAt < oldestAt {
			oldestID = closedID
			oldestAt = closedAt
			first = false
		}
	}
	delete(closed, oldestID)
}

func (s *streamStateStore) isRecentlyClosedLocked(sessionID uint8, streamID uint16, nowUnix int64) bool {
	closed := s.closed[sessionID]
	if len(closed) == 0 {
		return false
	}
	closedAt, ok := closed[streamID]
	if !ok {
		return false
	}
	if nowUnix-closedAt <= serverClosedStreamRecordTTL.Nanoseconds() {
		return true
	}
	delete(closed, streamID)
	if len(closed) == 0 {
		delete(s.closed, sessionID)
	}
	return false
}

func cloneStreamStateRecord(record *streamStateRecord) *streamStateRecord {
	if record == nil {
		return nil
	}
	cloned := *record
	cloned.InboundPending = nil
	return &cloned
}
