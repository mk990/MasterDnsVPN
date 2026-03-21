package udpserver

import (
	"time"

	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type streamDataFragmentKey struct {
	sessionID   uint8
	streamID    uint16
	sequenceNum uint16
}

func (s *Server) collectStreamDataFragments(packet VpnProto.Packet, now time.Time) ([]byte, bool, bool) {
	if s == nil || s.streamDataFragments == nil {
		return packet.Payload, true, false
	}
	totalFragments := packet.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	return s.streamDataFragments.Collect(
		streamDataFragmentKey{
			sessionID:   packet.SessionID,
			streamID:    packet.StreamID,
			sequenceNum: packet.SequenceNum,
		},
		packet.Payload,
		packet.FragmentID,
		totalFragments,
		now,
		s.dnsFragmentTimeout,
	)
}

func (s *Server) purgeStreamDataFragments(now time.Time) {
	if s == nil || s.streamDataFragments == nil {
		return
	}
	s.streamDataFragments.Purge(now, s.dnsFragmentTimeout)
}

func (s *Server) removeStreamDataFragmentsForSession(sessionID uint8) {
	if s == nil || s.streamDataFragments == nil || sessionID == 0 {
		return
	}
	s.streamDataFragments.RemoveIf(func(key streamDataFragmentKey) bool {
		return key.sessionID == sessionID
	})
}

func (s *Server) removeStreamDataFragmentsForStream(sessionID uint8, streamID uint16) {
	if s == nil || s.streamDataFragments == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.streamDataFragments.RemoveIf(func(key streamDataFragmentKey) bool {
		return key.sessionID == sessionID && key.streamID == streamID
	})
}
