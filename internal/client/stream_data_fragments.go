package client

import (
	"time"

	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (c *Client) collectInboundStreamDataFragments(packet VpnProto.Packet) ([]byte, bool, bool) {
	if c == nil || c.streamDataFragments == nil {
		return packet.Payload, true, false
	}
	totalFragments := packet.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	return c.streamDataFragments.Collect(
		clientStreamDataFragmentKey{
			streamID:    packet.StreamID,
			sequenceNum: packet.SequenceNum,
		},
		packet.Payload,
		packet.FragmentID,
		totalFragments,
		time.Now(),
		c.localDNSFragmentTimeout(),
	)
}

func (c *Client) removeStreamDataFragments(streamID uint16) {
	if c == nil || c.streamDataFragments == nil || streamID == 0 {
		return
	}
	c.streamDataFragments.RemoveIf(func(key clientStreamDataFragmentKey) bool {
		return key.streamID == streamID
	})
}

func clonePendingChunkMap(source map[uint16][]byte) map[uint16][]byte {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[uint16][]byte, len(source))
	for seq, payload := range source {
		cloned[seq] = append([]byte(nil), payload...)
	}
	return cloned
}

func drainClientInboundReadyChunks(stream *clientStream) [][]byte {
	if stream == nil || !stream.InboundNextSet || len(stream.InboundPending) == 0 {
		return nil
	}
	var ready [][]byte
	for {
		payload, ok := stream.InboundPending[stream.InboundNextSeq]
		if !ok {
			break
		}
		ready = append(ready, payload)
		delete(stream.InboundPending, stream.InboundNextSeq)
		stream.InboundDataSeq = stream.InboundNextSeq
		stream.InboundDataSet = true
		stream.InboundNextSeq++
		if stream.InboundNextSeq == 0 {
			stream.InboundNextSeq = 1
		}
	}
	return ready
}

var _ = fragmentStore.New[clientStreamDataFragmentKey]
