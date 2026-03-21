// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type clientDNSFragmentKey struct {
	sessionID   uint8
	sequenceNum uint16
}

func (c *Client) localDNSFragmentTimeout() time.Duration {
	if c == nil || c.localDNSFragTTL <= 0 {
		return 5 * time.Minute
	}
	return c.localDNSFragTTL
}

func (c *Client) hasPendingDNSWork() bool {
	if c == nil {
		return false
	}
	s, ok := c.getStream(0)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.TXQueue) > 0
}

func (c *Client) queueDNSDispatch(request *dnsDispatchRequest) {
	if c == nil || request == nil || len(request.Query) == 0 {
		return
	}

	if !c.SessionReady() {
		return
	}

	c.QueueControlPacket(Enums.PACKET_DNS_QUERY_REQ, request.Query)
}

func (c *Client) handleInboundDNSResponseFragment(packet VpnProto.Packet) error {
	if c == nil || c.dnsResponses == nil || packet.PacketType != Enums.PACKET_DNS_QUERY_RES || !packet.HasSequenceNum {
		return nil
	}

	if c.log != nil {
		c.log.Debugf(
			"\U0001F9E9 <blue>Resolved Tunnel DNS Request, Seq: <cyan>%d</cyan> | Fragment: <cyan>%d/%d</cyan></blue>",
			packet.SequenceNum,
			packet.FragmentID+1,
			max(1, int(packet.TotalFragments)),
		)
	}

	_ = c.sendStreamProtocolOneWay(Enums.PACKET_DNS_QUERY_RES_ACK, 0, packet.SequenceNum, nil, time.Second)

	now := c.now()
	assembled, ready, completed := c.dnsResponses.Collect(
		clientDNSFragmentKey{
			sessionID:   packet.SessionID,
			sequenceNum: packet.SequenceNum,
		},
		packet.Payload,
		packet.FragmentID,
		packet.TotalFragments,
		now,
		c.localDNSFragTTL,
	)

	if completed || !ready || len(assembled) == 0 {
		return nil
	}

	parsed, err := DnsParser.ParsePacketLite(assembled)
	if err != nil || !parsed.HasQuestion {
		return nil
	}

	if shouldCacheTunnelDNSResponse(assembled) {
		cacheKey := dnscache.BuildKey(
			parsed.FirstQuestion.Name,
			parsed.FirstQuestion.Type,
			parsed.FirstQuestion.Class,
		)
		c.persistResolvedLocalDNSCacheEntry(
			cacheKey,
			parsed.FirstQuestion.Name,
			parsed.FirstQuestion.Type,
			parsed.FirstQuestion.Class,
			assembled,
			now,
		)
	}

	return nil
}

func arqQueuedDNSAck(packet VpnProto.Packet) arq.QueuedPacket {
	totalFragments := packet.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	return arq.QueuedPacket{
		PacketType:     Enums.PACKET_DNS_QUERY_RES_ACK,
		StreamID:       0,
		SequenceNum:    packet.SequenceNum,
		FragmentID:     packet.FragmentID,
		TotalFragments: totalFragments,
		Priority:       arq.DefaultPriorityForPacket(Enums.PACKET_DNS_QUERY_RES_ACK),
	}
}
