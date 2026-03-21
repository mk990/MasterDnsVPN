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
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (c *Client) handleAsyncServerPacket(packet VpnProto.Packet, timeout time.Duration) error {
	return c.handleFollowUpServerPacket(packet, timeout)
}

func (c *Client) pollServerPacketWithConnection(connection Connection, timeout time.Duration) (VpnProto.Packet, error) {
	payload, err := buildClientPingPayload()
	if err != nil {
		return VpnProto.Packet{}, err
	}
	return c.sendSessionControlPacketWithConnection(connection, Enums.PACKET_PING, payload, timeout)
}

func buildClientPingPayload() ([]byte, error) {
	payload := []byte{'P', 'O', ':'}
	randomPart, err := randomBytes(4)
	if err != nil {
		return nil, err
	}
	return append(payload, randomPart...), nil
}

func matchesExpectedStreamResponse(sentType uint8, streamID uint16, sequenceNum uint16, packet VpnProto.Packet) bool {
	if packet.StreamID != streamID || packet.SequenceNum != sequenceNum {
		return false
	}

	switch sentType {
	case Enums.PACKET_STREAM_SYN:
		return packet.PacketType == Enums.PACKET_STREAM_SYN_ACK
	case Enums.PACKET_SOCKS5_SYN:
		return packet.PacketType == Enums.PACKET_SOCKS5_SYN_ACK || isSOCKS5ErrorPacket(packet.PacketType)
	case Enums.PACKET_STREAM_DATA:
		return packet.PacketType == Enums.PACKET_STREAM_DATA_ACK
	case Enums.PACKET_STREAM_FIN:
		return packet.PacketType == Enums.PACKET_STREAM_FIN_ACK
	case Enums.PACKET_STREAM_RST:
		return packet.PacketType == Enums.PACKET_STREAM_RST_ACK
	default:
		return false
	}
}

type serverPacketDispatchResult struct {
	next        VpnProto.Packet
	hasNext     bool
	stop        bool
	ackedQueued bool
}

func (c *Client) applyClientACKState(packet VpnProto.Packet) {
	if c == nil {
		return
	}
	switch packet.PacketType {
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_DNS_QUERY_REQ_ACK:
		c.noteStreamProgress(packet.StreamID)
		if stream, ok := c.getStream(packet.StreamID); ok {
			if packet.PacketType == Enums.PACKET_STREAM_FIN_ACK {
				c.clearStreamControlState(Enums.PACKET_STREAM_FIN, packet.StreamID, packet.SequenceNum)
			}
			if packet.PacketType == Enums.PACKET_STREAM_RST_ACK {
				c.clearStreamControlState(Enums.PACKET_STREAM_RST, packet.StreamID, packet.SequenceNum)
			}
			notifyStreamWake(stream)
			if packet.PacketType == Enums.PACKET_STREAM_FIN_ACK && streamFinished(stream) {
				c.deleteStream(stream.ID)
			}
			if packet.PacketType == Enums.PACKET_STREAM_RST_ACK && stream.ID != 0 {
				stream.mu.Lock()
				stream.Closed = true
				stream.mu.Unlock()
				c.deleteStream(stream.ID)
			}
		}
	case Enums.PACKET_STREAM_SYN_ACK, Enums.PACKET_SOCKS5_SYN_ACK:
		c.noteStreamProgress(packet.StreamID)
		if packet.PacketType == Enums.PACKET_STREAM_SYN_ACK {
			c.clearStreamControlState(Enums.PACKET_STREAM_SYN, packet.StreamID, packet.SequenceNum)
		}
		if packet.PacketType == Enums.PACKET_SOCKS5_SYN_ACK {
			c.clearStreamControlState(Enums.PACKET_SOCKS5_SYN, packet.StreamID, packet.SequenceNum)
		}
	}
	if isCacheableStreamControlReply(packet.PacketType) {
		c.cacheStreamControlReply(packet)
	}
}

func (c *Client) dispatchServerPacket(packet VpnProto.Packet, timeout time.Duration, sent *arq.QueuedPacket) (serverPacketDispatchResult, error) {
	result := serverPacketDispatchResult{stop: true}
	if c == nil {
		return result, nil
	}

	if packet.PacketType != 0 && packet.PacketType != Enums.PACKET_PONG {
		c.pingManager.NotifyMeaningfulActivity()
	}

	if sent != nil && matchesQueuedPacketAck(*sent, packet.PacketType, packet.StreamID, packet.SequenceNum, packet.FragmentID, packet.TotalFragments) {
		result.ackedQueued = true
	}

	switch packet.PacketType {
	case 0, Enums.PACKET_PONG, Enums.PACKET_SESSION_BUSY:
		return result, nil
	case Enums.PACKET_ERROR_DROP:
		return result, c.handleServerDropPacket(packet)
	case Enums.PACKET_PACKED_CONTROL_BLOCKS:
		acked, err := c.handlePackedServerControlBlocksForQueuedPacket(packet.Payload, timeout, sent)
		result.ackedQueued = result.ackedQueued || acked
		return result, err
	case Enums.PACKET_DNS_QUERY_REQ_ACK:
		c.applyClientACKState(packet)
		return result, nil
	case Enums.PACKET_DNS_QUERY_RES:
		return result, c.handleInboundDNSResponseFragment(packet)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK:
		c.applyClientACKState(packet)
		return result, nil
	case Enums.PACKET_STREAM_SYN_ACK, Enums.PACKET_SOCKS5_SYN_ACK:
		c.applyClientACKState(packet)
		return result, nil
	default:
		if isSOCKS5ErrorPacket(packet.PacketType) {
			c.clearStreamControlState(Enums.PACKET_SOCKS5_SYN, packet.StreamID, packet.SequenceNum)
			c.applyClientACKState(packet)
			return result, nil
		}
		if packet.PacketType == Enums.PACKET_STREAM_DATA || packet.PacketType == Enums.PACKET_STREAM_FIN || packet.PacketType == Enums.PACKET_STREAM_RST {
			nextPacket, err := c.handleInboundStreamPacket(packet, timeout)
			if err != nil {
				return result, err
			}
			if nextPacket.PacketType != 0 {
				result.next = nextPacket
				result.hasNext = true
				result.stop = false
			}
		}
		return result, nil
	}
}
