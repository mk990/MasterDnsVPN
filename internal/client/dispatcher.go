// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"sort"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

const PackedControlBlockSize = 7

func isPackableControlPacket(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_DNS_QUERY_RES_ACK, Enums.PACKET_STREAM_SYN, Enums.PACKET_STREAM_SYN_ACK,
		Enums.PACKET_STREAM_FIN, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST,
		Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_SOCKS5_SYN_ACK, Enums.PACKET_SOCKS5_CONNECT_FAIL,
		Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK, Enums.PACKET_SOCKS5_RULESET_DENIED,
		Enums.PACKET_SOCKS5_RULESET_DENIED_ACK, Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK, Enums.PACKET_SOCKS5_HOST_UNREACHABLE,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK, Enums.PACKET_SOCKS5_CONNECTION_REFUSED,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK, Enums.PACKET_SOCKS5_TTL_EXPIRED,
		Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK, Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK, Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK, Enums.PACKET_SOCKS5_AUTH_FAILED,
		Enums.PACKET_SOCKS5_AUTH_FAILED_ACK, Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK:
		return true
	default:
		return false
	}
}

func appendPackedControlBlockFromClient(dst []byte, p *clientStreamTXPacket, streamID uint16) []byte {
	return append(
		dst,
		p.PacketType,
		byte(streamID>>8),
		byte(streamID),
		byte(p.SequenceNum>>8),
		byte(p.SequenceNum),
		0, 0, // Fragment ID and Total Fragments (always 0 for control blocks from client streams)
	)
}

// selectTargetConnections determines how many redundant packets should be sent and which connections to use.
func (c *Client) selectTargetConnections(packetType uint8, streamID uint16) []Connection {
	targetCount := c.cfg.PacketDuplicationCount
	if targetCount < 1 {
		targetCount = 1
	}

	// SYN packets often use higher duplication for reliability during handshake
	if packetType == Enums.PACKET_STREAM_SYN || packetType == Enums.PACKET_SOCKS5_SYN {
		if c.cfg.SetupPacketDuplicationCount > targetCount {
			targetCount = c.cfg.SetupPacketDuplicationCount
		}
	}

	// If duplication is disabled, just return the best connection (preferred if possible)
	if targetCount <= 1 {
		if streamID > 0 {
			c.streamsMu.RLock()
			s := c.active_streams[streamID]
			c.streamsMu.RUnlock()
			if s != nil && s.PreferredServerKey != "" {
				if idx, ok := c.connectionsByKey[s.PreferredServerKey]; ok {
					return []Connection{c.connections[idx]}
				}
			}
		}
		best, ok := c.balancer.GetBestConnection()
		if ok {
			return []Connection{best}
		}
		return nil
	}

	// For multiple packets, use unique connections from balancer
	return c.balancer.GetUniqueConnections(targetCount)
}

// asyncStreamDispatcher cycles through all active streams using a fair Round-Robin algorithm
// and transmits the highest priority packets to the TX workers, packing control blocks when possible.
func (c *Client) asyncStreamDispatcher(ctx context.Context) {
	c.log.Debugf("🚀 <cyan>Stream Dispatcher started</cyan>")
	defer c.asyncWG.Done()

	var rrCursor uint16 = 0

	for {
		// Wait for signal or timeout
		select {
		case <-ctx.Done():
			return
		case <-c.txSignal:
		case <-time.After(20 * time.Millisecond):
		}

		c.streamsMu.RLock()
		streamCount := len(c.active_streams)
		if streamCount == 0 {
			c.streamsMu.RUnlock()
			continue
		}

		ids := make([]uint16, 0, streamCount)
		for id := range c.active_streams {
			ids = append(ids, id)
		}
		c.streamsMu.RUnlock()

		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

		highestPrio := -1
		for _, id := range ids {
			c.streamsMu.RLock()
			s := c.active_streams[id]
			c.streamsMu.RUnlock()
			if s == nil || s.txQueue == nil {
				continue
			}
			p := s.txQueue.HighestPriority()
			if p != -1 {
				if highestPrio == -1 || p < highestPrio {
					highestPrio = p
				}
			}
		}

		if highestPrio == -1 {
			continue
		}

		// Find candidates having this highest priority
		var candidates []*Stream_client
		for _, id := range ids {
			c.streamsMu.RLock()
			s := c.active_streams[id]
			c.streamsMu.RUnlock()
			if s != nil && s.txQueue != nil && s.txQueue.HighestPriority() == highestPrio {
				candidates = append(candidates, s)
			}
		}

		if len(candidates) == 0 {
			continue
		}

		// Fair Round-Robin Pick
		var selected *Stream_client
		for _, s := range candidates {
			if s.StreamID >= rrCursor {
				selected = s
				break
			}
		}
		if selected == nil {
			selected = candidates[0] // Wrap around
		}

		rrCursor = selected.StreamID + 1

		item, prio, ok := selected.PopNextTXPacket()
		if !ok || item == nil {
			continue
		}

		var finalPacket asyncPacket
		wasPacked := false
		maxBlocks := c.maxPackedBlocks
		if maxBlocks < 1 {
			maxBlocks = 1
		}

		if isPackableControlPacket(item.PacketType) && maxBlocks > 1 {
			payload := make([]byte, 0, maxBlocks*PackedControlBlockSize)
			payload = appendPackedControlBlockFromClient(payload, item, selected.StreamID)
			blocks := 1

			// Pop more from current stream if possible
			for blocks < maxBlocks {
				popped, poppedOk := selected.txQueue.PopIf(prio, func(p *clientStreamTXPacket) bool {
					return isPackableControlPacket(p.PacketType)
				}, nil)
				if !poppedOk {
					break
				}
				payload = appendPackedControlBlockFromClient(payload, popped, selected.StreamID)
				blocks++
				selected.ReleaseTXPacket(popped)
			}

			// Pop from other streams to fill block if space remains
			if blocks < maxBlocks {
				for _, sid := range ids {
					if blocks >= maxBlocks {
						break
					}
					if sid == selected.StreamID {
						continue
					}

					c.streamsMu.RLock()
					otherStream := c.active_streams[sid]
					c.streamsMu.RUnlock()

					if otherStream == nil || otherStream.txQueue == nil {
						continue
					}
					for blocks < maxBlocks {
						popped, poppedOk := otherStream.txQueue.PopIf(prio, func(p *clientStreamTXPacket) bool {
							return isPackableControlPacket(p.PacketType)
						}, nil)
						if !poppedOk {
							break
						}
						payload = appendPackedControlBlockFromClient(payload, popped, sid)
						blocks++
						otherStream.ReleaseTXPacket(popped)
					}
				}
			}

			if blocks > 1 {
				// Send as packed controls
				finalPacket = asyncPacket{
					packetType: Enums.PACKET_PACKED_CONTROL_BLOCKS,
					payload:    payload,
				}
				selected.ReleaseTXPacket(item)
				wasPacked = true
			} else {
				// Fallback natively if only 1 block found
				finalPacket = asyncPacket{
					packetType: item.PacketType,
					payload:    item.Payload,
				}
			}
		} else {
			finalPacket = asyncPacket{
				packetType: item.PacketType,
				payload:    item.Payload,
			}
		}

		// Packet Duplication Logic
		conns := c.selectTargetConnections(finalPacket.packetType, selected.StreamID)
		if len(conns) == 0 {
			if !wasPacked {
				selected.ReleaseTXPacket(item)
			}
			continue
		}

		for _, conn := range conns {
			pkt := finalPacket
			pkt.conn = conn

			// Send to TX channel
			select {
			case c.txChannel <- pkt:
			default:
				// Channel full, drop or wait? Python TX worker might be slow.
				// In Go, we'll try to push to avoid blocking the dispatcher too much.
			}
		}

		if !wasPacked {
			selected.ReleaseTXPacket(item)
		}

		// Loop quickly if there's more potential work
		select {
		case c.txSignal <- struct{}{}:
		default:
		}
	}
}
