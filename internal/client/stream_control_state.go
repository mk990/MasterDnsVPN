// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import "time"

func (c *Client) streamControlStateKey(packetType uint8, streamID uint16, sequenceNum uint16) streamControlStateKey {
	return streamControlStateKey{
		streamID:    streamID,
		sequenceNum: sequenceNum,
		packetType:  packetType,
	}
}

func (c *Client) getOrCreateStreamControlState(packetType uint8, streamID uint16, sequenceNum uint16, now time.Time) clientStreamControlState {
	if c == nil {
		return clientStreamControlState{}
	}
	key := c.streamControlStateKey(packetType, streamID, sequenceNum)
	c.streamControlStateMu.Lock()
	defer c.streamControlStateMu.Unlock()
	state, ok := c.streamControlStates[key]
	if !ok {
		state = clientStreamControlState{
			createdAt:  now,
			retryAt:    now,
			retryDelay: streamControlRetryBaseDelay,
		}
		c.streamControlStates[key] = state
	}
	return state
}

func (c *Client) updateStreamControlState(packetType uint8, streamID uint16, sequenceNum uint16, state clientStreamControlState) {
	if c == nil {
		return
	}
	key := c.streamControlStateKey(packetType, streamID, sequenceNum)
	c.streamControlStateMu.Lock()
	c.streamControlStates[key] = state
	c.streamControlStateMu.Unlock()
}

func (c *Client) noteStreamControlSend(packetType uint8, streamID uint16, sequenceNum uint16, sentAt time.Time) clientStreamControlState {
	state := c.getOrCreateStreamControlState(packetType, streamID, sequenceNum, sentAt)
	delay := state.retryDelay
	if delay <= 0 {
		delay = streamControlRetryBaseDelay
	}
	state.lastSentAt = sentAt
	state.retryAt = sentAt.Add(delay)
	state.retryCount++
	delay *= 2
	if delay > streamControlRetryMaxDelay {
		delay = streamControlRetryMaxDelay
	}
	state.retryDelay = delay
	c.updateStreamControlState(packetType, streamID, sequenceNum, state)
	return state
}

func (c *Client) clearStreamControlState(packetType uint8, streamID uint16, sequenceNum uint16) {
	if c == nil {
		return
	}
	key := c.streamControlStateKey(packetType, streamID, sequenceNum)
	c.streamControlStateMu.Lock()
	delete(c.streamControlStates, key)
	c.streamControlStateMu.Unlock()
}

func (c *Client) streamControlRetryAt(packetType uint8, streamID uint16, sequenceNum uint16) (time.Time, bool) {
	if c == nil {
		return time.Time{}, false
	}
	key := c.streamControlStateKey(packetType, streamID, sequenceNum)
	c.streamControlStateMu.Lock()
	defer c.streamControlStateMu.Unlock()
	state, ok := c.streamControlStates[key]
	if !ok {
		return time.Time{}, false
	}
	return state.retryAt, true
}
