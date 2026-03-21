// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrStream0RuntimeStopped = errors.New("stream 0 runtime stopped")

var (
	stream0DNSRetryBaseDelay       = 350 * time.Millisecond
	stream0DNSRetryMaxDelay        = 2 * time.Second
	stream0DNSOnlyWarmDuration     = 30 * time.Second
	stream0DNSOnlyWarmPingInterval = time.Second
	stream0PingIdleHighThreshold   = 10 * time.Second
	stream0PingIdleMediumThreshold = 5 * time.Second
	stream0DNSOnlyPingInterval     = 10 * time.Second
	stream0PingHighIdleInterval    = 3 * time.Second
	stream0PingMediumIdleInterval  = time.Second
	stream0PingBusyInterval        = 200 * time.Millisecond
	stream0DNSOnlyWarmMaxSleep     = 500 * time.Millisecond
	stream0PingDNSOnlyMaxSleep     = time.Second
	stream0PingHighIdleMaxSleep    = 500 * time.Millisecond
	stream0PingMediumIdleMaxSleep  = 200 * time.Millisecond
	stream0PingBusyMaxSleep        = 180 * time.Millisecond
)

type stream0DNSRequestState struct {
	fragments map[uint8]*stream0DNSFragmentState
}

type stream0DNSFragmentState struct {
	packet     arq.QueuedPacket
	createdAt  time.Time
	retryAt    time.Time
	retryDelay time.Duration
	retryCount int
	scheduled  bool
}

type stream0Runtime struct {
	client    *Client
	scheduler *arq.Scheduler

	mu               sync.Mutex
	schedulerMu      sync.Mutex
	running          atomic.Bool
	inFlight         atomic.Int32
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	wakeCh           chan struct{}
	dnsRequests      map[uint16]*stream0DNSRequestState
	dnsActivitySeen  atomic.Bool
	lastDataActivity atomic.Int64 // UnixNano
	lastPingTime     atomic.Int64 // UnixNano
}

func newStream0Runtime(client *Client) *stream0Runtime {
	now := time.Now().UnixNano()
	r := &stream0Runtime{
		client:      client,
		scheduler:   arq.NewScheduler(1),
		wakeCh:      make(chan struct{}, 1),
		dnsRequests: make(map[uint16]*stream0DNSRequestState, 16),
	}
	r.lastDataActivity.Store(now)
	r.lastPingTime.Store(now)
	return r
}

func (r *stream0Runtime) Start(parent context.Context) error {
	if r == nil {
		return ErrStream0RuntimeStopped
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running.Load() {
		return nil
	}

	if parent == nil {
		parent = context.Background()
	}
	r.ctx, r.cancel = context.WithCancel(parent)
	r.running.Store(true)

	now := time.Now().UnixNano()
	r.lastDataActivity.Store(now)
	r.lastPingTime.Store(now)

	r.schedulerMu.Lock()
	r.scheduler.SetMaxPackedBlocks(r.client.MaxPackedBlocks())
	r.schedulerMu.Unlock()
	r.wg.Add(2)
	go r.txLoop()
	go r.pingLoop()
	return nil
}

func (r *stream0Runtime) IsRunning() bool {
	if r == nil {
		return false
	}
	return r.running.Load()
}

func (r *stream0Runtime) SetMaxPackedBlocks(limit int) {
	if r == nil {
		return
	}
	r.schedulerMu.Lock()
	r.scheduler.SetMaxPackedBlocks(limit)
	r.schedulerMu.Unlock()
}

func (r *stream0Runtime) NotifyDNSActivity() {
	if r == nil {
		return
	}
	r.dnsActivitySeen.Store(true)
	r.lastDataActivity.Store(time.Now().UnixNano())
}

func (r *stream0Runtime) QueueMainPacket(packet arq.QueuedPacket) bool {
	if r == nil || !r.IsRunning() || r.client == nil || !r.client.SessionReady() {
		return false
	}
	if packet.Priority == 0 {
		packet.Priority = arq.DefaultPriorityForPacket(packet.PacketType)
	}
	if !r.enqueuePacket(arq.QueueTargetMain, packet) {
		return false
	}
	if r.client != nil && r.client.log != nil {
		r.client.log.Debugf(
			"🚀 <blue>Queued Main Packet, Packet: <cyan>%s</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan> | InFlight: <cyan>%d</cyan></blue>",
			Enums.PacketTypeName(packet.PacketType),
			packet.SequenceNum,
			len(packet.Payload),
			r.inFlight.Load(),
		)
	}
	r.notifyWake()
	return true
}

func (r *stream0Runtime) QueueDNSRequest(payload []byte) error {
	if r == nil || !r.IsRunning() {
		return ErrStream0RuntimeStopped
	}
	if r.client == nil || !r.client.SessionReady() {
		return ErrSessionInitFailed
	}

	fragments, err := r.client.fragmentQueuedMainPayload(Enums.PACKET_DNS_QUERY_REQ, payload)
	if err != nil {
		return err
	}

	sequenceNum := r.client.nextMainSequence()
	now := time.Now()
	state := &stream0DNSRequestState{
		fragments: make(map[uint8]*stream0DNSFragmentState, len(fragments)),
	}

	for fragmentID, fragmentPayload := range fragments {
		packet := arq.QueuedPacket{
			PacketType:      Enums.PACKET_DNS_QUERY_REQ,
			StreamID:        0,
			SequenceNum:     sequenceNum,
			FragmentID:      uint8(fragmentID),
			TotalFragments:  uint8(len(fragments)),
			CompressionType: r.client.uploadCompression,
			Payload:         fragmentPayload,
			Priority:        arq.DefaultPriorityForPacket(Enums.PACKET_DNS_QUERY_REQ),
		}
		if !r.enqueuePacket(arq.QueueTargetMain, packet) {
			r.mu.Lock()
			delete(r.dnsRequests, sequenceNum)
			r.mu.Unlock()
			return ErrTunnelDNSDispatchFailed
		}
		state.fragments[uint8(fragmentID)] = &stream0DNSFragmentState{
			packet:     packet,
			createdAt:  now,
			retryAt:    now.Add(stream0DNSRetryBaseDelay),
			retryDelay: stream0DNSRetryBaseDelay,
			scheduled:  true,
		}
	}

	r.mu.Lock()
	if !r.running.Load() {
		r.mu.Unlock()
		return ErrStream0RuntimeStopped
	}
	r.dnsRequests[sequenceNum] = state
	r.mu.Unlock()

	r.dnsActivitySeen.Store(true)
	r.lastDataActivity.Store(now.UnixNano())

	r.notifyWake()
	return nil
}

func (r *stream0Runtime) QueuePing() bool {
	if r == nil || !r.IsRunning() || r.client == nil || !r.client.SessionReady() {
		return false
	}
	if r.pendingPings() > 0 {
		return false
	}

	payload, err := buildClientPingPayload()
	if err != nil {
		return false
	}

	if !r.enqueuePacket(arq.QueueTargetMain, arq.QueuedPacket{
		PacketType: Enums.PACKET_PING,
		Payload:    payload,
		Priority:   arq.DefaultPriorityForPacket(Enums.PACKET_PING),
	}) {
		return false
	}
	if r.client != nil && r.client.log != nil {
		r.client.log.Debugf(
			"🏓 <blue>Queued Poll Ping | InFlight: <cyan>%d</cyan></blue>",
			r.inFlight.Load(),
		)
	}
	r.notifyWake()
	return true
}

func (r *stream0Runtime) QueueStreamPacket(streamID uint16, packetType uint8, sequenceNum uint16, payload []byte) bool {
	if r == nil || !r.IsRunning() || streamID == 0 || r.client == nil || !r.client.SessionReady() {
		return false
	}
	if !r.enqueuePacket(arq.QueueTargetStream, arq.QueuedPacket{
		PacketType:  packetType,
		StreamID:    streamID,
		SequenceNum: sequenceNum,
		Payload:     payload,
		Priority:    arq.DefaultPriorityForPacket(packetType),
	}) {
		return false
	}
	if r.client != nil && r.client.log != nil {
		r.client.log.Debugf(
			"🚀 <blue>Queued Runtime Stream Packet, Stream ID: <cyan>%d</cyan> | Packet: <cyan>%s</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan> | InFlight: <cyan>%d</cyan></blue>",
			streamID,
			Enums.PacketTypeName(packetType),
			sequenceNum,
			len(payload),
			r.inFlight.Load(),
		)
	}
	r.notifyWake()
	return true
}

func (r *stream0Runtime) txLoop() {
	defer r.wg.Done()
	for {
		if r.ctx.Err() != nil {
			r.failAllPending()
			return
		}

		dispatched := false
		for r.canDispatchMore() {
			result, ok := r.dequeuePacket()
			if !ok {
				break
			}
			if r.client != nil && r.client.log != nil {
				r.client.log.Debugf(
					"🚀 <blue>Dequeued Runtime Packet, Packet: <cyan>%s</cyan> | Stream: <cyan>%d</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan> | InFlight: <cyan>%d/%d</cyan></blue>",
					Enums.PacketTypeName(result.Packet.PacketType),
					result.Packet.StreamID,
					result.Packet.SequenceNum,
					len(result.Packet.Payload),
					r.inFlight.Load(),
					r.dispatchLimit(),
				)
			}
			dispatched = true
			r.dispatchPacket(result.Packet)
		}
		if dispatched {
			continue
		}

		select {
		case <-r.ctx.Done():
			r.failAllPending()
			return
		case <-r.wakeCh:
		}
	}
}

func (r *stream0Runtime) pingLoop() {
	defer r.wg.Done()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		now := time.Now()
		if r.client != nil && r.client.dnsResponses != nil {
			r.client.dnsResponses.Purge(now, r.client.localDNSFragmentTimeout())
		}
		retrySleep := r.queueDueDNSRetries(now)
		shouldPing, pingSleep := r.nextPingSchedule(now)
		if shouldPing {
			if r.QueuePing() {
				r.lastPingTime.Store(now.UnixNano())
			}
		}

		sleepFor := minPositiveDuration(retrySleep, pingSleep)
		if sleepFor <= 0 {
			sleepFor = 100 * time.Millisecond
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(sleepFor)
		select {
		case <-r.ctx.Done():
			return
		case <-timer.C:
		}
	}
}

func (r *stream0Runtime) nextPingSchedule(now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	hasPendingDNS := r.client != nil && r.client.hasPendingDNSWork()
	activeStreams := 0
	hasStreamTXWork := false
	hasControlWork := false
	if r.client != nil {
		activeStreams = r.client.activeStreamCount()
		hasStreamTXWork = r.client.hasActiveStreamTXWork()
		hasControlWork = r.client.hasPendingStreamControlWork()
	}

	lastPingTime := time.Unix(0, r.lastPingTime.Load())
	lastDataActivity := time.Unix(0, r.lastDataActivity.Load())
	timeSinceLastPing := now.Sub(lastPingTime)
	idleTime := now.Sub(lastDataActivity)

	// Default: 30s keep-alive for everything
	pingInterval := 30 * time.Second
	maxSleep := time.Second

	// Context-aware interval optimization
	if activeStreams > 0 || hasControlWork {
		if hasStreamTXWork {
			pingInterval = 80 * time.Millisecond
			maxSleep = 50 * time.Millisecond
		} else if hasControlWork {
			pingInterval = 100 * time.Millisecond
			maxSleep = 60 * time.Millisecond
		} else if !r.dnsActivitySeen.Load() {
			// Session is active but no DNS traffic yet, ping slowly but consistently
			pingInterval = 2 * time.Second
			maxSleep = 250 * time.Millisecond
		} else if idleTime < stream0PingIdleMediumThreshold {
			// Very active data flow
			pingInterval = 120 * time.Millisecond
			maxSleep = 80 * time.Millisecond
		} else if idleTime < stream0PingIdleHighThreshold {
			// Moderate activity
			pingInterval = 300 * time.Millisecond
			maxSleep = 120 * time.Millisecond
		} else {
			// High idle but still has active streams
			pingInterval = 750 * time.Millisecond
			maxSleep = 200 * time.Millisecond
		}
	} else if hasPendingDNS {
		if idleTime < stream0DNSOnlyWarmDuration {
			// DNS is active and "warm"
			pingInterval = stream0DNSOnlyWarmPingInterval
			maxSleep = stream0DNSOnlyWarmMaxSleep
		} else {
			// DNS is active but "cold"
			pingInterval = stream0DNSOnlyPingInterval
			maxSleep = stream0PingDNSOnlyMaxSleep
		}
	}

	// Safety cap at 30s for ALL conditions (Keep-alive)
	if pingInterval > 30*time.Second {
		pingInterval = 30 * time.Second
	}

	if timeSinceLastPing >= pingInterval {
		return true, pingInterval
	}

	sleepFor := pingInterval - timeSinceLastPing
	if sleepFor > maxSleep {
		sleepFor = maxSleep
	}
	return false, sleepFor
}

func (r *stream0Runtime) processDequeue(packet arq.QueuedPacket) {
	defer arq.FreePayload(packet.Payload)

	if packet.PacketType != Enums.PACKET_PING {
		sentAt := time.Now()
		if r.client.log != nil {
			r.client.log.Debugf(
				"🚀 <blue>Shooting Runtime Packet, Packet: <cyan>%s</cyan> | Stream: <cyan>%d</cyan> | Seq: <cyan>%d</cyan> | Bytes: <cyan>%d</cyan> | InFlight: <cyan>%d</cyan></blue>",
				Enums.PacketTypeName(packet.PacketType),
				packet.StreamID,
				packet.SequenceNum,
				len(packet.Payload),
				r.inFlight.Load(),
			)
		}
		if err := r.client.sendQueuedRuntimePacket(packet); err != nil {
			r.handleDequeueFailure(packet, sentAt)
			return
		}
		if r.client.log != nil {
			r.client.log.Debugf(
				"🚀 <blue>Shot Runtime Packet, Packet: <cyan>%s</cyan> | Stream: <cyan>%d</cyan> | Seq: <cyan>%d</cyan> | Elapsed: <cyan>%s</cyan></blue>",
				Enums.PacketTypeName(packet.PacketType),
				packet.StreamID,
				packet.SequenceNum,
				time.Since(sentAt).Round(time.Millisecond),
			)
		}
		if r.client.sessionResetPending.Load() {
			return
		}
		switch {
		case packet.StreamID != 0:
			armClientStreamTXRetry(r.client, packet.StreamID, packet.SequenceNum, sentAt)
		case packet.PacketType == Enums.PACKET_DNS_QUERY_REQ:
			r.armDNSRequestFragmentRetry(packet, sentAt)
		}
		return
	}

	response, err := r.client.sendScheduledPacket(packet)
	if err != nil {
		if r.client != nil && r.client.log != nil {
			r.client.log.Debugf(
				"🏓 <yellow>Runtime Packet Roundtrip Failed, Packet: <cyan>%s</cyan> | Stream: <cyan>%d</cyan> | Seq: <cyan>%d</cyan></yellow>",
				Enums.PacketTypeName(packet.PacketType),
				packet.StreamID,
				packet.SequenceNum,
			)
		}
		r.handleDequeueFailure(packet, time.Now())
		return
	}
	if r.client != nil && r.client.log != nil {
		r.client.log.Debugf(
			"🏓 <blue>Runtime Packet Reply Received, Sent: <cyan>%s</cyan> | Reply: <cyan>%s</cyan> | Stream: <cyan>%d</cyan> | Seq: <cyan>%d</cyan></blue>",
			Enums.PacketTypeName(packet.PacketType),
			Enums.PacketTypeName(response.PacketType),
			packet.StreamID,
			packet.SequenceNum,
		)
	}

	queuedAcked := false
	now := time.Now()
	if response.PacketType != 0 {
		r.noteServerDataActivity()
		dispatch, dispatchErr := r.client.dispatchServerPacket(response, time.Second, &packet)
		queuedAcked = dispatch.ackedQueued
		if dispatchErr != nil && !errors.Is(dispatchErr, ErrSessionDropped) && r.client.log != nil {
			r.client.log.Debugf(
				"🧵 <yellow>Runtime Packet Dispatch Failed: <cyan>%v</cyan></yellow>",
				dispatchErr,
			)
		}
		if dispatch.hasNext {
			if err := r.client.handleFollowUpServerPacket(dispatch.next, time.Second); err != nil && r.client.log != nil {
				r.client.log.Debugf(
					"🧵 <yellow>Runtime Follow-up Handling Failed: <cyan>%v</cyan></yellow>",
					err,
				)
			}
		}
	}

	if r.client != nil && r.client.sessionResetPending.Load() {
		return
	}

	switch {
	case packet.StreamID != 0:
		if !queuedAcked && !isResolvedStreamPacketResponse(packet, response) {
			r.rescheduleStreamPacket(packet.StreamID, packet.SequenceNum)
		}
	case packet.PacketType == Enums.PACKET_DNS_QUERY_REQ:
		if !queuedAcked {
			r.rescheduleDNSRequestFragment(packet, now)
		}
	}
}

func (r *stream0Runtime) handleDequeueFailure(packet arq.QueuedPacket, now time.Time) {
	if r != nil && r.client != nil && r.client.sessionResetPending.Load() {
		return
	}
	switch {
	case packet.StreamID != 0:
		r.rescheduleStreamPacket(packet.StreamID, packet.SequenceNum)
	case packet.PacketType == Enums.PACKET_DNS_QUERY_REQ:
		r.rescheduleDNSRequestFragment(packet, now)
	}
}

func (r *stream0Runtime) ackDNSRequestFragment(packet VpnProto.Packet) bool {
	if packet.PacketType != Enums.PACKET_DNS_QUERY_REQ_ACK || !packet.HasSequenceNum {
		return false
	}
	totalFragments := packet.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	state := r.dnsRequests[packet.SequenceNum]
	if state == nil {
		return false
	}
	fragment := state.fragments[packet.FragmentID]
	if fragment == nil {
		return false
	}
	if fragment.packet.TotalFragments != totalFragments {
		return false
	}
	delete(state.fragments, packet.FragmentID)
	if len(state.fragments) == 0 {
		delete(r.dnsRequests, packet.SequenceNum)
	}
	return true
}

func (r *stream0Runtime) completeDNSRequest(sequenceNum uint16) bool {
	if r == nil || sequenceNum == 0 {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.dnsRequests[sequenceNum]; !ok {
		return false
	}
	delete(r.dnsRequests, sequenceNum)
	return true
}

func (r *stream0Runtime) rescheduleDNSRequestFragment(packet arq.QueuedPacket, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state := r.dnsRequests[packet.SequenceNum]
	if state == nil {
		return
	}
	fragment := state.fragments[packet.FragmentID]
	if fragment == nil {
		return
	}
	if now.Sub(fragment.createdAt) >= r.client.localDNSFragmentTimeout() {
		delete(state.fragments, packet.FragmentID)
		if len(state.fragments) == 0 {
			delete(r.dnsRequests, packet.SequenceNum)
		}
		return
	}
	delay := fragment.retryDelay
	if delay <= 0 {
		delay = stream0DNSRetryBaseDelay
	}
	fragment.scheduled = false
	fragment.retryAt = now.Add(delay)
	fragment.retryCount++
	delay *= 2
	if delay > stream0DNSRetryMaxDelay {
		delay = stream0DNSRetryMaxDelay
	}
	fragment.retryDelay = delay
}

func (r *stream0Runtime) armDNSRequestFragmentRetry(packet arq.QueuedPacket, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state := r.dnsRequests[packet.SequenceNum]
	if state == nil {
		return
	}
	fragment := state.fragments[packet.FragmentID]
	if fragment == nil {
		return
	}
	delay := fragment.retryDelay
	if delay <= 0 {
		delay = stream0DNSRetryBaseDelay
	}
	fragment.scheduled = false
	fragment.retryAt = now.Add(delay)
}

func (r *stream0Runtime) queueDueDNSRetries(now time.Time) time.Duration {
	if r == nil || r.client == nil {
		return time.Second
	}

	timeout := r.client.localDNSFragmentTimeout()
	nextWait := time.Second
	due := make([]arq.QueuedPacket, 0, 4)

	r.mu.Lock()
	for sequenceNum, state := range r.dnsRequests {
		if state == nil || len(state.fragments) == 0 {
			delete(r.dnsRequests, sequenceNum)
			continue
		}
		for fragmentID, fragment := range state.fragments {
			if fragment == nil {
				delete(state.fragments, fragmentID)
				continue
			}
			if now.Sub(fragment.createdAt) >= timeout {
				delete(state.fragments, fragmentID)
				continue
			}
			if fragment.scheduled {
				continue
			}
			if !fragment.retryAt.After(now) {
				due = append(due, fragment.packet)
				fragment.scheduled = true
				continue
			}
			nextWait = minPositiveDuration(nextWait, fragment.retryAt.Sub(now))
		}
		if len(state.fragments) == 0 {
			delete(r.dnsRequests, sequenceNum)
		}
	}
	r.mu.Unlock()

	if len(due) == 0 {
		return nextWait
	}

	for _, packet := range due {
		if r.enqueuePacket(arq.QueueTargetMain, packet) {
			continue
		}
		r.mu.Lock()
		state := r.dnsRequests[packet.SequenceNum]
		if state != nil {
			if fragment := state.fragments[packet.FragmentID]; fragment != nil {
				fragment.scheduled = false
				fragment.retryAt = now.Add(100 * time.Millisecond)
			}
		}
		r.mu.Unlock()
	}
	r.notifyWake()
	return 50 * time.Millisecond
}

func (r *stream0Runtime) noteServerDataActivity() {
	if r == nil {
		return
	}
	r.lastDataActivity.Store(time.Now().UnixNano())
}

func (r *stream0Runtime) notifyWake() {
	select {
	case r.wakeCh <- struct{}{}:
	default:
	}
}

func (r *stream0Runtime) canDispatchMore() bool {
	if r == nil {
		return false
	}
	return int(r.inFlight.Load()) < r.dispatchLimit()
}

func (r *stream0Runtime) dispatchLimit() int {
	if r == nil || r.client == nil {
		return 4
	}
	limit := r.client.effectiveStreamTXWindow()
	if limit < 4 {
		limit = 4
	}
	if limit > 8 {
		limit = 8
	}
	return limit
}

func (r *stream0Runtime) dispatchPacket(packet arq.QueuedPacket) {
	if r == nil {
		return
	}
	r.inFlight.Add(1)
	go func() {
		defer func() {
			r.inFlight.Add(-1)
			r.notifyWake()
		}()
		r.processDequeue(packet)
	}()
}

func (r *stream0Runtime) failAllPending() {
	r.mu.Lock()
	r.dnsRequests = make(map[uint16]*stream0DNSRequestState, 4)
	r.mu.Unlock()
	r.running.Store(false)
}

func (r *stream0Runtime) ResetForReconnect() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.dnsRequests = make(map[uint16]*stream0DNSRequestState, 4)
	r.mu.Unlock()

	r.dnsActivitySeen.Store(false)
	now := time.Now().UnixNano()
	r.lastDataActivity.Store(now)
	r.lastPingTime.Store(now)
	if r.scheduler != nil {
		r.schedulerMu.Lock()
		r.scheduler.HandleSessionReset()
		r.schedulerMu.Unlock()
	}
}

func (r *stream0Runtime) enqueuePacket(target arq.QueueTarget, packet arq.QueuedPacket) bool {
	if r == nil || r.scheduler == nil {
		return false
	}
	r.schedulerMu.Lock()
	defer r.schedulerMu.Unlock()
	return r.scheduler.Enqueue(target, packet)
}

func (r *stream0Runtime) dequeuePacket() (arq.DequeueResult, bool) {
	if r == nil || r.scheduler == nil {
		return arq.DequeueResult{}, false
	}
	r.schedulerMu.Lock()
	defer r.schedulerMu.Unlock()
	return r.scheduler.Dequeue()
}

func (r *stream0Runtime) pendingPings() int {
	if r == nil || r.scheduler == nil {
		return 0
	}
	r.schedulerMu.Lock()
	defer r.schedulerMu.Unlock()
	return r.scheduler.PendingPings()
}

func (r *stream0Runtime) rescheduleStreamPacket(streamID uint16, sequenceNum uint16) {
	if r == nil || r.client == nil {
		return
	}
	stream, ok := r.client.getStream(streamID)
	if !ok || stream == nil {
		return
	}
	rescheduleClientStreamTX(stream, sequenceNum)
	notifyStreamWake(stream)
}

func isResolvedStreamPacketResponse(sent arq.QueuedPacket, response VpnProto.Packet) bool {
	switch response.PacketType {
	case Enums.PACKET_STREAM_DATA_ACK:
		return sent.PacketType == Enums.PACKET_STREAM_DATA && response.StreamID == sent.StreamID && response.SequenceNum == sent.SequenceNum
	case Enums.PACKET_STREAM_FIN_ACK:
		return sent.PacketType == Enums.PACKET_STREAM_FIN && response.StreamID == sent.StreamID && response.SequenceNum == sent.SequenceNum
	case Enums.PACKET_STREAM_RST_ACK:
		return sent.PacketType == Enums.PACKET_STREAM_RST && response.StreamID == sent.StreamID && response.SequenceNum == sent.SequenceNum
	case Enums.PACKET_STREAM_SYN_ACK:
		return sent.PacketType == Enums.PACKET_STREAM_SYN && response.StreamID == sent.StreamID && response.SequenceNum == sent.SequenceNum
	case Enums.PACKET_SOCKS5_SYN_ACK:
		return sent.PacketType == Enums.PACKET_SOCKS5_SYN && response.StreamID == sent.StreamID && response.SequenceNum == sent.SequenceNum
	default:
		return false
	}
}

func minPositiveDuration(current time.Duration, candidate time.Duration) time.Duration {
	if candidate <= 0 {
		return current
	}
	if current <= 0 || candidate < current {
		return candidate
	}
	return current
}
