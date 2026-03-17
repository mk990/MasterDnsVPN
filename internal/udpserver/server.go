// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/dnsparser"
	"masterdnsvpn-go/internal/logger"
)

type Server struct {
	cfg             config.ServerConfig
	log             *logger.Logger
	packetPool      sync.Pool
	droppedPackets  atomic.Uint64
	lastDropLogUnix atomic.Int64
}

type request struct {
	buf  []byte
	size int
	addr *net.UDPAddr
}

func New(cfg config.ServerConfig, log *logger.Logger) *Server {
	return &Server{
		cfg: cfg,
		log: log,
		packetPool: sync.Pool{
			New: func() any {
				return make([]byte, cfg.MaxPacketSize)
			},
		},
	}
}

func (s *Server) Run(ctx context.Context) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(s.cfg.UDPHost),
		Port: s.cfg.UDPPort,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetReadBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("[!] <yellow>Failed To Set UDP Read Buffer</yellow>: <cyan>%v</cyan>", err)
	}
	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("[!] <yellow>Failed To Set UDP Write Buffer</yellow>: <cyan>%v</cyan>", err)
	}

	s.log.Infof(
		"[*] <green>UDP Listener Ready</green>  Addr: <cyan>%s</cyan>  |  Readers: <magenta>%d</magenta>  |  Workers: <magenta>%d</magenta>  |  Queue: <magenta>%d</magenta>",
		s.cfg.Address(),
		s.cfg.UDPReaders,
		s.cfg.DNSRequestWorkers,
		s.cfg.MaxConcurrentRequests,
	)

	reqCh := make(chan request, s.cfg.MaxConcurrentRequests)
	var workerWG sync.WaitGroup

	for i := 0; i < s.cfg.DNSRequestWorkers; i++ {
		workerWG.Add(1)
		go func(workerID int) {
			defer workerWG.Done()
			s.worker(ctx, conn, reqCh, workerID)
		}(i + 1)
	}

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	readErrCh := make(chan error, s.cfg.UDPReaders)
	var readerWG sync.WaitGroup
	for i := 0; i < s.cfg.UDPReaders; i++ {
		readerWG.Add(1)
		go func(readerID int) {
			defer readerWG.Done()
			if err := s.readLoop(ctx, conn, reqCh, readerID); err != nil {
				select {
				case readErrCh <- err:
				default:
				}
			}
		}(i + 1)
	}

	readerWG.Wait()
	close(reqCh)
	workerWG.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	select {
	case err := <-readErrCh:
		return err
	default:
		return nil
	}
}

func (s *Server) readLoop(ctx context.Context, conn *net.UDPConn, reqCh chan<- request, readerID int) error {
	for {
		buffer := s.packetPool.Get().([]byte)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			s.packetPool.Put(buffer)
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Debugf(
				"Reader <cyan>%d</cyan> returned a UDP read error: <yellow>%v</yellow>",
				readerID,
				err,
			)
			return err
		}

		select {
		case reqCh <- request{buf: buffer, size: n, addr: addr}:
		case <-ctx.Done():
			s.packetPool.Put(buffer)
			return nil
		default:
			s.packetPool.Put(buffer)
			s.onDrop(addr)
		}
	}
}

func (s *Server) worker(ctx context.Context, conn *net.UDPConn, reqCh <-chan request, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqCh:
			if !ok {
				return
			}

			payload := req.buf[:req.size]
			response := s.handlePacket(payload)
			if len(response) == 0 {
				s.packetPool.Put(req.buf)
				continue
			}

			if _, err := conn.WriteToUDP(response, req.addr); err != nil {
				s.log.Debugf(
					"Worker <cyan>%d</cyan> failed to send a UDP response to <cyan>%s</cyan>: <yellow>%v</yellow>",
					workerID,
					req.addr.String(),
					err,
				)
				s.packetPool.Put(req.buf)
				continue
			}

			s.packetPool.Put(req.buf)
		}
	}
}

func (s *Server) handlePacket(packet []byte) []byte {
	parsed, err := dnsparser.ParsePacketLite(packet)
	if err != nil {
		response, responseErr := dnsparser.BuildEmptyNoErrorResponse(packet)
		if responseErr == nil {
			s.log.Debugf(
				"[DNS] <yellow>Malformed DNS Packet Rejected</yellow> id=<cyan>%d</cyan> action=<green>empty-noerror</green>",
				binary.BigEndian.Uint16(packet[:2]),
			)
			return response
		}
		return nil
	}

	if parsed.HasQuestion {
		q := parsed.FirstQuestion
		s.log.Debugf(
			"[DNS] <green>Parsed Packet</green> id=<cyan>%d</cyan> qr=<cyan>%d</cyan> opcode=<cyan>%d</cyan> qd=<cyan>%d</cyan> an=<cyan>%d</cyan> ns=<cyan>%d</cyan> ar=<cyan>%d</cyan> qname=<yellow>%s</yellow> qtype=<magenta>%d</magenta> qclass=<magenta>%d</magenta>",
			parsed.Header.ID,
			parsed.Header.QR,
			parsed.Header.OpCode,
			parsed.Header.QDCount,
			parsed.Header.ANCount,
			parsed.Header.NSCount,
			parsed.Header.ARCount,
			q.Name,
			q.Type,
			q.Class,
		)
	} else {
		s.log.Debugf(
			"[DNS] <green>Parsed Packet</green> id=<cyan>%d</cyan> qr=<cyan>%d</cyan> opcode=<cyan>%d</cyan> qd=<cyan>%d</cyan> an=<cyan>%d</cyan> ns=<cyan>%d</cyan> ar=<cyan>%d</cyan>",
			parsed.Header.ID,
			parsed.Header.QR,
			parsed.Header.OpCode,
			parsed.Header.QDCount,
			parsed.Header.ANCount,
			parsed.Header.NSCount,
			parsed.Header.ARCount,
		)
	}

	if !s.allowDNSPacket(parsed) {
		response, responseErr := dnsparser.BuildEmptyNoErrorResponse(packet)
		if responseErr == nil {
			s.log.Debugf(
				"[DNS] <yellow>DNS Packet Rejected By Policy</yellow> id=<cyan>%d</cyan> action=<green>empty-noerror</green>",
				parsed.Header.ID,
			)
			return response
		}
		return nil
	}

	response, responseErr := dnsparser.BuildEmptyNoErrorResponse(packet)
	if responseErr != nil {
		return nil
	}
	return response
}

func (s *Server) allowDNSPacket(_ dnsparser.LitePacket) bool {
	return true
}

func (s *Server) onDrop(addr *net.UDPAddr) {
	total := s.droppedPackets.Add(1)

	now := logger.NowUnixNano()
	last := s.lastDropLogUnix.Load()
	interval := s.cfg.DropLogInterval().Nanoseconds()
	if interval <= 0 {
		interval = 2_000_000_000
	}
	if now-last < interval {
		return
	}
	if !s.lastDropLogUnix.CompareAndSwap(last, now) {
		return
	}

	s.log.Warnf(
		"[!] <yellow>Request Queue Overloaded</yellow>  |  Total Dropped: <magenta>%d</magenta>  |  Last Remote: <cyan>%s</cyan>",
		total,
		addr.String(),
	)
}
