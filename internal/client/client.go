// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic and initialization for the MasterDnsVPN client.
// This file (client.go) defines the main Client struct and bootstrapping process.
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	EDnsSafeUDPSize = 4096
)

type Client struct {
	cfg      config.ClientConfig
	log      *logger.Logger
	codec    *security.Codec
	balancer *Balancer

	connections      []Connection
	connectionsByKey map[string]int
	successMTUChecks bool
	udpBufferPool    sync.Pool
	resolverConnsMu  sync.Mutex
	resolverConns    map[string]chan *net.UDPConn

	// MTU States
	syncedUploadMTU           int
	syncedDownloadMTU         int
	syncedUploadChars         int
	safeUploadMTU             int
	maxPackedBlocks           int
	uploadCompression         uint8
	downloadCompression       uint8
	mtuCryptoOverhead         int
	mtuProbeCounter           atomic.Uint32
	mtuTestRetries            int
	mtuTestTimeout            time.Duration
	mtuSaveToFile             bool
	mtuServersFileName        string
	mtuServersFileFormat      string
	mtuSuccessOutputPath      string
	mtuOutputMu               sync.Mutex
	mtuUsageSeparatorWritten  bool
	mtuUsingSeparatorText     string
	mtuRemovedServerLogFormat string
	mtuAddedServerLogFormat   string

	// Session States
	sessionID           uint8
	sessionCookie       uint8
	responseMode        uint8
	sessionReady        bool
	initStateMu         sync.Mutex
	sessionInitReady    bool
	sessionInitBase64   bool
	sessionInitPayload  []byte
	sessionInitVerify   [4]byte
	sessionInitCursor   int
	sessionInitBusyUnix atomic.Int64
	sessionResetPending atomic.Bool

	// Async Runtime Workers & Channels
	asyncWG              sync.WaitGroup
	asyncCancel          context.CancelFunc
	tunnelConn           *net.UDPConn
	txChannel            chan asyncPacket
	rxChannel            chan asyncReadPacket
	tunnelReaderWorkers  int
	tunnelWriterWorkers  int
	tunnelProcessWorkers int
	tunnelPacketTimeout  time.Duration

	// Local Proxy Daemons
	tcpListener *TCPListener
	dnsListener *DNSListener
}

// Connection represents a unique domain-resolver pair with its associated metadata and MTU states.
type Connection struct {
	Domain           string
	Resolver         string
	ResolverPort     int
	ResolverLabel    string
	Key              string
	IsValid          bool
	UploadMTUBytes   int
	UploadMTUChars   int
	DownloadMTUBytes int
}

// Bootstrap initializes a new Client by loading configuration, setting up logging,
// and preparing the connection map.
func Bootstrap(configPath string, logPath string) (*Client, error) {
	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		return nil, err
	}

	var log *logger.Logger
	if logPath != "" {
		log = logger.NewWithFile("MasterDnsVPN Client", cfg.LogLevel, logPath)
	} else {
		log = logger.New("MasterDnsVPN Client", cfg.LogLevel)
	}

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("client codec setup failed: %w", err)
	}

	c := New(cfg, log, codec)
	if err := c.BuildConnectionMap(); err != nil {
		if c.log != nil {
			c.log.Errorf("<red>%v</red>", err)
		}
		return nil, err
	}
	return c, nil
}

func New(cfg config.ClientConfig, log *logger.Logger, codec *security.Codec) *Client {
	var responseMode uint8
	if cfg.BaseEncodeData {
		responseMode = mtuProbeBase64Reply
	}

	return &Client{
		cfg:                 cfg,
		log:                 log,
		codec:               codec,
		balancer:            NewBalancer(cfg.ResolverBalancingStrategy),
		uploadCompression:   uint8(cfg.UploadCompressionType),
		downloadCompression: uint8(cfg.DownloadCompressionType),
		mtuCryptoOverhead:   mtuCryptoOverhead(cfg.DataEncryptionMethod),
		maxPackedBlocks:     1,
		responseMode:        responseMode,
		connectionsByKey:    make(map[string]int, len(cfg.Domains)*len(cfg.Resolvers)),
		udpBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, runtimeUDPReadBufferSize())
			},
		},
		resolverConns:             make(map[string]chan *net.UDPConn),
		mtuTestRetries:            cfg.MTUTestRetries,
		mtuTestTimeout:            time.Duration(cfg.MTUTestTimeout * float64(time.Second)),
		mtuSaveToFile:             cfg.SaveMTUServersToFile,
		mtuServersFileName:        cfg.MTUServersFileName,
		mtuServersFileFormat:      cfg.MTUServersFileFormat,
		mtuUsingSeparatorText:     cfg.MTUUsingSeparatorText,
		mtuRemovedServerLogFormat: cfg.MTURemovedServerLogFormat,
		mtuAddedServerLogFormat:   cfg.MTUAddedServerLogFormat,

		// Workers config
		tunnelReaderWorkers:  4,
		tunnelWriterWorkers:  4,
		tunnelProcessWorkers: 2,
		tunnelPacketTimeout:  time.Second * 5,
		txChannel:            make(chan asyncPacket, 1024),
		rxChannel:            make(chan asyncReadPacket, 1024),
	}
}

func (c *Client) Config() config.ClientConfig {
	return c.cfg
}

func (c *Client) Logger() *logger.Logger {
	return c.log
}

func (c *Client) Balancer() *Balancer {
	return c.balancer
}

func (c *Client) PrintBanner() {
	if c.log == nil {
		return
	}

	c.log.Infof("============================================================")
	c.log.Infof("<magenta>Starting MasterDnsVPN Client...</magenta>")
	// Build version skipped as per user request
	c.log.Infof("<cyan>GitHub:</cyan> <blue>https://github.com/masterking32/MasterDnsVPN</blue>")
	c.log.Infof("<cyan>Telegram:</cyan> <yellow>@MasterDnsVPN</yellow>")
	c.log.Infof("============================================================")

	c.log.Infof("🚀 <green>Client Configuration Loaded</green>")

	c.log.Infof("🚀 <cyan>Client Mode, Protocol:</cyan> <yellow>%s</yellow> <cyan>Encryption:</cyan> <yellow>%d</yellow>", c.cfg.ProtocolType, c.cfg.DataEncryptionMethod)

	strategyName := "Round-Robin"
	switch c.cfg.ResolverBalancingStrategy {
	case 0:
		strategyName = "Round-Robin Default"
	case 1:
		strategyName = "Random"
	case 2:
		strategyName = "Round-Robin"
	case 3:
		strategyName = "Least Loss"
	case 4:
		strategyName = "Lowest Latency"
	}
	c.log.Infof("⚖  <cyan>Resolver Balancing, Strategy:</cyan> <yellow>%s (%d)</yellow>", strategyName, c.cfg.ResolverBalancingStrategy)

	domainList := ""
	if len(c.cfg.Domains) > 0 {
		domainList = c.cfg.Domains[0]
	}
	c.log.Infof("🌐 <cyan>Configured Domains:</cyan> <yellow>%d (%s)</yellow>", len(c.cfg.Domains), domainList)
	c.log.Infof("📡 <cyan>Loaded Resolvers:</cyan> <yellow>%d endpoints.</yellow>", len(c.cfg.Resolvers))
}

func (c *Client) Connections() []Connection {
	return c.connections
}

// BuildConnectionMap iterates through all domains and resolvers in the configuration
// and builds a comprehensive list of unique Connection objects.
func (c *Client) BuildConnectionMap() error {
	domains := c.cfg.Domains
	resolvers := c.cfg.Resolvers

	total := len(domains) * len(resolvers)
	if total <= 0 {
		return fmt.Errorf("Domains or Resolvers are missing in config.")
	}

	connections := make([]Connection, 0, total)
	indexByKey := make(map[string]int, total)

	for _, domain := range domains {
		for _, resolver := range resolvers {
			label := formatResolverEndpoint(resolver.IP, resolver.Port)
			key := makeConnectionKey(resolver.IP, resolver.Port, domain)
			if _, exists := indexByKey[key]; exists {
				continue
			}

			indexByKey[key] = len(connections)
			connections = append(connections, Connection{
				Domain:        domain,
				Resolver:      resolver.IP,
				ResolverPort:  resolver.Port,
				ResolverLabel: label,
				Key:           key,
				IsValid:       true,
			})
		}
	}

	c.connections = connections
	c.connectionsByKey = indexByKey

	pointers := make([]*Connection, len(c.connections))
	for i := range c.connections {
		pointers[i] = &c.connections[i]
	}
	c.balancer.SetConnections(pointers)

	return nil
}

// Run starts the main execution loop of the client.
func (c *Client) Run(ctx context.Context) error {
	c.successMTUChecks = false
	c.log.Infof("\U0001F504 <cyan>Starting main runtime loop...</cyan>")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if !c.successMTUChecks {
				if err := c.RunInitialMTUTests(ctx); err != nil {
					c.log.Errorf("<red>MTU tests failed: %v</red>", err)
					// Wait a bit before retrying or exiting if critical
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(5 * time.Second):
					}
					continue
				}
			}

			if !c.sessionReady {
				retries := c.cfg.MTUTestRetries
				if retries < 1 {
					retries = 3
				}

				if err := c.InitializeSession(retries); err != nil {
					c.log.Errorf("<red>❌ Session initialization failed: %v</red>", err)
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(time.Second * 5):
					}
					continue
				}
				c.log.Infof("<green>✅ Session Initialized Successfully (ID: <cyan>%d</cyan>)</green>", c.sessionID)

				// Start the asynchronous workers processing the raw pipeline
				if err := c.StartAsyncRuntime(ctx); err != nil {
					c.log.Errorf("<red>❌ Async Runtime failed to launch: %v</red>", err)
					return err
				}
			}

			// Placeholder for the rest of the runtime logic (session management, etc.)
			select {
			case <-ctx.Done():
				c.StopAsyncRuntime()
				return nil
			case <-time.After(1 * time.Second):
				c.log.Infof("\U0001F517 <gray>Runtime loop active (MTU Success: %t, Session: %d)...</gray>", c.successMTUChecks, c.sessionID)
			}
		}
	}
}

func formatResolverEndpoint(resolver string, port int) string {
	if strings.IndexByte(resolver, ':') >= 0 && !strings.HasPrefix(resolver, "[") {
		return fmt.Sprintf("[%s]:%d", resolver, port)
	}
	return fmt.Sprintf("%s:%d", resolver, port)
}

func makeConnectionKey(resolver string, port int, domain string) string {
	return resolver + "|" + strconv.Itoa(port) + "|" + domain
}

// now returns the current time.
func (c *Client) now() time.Time {
	return time.Now()
}

// validateServerPacket checks if the incoming VPN packet is valid for the current session.
func (c *Client) validateServerPacket(packet VpnProto.Packet) bool {
	// For MTU and initial handshake, we might not have a session ready
	if isPreSessionResponseType(packet.PacketType) {
		return true
	}
	// In this minimal version, we might not have session state yet,
	// so we'll just return true for now to allow MTU tests to pass.
	// Once session logic is added, we will restore the proper check.
	return true
}

// isPreSessionResponseType returns true if the packet type is expected before a session is fully established.
func isPreSessionResponseType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_MTU_UP_RES,
		Enums.PACKET_MTU_DOWN_RES,
		Enums.PACKET_SESSION_ACCEPT,
		Enums.PACKET_SESSION_BUSY,
		Enums.PACKET_ERROR_DROP:
		return true
	default:
		return false
	}
}

// applySyncedMTUState updates the client's internal MTU state after successful probing.
func (c *Client) applySyncedMTUState(uploadMTU int, downloadMTU int, uploadChars int) {
	if c == nil {
		return
	}
	c.successMTUChecks = uploadMTU > 0 && downloadMTU > 0
	c.syncedUploadMTU = uploadMTU
	c.syncedDownloadMTU = downloadMTU
	c.syncedUploadChars = uploadChars
	c.safeUploadMTU = computeSafeUploadMTU(uploadMTU, c.mtuCryptoOverhead)
	c.updateMaxPackedBlocks()
	c.applySessionCompressionPolicy()
	if c.log != nil && c.successMTUChecks {
		c.log.Infof("\U0001F4CF <green>MTU state applied: UP=%d, DOWN=%d</green>", uploadMTU, downloadMTU)
	}
}

func (c *Client) updateMaxPackedBlocks() {
	c.maxPackedBlocks = computeClientPackedControlBlockLimit(
		c.syncedUploadMTU,
		c.cfg.MaxPacketsPerBatch,
	)
}

func (c *Client) applySessionCompressionPolicy() {
	if c == nil {
		return
	}

	minSize := c.cfg.CompressionMinSize
	if minSize <= 0 {
		minSize = compression.DefaultMinSize
	}

	uploadCompression := compression.NormalizeAvailableType(c.uploadCompression)
	downloadCompression := compression.NormalizeAvailableType(c.downloadCompression)

	const mtuWarningThreshold = 100

	if c.syncedUploadMTU > 0 && c.syncedUploadMTU < mtuWarningThreshold {
		if uploadCompression != compression.TypeOff && c.log != nil {
			c.log.Warnf(
				"⚠️ <red>Session Compression Upload: <cyan>%s</cyan> (Disabled due to low MTU: <cyan>%d</cyan>)</red>",
				compression.TypeName(uploadCompression),
				c.syncedUploadMTU,
			)
		}
		uploadCompression = compression.TypeOff
		c.cfg.UploadCompressionType = int(compression.TypeOff)
	} else if c.syncedUploadMTU > 0 && c.syncedUploadMTU <= minSize {
		if uploadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Upload: <cyan>%s</cyan> (Disabled due to MinSize MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(uploadCompression),
				c.syncedUploadMTU,
			)
		}
		uploadCompression = compression.TypeOff
	}

	if c.syncedDownloadMTU > 0 && c.syncedDownloadMTU < mtuWarningThreshold {
		if downloadCompression != compression.TypeOff && c.log != nil {
			c.log.Warnf(
				"⚠️ <red>Session Compression Download: <cyan>%s</cyan> (Disabled due to low MTU: <cyan>%d</cyan>)</red>",
				compression.TypeName(downloadCompression),
				c.syncedDownloadMTU,
			)
		}
		downloadCompression = compression.TypeOff
		c.cfg.DownloadCompressionType = int(compression.TypeOff)
	} else if c.syncedDownloadMTU > 0 && c.syncedDownloadMTU <= minSize {
		if downloadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Download: <cyan>%s</cyan> (Disabled due to MinSize MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(downloadCompression),
				c.syncedDownloadMTU,
			)
		}
		downloadCompression = compression.TypeOff
	}

	c.uploadCompression = uploadCompression
	c.downloadCompression = downloadCompression

	if c.log != nil {
		c.log.Infof(
			"\U0001F9E9 <green>Effective Compression Upload: <cyan>%s</cyan> Download: <cyan>%s</cyan></green>",
			compression.TypeName(c.uploadCompression),
			compression.TypeName(c.downloadCompression),
		)
	}
}

const (
	packedControlBlockSize         = 7
	clientPackedBlockUsagePercent  = 50
	defaultPackedControlBlockLimit = 1
)

func computeClientPackedControlBlockLimit(mtu int, maxPacketsPerBatch int) int {
	if mtu < 1 {
		return defaultPackedControlBlockLimit
	}
	usableBudget := (mtu * clientPackedBlockUsagePercent) / 100
	mtuLimit := usableBudget / packedControlBlockSize
	if mtuLimit < 1 {
		mtuLimit = defaultPackedControlBlockLimit
	}
	userLimit := maxPacketsPerBatch
	if userLimit < 1 {
		userLimit = defaultPackedControlBlockLimit
	}
	if userLimit < mtuLimit {
		return userLimit
	}
	return mtuLimit
}

// initResolverRecheckMeta initializes metadata for resolver health monitoring.
func (c *Client) initResolverRecheckMeta() {
	// Recheck logic not fully implemented yet
}

// connectionPtrByKey returns a pointer to a Connection object based on its unique key.
func (c *Client) connectionPtrByKey(key string) *Connection {
	if idx, ok := c.connectionsByKey[key]; ok {
		return &c.connections[idx]
	}
	return nil
}

// SetConnectionValidity updates the validity status of a connection.
func (c *Client) SetConnectionValidity(key string, isValid bool) bool {
	conn := c.connectionPtrByKey(key)
	if conn == nil {
		return false
	}
	conn.IsValid = isValid
	return true
}
