// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"time"

	dnsCache "masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
)

type dnsDispatchRequest struct {
	Query  []byte
	Domain string
	QType  uint16
	QClass uint16
}

type dnsQueryMetadata struct {
	Domain string
	QType  uint16
	QClass uint16
	Parsed DnsParser.LitePacket
}

func (c *Client) handleDNSQueryPacket(query []byte, now time.Time) ([]byte, *dnsDispatchRequest) {

	metadata, err := parseDNSQueryMetadata(query)
	if err != nil {
		if err == DnsParser.ErrNotDNSRequest || err == DnsParser.ErrPacketTooShort {
			return nil, nil
		}

		response, err := DnsParser.BuildFormatErrorResponse(query)
		if err != nil {
			return nil, nil
		}

		return response, nil
	}

	if !DnsParser.IsSupportedTunnelDNSQuery(metadata.QType, metadata.QClass) {
		response, err := DnsParser.BuildNotImplementedResponseFromLite(query, metadata.Parsed)
		if err != nil {
			return nil, nil
		}

		return response, nil
	}

	cacheKey := dnsCache.BuildKey(metadata.Domain, metadata.QType, metadata.QClass)
	recordTypeName := ""

	if c.log != nil {
		recordTypeName = Enums.DNSRecordTypeName(metadata.QType)
	}

	if cached, ok := c.localDNSCache.GetReady(cacheKey, query, now); ok {
		if c.log != nil {
			c.log.Infof(
				"\U0001F4E6 <green>Local DNS Cache Hit: <cyan>%s</cyan> (Type: <cyan>%s</cyan>)</green>",
				metadata.Domain,
				recordTypeName,
			)
		}
		return cached, nil
	}

	result := c.localDNSCache.LookupOrCreatePending(cacheKey, metadata.Domain, metadata.QType, metadata.QClass, now)
	response, err := DnsParser.BuildServerFailureResponseFromLite(query, metadata.Parsed)
	if err != nil {
		response = nil
	}

	if !result.DispatchNeeded {
		return response, nil
	}

	dispatch := &dnsDispatchRequest{
		Query:  query,
		Domain: metadata.Domain,
		QType:  metadata.QType,
		QClass: metadata.QClass,
	}

	return response, dispatch
}

func (c *Client) resolveDNSQueryPacket(query []byte, now time.Time) []byte {
	response, dispatch := c.handleDNSQueryPacket(query, now)
	if dispatch == nil {
		return response
	}

	if c.log != nil {
		c.log.Infof(
			"\U0001F687 <green>Local DNS Redirected To Tunnel: <cyan>%s</cyan> (Type: <cyan>%s</cyan>)</green>",
			dispatch.Domain,
			Enums.DNSRecordTypeName(dispatch.QType),
		)
	}

	c.queueDNSDispatch(dispatch)
	return response
}

func parseDNSQueryMetadata(query []byte) (dnsQueryMetadata, error) {
	parsed, err := DnsParser.ParseDNSRequestLite(query)
	if err != nil {
		return dnsQueryMetadata{}, err
	}
	if !parsed.HasQuestion {
		return dnsQueryMetadata{}, DnsParser.ErrInvalidQuestion
	}

	question := parsed.FirstQuestion
	return dnsQueryMetadata{
		Domain: question.Name,
		QType:  question.Type,
		QClass: question.Class,
		Parsed: parsed,
	}, nil
}
