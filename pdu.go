package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"slices"
)

const (
	// PDU Types
	serialNotify  uint8 = 0
	serialQuery   uint8 = 1
	resetQuery    uint8 = 2
	cacheResponse uint8 = 3
	ipv4Prefix    uint8 = 4
	ipv6Prefix    uint8 = 6
	endOfData     uint8 = 7
	cacheReset    uint8 = 8
	routerKey     uint8 = 9
	errorReport   uint8 = 10

	// protocol versions
	version1 uint8 = 1
	version2 uint8 = 2

	minPDULength  = 8
	headPDULength = 2

	// flags
	withdraw uint8 = 0
	announce uint8 = 1
)

// headerPDU is used to extract the header of each incoming PDU
type headerPDU struct {
	Version uint8
	Ptype   uint8
}

var supportedVersions = []uint8{
	version1,
	version2,
}

type PDUSerializer interface {
	SerialNotify(sessionID uint16, serial uint32) ([]byte, error)
	SerialQuery(sessionID uint16) ([]byte, error)
	ResetQuery(sessionID uint16) ([]byte, error)
	CacheResponse(sessionID uint16) ([]byte, error)
	IPv4Prefix(flags, min, max uint8, prefix [4]byte, asn uint32) ([]byte, error)
	IPv6Prefix(flags, min, max uint8, prefix [16]byte, asn uint32) ([]byte, error)
	EndOfData(sessionID uint16, serial, refresh, retry, expire uint32) ([]byte, error)
	CacheReset() ([]byte, error)
	ErrorReport(code uint16, report string) ([]byte, error)
}

func NewPDUSerializer(version uint8) (PDUSerializer, error) {
	switch version {
	case 0:
		return &V1Serializer{}, nil
	case 1:
		return &V2Serializer{}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol version: %d", version)
	}
}

type V1Serializer struct{}
type V2Serializer struct{}

type serialNotifyPDU struct {
	/*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |     Session ID      |
		|    X     |    0     |                     |
		+-------------------------------------------+
		|                                           |
		|                Length=12                  |
		|                                           |
		+-------------------------------------------+
		|                                           |
		|               Serial Number               |
		|                                           |
		`-------------------------------------------'
	*/
	Session uint16
	Serial  uint32
}

func (s *V1Serializer) SerialNotify(sessionID uint16, serial uint32, wr io.Writer) error {
	snpdu := &serialNotifyPDU{
		Session: sessionID,
		Serial:  serial,
	}
	log.Printf("Sending a serial notify PDU: %+v\n", *snpdu)
	pdu := struct {
		version uint8
		ptype   uint8
		session uint16
		length  uint32
		serial  uint32
	}{
		version1,
		serialNotify,
		snpdu.Session,
		uint32(12),
		snpdu.Serial,
	}
	if err := binary.Write(wr, binary.BigEndian, pdu); err != nil {
		return fmt.Errorf("failed to serialize serial notify PDU: %w", err)
	}
	return nil
}

func (s *V2Serializer) SerialNotify(sessionID uint16, serial uint32, wr io.Writer) error {
	snpdu := &serialNotifyPDU{
		Session: sessionID,
		Serial:  serial,
	}
	log.Printf("Sending a serial notify PDU: %+v\n", *snpdu)
	pdu := struct {
		version uint8
		ptype   uint8
		session uint16
		length  uint32
		serial  uint32
	}{
		version2,
		serialNotify,
		snpdu.Session,
		uint32(12),
		snpdu.Serial,
	}
	if err := binary.Write(wr, binary.BigEndian, pdu); err != nil {
		return fmt.Errorf("failed to serialize serial notify PDU: %w", err)
	}
	return nil
}

func (p *serialNotifyPDU) serialize(wr io.Writer) {
	log.Printf("Sending a serial notify PDU: %+v\n", *p)
	pdu := struct {
		version uint8
		ptype   uint8
		session uint16
		length  uint32
		serial  uint32
	}{
		version1,
		serialNotify,
		p.Session,
		uint32(12),
		p.Serial,
	}
	binary.Write(wr, binary.BigEndian, pdu)
}

type serialQueryPDU struct {
	/*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |     Session ID      |
		|    X     |    1     |                     |
		+-------------------------------------------+
		|                                           |
		|                 Length=12                 |
		|                                           |
		+-------------------------------------------+
		|                                           |
		|               Serial Number               |
		|                                           |
		`-------------------------------------------'
	*/
	Session uint16
	Length  uint32
	Serial  uint32
}

type resetQueryPDU struct {
	/*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |         zero        |
		|    X     |    2     |                     |
		+-------------------------------------------+
		|                                           |
		|                 Length=8                  |
		|                                           |
		`-------------------------------------------'
	*/
	Zero   uint16
	Length uint32
}

type cacheResponsePDU struct {
	/*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |     Session ID      |
		|    X     |    3     |                     |
		+-------------------------------------------+
		|                                           |
		|                 Length=8                  |
		|                                           |
		`-------------------------------------------'
	*/
	sessionID uint16
}

func (p *cacheResponsePDU) serialize(wr io.Writer) {
	log.Printf("Sending a cache Response PDU: %v\n", *p)
	pdu := struct {
		version uint8
		ptype   uint8
		session uint16
		length  uint32
	}{
		version1,
		cacheResponse,
		p.sessionID,
		uint32(8),
	}
	binary.Write(wr, binary.BigEndian, pdu)
}

func (s *V1Serializer) CacheResponse(sessionID uint16, serial uint32, wr io.Writer) error {
	crpdu := &cacheResponsePDU{
		sessionID: sessionID,
	}
	log.Printf("Sending a cache response PDU: %+v\n", *crpdu)
	pdu := struct {
		version uint8
		ptype   uint8
		session uint16
		length  uint32
	}{
		version1,
		cacheResponse,
		crpdu.sessionID,
		uint32(8),
	}
	if err := binary.Write(wr, binary.BigEndian, pdu); err != nil {
		return fmt.Errorf("failed to serialize cache response PDU: %w", err)
	}
	return nil
}

func (s *V2Serializer) CacheResponse(sessionID uint16, serial uint32, wr io.Writer) error {
	crpdu := &cacheResponsePDU{
		sessionID: sessionID,
	}
	log.Printf("Sending a cache response PDU: %+v\n", *crpdu)
	pdu := struct {
		version uint8
		ptype   uint8
		session uint16
		length  uint32
	}{
		version2,
		cacheResponse,
		crpdu.sessionID,
		uint32(8),
	}
	if err := binary.Write(wr, binary.BigEndian, pdu); err != nil {
		return fmt.Errorf("failed to serialize cache response PDU: %w", err)
	}
	return nil
}

type ipv4PrefixPDU struct {
	/*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |         zero        |
		|    X     |    4     |                     |
		+-------------------------------------------+
		|                                           |
		|                 Length=20                 |
		|                                           |
		+-------------------------------------------+
		|          |  Prefix  |   Max    |          |
		|  Flags   |  Length  |  Length  |   zero   |
		|          |   0..32  |   0..32  |          |
		+-------------------------------------------+
		|                                           |
		|                IPv4 Prefix                |
		|                                           |
		+-------------------------------------------+
		|                                           |
		|         Autonomous System Number          |
		|                                           |
		`-------------------------------------------'
	*/
	flags  uint8
	min    uint8
	max    uint8
	prefix [4]byte
	asn    uint32
}

func (p *ipv4PrefixPDU) serialize(wr io.Writer) {
	pdu := struct {
		version uint8
		ptype   uint8
		zero16  uint16
		length  uint32
		flags   uint8
		min     uint8
		max     uint8
		zero8   uint8
		prefix  [4]byte
		asn     uint32
	}{
		version1,
		ipv4Prefix,
		uint16(0),
		uint32(20),
		p.flags,
		p.min,
		p.max,
		uint8(0),
		p.prefix,
		p.asn,
	}
	binary.Write(wr, binary.BigEndian, pdu)
}
func (s *V1Serializer) IPv4Prefix(ip ipv4PrefixPDU, wr io.Writer) error {
	pdu := struct {
		version uint8
		ptype   uint8
		zero16  uint16
		length  uint32
		flags   uint8
		min     uint8
		max     uint8
		zero8   uint8
		prefix  [4]byte
		asn     uint32
	}{
		version1,
		ipv4Prefix,
		uint16(0),
		uint32(20),
		ip.flags,
		ip.min,
		ip.max,
		uint8(0),
		ip.prefix,
		ip.asn,
	}
	if err := binary.Write(wr, binary.BigEndian, pdu); err != nil {
		return fmt.Errorf("failed to serialize IPv4 Prefix PDU: %w", err)
	}
	return nil
}

func (s *V2Serializer) IPv4Prefix(ip ipv4PrefixPDU, wr io.Writer) error {
	pdu := struct {
		version uint8
		ptype   uint8
		zero16  uint16
		length  uint32
		flags   uint8
		min     uint8
		max     uint8
		zero8   uint8
		prefix  [4]byte
		asn     uint32
	}{
		version2,
		ipv4Prefix,
		uint16(0),
		uint32(20),
		ip.flags,
		ip.min,
		ip.max,
		uint8(0),
		ip.prefix,
		ip.asn,
	}
	if err := binary.Write(wr, binary.BigEndian, pdu); err != nil {
		return fmt.Errorf("failed to serialize IPv4 Prefix PDU: %w", err)
	}
	return nil
}

type ipv6PrefixPDU struct {
	/*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |         zero        |
		|    X     |    6     |                     |
		+-------------------------------------------+
		|                                           |
		|                 Length=32                 |
		|                                           |
		+-------------------------------------------+
		|          |  Prefix  |   Max    |          |
		|  Flags   |  Length  |  Length  |   zero   |
		|          |  0..128  |  0..128  |          |
		+-------------------------------------------+
		|                                           |
		+---                                     ---+
		|                                           |
		+---            IPv6 Prefix              ---+
		|                                           |
		+---                                     ---+
		|                                           |
		+-------------------------------------------+
		|                                           |
		|         Autonomous System Number          |
		|                                           |
		`-------------------------------------------'
	*/
	flags  uint8
	min    uint8
	max    uint8
	prefix [16]byte
	asn    uint32
}

func (p *ipv6PrefixPDU) serialize(wr io.Writer) {
	pdu := struct {
		version uint8
		ptype   uint8
		zero16  uint16
		length  uint32
		flags   uint8
		min     uint8
		max     uint8
		zero8   uint8
		prefix  [16]byte
		asn     uint32
	}{
		version1,
		ipv6Prefix,
		uint16(0),
		uint32(32),
		p.flags,
		p.min,
		p.max,
		uint8(0),
		p.prefix,
		p.asn,
	}
	binary.Write(wr, binary.BigEndian, pdu)
}

func (s *V1Serializer) IPv6Prefix(ip ipv6PrefixPDU, wr io.Writer) error {
	pdu := struct {
		version uint8
		ptype   uint8
		zero16  uint16
		length  uint32
		flags   uint8
		min     uint8
		max     uint8
		zero8   uint8
		prefix  [16]byte
		asn     uint32
	}{
		version1,
		ipv6Prefix,
		uint16(0),
		uint32(32),
		ip.flags,
		ip.min,
		ip.max,
		uint8(0),
		ip.prefix,
		ip.asn,
	}
	if err := binary.Write(wr, binary.BigEndian, pdu); err != nil {
		return fmt.Errorf("failed to serialize IPv6 Prefix PDU: %w", err)
	}
	return nil
}

func (s *V2Serializer) IPv6Prefix(ip ipv6PrefixPDU, wr io.Writer) error {
	pdu := struct {
		version uint8
		ptype   uint8
		zero16  uint16
		length  uint32
		flags   uint8
		min     uint8
		max     uint8
		zero8   uint8
		prefix  [16]byte
		asn     uint32
	}{
		version1,
		ipv6Prefix,
		uint16(0),
		uint32(32),
		ip.flags,
		ip.min,
		ip.max,
		uint8(0),
		ip.prefix,
		ip.asn,
	}
	if err := binary.Write(wr, binary.BigEndian, pdu); err != nil {
		return fmt.Errorf("failed to serialize IPv6 Prefix PDU: %w", err)
	}
	return nil
}

type endOfDataPDU struct {
	/*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |     Session ID      |
		|    X     |    7     |                     |
		+-------------------------------------------+
		|                                           |
		|                 Length=24                 |
		|                                           |
		+-------------------------------------------+
		|                                           |
		|               Serial Number               |
		|                                           |
		+-------------------------------------------+
		|                                           |
		|              Refresh Interval             |
		|                                           |
		+-------------------------------------------+
		|                                           |
		|               Retry Interval              |
		|                                           |
		+-------------------------------------------+
		|                                           |
		|              Expire Interval              |
		|                                           |
		`-------------------------------------------'
	*/
	session uint16
	serial  uint32
	refresh uint32
	retry   uint32
	expire  uint32
}

func (p *endOfDataPDU) serialize(wr io.Writer) {
	log.Printf("Sending end of data PDU: %v\n", *p)
	pdu := struct {
		version uint8
		ptype   uint8
		session uint16
		length  uint32
		serual  uint32
		refresh uint32
		retry   uint32
		expire  uint32
	}{
		version1,
		endOfData,
		p.session,
		uint32(24),
		p.serial,
		p.refresh,
		p.retry,
		p.expire,
	}
	binary.Write(wr, binary.BigEndian, pdu)
}

type cacheResetPDU struct { /*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |         zero        |
		|    X     |    8     |                     |
		+-------------------------------------------+
		|                                           |
		|                 Length=8                  |
		|                                           |
		`-------------------------------------------'
	*/
}

func (p *cacheResetPDU) serialize(wr io.Writer) {
	log.Printf("Sending a cache reset PDU: %v\n", *p)
	pdu := struct {
		version uint8
		ptype   uint8
		zero    uint16
		length  uint32
	}{
		version1,
		cacheReset,
		uint16(0),
		uint32(8),
	}
	binary.Write(wr, binary.BigEndian, pdu)
}

type errorReportPDU struct {
	/*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |     Error Code      |
		|    X     |    10    |                     |
		+-------------------------------------------+
		|                                           |
		|                  Length                   |
		|                                           |
		+-------------------------------------------+
		|                                           |
		|       Length of Encapsulated PDU          |
		|                                           |
		+-------------------------------------------+
		|                                           |
		~               Erroneous PDU               ~
		|                                           |
		+-------------------------------------------+
		|                                           |
		|           Length of Error Text            |
		|                                           |
		+-------------------------------------------+
		|                                           |
		|              Arbitrary Text               |
		|                    of                     |
		~          Error Diagnostic Message         ~
		|                                           |
		`-------------------------------------------'
	*/
	code   uint16
	report string
}

func (p *errorReportPDU) serialize(wr io.Writer) {
	log.Printf("Sending an error report PDU: %v\n", *p)
	// length of encapped PDU 0 for now
	// not encapping PDU, so empty field there
	reportLength := len([]byte(p.report))
	totalLength := 128 + reportLength

	binary.Write(wr, binary.BigEndian, version1)
	binary.Write(wr, binary.BigEndian, errorReport)
	binary.Write(wr, binary.BigEndian, p.code)
	binary.Write(wr, binary.BigEndian, totalLength)
	binary.Write(wr, binary.BigEndian, uint32(0))
	binary.Write(wr, binary.BigEndian, reportLength)
	binary.Write(wr, binary.BigEndian, p.report)
}

func getSerialQueryPDU(pdu []byte) serialQueryPDU {
	var q serialQueryPDU
	q.Session = binary.BigEndian.Uint16(pdu[:2])
	q.Length = binary.BigEndian.Uint32(pdu[2:6])
	q.Serial = binary.BigEndian.Uint32(pdu[6:10])

	return q
}

// getPDU will return a byte slice which contains a PDU.
func getPDU(r io.Reader) ([]byte, error) {
	/*
		0          8          16         24        31
		.-------------------------------------------.
		| Protocol |   PDU    |                     |
		| Version  |   Type   |     Session ID      |
		+-------------------------------------------+
		|                                           |
		|                 Length                    |
		|                                           |
		`-------------------------------------------'
	*/
	buf := make([]byte, minPDULength)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	// Read the rest of the PDU, minus the header.
	length := binary.BigEndian.Uint32(buf[4:8]) - 8
	if length > 0 {
		lr := io.LimitReader(r, int64(length))
		data := make([]byte, length)
		if _, err := io.ReadFull(lr, data); err != nil {
			return nil, err
		}
		buf = append(buf, data...)
	}
	return buf, nil
}

// decodePDUHeader does a size and version check. Otherwise it returns just the header.
func decodePDUHeader(pdu []byte, ver uint8, new bool) (headerPDU, error) {
	var header headerPDU
	if len(pdu) < headPDULength {
		return header, fmt.Errorf("PDU headers have a minimin size of 2. PDU passed has length %d", len(pdu))
	}
	if !slices.Contains(supportedVersions, uint8(pdu[0])) {
		return header, fmt.Errorf("unsupported PDU version received: %d", int(pdu[0]))
	}
	// If the client sends a PDU with a version different from the initial negotiated one, the session should be reset.
	if !new && uint8(pdu[0]) != ver {
		return header, fmt.Errorf("only version 1 is supported. PDU has version %d", int(pdu[0]))
	}
	header.Version = uint8(pdu[0])
	header.Ptype = uint8(pdu[1])

	// PDU types currently number from 0 to 10, excluding 5. Anything else is invalid.
	if header.Ptype > 10 || header.Ptype == 5 {
		return header, fmt.Errorf("unsupported pdu version received: %d", header.Ptype)
	}

	if new {
		log.Printf("Client is connected with version %d and PDU type %d\n", header.Version, header.Ptype)
	}

	return header, nil
}
