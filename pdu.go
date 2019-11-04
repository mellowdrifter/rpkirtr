package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
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
	version0 uint8 = 0
	version1 uint8 = 1

	zeroUint16    uint16 = 0
	length8Uint8  uint8  = 8
	length8Uint32 uint32 = 8
	length20Uint8 uint8  = 20
)

type cacheResponsePDU struct {
	sessionID uint16
}

func (p *cacheResponsePDU) serialize(wr io.Writer) {
	/*
	   0          8          16         24        31
	   .-------------------------------------------.
	   | Protocol |   PDU    |                     |
	   | Version  |   Type   |     Session ID      |
	   |    1     |    3     |                     |
	   +-------------------------------------------+
	   |                                           |
	   |                 Length=8                  |
	   |                                           |
	   `-------------------------------------------'
	*/
	fmt.Printf("Sending a cache Repsonse PDU: %v\n", *p)
	binary.Write(wr, binary.BigEndian, version1)
	binary.Write(wr, binary.BigEndian, cacheResponse)
	binary.Write(wr, binary.BigEndian, p.sessionID)
	binary.Write(wr, binary.BigEndian, length8Uint32)
}

type ipv4PrefixPDU struct {
	flags  uint8
	min    uint8
	max    uint8
	prefix net.IP // For IPv4 this should be 4 bytes
	asn    uint32
}

func (p *ipv4PrefixPDU) serialize(wr io.Writer) {
	/*
	   0          8          16         24        31
	   .-------------------------------------------.
	   | Protocol |   PDU    |                     |
	   | Version  |   Type   |         zero        |
	   |    1     |    4     |                     |
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
	binary.Write(wr, binary.BigEndian, version1)
	binary.Write(wr, binary.BigEndian, ipv4Prefix)
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(20))
	binary.Write(wr, binary.BigEndian, p.flags)
	binary.Write(wr, binary.BigEndian, p.min)
	binary.Write(wr, binary.BigEndian, p.max)
	binary.Write(wr, binary.BigEndian, uint8(0))
	binary.Write(wr, binary.BigEndian, p.prefix)
	binary.Write(wr, binary.BigEndian, p.asn)

}

type ipv6PrefixPDU struct {
	flags  uint8
	min    uint8
	max    uint8
	prefix net.IP // For IPv6 this should be 16 bytes
	asn    uint32
}

func (p *ipv6PrefixPDU) serialize(wr io.Writer) {
	/*
	   0          8          16         24        31
	   .-------------------------------------------.
	   | Protocol |   PDU    |                     |
	   | Version  |   Type   |         zero        |
	   |    1     |    6     |                     |
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
	binary.Write(wr, binary.BigEndian, version1)
	binary.Write(wr, binary.BigEndian, ipv6Prefix)
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, uint32(32))
	binary.Write(wr, binary.BigEndian, p.flags)
	binary.Write(wr, binary.BigEndian, p.min)
	binary.Write(wr, binary.BigEndian, p.max)
	binary.Write(wr, binary.BigEndian, uint8(0))
	binary.Write(wr, binary.BigEndian, p.prefix)
	binary.Write(wr, binary.BigEndian, p.asn)

}

type endOfDataPDU struct {
	sessionID uint16
	serial    uint32
	refresh   uint32
	retry     uint32
	expire    uint32
}

func (p *endOfDataPDU) serialize(wr io.Writer) {
	/*
	   0          8          16         24        31
	   .-------------------------------------------.
	   | Protocol |   PDU    |                     |
	   | Version  |   Type   |     Session ID      |
	   |    1     |    7     |                     |
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
	binary.Write(wr, binary.BigEndian, version1)
	binary.Write(wr, binary.BigEndian, endOfData)
	binary.Write(wr, binary.BigEndian, p.sessionID)
	binary.Write(wr, binary.BigEndian, uint32(24))
	binary.Write(wr, binary.BigEndian, p.serial)
	binary.Write(wr, binary.BigEndian, p.refresh)
	binary.Write(wr, binary.BigEndian, p.retry)
	binary.Write(wr, binary.BigEndian, p.expire)
	fmt.Printf("Finished sending end of data PDU: %v\n", *p)
}

type cacheResetPDU struct {
}

func (p *cacheResetPDU) serialize(wr io.Writer) {
	/*
	   0          8          16         24        31
	   .-------------------------------------------.
	   | Protocol |   PDU    |                     |
	   | Version  |   Type   |         zero        |
	   |    1     |    8     |                     |
	   +-------------------------------------------+
	   |                                           |
	   |                 Length=8                  |
	   |                                           |
	   `-------------------------------------------'
	*/
	fmt.Printf("Sending a cache reset PDU: %v\n", *p)
	binary.Write(wr, binary.BigEndian, version1)
	binary.Write(wr, binary.BigEndian, cacheReset)
	binary.Write(wr, binary.BigEndian, uint16(0))
	binary.Write(wr, binary.BigEndian, length8Uint32)
}