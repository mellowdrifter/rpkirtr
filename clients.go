package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
)

// Each client has their own stuff
type client struct {
	conn    net.Conn
	session *uint16
	addr    string
	roas    *[]roa
	serial  *uint32
	mutex   *sync.RWMutex
	diff    *serialDiff
}

// reset has no data besides the header
func (c *client) sendReset() {
	r := cacheResetPDU{}
	r.serialize(c.conn)
}

// sendDiff should send additions and deletions to the client.
func (c *client) sendDiff(diff *serialDiff, session uint16) {
	cpdu := cacheResponsePDU{
		sessionID: session,
	}
	cpdu.serialize(c.conn)
	if diff.diff {
		for _, roa := range diff.addRoa {
			writePrefixPDU(&roa, c.conn, announce)
		}
		for _, roa := range diff.delRoa {
			writePrefixPDU(&roa, c.conn, withdraw)
		}
		log.Println("Finished sending all diffs")
	}
	epdu := endOfDataPDU{
		session: uint16(session),
		serial:  *c.serial,
		refresh: uint32(900),
		retry:   uint32(30),
		expire:  uint32(171999),
	}
	epdu.serialize(c.conn)

}

// writePrefixPDU will directly write the update or withdraw prefix PDU.
func writePrefixPDU(r *roa, c net.Conn, flag uint8) {
	IPAddress := net.ParseIP(r.Prefix)
	switch r.IsV4 {
	case true:
		ppdu := ipv4PrefixPDU{
			flags:  flag,
			min:    r.MinMask,
			max:    r.MaxMask,
			prefix: ipv4ToByte(IPAddress.To4()),
			asn:    r.ASN,
		}
		ppdu.serialize(c)
	case false:
		ppdu := ipv6PrefixPDU{
			flags:  flag,
			min:    r.MinMask,
			max:    r.MaxMask,
			prefix: ipv6ToByte(IPAddress.To16()),
			asn:    r.ASN,
		}
		ppdu.serialize(c)
	}
}

// Notify client that an update has taken place
func (c *client) notify(serial uint32, session uint16) {
	npdu := serialNotifyPDU{
		Session: session,
		Serial:  serial,
	}
	npdu.serialize(c.conn)

}

// sendEmpty sends an empty response if there is no update required.
func (c *client) sendEmpty(session uint16) {
	cpdu := cacheResponsePDU{
		sessionID: session,
	}
	cpdu.serialize(c.conn)
	epdu := endOfDataPDU{
		session: uint16(session),
		serial:  *c.serial,
		refresh: uint32(900),
		retry:   uint32(30),
		expire:  uint32(171999),
	}
	epdu.serialize(c.conn)

}

func (c *client) sendRoa() {
	session := rand.Intn(100)
	cpdu := cacheResponsePDU{
		sessionID: uint16(session),
	}
	cpdu.serialize(c.conn)

	c.mutex.RLock()
	for _, roa := range *c.roas {
		writePrefixPDU(&roa, c.conn, announce)
	}
	c.mutex.RUnlock()
	log.Println("Finished sending all prefixes")
	epdu := endOfDataPDU{
		session: uint16(session),
		serial:  *c.serial,
		refresh: refresh,
		retry:   retry,
		expire:  expire,
	}
	epdu.serialize(c.conn)
}

// TODO: Test this somehow
func (c *client) error(code int, report string) {
	epdu := errorReportPDU{
		code:   uint16(code),
		report: report,
	}
	epdu.serialize(c.conn)

}

// Handle each client.
func (s *CacheServer) handleClient(c *client) {
	log.Printf("Serving %s\n", c.conn.RemoteAddr().String())

	// Remove client when exiting
	defer s.remove(c)
	defer c.conn.Close()

	for {

		// What is the incoming PDU?
		pdu, err := getPDU(c.conn)
		if err != nil {
			log.Printf("error received when getting the pdu: %v", err)
			return
		}
		header, err := decodePDUHeader(pdu[:2])
		if err != nil {
			log.Printf("error received when decoding the header: %v", err)
			return
		}

		switch {
		case header.Ptype == resetQuery:
			log.Printf("received a reset Query PDU from %s\n", c.addr)
			c.sendRoa()

		case header.Ptype == serialQuery:
			log.Printf("received a serial Query PDU from %s\n", c.addr)
			q := getSerialQueryPDU(pdu[2:])
			// If the client sends in the current or previous serial, then we can handle it.
			// If the serial is older or unknown, we need to send a reset.
			c.mutex.RLock()
			serial := c.diff.newSerial
			c.mutex.RUnlock()
			if q.Serial != serial && q.Serial != serial-1 {
				log.Printf("received a serial query PDU, with an unmanagable serial from %s\n", c.addr)
				log.Printf("Serial received: %d. Current server serial: %d\n", q.Serial, serial)
				c.sendReset()
			}
			if q.Serial == serial {
				log.Printf("received a serial number which currently matches my own from %s\n", c.addr)
				log.Printf("Serial received: %d. Current server serial: %d\n", q.Serial, serial)
				c.sendEmpty(q.Session)
			}
			if q.Serial == serial-1 {
				log.Printf("received a serial number one less, so sending diff to %s\n", c.addr)
				log.Printf("Serial received: %d. Current server serial: %d\n", q.Serial, serial)
				c.mutex.RLock()
				c.sendDiff(c.diff, q.Session)
				c.mutex.RUnlock()
			}
		}
	}
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
		log.Printf("Returning on line 222: %v", buf)
		return nil, err
	}

	// Read the rest of the PDU, minus the header.
	length := binary.BigEndian.Uint32(buf[4:8]) - 8
	if length > 0 {
		lr := io.LimitReader(r, int64(length))
		data := make([]byte, length)
		if _, err := io.ReadFull(lr, data); err != nil {
			log.Printf("Returning on line 232: %v", buf)
			return nil, err
		}
		buf = append(buf, data...)
	}
	return buf, nil
}

// decodePDUHeader does a size and version check. Otherwise it returns just the header.
func decodePDUHeader(pdu []byte) (headerPDU, error) {
	var header headerPDU
	if len(pdu) < headPDULength {
		return header, fmt.Errorf("PDU headers have a minimin size of 2. PDU passed has length %d", len(pdu))
	}
	if int(pdu[0]) != 1 {
		return header, fmt.Errorf("only version 1 is supported. PDU has version %s", int(pdu[0]))
	}
	header.Version = uint8(pdu[0])
	header.Ptype = uint8(pdu[1])
	log.Printf("Line 251: %v", header)

	return header, nil
}
