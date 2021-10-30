package main

import (
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

// updateClient will check to see if there are diffs to send.
// If so it'll send them, otherwise it'll just send an end of data PDU updating
// the serial.
func (c *client) updateClient(session uint16, serial uint32, sendDiff bool) {
	cpdu := cacheResponsePDU{
		sessionID: session,
	}
	cpdu.serialize(c.conn)

	// diff will only be sent if there is an actual update to send
	if sendDiff && c.diff.diff {
		c.mutex.RLock()
		for _, roa := range c.diff.addRoa {
			writePrefixPDU(&roa, c.conn, announce)
		}
		for _, roa := range c.diff.delRoa {
			writePrefixPDU(&roa, c.conn, withdraw)
		}
		c.mutex.RUnlock()
		log.Println("Finished sending all diffs")
	}

	epdu := getEndOfDataPDU(session, *c.serial)
	epdu.serialize(c.conn)
}

// writePrefixPDU will directly write the update or withdraw prefix PDU.
func writePrefixPDU(r *roa, c net.Conn, flag uint8) {
	switch r.Prefix.IP().Is4() {
	case true:
		ppdu := ipv4PrefixPDU{
			flags:  flag,
			min:    r.Prefix.Bits(),
			max:    r.MaxMask,
			prefix: r.Prefix.IP().As4(),
			asn:    r.ASN,
		}
		ppdu.serialize(c)
	case false:
		ppdu := ipv6PrefixPDU{
			flags:  flag,
			min:    r.Prefix.Bits(),
			max:    r.MaxMask,
			prefix: r.Prefix.IP().As16(),
			asn:    r.ASN,
		}
		ppdu.serialize(c)
	}
}

func getEndOfDataPDU(session uint16, serial uint32) endOfDataPDU {
	return endOfDataPDU{
		session: session,
		serial:  serial,
		refresh: RefreshInterval,
		retry:   RetryInterval,
		expire:  ExpireInterval,
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
		refresh: RefreshInterval,
		retry:   RetryInterval,
		expire:  ExpireInterval,
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
			// TODO: Is 2 a magic number?
			sq := getSerialQueryPDU(pdu[2:])
			c.mutex.RLock()
			serial := c.diff.newSerial
			c.mutex.RUnlock()

			// If the client sends in the current or previous serial, then we can handle it.
			// If the serial is older or unknown, we need to send a reset.
			if sq.Serial != serial && sq.Serial != serial-1 {
				log.Printf("received a serial query PDU, with an unmanagable serial from %s\n", c.addr)
				log.Printf("Serial received: %d. Current server serial: %d\n", sq.Serial, serial)
				c.sendReset()
			}
			if sq.Serial == serial {
				log.Printf("received a serial number which currently matches my own from %s\n", c.addr)
				log.Printf("Serial received: %d. Current server serial: %d\n", sq.Serial, serial)
				c.updateClient(sq.Session, serial, false)
			}
			if sq.Serial == serial-1 {
				log.Printf("received a serial number one less, so sending diff to %s\n", c.addr)
				log.Printf("Serial received: %d. Current server serial: %d\n", sq.Serial, serial)
				c.updateClient(sq.Session, serial, true)
			}
		}
	}
}
