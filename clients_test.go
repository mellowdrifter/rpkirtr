package main

import (
	"bytes"
	"testing"
)

func TestGetPDU(t *testing.T) {
	tests := []struct {
		desc    string
		input   []byte
		pdu     []byte
		wantErr bool
	}{
		{
			desc:  "valid serial notify pdu",
			input: []byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00},
			pdu:   []byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00},
		},
		{
			desc:  "valid serial query pdu",
			input: []byte{0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01},
			pdu:   []byte{0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01},
		},
		{
			desc:  "valid reset query pdu",
			input: []byte{0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
			pdu:   []byte{0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
		},
		{
			desc:  "valid cache response pdu",
			input: []byte{0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
			pdu:   []byte{0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
		},
		{
			desc:  "valid cache reset pdu",
			input: []byte{0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
			pdu:   []byte{0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
		},
		{
			desc:    "invalid pdu. Length longer than actual pdu",
			input:   []byte{0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c},
			wantErr: true,
		},
	}
	for _, v := range tests {
		got, err := getPDU(bytes.NewReader(v.input))
		if err == nil && v.wantErr {
			t.Errorf("Error on %s. Wanted an error, but none received: %v", v.desc, err)
		}
		if err != nil && !v.wantErr {
			t.Errorf("Error on %s. No error expected, but error received: %v", v.desc, err)
		}
		if !bytes.Equal(got, v.pdu) {
			t.Errorf("Error on %s. Got %d, Want %d\n", v.desc, got, v.pdu)
		}
	}
}

func TestDecodePDUHeader(t *testing.T) {
	tests := []struct {
		desc    string
		input   []byte
		pdu     uint8
		wantErr bool
	}{
		{
			desc:  "valid serial notify pdu",
			input: []byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00},
			pdu:   serialNotify,
		},
		{
			desc:  "valid serial query pdu",
			input: []byte{0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01},
			pdu:   serialQuery,
		},
		{
			desc:  "valid reset query pdu",
			input: []byte{0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
			pdu:   resetQuery,
		},
		{
			desc:  "valid cache response pdu",
			input: []byte{0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
			pdu:   cacheResponse,
		},
		{
			desc:  "valid cache reset pdu",
			input: []byte{0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
			pdu:   cacheReset,
		},
		{
			desc:    "Invalid pdu number 5",
			input:   []byte{0x01, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
			wantErr: true,
			pdu:     5,
		},
		{
			desc:    "Invalid pdu number 11",
			input:   []byte{0x01, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08},
			wantErr: true,
			pdu:     11,
		},
	}
	for _, v := range tests {
		got, err := decodePDUHeader(v.input[:2])
		if err == nil && v.wantErr {
			t.Errorf("Error on %s. Wanted an error, but none received: %v", v.desc, err)
			break
		}
		if err != nil && !v.wantErr {
			t.Errorf("Error on %s. No error expected, but error received: %v", v.desc, err)
			break
		}
		if got.Ptype != v.pdu {
			t.Errorf("Error on %s: Wanted pdu value %d, got %d", v.desc, v.pdu, got.Ptype)
			break
		}
	}
}
