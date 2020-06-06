package main

import "testing"

func TestGetPDU(t *testing.T) {
	tests := []struct {
		desc    string
		input   []byte
		pdu     []byte
		wantErr bool
	}{
		{
			desc:  "test 1",
			input: []byte{0x01, 0x01, 0x00, 0x48, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00},
		},
	}
	for _, v := range tests {
		got := getPDU(v.pdu)
		if got != v.pdu {
			t.Errorf("Error on %s. Got %d, Want %d\n", v.desc, got, v.pdu)
		}
	}
}
