package main

import (
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"inet.af/netaddr"
)

func TestStringToInt(t *testing.T) {
	tests := []struct {
		desc   string
		number string
		want   int
	}{
		{
			desc:   "test 1",
			number: "1",
			want:   1,
		},
		{
			desc:   "test word",
			number: "word",
			want:   0,
		},
	}
	for _, v := range tests {
		got := stringToInt(v.number)
		if got != v.want {
			t.Errorf("Error on %s. Got %d, Want %d\n", v.desc, got, v.want)
		}
	}
}

func TestAsnToInt(t *testing.T) {
	tests := []struct {
		desc    string
		asnText string
		want    uint32
	}{
		{
			desc:    "test 1",
			asnText: "AS123",
			want:    123,
		},
		{
			desc:    "test 2",
			asnText: "word",
			want:    0,
		},
	}
	for _, v := range tests {
		got := asnToUint32(v.asnText)
		if got != v.want {
			t.Errorf("Error on %s. Got %d, Want %d\n", v.desc, got, v.want)
		}
	}
}

func TestMakeDiff(t *testing.T) {
	tests := []struct {
		desc   string
		new    []roa
		old    []roa
		serial uint32
		want   serialDiff
	}{
		{
			desc:   "empty, no diff",
			new:    []roa{},
			old:    []roa{},
			serial: 0,
			want: serialDiff{
				oldSerial: 0,
				newSerial: 1,
				delRoa:    nil,
				addRoa:    nil,
				diff:      false,
			},
		}, {
			desc: "one ROA, no diff",
			new: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     123,
				},
			},
			old: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     123,
				},
			},
			serial: 1,
			want: serialDiff{
				oldSerial: 1,
				newSerial: 2,
				delRoa:    nil,
				addRoa:    nil,
				diff:      false,
			},
		}, {
			desc: "Min mask change",
			new: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/23"),
					MaxMask: 32,
					ASN:     123,
				},
			},
			old: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     123,
				},
			},
			serial: 1,
			want: serialDiff{
				oldSerial: 1,
				newSerial: 2,
				delRoa: []roa{
					{
						Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
						MaxMask: 32,
						ASN:     123,
					},
				},
				addRoa: []roa{
					{
						Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/23"),
						MaxMask: 32,
						ASN:     123,
					},
				},
				diff: true,
			},
		}, {
			desc: "Max mask change",
			new: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 31,
					ASN:     123,
				},
			},
			old: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     123,
				},
			},
			serial: 1,
			want: serialDiff{
				oldSerial: 1,
				newSerial: 2,
				delRoa: []roa{
					{
						Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
						MaxMask: 32,
						ASN:     123,
					},
				},
				addRoa: []roa{
					{
						Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
						MaxMask: 31,
						ASN:     123,
					},
				},
				diff: true,
			},
		}, {
			desc: "ASN change",
			new: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     123,
				},
			},
			old: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     1234,
				},
			},
			serial: 1,
			want: serialDiff{
				oldSerial: 1,
				newSerial: 2,
				delRoa: []roa{
					{
						Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
						MaxMask: 32,
						ASN:     1234,
					},
				},
				addRoa: []roa{
					{
						Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
						MaxMask: 32,
						ASN:     123,
					},
				},
				diff: true,
			},
		}, {
			desc: "Two ROAs to one",
			new: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     123,
				},
			},
			old: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     123,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("2001:db8::/32"),
					MaxMask: 48,
					ASN:     123,
				},
			},
			serial: 1,
			want: serialDiff{
				oldSerial: 1,
				newSerial: 2,
				delRoa: []roa{
					{
						Prefix:  netaddr.MustParseIPPrefix("2001:db8::/32"),
						MaxMask: 48,
						ASN:     123,
					},
				},
				addRoa: nil,
				diff:   true,
			},
		}, {
			desc: "One ROA to two",
			new: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     123,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("2001:db8::/32"),
					MaxMask: 48,
					ASN:     123,
				},
			},
			old: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("192.168.1.1/24"),
					MaxMask: 32,
					ASN:     123,
				},
			},
			serial: 1,
			want: serialDiff{
				oldSerial: 1,
				newSerial: 2,
				delRoa:    nil,
				addRoa: []roa{
					{
						Prefix:  netaddr.MustParseIPPrefix("2001:db8::/32"),
						MaxMask: 48,
						ASN:     123,
					},
				},
				diff: true,
			},
		},
	}
	for _, v := range tests {
		got := makeDiff(v.new, v.old, v.serial)
		if !diffIsEqual(got, v.want) {
			t.Errorf("Error on %s. got %#v, Want %#v\n", v.desc, got, v.want)
		}
	}
}

// diffIsEqual will ensure two serialDiffs are equal.
func diffIsEqual(first, second serialDiff) bool {
	if first.oldSerial != second.oldSerial {
		return false
	}
	if first.newSerial != second.newSerial {
		return false
	}
	if len(first.delRoa) != len(second.delRoa) {
		return false
	}
	if len(first.addRoa) != len(second.addRoa) {
		return false
	}
	if len(first.addRoa) > 0 {
		for i := 0; i < len(first.addRoa); i++ {
			if first.addRoa[i].MaxMask != second.addRoa[i].MaxMask {
				return false
			}
			if first.addRoa[i].ASN != second.addRoa[i].ASN {
				return false
			}
			// TODO: Add rir if I ever get around to doing that.
			if first.addRoa[i].Prefix != second.addRoa[i].Prefix {
				return false
			}
		}
	}
	if len(first.delRoa) > 0 {
		for i := 0; i < len(first.delRoa); i++ {
			if first.delRoa[i].MaxMask != second.delRoa[i].MaxMask {
				return false
			}
			if first.delRoa[i].ASN != second.delRoa[i].ASN {
				return false
			}
			// TODO: Add rir if I ever get around to doing that.
			if first.delRoa[i].Prefix != second.delRoa[i].Prefix {
				return false
			}
		}
	}
	return true
}

func stringHandler(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("data/string.json")
	if err != nil {
		panic(err)
	}
	w.Write(data)
}

func intHandler(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("data/int.json")
	if err != nil {
		panic(err)
	}
	w.Write(data)
}

func TestReadROAs(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/string", stringHandler)
	mux.HandleFunc("/int", intHandler)
	go http.ListenAndServe(":8181", mux)
	time.Sleep(1 * time.Second)

	tests := []struct {
		desc     string
		one, two string
		want     []roa
		wantErr  bool
	}{
		{
			desc: "first",
			one:  "http://127.0.0.1:8181/int",
			two:  "http://127.0.0.1:8181/string",
			want: []roa{
				{
					Prefix:  netaddr.MustParseIPPrefix("1.0.0.0/24"),
					MaxMask: 24,
					ASN:     13335,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("1.0.0.0/24"),
					MaxMask: 24,
					ASN:     38803,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("1.0.0.0/22"),
					MaxMask: 22,
					ASN:     38803,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("1.0.5.0/24"),
					MaxMask: 24,
					ASN:     38803,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("2c0f:ffb8::/32"),
					MaxMask: 32,
					ASN:     3721,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("2c0f:ffe8::/32"),
					MaxMask: 32,
					ASN:     37443,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("2001:678:cdc::/48"),
					MaxMask: 128,
					ASN:     333333,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("1.0.0.0/22"),
					MaxMask: 23,
					ASN:     38803,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("2001:678:cdc::/48"),
					MaxMask: 128,
					ASN:     210660,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("50.128.0.0/9"),
					MaxMask: 9,
					ASN:     7922,
				},
				{
					Prefix:  netaddr.MustParseIPPrefix("73.0.0.0/8"),
					MaxMask: 8,
					ASN:     7922,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := readROAs([]string{"http://127.0.0.1:8181/int", "http://127.0.0.1:8181/string"})
			if err != nil {
				panic(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Got (%v), Wanted (%v)", got, tc.want)
			}
		})
	}
}
