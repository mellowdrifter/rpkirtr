package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"

	"inet.af/netaddr"
)

type jsonroa struct {
	Prefix string      `json:"prefix"`
	Mask   uint8       `json:"maxLength"`
	ASN    interface{} `json:"asn"`
}

type roas struct {
	Roas []jsonroa `json:"roas"`
}

type rpkiResponse struct {
	roas
}

// makeDiff will return a list of ROAs that need to be deleted or updated
// in order for a particular serial version to updated to the latest version.
func makeDiff(new, old []roa, serial uint32) serialDiff {
	var addROA, delROA []roa

	newm := roasToMap(new)
	oldm := roasToMap(old)

	// If ROA is in newMap but not oldMap, we need to add it
	for k, v := range newm {
		_, ok := oldm[k]
		if !ok {
			addROA = append(addROA, v)
		}
	}

	// If ROA is in oldMap but not newMap, we need to delete it.
	for k, v := range oldm {
		_, ok := newm[k]
		if !ok {
			delROA = append(delROA, v)
		}
	}

	// There is only a diff is something is added or deleted.
	diff := len(addROA) > 0 || len(delROA) > 0

	return serialDiff{
		oldSerial: serial,
		newSerial: serial + 1,
		addRoa:    addROA,
		delRoa:    delROA,
		diff:      diff,
	}
}

// roasToMap will convert a slice of ROAs into a map of formatted ROA to a ROA.
func roasToMap(roas []roa) map[string]roa {
	rm := make(map[string]roa, len(roas))
	for _, roa := range roas {
		rm[fmt.Sprintf("%s%d%d", roa.Prefix.IPNet().String(), roa.MaxMask, roa.ASN)] = roa
	}
	return rm
}

func readROAs(urls []string) ([]roa, error) {
	var roas []roa

	// Will this blend?
	ch := make(chan []roa, len(urls))
	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go fetchAndDecodeJSON(url, ch, &wg)
	}
	wg.Wait()
	close(ch)
	for v := range ch {
		roas = append(roas, v...)
	}

	validROAs := GetSetOfValidatedROAs(roas)

	log.Printf("Created a unique set of %d ROAs\n", len(validROAs))

	return validROAs, nil
}

// fetchAndDecodeJSON will fetch the latest set of ROAs and add to a local struct
// https://console.rpki-client.org/vrps.json
/*func fetchAndDecodeJSON(url string, ch chan []roa) ([]roa, error) {
	log.Printf("Downloading from %s\n", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve ROAs from url: %w", err)
	}
	defer resp.Body.Close()

	f, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read body of response: %w", err)
	}

	var r rpkiResponse
	if err = json.Unmarshal(f, &r); err != nil {
		return nil, err
	}

	// We know how many ROAs we have, so we can add that capacity directly
	newROAs := make([]roa, 0, len(r.roas.Roas))

	for _, r := range r.roas.Roas {
		prefix, err := netaddr.ParseIPPrefix(r.Prefix)
		if err != nil {
			return nil, err
		}
		asn := decodeASN(r)
		newROAs = append(newROAs, roa{
			Prefix:  prefix,
			MaxMask: r.Mask,
			ASN:     asn,
		})
	}

	log.Printf("Returning %d ROAs from %s\n", len(newROAs), url)

	return newROAs, nil
}*/

func fetchAndDecodeJSON(url string, ch chan []roa, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Printf("Downloading from %s\n", url)
	var roas []roa
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("unable to retrieve ROAs from url: %v", err)
		ch <- roas
	}
	defer resp.Body.Close()

	f, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("unable to read body of response: %v", err)
		ch <- roas
	}

	var r rpkiResponse
	if err = json.Unmarshal(f, &r); err != nil {
		log.Printf("unable to unmarshal: %v", err)
		ch <- roas
	}

	// We know how many ROAs we have, so we can add that capacity directly
	newROAs := make([]roa, 0, len(r.roas.Roas))

	for _, r := range r.roas.Roas {
		prefix, err := netaddr.ParseIPPrefix(r.Prefix)
		if err != nil {
			log.Printf("%v", err)
			ch <- newROAs
		}
		asn := decodeASN(r)
		newROAs = append(newROAs, roa{
			Prefix:  prefix,
			MaxMask: r.Mask,
			ASN:     asn,
		})
	}

	ch <- newROAs

	log.Printf("Returning %d ROAs from %s\n", len(newROAs), url)
}

func decodeASN(data jsonroa) uint32 {
	switch atype := data.ASN.(type) {
	case string:
		return asnToUint32(atype)
	case float64:
		return uint32(atype)
	}
	return 0
}

// GetSetOfValidatedROAs returns a slice of ROAs with no duplicates.
// It only appends if the ROA is valid
func GetSetOfValidatedROAs(roas []roa) []roa {
	u := make([]roa, 0, len(roas))
	m := make(map[roa]bool)
	for _, roa := range roas {
		if _, ok := m[roa]; !ok {
			m[roa] = true
			if roa.isValid() {
				u = append(u, roa)
			}
		}
	}
	return u
}

// https://datatracker.ietf.org/doc/html/rfc6482#section-3.3
func (roa *roa) isValid() bool {
	// MaxLength cannot be zero or negative
	// MaxMask is a uint8 so cannot be negative
	if roa.MaxMask == 0 {
		log.Printf("maxmask <= 0: %#v\n", roa)
		return false
	}

	// MaxLength cannot be smaller than prefix length
	if roa.MaxMask < roa.Prefix.Bits() {
		log.Printf("maxmask < mask: %#v\n", roa)
		return false
	}

	// MaxLength cannot be larger than the max allowed for that address family
	if roa.Prefix.IP().Is4() && roa.MaxMask > 32 {
		log.Printf("maxmask > max: %#v\n", roa)
		return false
	} else if roa.MaxMask > 128 {
		log.Printf("maxmask > max: %#v\n", roa)
		return false
	}

	return true
}

// stringToInt does inline convertions and logs errors, instead of panicing.
func stringToInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		log.Printf("Unable to convert %s to int", s)
		return 0
	}

	return n
}

// Some json VRPs contain ASXXX instead of just XXX as the ASN
func asnToUint32(a string) uint32 {
	n, err := strconv.Atoi(a[2:])
	if err != nil {
		log.Printf("Unable to convert ASN %s to int", a)
		return 0
	}

	return uint32(n)
}
