package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
)

type jsonroa struct {
	Prefix string `json:"prefix"`
	Mask   uint8  `json:"maxLength"`
	ASN    any    `json:"asn"`
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

	// If ROA is in newMap but not oldMap, we need to add it
	for _, roa := range new {
		if !slices.Contains(old, roa) {
			addROA = append(addROA, roa)
		}
	}

	// If ROA is in oldMap but not newMap, we need to delete it.
	for _, roa := range old {
		if !slices.Contains(new, roa) {
			delROA = append(delROA, roa)
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

func readROAs(urls []string) ([]roa, error) {
	var roas []roa
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
func fetchAndDecodeJSON(url string, ch chan []roa, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Printf("Downloading from %s\n", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("unable to retrieve ROAs from url: %v", err)
		return
	}
	defer resp.Body.Close()

	f, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("unable to read body of response: %v", err)
		return
	}

	var r rpkiResponse
	if err = json.Unmarshal(f, &r); err != nil {
		log.Printf("unable to unmarshal: %v", err)
		return
	}

	// We know how many ROAs we have, so we can add that capacity directly
	newROAs := make([]roa, 0, len(r.roas.Roas))

	for _, r := range r.roas.Roas {
		prefix, err := netip.ParsePrefix(r.Prefix)
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

// Some URLs have the AS Number as a number while others as a string.
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
	if roa.MaxMask < uint8(roa.Prefix.Bits()) {
		log.Printf("maxmask < mask: %#v\n", roa)
		return false
	}

	// MaxLength cannot be larger than the max allowed for that address family
	if roa.Prefix.Addr().Is4() && roa.MaxMask > 32 {
		log.Printf("maxmask > max: %#v\n", roa)
		return false
	} else if roa.MaxMask > 128 {
		log.Printf("maxmask > max: %#v\n", roa)
		return false
	}

	return true
}

// Some json VRPs contain ASXXX instead of just XXX as the ASN
// TODO: Use a regex to remove letter instead of assuming its the first two
func asnToUint32(a string) uint32 {
	n, err := strconv.Atoi(a[2:])
	if err != nil {
		log.Printf("Unable to convert ASN %s to int", a)
		return 0
	}

	return uint32(n)
}
