package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

type PddZone struct {
	Records []PddRecord `json:"records"`
}

type PddRecord struct {
	Fqdn string `json:"fqdn"`
	Type string `json:"type"`
}

type PddZonePage struct {
	Page    int         `json:"page"`
	OnPage  int         `json:"on_page"` // number of domains on every page
	Found   int         `json:"found"`   // number of domains on current page
	Domains []PddDomain `json:"domains"`
}

type PddDomain struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// request zone list and write them to struct
func GetPddZones(token *string) []string {
	pages := []PddZonePage{}
	p := PddZonePage{}

	u, err := url.Parse("https://pddimp.yandex.ru/api2/admin/domain/domains")
	if err != nil {
		log.Fatal(err)
	}

	for i := 1; ; i++ {
		params := url.Values{}
		params.Add("page", strconv.Itoa(i))
		u.RawQuery = params.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			log.Fatal(err)
		}
		req.Header.Set("PddToken", *token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(err)
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		resp.Body.Close()

		// clear page struct before unmarshaling
		p = PddZonePage{}
		err = json.Unmarshal(b, &p)
		if err != nil {
			log.Fatal(err)
		}
		pages = append(pages, p)

		// stop requesting pages if last page reached
		if p.Found < p.OnPage {
			break
		}
	}

	// process list of pages and form zones list
	zones := []string{}
	for _, pg := range pages {
		for _, z := range pg.Domains {
			zones = append(zones, z.Name)
		}
	}
	log.Printf("got pdd zones (%d total): %s", len(zones), zones)
	return zones
}

// get list of domains from all nic zones
func GetPddDomains(token *string, zones *[]string) []string {
	records := PddZone{}
	domains := []string{}

	u, err := url.Parse("https://pddimp.yandex.ru/api2/admin/dns/list")
	if err != nil {
		log.Fatal(err)
	}

	for _, z := range *zones {
		params := url.Values{}
		params.Add("domain", z)
		u.RawQuery = params.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			log.Fatal(err)
		}
		req.Header.Set("PddToken", *token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(err)
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		resp.Body.Close()

		// clear records struct before unmarshaling
		records = PddZone{}
		err = json.Unmarshal(b, &records)
		if err != nil {
			log.Fatal(err)
		}

		// get list of records from each zone
		for _, rr := range records.Records {
			if rr.Type == "CNAME" || rr.Type == "A" {
				domains = append(domains, rr.Fqdn)
			}
		}
	}
	return domains
}
