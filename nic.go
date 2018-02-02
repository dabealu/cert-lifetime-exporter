package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

type NicToken struct {
	Expires string `json:"expires_in"` // 14400 - 4h
	Token   string `json:"access_token"`
}

type NicZone struct {
	Name    string `xml:"name,attr"`
	IdnName string `xml:"idn-name,attr"`
	Enable  string `xml:"enable,attr"`
	Service string `xml:"service,attr"`
}

type NicZones struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status"`
	Data    struct {
		Zone []NicZone `xml:"zone"`
	} `xml:"data"`
}

type NicRecords struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status"`
	Data    struct {
		Zone struct {
			Name    string `xml:"name,attr"`
			IdnName string `xml:"idn-name,attr"`
			Rr      []struct {
				Name    string `xml:"name"`
				IdnName string `xml:"idn-name"`
				Type    string `xml:"type"`
			} `xml:"rr"`
		} `xml:"zone"`
	} `xml:"data"`
}

// get token to access nic api
func (t *NicToken) Get(c *Config) {
	// create token url
	u, err := url.Parse("https://api.nic.ru/oauth/token")
	if err != nil {
		log.Fatal(err)
	}
	params := url.Values{}
	params.Add("grant_type", "password")
	params.Add("scope", "GET:/dns-master/.+")
	params.Add("username", c.Nic.Login)
	params.Add("password", c.Nic.Password)
	u.RawQuery = params.Encode()

	// request token
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		log.Fatal(err)
	}
	appAuth := fmt.Sprintf("%s:%s", c.Nic.AppLogin, c.Nic.AppPassword)
	req.Header.Set("Authorization", "Basic "+base64.URLEncoding.EncodeToString([]byte(appAuth)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(b, &t)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("acquired nic token: %s", t.Token)
}

// request zone list and write them to struct
func (z *NicZones) GetZones(t *NicToken) {
	req, err := http.NewRequest("GET", "https://api.nic.ru/dns-master/zones", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// clear list of zones before unmarshal
	*z = NicZones{}

	err = xml.Unmarshal(b, &z)
	if err != nil {
		log.Fatal(err)
	}

	zoneNames := []string{}
	for _, zone := range z.Data.Zone {
		zoneNames = append(zoneNames, zone.Name)
	}
	log.Printf("got nic zones (%d total): %s", len(zoneNames), zoneNames)
}

// get list of domains from all nic zones
func (z *NicZones) GetDomains(t *NicToken) []string {
	records := []NicRecords{}
	r := NicRecords{}

	for _, zone := range z.Data.Zone {
		// request resourse records
		url := fmt.Sprintf("https://api.nic.ru/dns-master/services/%s/zones/%s/records", zone.Service, zone.Name)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+t.Token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(err)
		}

		// parse response
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		resp.Body.Close()

		err = xml.Unmarshal(b, &r)
		if err != nil {
			log.Fatal(err)
		}

		// append records struct to slice
		records = append(records, r)
	}

	// parse slice of structs and get A and CNAME records
	domains := []string{}
	for _, entry := range records {
		zone := entry.Data.Zone.Name
		for _, record := range entry.Data.Zone.Rr {
			if (record.Type == "A" || record.Type == "CNAME") && record.Name != "@" {
				domains = append(domains, record.Name+"."+zone)
			}
		}
	}

	return domains
}
