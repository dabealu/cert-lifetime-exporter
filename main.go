package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

type Config struct {
	Nic struct {
		Enabled     bool   `json:"enabled"`
		Login       string `json:"login"`
		Password    string `json:"password"`
		AppLogin    string `json:"app_login"`
		AppPassword string `json:"app_password"`
	} `json:"nic"`

	Pdd struct {
		Enabled bool   `json:"enabled"`
		Token   string `json:"token"`
	} `json:"pdd"`

	Global struct {
		ExcludeDomains []string `json:"exclude_domains"`
		AddDomains     []string `json:"add_domains"`
	} `json:"global"`
}

// load config file
func (c *Config) load(path string) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal([]byte(f), c)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("config loaded: %s", path)
}

// print example of config file
func (c *Config) printSample() {
	c.Pdd.Enabled = true
	c.Global.ExcludeDomains = []string{"^foo\\.com$", "^ba(r|z)\\.(org|ru)"}
	c.Global.AddDomains = []string{"baz.io:3000", "fiz.svc.cluster.local:8080"}
	sample, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(sample))
	os.Exit(0)
}

// put domains from slice into channel
func queueDomains(c chan string, rc *RuntimeConf, verbose bool, pause int) {
	slc := []string{}
	for {
		rc.Mux.Lock()
		slc = rc.Domains
		rc.Mux.Unlock()
		for _, d := range slc {
			c <- d
		}
		slc = []string{}
		if verbose {
			log.Printf("domains list processed, pausing for %d until next iteration", pause)
		}
		time.Sleep(time.Second * time.Duration(pause))
	}
}

type Check struct {
	CertLifetime float64
	CheckStatus  string // ok|fail
}

type Results struct {
	Mux sync.Mutex
	Map map[string]Check
}

// endlessly get domains from channel and evaluate certificate expiration time
func certTimeLeft(c chan string, timeout int, verbose bool, results *Results) {
	for {
		url := <-c

		req, err := http.NewRequest("HEAD", "https://"+url, nil)
		if err != nil {
			if verbose {
				log.Println("request error:", err)
			}
			results.Mux.Lock()
			results.Map[url] = Check{0, "fail"}
			results.Mux.Unlock()
			continue
		}

		// ignore cert expiration when doing request
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client := &http.Client{
			Transport: tr,
			Timeout:   time.Duration(timeout) * time.Second,
		}

		resp, err := client.Do(req)
		if err != nil {
			if verbose {
				log.Println("request error:", err)
			}
			results.Mux.Lock()
			results.Map[url] = Check{0, "fail"}
			results.Mux.Unlock()
			continue
		}

		// []*x509.Certificate
		peerCerts := resp.TLS.PeerCertificates
		resp.Body.Close()

		for _, c := range peerCerts {
			if len(c.DNSNames) != 0 {
				lifetime := time.Until(c.NotAfter).Seconds()
				if verbose {
					// log domain processing
					log.Printf("checked: %s (%d total domains), expires: %s, days left: %f",
						url, len(c.DNSNames), c.NotAfter, lifetime/(24*3600))
				}
				// write domain cert's remaining lifetime and check status
				results.Mux.Lock()
				results.Map[url] = Check{lifetime, "ok"}
				results.Mux.Unlock()
			}
		}
	}
}

// struct that stores all config parameters and tokens during runtime
type RuntimeConf struct {
	Mux sync.Mutex
	Config
	NicToken
	NicZones
	Domains []string
}

// refresh nic token, zones, and add domains to list
func (rc *RuntimeConf) refreshNicConfig() {
	rc.NicToken.Get(&rc.Config)
	rc.NicZones.GetZones(&rc.NicToken)
	rc.Mux.Lock()
	rc.Domains = append(rc.Domains, rc.NicZones.GetDomains(&rc.NicToken)...)
	rc.Mux.Unlock()
}

// get pdd zones and add pdd domains to list
func (rc *RuntimeConf) refreshPddConfig() {
	t := rc.Config.Pdd.Token
	z := GetPddZones(&t)
	rc.Mux.Lock()
	rc.Domains = append(rc.Domains, GetPddDomains(&t, &z)...)
	rc.Mux.Unlock()
}

// refresh tokens, zones and domains list from all providers
func (rc *RuntimeConf) refreshConfig() {
	if !rc.Config.Nic.Enabled && !rc.Config.Pdd.Enabled {
		log.Println("all DNS providers are disabled, exiting")
		os.Exit(0)
	}

	// clear domains slice before filling it
	rc.Mux.Lock()
	rc.Domains = []string{}
	rc.Mux.Unlock()

	if rc.Config.Nic.Enabled {
		rc.refreshNicConfig()
	}
	if rc.Config.Pdd.Enabled {
		rc.refreshPddConfig()
	}

	rc.excludeDomains()
	rc.addStaticDomains()
}

// exclude domains from list via regexps
func (rc *RuntimeConf) excludeDomains() {
	result := []string{}
	match := false
	for _, domain := range rc.Domains {
		for _, exclude := range rc.Config.Global.ExcludeDomains {
			re := regexp.MustCompile(exclude)
			if re.MatchString(domain) {
				match = true
				break
			} else {
				match = false
			}
		}
		// append domain to result if no regexp matches
		if !match {
			result = append(result, domain)
		}
	}
	// overwrite domains list with result list
	rc.Mux.Lock()
	rc.Domains = make([]string, len(result))
	copy(rc.Domains, result)
	rc.Mux.Unlock()
}

// add domains from config static list
func (rc *RuntimeConf) addStaticDomains() {
	rc.Mux.Lock()
	for _, d := range rc.Config.Global.AddDomains {
		rc.Domains = append(rc.Domains, d)
	}
	rc.Mux.Unlock()
	log.Printf("got domains list (%d total): %s", len(rc.Domains), rc.Domains)
}

// start http server and serve metrics in prometheus format
func serveMetrics(address, location string, results *Results) {
	// handler func
	results.Mux.Lock()
	metrics := func(w http.ResponseWriter, r *http.Request) {
		for k, v := range results.Map {
			fmt.Fprintf(w, "certificate_lifetime{domain=\"%s\",check=\"%s\"} %f\n", k, v.CheckStatus, v.CertLifetime)
		}
	}
	results.Mux.Unlock()

	// start server
	log.Printf("serving metrics at: %s%s", address, location) // e.g 127.0.0.1:8080/metrics
	http.HandleFunc(location, metrics)
	err := http.ListenAndServe(address, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// parse flags
	confPath := flag.String("config", "config.json", "path to the config file")
	concur := flag.Int("concur", 10, "how many check requests performed parallelly")
	pause := flag.Int("pause", 1800, "after domains list processed, seconds to wait before next iteration")
	timeout := flag.Int("timeout", 5, "domain check request timeout")
	verbose := flag.Bool("verbose", false, "log every domain checking request")
	listen := flag.String("listen", "0.0.0.0:8080", "serve metrics on selected address")
	location := flag.String("location", "/metrics", "serve metrics on selected location")
	sample := flag.Bool("sample", false, "print sample configuration file and exit")
	flag.Parse()

	rc := RuntimeConf{}

	// load config or print sample
	if *sample {
		rc.Config.printSample()
	}
	rc.Config.load(*confPath)

	// initial configuration, get all required values
	rc.refreshConfig()

	// refresh configuration periodically
	go func() {
		for {
			time.Sleep(time.Minute * 120)
			log.Println("refreshing tokens, zones and domains list")
			rc.refreshConfig()
		}
	}()

	// start putting domains into queue
	domainsChan := make(chan string, *concur)
	checkResults := Results{Map: make(map[string]Check)}
	go queueDomains(domainsChan, &rc, *verbose, *pause)

	// start workers
	for i := 0; i < *concur; i++ {
		go certTimeLeft(domainsChan, *timeout, *verbose, &checkResults)
	}

	// start serving metrics
	serveMetrics(*listen, *location, &checkResults)
}
