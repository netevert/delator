package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/tcnksm/go-latest"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"text/tabwriter"
	"time"
)

var (
	githubTag = &latest.GithubTag{
		Owner:             "netevert",
		Repository:        "delator",
		FixVersionStrFunc: latest.DeleteFrontV()}
	g               = color.New(color.FgHiGreen)
	y               = color.New(color.FgHiYellow)
	r               = color.New(color.FgHiRed)
	writer          = new(tabwriter.Writer)
	wg              = &sync.WaitGroup{}
	domain          = flag.String("d", "", "input domain")
	resolve         = flag.Bool("a", false, "view A record")
	ver             = flag.Bool("v", false, "check version")
	utilDescription = "delator -d domain [-av]"
	myClient        = &http.Client{Timeout: 10 * time.Second}
	appVersion      = "1.1.1"
	banner          = `
8"""8 8""" 8    8"""8 ""8"" 8""88 8""8  
8e  8 8eee 8e   8eee8   8e  8   8 8ee8e
88  8 88   88   88  8   88  8   8 88  8
88ee8 88ee 88ee 88  8   88  8eee8 88  8`
)

type data struct {
	IssuerCaID        int    `json:"issuer_ca_id"`
	IssuerName         string `json:"issuer_name"`
	NameValue          string `json:"name_value"`
	MinCertID         int    `json:"min_cert_id"`
	MinEntryTimestamp string `json:"min_entry_timestamp"`
	NotAfter           string `json:"not_after"`
	NotBefore          string `json:"not_before"`
}

type record struct {
	Subdomain string `json:"subdomain"`
	A         string `json:"a_record"`
}

// helper function to print errors and exit
func printError(err string) {
	fmt.Println("error:", err)
	os.Exit(1)
}

// helper function to grab url and robustly handle errors
func grabURL(URL string) (resp *http.Response) {
	resp, err := http.Get(URL)
	if err, ok := err.(*url.Error); ok {
		if err.Timeout() {
			printError("request timed out")
		} else if err.Temporary() {
			printError("temporary error")
		} else {
			printError(fmt.Sprintf("%s", err.Err))
		}
	}
	if resp.StatusCode != 200 {
		printError(fmt.Sprintf("unexpected status code returned: %d", resp.StatusCode))
	}
	return resp
}

// fetches certificate transparency json data
func fetchData(URL string) []data {
	res := grabURL(URL)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}

	keys := make([]data, 0)
	json.Unmarshal([]byte(body), &keys)
	return keys
}

// deduplicates and prints subdomains
func printData(Data []data) {
	counter := make(map[string]int)
	for _, i := range Data {
		counter[i.NameValue]++
		if counter[i.NameValue] == 1 {
			y.Println(i.NameValue)
		}
	}
}

// deduplicates and returns subdomain list
func extractSubdomains(Data []data) []string {
	counter := make(map[string]int)
	var subdomains []string
	for _, i := range Data {
		counter[i.NameValue]++
		if counter[i.NameValue] == 1 {
			subdomains = append(subdomains, i.NameValue)
		}
	}
	return subdomains
}

// sets up command-line arguments and default responses
func setup() {
	flag.Usage = func() {
		g.Printf(banner)
		y.Printf("\nwritten & maintained with ♥ by NetEvert\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *ver {
		y.Printf("DELATOR")
		fmt.Printf(" v.%s\n", appVersion)
		res, _ := latest.Check(githubTag, appVersion)
		if res.Outdated {
			r.Printf("v.%s available\n", res.Current)
		}
		os.Exit(1)
	}

	if *domain == "" {
		r.Printf("\nplease supply a domain\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
		os.Exit(1)
	}
}

// validates domains using regex
func validateDomainName(domain string) bool {

	patternStr := `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`

	RegExp := regexp.MustCompile(patternStr)
	return RegExp.MatchString(domain)
}

// performs an A record DNS lookup
func aLookup(subdomain string) string {
	ip, err := net.ResolveIPAddr("ip4", subdomain)
	if err != nil {
		return ""

	}
	return ip.String() // todo: fix to return only one IP
}

// performs lookups on individual subdomain record
func doLookups(subdomain string, resolve bool, out chan<- record) {
	defer wg.Done()
	r := new(record)
	r.Subdomain = subdomain
	if resolve {
		r.A = aLookup(r.Subdomain)
	}
	out <- *r
}

// runs bulk lookups on list of subdomains
func runConcurrentLookups(subdomains []string, resolve bool, out chan<- record) {
	for _, subdomain := range subdomains {
		wg.Add(1)
		go doLookups(subdomain, resolve, out)
	}
}

// helper function to wait for goroutines collection to finish and close channel
func monitorWorker(wg *sync.WaitGroup, channel chan record) {
	wg.Wait()
	close(channel)
}

// helper function to run lookups and print results
func printResults(subdomains []string) {
	out := make(chan record)
	writer.Init(os.Stdout, 14, 8, 0, '\t', tabwriter.DiscardEmptyColumns)
	runConcurrentLookups(subdomains, *resolve, out)
	go monitorWorker(wg, out)
	for r := range out {
		fmt.Fprintln(writer, r.A+"\t"+r.Subdomain+"\t")
		writer.Flush()
	}
}

// sanitizes domain inputs
func sanitizedInput(input string) (sanitizedDomain string) {
	if !validateDomainName(input) {
		r.Printf("\nplease supply a valid domain\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
		os.Exit(1)
	}
	sanitizedDomain, _ = publicsuffix.EffectiveTLDPlusOne(input)
	return "%." + sanitizedDomain
}

// main program entry point
func main() {
	setup()
	sanitizedDomain := sanitizedInput(*domain)
	subdomains := fetchData(fmt.Sprintf("https://crt.sh/?q=%s&output=json", sanitizedDomain))
	if *resolve {
		printResults(extractSubdomains(subdomains))
	} else {
		printData(subdomains)
	}
}
