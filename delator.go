package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fatih/color"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/tcnksm/go-latest"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"net"
	http "net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
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
	store           = flag.Bool("s", false, "store ct logs")
	ver             = flag.Bool("c", false, "check version")
	utilDescription = "delator -d domain [-av]"
	myClient        = &http.Client{Timeout: 10 * time.Second}
	appVersion      = "1.2.0"
	banner          = `
8"""8 8""" 8    8"""8 ""8"" 8""88 8""8  
8e  8 8eee 8e   8eee8   8e  8   8 8ee8e
88  8 88   88   88  8   88  8   8 88  8
88ee8 88ee 88ee 88  8   88  8eee8 88  8`
)

type Data struct {
	Issuer_ca_id        int    `json:"issuer_ca_id"`
	Issuer_name         string `json:"issuer_name"`
	Name_value          string `json:"name_value"`
	Min_cert_id         int    `json:"min_cert_id"`
	Min_entry_timestamp string `json:"min_entry_timestamp"`
	Not_after           string `json:"not_after"`
	Not_before          string `json:"not_before"`
}

type Record struct {
	Subdomain string `json:"subdomain"`
	A         string `json:"a_record"`
}

// helper function to print errors and exit
func printError(err string) {
	fmt.Println("error:", err)
	os.Exit(1)
}

// helper function to grab url and robustly handle errors
func grabUrl(Url string) (resp *http.Response) {
	resp, err := http.Get(Url)
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
func fetchData(Url string) []Data {
	res := grabUrl(Url)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}
	result := strings.Replace(string(body), "}{", "},{", -1)
	d := fmt.Sprintf("[%s]", result)

	keys := make([]Data, 0)
	json.Unmarshal([]byte(d), &keys)
	return keys
}

// deduplicates and prints subdomains
func printData(data []Data) {
	counter := make(map[string]int)
	for _, i := range data {
		counter[i.Name_value]++
		if counter[i.Name_value] == 1 {
			y.Println(i.Name_value)
		}
	}
}

// deduplicates and returns subdomain list
func extractSubdomains(data []Data) []string {
	counter := make(map[string]int)
	var subdomains []string
	for _, i := range data {
		counter[i.Name_value]++
		if counter[i.Name_value] == 1 {
			subdomains = append(subdomains, i.Name_value)
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

	if *store{
		grabCTLog("https://ct.googleapis.com/aviator")
		os.Exit(1)
	}

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
func doLookups(subdomain string, resolve bool, out chan<- Record) {
	defer wg.Done()
	r := new(Record)
	r.Subdomain = subdomain
	if resolve {
		r.A = aLookup(r.Subdomain)
	}
	out <- *r
}

// runs bulk lookups on list of subdomains
func runConcurrentLookups(subdomains []string, resolve bool, out chan<- Record) {
	for _, subdomain := range subdomains {
		wg.Add(1)
		go doLookups(subdomain, resolve, out)
	}
}

// helper function to wait for goroutines collection to finish and close channel
func monitorWorker(wg *sync.WaitGroup, channel chan Record) {
	wg.Wait()
	close(channel)
}

// helper function to run lookups and print results
func printResults(subdomains []string) {
	out := make(chan Record)
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

// Prints out a short bit of info about |cert|, found at |index| in the
// specified log
func logCertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		fmt.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		fmt.Printf("%s\n", parsedEntry.X509Cert.Subject.CommonName)
	}
	// dumpData(entry)
}

// Prints out a short bit of info about |precert|, found at |index| in the
// specified log
func logPrecertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		fmt.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		fmt.Printf("%s\n", parsedEntry.Precert.TBSCertificate.Subject.CommonName)
	}
	// dumpData(entry)
}

func createRegexes(regexValue string) (*regexp.Regexp, *regexp.Regexp) {
	// Make a regex matcher
	var certRegex *regexp.Regexp
	precertRegex := regexp.MustCompile(regexValue)
	certRegex = precertRegex
	return certRegex, precertRegex
}

func grabCTLog(inputLog string) {
	logClient, err := client.New(inputLog, &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, jsonclient.Options{UserAgent: "delator-scanner/1.2"})
	if err != nil {
		printError("an error occurred")
	}

	certRegex, precertRegex := createRegexes(".*")
	matcher, err := scanner.MatchSubjectRegex{
		CertificateSubjectRegex:    certRegex,
		PrecertificateSubjectRegex: precertRegex}, nil

	if err != nil {
		printError("an error occurred")
	}

	opts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     1000,
			ParallelFetch: 2,
			StartIndex:    0,
			EndIndex:      0,
		},
		Matcher:    matcher,
		NumWorkers: 2,
	}
	scanner := scanner.NewScanner(logClient, opts)

	ctx := context.Background()
	scanner.Scan(ctx, logCertInfo, logPrecertInfo)
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
