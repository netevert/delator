package main

import (
	"flag"
	"fmt"
	"os"
	"github.com/fatih/color"
	"golang.org/x/net/publicsuffix"
	"regexp"
)

var (
	g = color.New(color.FgHiGreen)
	y = color.New(color.FgYellow)
	r = color.New(color.FgHiRed)
	domain = flag.String("d", "", "target domain")
	version = flag.Bool("v", false, "display version")
	utilDescription = "delator -d domain"
	banner = `
8"""8 8""" 8    8"""8 ""8"" 8""88 8""8  
8e  8 8eee 8e   8eee8   8e  8   8 8ee8e
88  8 88   88   88  8   88  8   8 88  8
88ee8 88ee 88ee 88  8   88  8eee8 88  8`
	appVersion = "1.0.0"
)

func setup(){
	
	flag.Usage = func() {
		g.Printf(banner)
		y.Printf("\nwritten & maintained with ♥ by NetEvert\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *version {
		y.Printf("DELATOR")
		fmt.Printf(" v.%s\n", appVersion)
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

// sanitizes domains inputted into dnsmorph
func processInput(input string) (sanitizedDomain string) {
	if !validateDomainName(input) {
		r.Printf("\nplease supply a valid domain\n\n")
		fmt.Println(utilDescription)
		flag.PrintDefaults()
		os.Exit(1)
	}
	sanitizedDomain, _ = publicsuffix.EffectiveTLDPlusOne(input)
	return sanitizedDomain
}

func main(){
	setup()
	sanitizedDomain := processInput(*domain)
	fmt.Println(sanitizedDomain)
}