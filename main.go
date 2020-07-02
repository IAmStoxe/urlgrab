package main

import (
	"flag"
	"fmt"
	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/debug"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/mpvl/unique"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {

	var foundUrls []string
	var scrapedUrls []string

	// Params
	var (
		dbg            bool
		startUrl       string
		useRandomAgent bool
		randomDelay    int64
	)

	flag.StringVar(&startUrl, "url", "", "The URL where we should start crawling.")
	flag.Int64Var(&randomDelay, "delay", 2000, "Milliseconds to randomly apply as a delay between requests.")
	flag.BoolVar(&useRandomAgent, "random-agent", false, "Utilize a random user agent string.")
	flag.BoolVar(&dbg, "debug", false, "Turn on debug messaging from underlying colly module.")

	flag.Parse()

	// Validate the user passed URL
	parsedUrl, err := url.Parse(startUrl)

	if err != nil {
		fmt.Errorf("Error parsing URL: %s\n", startUrl)
		os.Exit(1)
	}

	// Instantiate default collector
	fmt.Printf("Domains: %v\n", parsedUrl.Host)

	// Handle collector instantiation with option debugging.
	var collector *colly.Collector = nil

	regexPattern := fmt.Sprintf("(http|s).*?\\.?%s(|/.*)", parsedUrl.Host)
	fmt.Printf("Regex: %s\n", regexPattern)

	if dbg == true {
		collector = colly.NewCollector(
			colly.Async(true),
			// Attach a debugger to the collector
			colly.Debugger(&debug.LogDebugger{}),
			colly.URLFilters(regexp.MustCompile(regexPattern)),
		)
	} else {
		collector = colly.NewCollector(
			colly.Async(true),
			colly.URLFilters(regexp.MustCompile(regexPattern)),
		)
	}

	splitHost := strings.Split(parsedUrl.Host, ".")
	rootDomainNameWithoutTld := splitHost[len(splitHost)-2]

	collector.Limit(&colly.LimitRule{
		DomainGlob:  fmt.Sprintf("*%s.*", rootDomainNameWithoutTld),
		Parallelism: 25,
		RandomDelay: time.Duration(randomDelay) * time.Millisecond,
	})

	if useRandomAgent {
		extensions.RandomUserAgent(collector)
	}

	// On every a element which has href attribute call callback
	collector.OnHTML("a[href]", func(e *colly.HTMLElement) {

		link := e.Attr("href")

		absoluteURL := e.Request.AbsoluteURL(link)

		// Strip the query portion of the URL and remove trailing slash
		var u, _ = url.Parse(absoluteURL)

		var strippedUrl = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
		strippedUrl = strings.TrimRight(strippedUrl, "/")

		if !strings.Contains(u.Scheme, "http") {
			return
		}

		foundUrls = append(foundUrls, strippedUrl)

		collector.Visit(absoluteURL)

	})

	collector.OnScraped(func(r *colly.Response) {

		// Strip the query portion of the URL and remove trailing slash
		u := r.Request.URL
		var strippedUrl = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
		strippedUrl = strings.TrimRight(strippedUrl, "/")

		scrapedUrls = append(scrapedUrls, strippedUrl)
	})

	// Before making a request print "Visiting ..."
	collector.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL.String())
	})

	collector.OnError(func(response *colly.Response, err error) {
		if err.Error() == "Not Found" {
			fmt.Printf("Not Found: %s\n", response.Request.URL)
			// 404
			return
		}
		fmt.Printf("ERROR: %s\n", err.Error())
	})

	// Start scraping on our start URL
	collector.Visit(startUrl)
	collector.Wait()

	fmt.Printf("Total scaped URLs: %v\n", len(foundUrls))
	var uniqueUrls = foundUrls

	unique.Sort(unique.StringSlice{P: &uniqueUrls})
	unique.Unique(unique.StringSlice{P: &uniqueUrls})
	fmt.Printf("Total scaped URLs after Unique: %v\n", len(uniqueUrls))

	writeOutput("./unique.txt", uniqueUrls)
	//writeOutput("./all.txt", foundUrls)

}

func writeOutput(outputPath string, data []string) {
	f, err := os.Create(outputPath)
	if nil != err {
		fmt.Println(err)
		return
	}
	for i := 0; i < len(data); i++ {
		_, err := f.WriteString(fmt.Sprintf("%s\n", data[i]))
		if err != nil {
			fmt.Println(err)
			f.Close()
			return
		}
	}

	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
}
