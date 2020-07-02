package main

import (
	"flag"
	"fmt"
	"github.com/gocolly/colly/v2"
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
		depth          int
		startUrl       string
		useRandomAgent bool
		randomDelay    int64
		threadCount    int
	)
	flag.StringVar(&startUrl, "url", "", "The URL where we should start crawling.")
	flag.IntVar(&depth, "depth", 100, "The  maximum depth to crawl.")
	flag.Int64Var(&randomDelay, "delay", 2000, "Milliseconds to randomly apply as a delay between requests.")
	flag.BoolVar(&useRandomAgent, "random-agent", false, "Utilize a random user agent string.")
	flag.IntVar(&threadCount, "threads", 5, "The number of threads to utilize.")

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

	// http or s
	// subdomain or not
	// domain name
	// path or not
	regexPattern := fmt.Sprintf("(http|s).*?\\.?%s(|/.*)", parsedUrl.Host)
	fmt.Printf("Regex: %s\n", regexPattern)

	collector = colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(depth),
		colly.URLFilters(regexp.MustCompile(regexPattern)),
	)

	splitHost := strings.Split(parsedUrl.Host, ".")
	rootDomainNameWithoutTld := splitHost[len(splitHost)-2]
	collector.Limit(&colly.LimitRule{
		DomainGlob:  fmt.Sprintf("*%s.*", rootDomainNameWithoutTld),
		Parallelism: threadCount,
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

		// Skip if we have this one
		if arrayContains(foundUrls, strippedUrl) {
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
		switch err.Error() {
		case "Not Found":
			fmt.Printf("Not Found: %s\n", response.Request.URL)
		case "Too Many Requests":
			fmt.Println("Too Many Requests - Consider lowering threads and/or increasing delay.")
		default:
			fmt.Errorf("ERROR - %s\n", err.Error())
		}
	})

	// Start scraping on our start URL
	collector.Visit(startUrl)
	collector.Wait()

	fmt.Printf("Total found URLs: %v\n", len(foundUrls))

	var uniqueFoundUrls = foundUrls
	unique.Sort(unique.StringSlice{P: &uniqueFoundUrls})
	unique.Unique(unique.StringSlice{P: &uniqueFoundUrls})
	writeOutput("./unique_found.txt", uniqueFoundUrls)
	fmt.Printf("Total unique found URLs: %v\n", len(uniqueFoundUrls))

	var uniqueScrapedUrls = scrapedUrls
	unique.Sort(unique.StringSlice{P: &uniqueScrapedUrls})
	unique.Unique(unique.StringSlice{P: &uniqueScrapedUrls})

	writeOutput("./unique_scraped.txt", uniqueScrapedUrls)

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

func arrayContains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}
