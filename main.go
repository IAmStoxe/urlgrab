package main

import (
	"flag"
	"fmt"
	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/gocolly/colly/v2/proxy"
	"github.com/mpvl/unique"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {

	var foundUrls []string
	var visitedUrls []string

	// Params
	var (
		depth          int
		startUrl       string
		suppliedProxy  string
		outputPath     string
		useRandomAgent bool
		randomDelay    int64
		threadCount    int
		ignoreQuery    bool
	)
	flag.StringVar(&startUrl, "url", "", "The URL where we should start crawling.")
	flag.IntVar(&depth, "depth", 100, "The  maximum depth to crawl.")
	flag.Int64Var(&randomDelay, "delay", 2000, "Milliseconds to randomly apply as a delay between requests.")
	flag.BoolVar(&ignoreQuery, "ignore-query", false, "Strip the query portion of the URL before determining if we've visited it yet.")
	flag.StringVar(&suppliedProxy, "proxy", "", "The SOCKS5 proxy to utilize (format: socks://127.0.0.1:8080 OR http://127.0.0.1:8080).")
	flag.StringVar(&outputPath, "output", "", "The directory where we should store the output files.")
	flag.BoolVar(&useRandomAgent, "random-agent", false, "Utilize a random user agent string.")
	flag.IntVar(&threadCount, "threads", 5, "The number of threads to utilize.")

	flag.Parse()

	// Validate the user passed URL
	parsedUrl, err := url.Parse(startUrl)

	if err != nil {
		fmt.Errorf("Error parsing URL: %s\n", startUrl)
		os.Exit(1)
	}

	fmt.Printf("Domain: %v\n", parsedUrl.Host)

	// Handle pageCollector instantiation with option debugging.
	var pageCollector *colly.Collector = nil
	var jsCollector *colly.Collector = nil

	// http or s
	// subdomain or not
	// domain name
	// path or not
	pageRegexPattern := fmt.Sprintf("(http|s).*?\\.?%s(|/.*)", parsedUrl.Host)
	jsRegexPattern := fmt.Sprintf("(http|s).*?\\.?%s(|/.*\\.js)", parsedUrl.Host)
	fmt.Printf("Regex: %s\n", pageRegexPattern)

	pageCollector = colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(depth),
		colly.URLFilters(regexp.MustCompile(pageRegexPattern)),
	)

	jsCollector = colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(depth),
		colly.URLFilters(regexp.MustCompile(jsRegexPattern)),
	)

	// Compile the JS parsing regex
	// Shamelessly stolen/ported from https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py
	urlParsingPattern := `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`
	urlParsingRegex, err := regexp.Compile(urlParsingPattern)

	if err != nil {
		panic(err)
	}

	// Setup proxy if supplied
	if suppliedProxy != "" {
		// Rotate proxies
		rp, err := proxy.RoundRobinProxySwitcher(fmt.Sprintf("%s", suppliedProxy))
		if err != nil {
			log.Fatal(err)
		}
		pageCollector.SetProxyFunc(rp)
	}

	splitHost := strings.Split(parsedUrl.Host, ".")
	rootDomainNameWithoutTld := splitHost[len(splitHost)-2]

	pageCollector.Limit(&colly.LimitRule{
		DomainGlob:  fmt.Sprintf("*%s.*", rootDomainNameWithoutTld),
		Parallelism: threadCount,
		RandomDelay: time.Duration(randomDelay) * time.Millisecond,
	})

	// Use random user-agent if requested
	if useRandomAgent {
		extensions.RandomUserAgent(pageCollector)
	}

	// On every a element which has href attribute call callback
	pageCollector.OnHTML("a[href]", func(e *colly.HTMLElement) {

		link := e.Attr("href")

		absoluteURL := e.Request.AbsoluteURL(link)

		// Strip the query portion of the URL and remove trailing slash
		var u, _ = url.Parse(absoluteURL)

		// Ensure we're not visiting a mailto: or similar link
		if !strings.Contains(u.Scheme, "http") {
			return
		}

		// If we're ignoring query strip it, otherwise add it to the queue
		var urlToVisit string
		if ignoreQuery {
			strippedUrl := stripQueryFromUrl(u)
			urlToVisit = strippedUrl
		} else {
			urlToVisit = absoluteURL
		}

		// Trim the trailing slash
		urlToVisit = strings.TrimRight(urlToVisit, "/")

		// Add only if we do not have it already
		if !arrayContains(foundUrls, urlToVisit) {
			foundUrls = append(foundUrls, urlToVisit)
		}

		pageCollector.Visit(urlToVisit)

	})

	// Scrape all found remote js files via src attribute
	pageCollector.OnHTML("script[src]", func(e *colly.HTMLElement) {

		link := e.Attr("src")

		absoluteURL := e.Request.AbsoluteURL(link)

		// Strip the query portion of the URL and remove trailing slash
		var u, _ = url.Parse(absoluteURL)
		var urlToVisit string

		if ignoreQuery {
			strippedUrl := stripQueryFromUrl(u)
			urlToVisit = strippedUrl
		} else {
			urlToVisit = absoluteURL
		}

		// Trim the trailing slash
		urlToVisit = strings.TrimRight(urlToVisit, "/")

		// Add only if we do not have it already
		if !arrayContains(foundUrls, urlToVisit) {
			foundUrls = append(foundUrls, urlToVisit)
			// Pass it to the JS collector

			jsCollector.Visit(urlToVisit)
		}

	})

	jsCollector.OnResponse(func(r *colly.Response) {

		regexLinks := urlParsingRegex.FindAll(r.Body, -1)

		for _, link := range regexLinks {
			u := string(link)

			// Skip blank entries
			if len(u) <= 0 {
				continue
			}

			// Remove the single and double quotes from the parsed link on the ends
			u = strings.Trim(u, "\"")
			u = strings.Trim(u, "'")
			absoluteURL := r.Request.AbsoluteURL(u)

			//fmt.Printf("[JS Parser] Parsed Link #%v: %s\n", i, absoluteURL)

			// Trim the trailing slash
			absoluteURL = strings.TrimRight(absoluteURL, "/")

			// We submit all links we find and the collector will handle the parsing based on our URL filter
			jsCollector.Visit(absoluteURL)
		}

		fmt.Printf("[JS Parser] Parsed %v urls from %s\n", len(regexLinks), r.Request.URL.String())

	})

	// These are the pages that were visited completely.
	pageCollector.OnScraped(func(r *colly.Response) {
		// Scraped a page
		visitedUrls = append(visitedUrls, r.Request.URL.String())
	})

	jsCollector.OnScraped(func(r *colly.Response) {
		// Scraped a JS URL
		visitedUrls = append(visitedUrls, r.Request.URL.String())
	})

	// Before making a request print "Visiting ..."
	pageCollector.OnRequest(func(r *colly.Request) {
		fmt.Println("[Page Collector] Visiting", r.URL.String())
	})

	jsCollector.OnRequest(func(r *colly.Request) {
		fmt.Printf("[JS Collector] Visiting %s\n", r.URL.String())
	})

	pageCollector.OnError(func(response *colly.Response, err error) {
		switch err.Error() {
		case "Not Found":
			fmt.Printf("[Page Collector ERROR] Not Found: %s\n", response.Request.URL)
		case "Too Many Requests":
			fmt.Println("Too Many Requests - Consider lowering threads and/or increasing delay.")
		default:
			fmt.Errorf("[Page Collector ERROR] %s\n", err.Error())
		}
	})

	jsCollector.OnError(func(response *colly.Response, err error) {
		switch err.Error() {
		case "Not Found":
			//fmt.Printf("[JS Collector ERROR] Not Found: %s\n", response.Request.URL)
			break
		case "Too Many Requests":
			//fmt.Println("[JS Collector ERROR] Too Many Requests - Consider lowering threads and/or increasing delay.")
			break
		default:
			fmt.Errorf("[JS Collector ERROR] %s\n", err.Error())
			break
		}
	})

	// If outputting files, verify the directory exists:
	if outputPath != "" {
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			log.Fatal(err)
			os.Exit(1)
		}
	}

	// Start scraping on our start URL
	pageCollector.Visit(startUrl)
	pageCollector.Wait()
	jsCollector.Wait()

	var uniqueFoundUrls = foundUrls
	var uniqueVisitedUrls = visitedUrls

	// Sort and removes duplicate entries
	unique.Sort(unique.StringSlice{P: &uniqueFoundUrls})
	unique.Sort(unique.StringSlice{P: &uniqueVisitedUrls})

	fmt.Printf("[~] Total found URLs: %v\n", len(foundUrls))
	fmt.Printf("[~] Unique found URLs: %v\n", len(uniqueFoundUrls))
	fmt.Printf("[~] Total visited URLs: %v\n", len(visitedUrls))
	fmt.Printf("[~] Unique visited URLs: %v\n", len(visitedUrls))

	// If and output path is specified, save the file in that directory.
	if outputPath != "" {
		path := fmt.Sprintf("%s/unique_visited.txt", outputPath)
		writeOutput(path, uniqueVisitedUrls)
	} else {
		fmt.Println("Found URLs: ")
		for i := 0; i < len(uniqueVisitedUrls); i++ {
			fmt.Printf("[+] %s\n", uniqueFoundUrls[i])
		}
	}

}

func stripQueryFromUrl(u *url.URL) string {
	// Ignoring the query portion on the query. Stripping it from the URL
	var strippedUrl = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
	strippedUrl = strings.TrimRight(strippedUrl, "/")
	return strippedUrl
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
