package main

import (
	"flag"
	"fmt"
	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/gocolly/colly/v2/proxy"
	"github.com/mpvl/unique"
	"github.com/op/go-logging"
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
		verbose        bool
	)
	flag.StringVar(&startUrl, "url", "", "The URL where we should start crawling.")
	flag.IntVar(&depth, "depth", 100, "The  maximum depth to crawl.")
	flag.Int64Var(&randomDelay, "delay", 2000, "Milliseconds to randomly apply as a delay between requests.")
	flag.BoolVar(&ignoreQuery, "ignore-query", false, "Strip the query portion of the URL before determining if we've visited it yet.")
	flag.StringVar(&suppliedProxy, "proxy", "", "The SOCKS5 proxy to utilize (format: socks5://127.0.0.1:8080 OR http://127.0.0.1:8080).")
	flag.StringVar(&outputPath, "output", "", "The directory where we should store the output files.")
	flag.BoolVar(&useRandomAgent, "random-agent", false, "Utilize a random user agent string.")
	flag.IntVar(&threadCount, "threads", 5, "The number of threads to utilize.")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")

	flag.Parse()

	// Setup the logging instance
	var log = logging.MustGetLogger("urlgrab")
	var format = logging.MustStringFormatter(
		`%{color}%{shortfunc} ▶ %{level:.5s}%{color:reset} %{message}`,
	)
	// Create backend for os.Stderr.
	loggingBackend1 := logging.NewLogBackend(os.Stderr, "", 0)

	// For messages written to loggingBackend1 we want to add some additional
	// information to the output, including the used log level and the name of
	// the function.
	backend1Formatter := logging.NewBackendFormatter(loggingBackend1, format)

	// Only errors and more severe messages should be sent to backend1'
	backend1Leveled := logging.AddModuleLevel(loggingBackend1)

	if verbose == true {
		backend1Leveled.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.ERROR, "urlgrab")
	}

	// Set the backends to be used.
	logging.SetBackend(backend1Leveled, backend1Formatter)

	// Validate the user passed URL
	parsedUrl, err := url.Parse(startUrl)

	if err != nil {
		log.Errorf("Error parsing URL: %s", startUrl)
		os.Exit(1)
	}

	log.Infof("Domain: %v", parsedUrl.Host)

	// Handle pageCollector instantiation with option debugging.
	var pageCollector *colly.Collector = nil
	var jsCollector *colly.Collector = nil

	pageRegexPattern := fmt.Sprintf("(http|https)://([^/]*\\.?%s)/?[^ ]*", parsedUrl.Host)
	jsRegexPattern := fmt.Sprintf("(http|https)://([^/]*\\.?%s)/?[^ ]*\\.js", parsedUrl.Host)

	log.Debugf("Regex: %s", pageRegexPattern)

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

		e.Request.Visit(urlToVisit)

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

	// These are the pages that were visited completely.
	pageCollector.OnScraped(func(r *colly.Response) {
		// Scraped a page

		// Trim trailing slash in the URL
		u := strings.TrimRight(r.Request.URL.String(), "/")
		visitedUrls = append(visitedUrls, u)
	})

	// Before making a request print "Visiting ..."
	pageCollector.OnRequest(func(r *colly.Request) {
		log.Debugf("[Page Collector] Visiting %s", r.URL.String())
	})

	// On error execute the callback
	pageCollector.OnError(func(response *colly.Response, err error) {
		switch err.Error() {
		case "Not Found":
			//log.Errorf("[Page Collector ERROR] Not Found: %s", response.Request.URL)
		case "Too Many Requests":
			//log.Errorf("[Page Collector ERROR] Too Many Requests - Consider lowering threads and/or increasing delay.")
		default:
			log.Errorf("[Page Collector ERROR] %s", err.Error())
		}
	})

	// Before making a request print "Visiting ..."
	jsCollector.OnRequest(func(r *colly.Request) {
		log.Debugf("[JS Collector] Visiting %s", r.URL.String())
	})

	// These are the pages that were visited completely.
	jsCollector.OnScraped(func(r *colly.Response) {
		// Scraped a JS URL

		// Trim trailing slash in the URL
		u := strings.TrimRight(r.Request.URL.String(), "/")
		visitedUrls = append(visitedUrls, u)
	})

	// On error call the callback
	jsCollector.OnError(func(response *colly.Response, err error) {
		switch err.Error() {
		case "Not Found":
			//log.Debugf("[JS Collector ERROR] Not Found: %s", response.Request.URL)
			break
		case "Too Many Requests":
			//log.Debugf("[JS Collector ERROR] Too Many Requests - Consider lowering threads and/or increasing delay.")
			break
		default:
			log.Errorf("[JS Collector ERROR] %s", err.Error())
			break
		}
	})

	// On initial response execute the callback
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

			//fmt.Printf("[JS Parser] Parsed Link #%v: %s", i, absoluteURL)

			// Trim the trailing slash
			absoluteURL = strings.TrimRight(absoluteURL, "/")

			// We submit all links we find and the collector will handle the parsing based on our URL filter
			// We submit them back to the main collector so it's parsed like any other page
			pageCollector.Visit(absoluteURL)
		}

		log.Debugf("[JS Parser] Parsed %v urls from %s", len(regexLinks), r.Request.URL.String())

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

	// Async means we must .Wait() on each Collector
	pageCollector.Wait()
	jsCollector.Wait()

	var uniqueFoundUrls = foundUrls
	var uniqueVisitedUrls = visitedUrls

	// Sort and removes duplicate entries
	unique.Sort(unique.StringSlice{P: &uniqueFoundUrls})
	unique.Sort(unique.StringSlice{P: &uniqueVisitedUrls})

	log.Infof("[~] Total found URLs: %v", len(foundUrls))
	log.Infof("[~] Unique found URLs: %v", len(uniqueFoundUrls))
	log.Infof("[~] Total visited URLs: %v", len(visitedUrls))
	log.Infof("[~] Unique visited URLs: %v", len(visitedUrls))

	// If and output path is specified, save the file in that directory.
	if outputPath != "" {
		path := fmt.Sprintf("%s/unique_visited.txt", outputPath)
		writeOutput(path, uniqueVisitedUrls)
	} else {
		log.Info("Found URLs: ")
		for i := 0; i < len(uniqueVisitedUrls); i++ {
			log.Infof("[+] %s", uniqueFoundUrls[i])
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
		panic(err)
	}

	for i := 0; i < len(data); i++ {
		_, err := f.WriteString(fmt.Sprintf("%s\n", data[i]))
		if err != nil {
			panic(err)
			f.Close()
			return
		}
	}

	err = f.Close()
	if err != nil {
		panic(err)
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
