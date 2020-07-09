package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/debug"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/gocolly/colly/v2/proxy"
	"github.com/mpvl/unique"
	"github.com/op/go-logging"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Setup the logging instance
var log = logging.MustGetLogger("")

type DomainInfo struct {
	Host  string   `json:"host"`
	Count int      `json:"count"`
	Urls  []string `json:"urls"`
}

func main() {
	var foundUrls []string
	var visitedUrls []string
	var results []DomainInfo

	// Params
	var (
		debugFlag           bool
		depth               int
		ignoreQuery         bool
		ignoreSSL           bool
		maxResponseBodySize int
		noHeadRequest       bool
		outputAllDirPath    string
		outputJsonFilePath  string
		randomDelay         int64
		startUrl            string
		rootDomain          string
		suppliedProxy       string
		threadCount         int
		timeout             int
		useRandomAgent      bool
		useReferer          bool
		verbose             bool
	)
	flag.StringVar(&startUrl, "url", "", "The URL where we should start crawling.")
	flag.StringVar(&rootDomain, "root-domain", "", "The root domain we should match links against.\nIf not specified it will default to the host of --url.\nExample: --root-domain google.com")
	flag.IntVar(&depth, "depth", 2, "The maximum limit on the recursion depth of visited URLs. ")
	flag.Int64Var(&randomDelay, "delay", 2000, "Milliseconds to randomly apply as a delay between requests.")
	flag.BoolVar(&ignoreQuery, "ignore-query", false, "Strip the query portion of the URL before determining if we've visited it yet.")
	flag.StringVar(&suppliedProxy, "proxy", "", "The SOCKS5 proxy to utilize (format: socks5://127.0.0.1:8080 OR http://127.0.0.1:8080).\nSupply multiple proxies by separating them with a comma.")
	flag.StringVar(&outputAllDirPath, "output-all", "", "The directory where we should store the output files.")
	flag.StringVar(&outputJsonFilePath, "json", "", "The filename where we should store the output JSON file.")
	flag.BoolVar(&useRandomAgent, "random-agent", false, "Utilize a random user agent string.")
	flag.IntVar(&threadCount, "threads", 5, "The number of threads to utilize.")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&debugFlag, "debug", false, "Extremely verbose debugging output. Useful mainly for development.")
	flag.BoolVar(&ignoreSSL, "ignore-ssl", false, "Scrape pages with invalid SSL certificates")
	flag.IntVar(&timeout, "timeout", 10, "The amount of seconds before a request should timeout.")
	flag.BoolVar(&useReferer, "use-referer", false, "Referer sets valid Referer HTTP header to requests from the crawled URL.")
	flag.BoolVar(&noHeadRequest, "no-head", false, "Do not send HEAD requests prior to GET for pre-validation.")
	flag.IntVar(&maxResponseBodySize, "max-body", 10*1024, "The limit of the retrieved response body in kilobytes.\n0 means unlimited.\nSupply this value in kilobytes. (i.e. 10 * 1024kb = 10MB)")

	flag.Parse()

	setupLogging(verbose)

	// startUrl isn't provided, maybe  is a piped value
	if len(startUrl) <= 0 {
		// Get the very last arg
		lastArg := os.Args[len(os.Args)-1]
		startUrl = lastArg
		log.Infof("No startUrl provided. Using piped value: %s", startUrl)
	}

	// Ensure that a protocol is specified
	if !strings.HasPrefix(strings.ToUpper(startUrl), strings.ToUpper("HTTP")) {
		startUrl = "https://" + startUrl
	}

	// Validate the user passed URL
	parsedUrl, err := url.Parse(startUrl)

	if err != nil {
		log.Fatalf("Error parsing URL: %s", startUrl)
	}

	log.Infof("Domain: %v", parsedUrl.Host)

	// Handle pageCollector instantiation with option debugging.
	var pageCollector *colly.Collector = nil
	var jsCollector *colly.Collector = nil

	var regexReplacedHost = ""

	// If root domain is specified use it, otherwise use the host from --url
	if len(rootDomain) > 0 {
		regexReplacedHost = strings.Replace(rootDomain, ".", `\.`, -1)
	} else {
		// rootDomain wasn't supplied so use the root domain as the filter
		// i.e. if abc.xyz.com is supplied, xyz.com will be the root domain
		splitHost := strings.Split(parsedUrl.Host, ".")
		rootDomainNameTld := splitHost[len(splitHost)-1]
		rootDomainNameWithoutTld := splitHost[len(splitHost)-2]
		rootDomainNameWithTld := fmt.Sprintf("%s.%s", rootDomainNameWithoutTld, rootDomainNameTld)

		rootDomain = rootDomainNameWithTld

		regexReplacedHost = strings.Replace(rootDomainNameWithTld, ".", `\.`, -1)
	}

	pageRegexPattern := fmt.Sprintf(`(https?)://[^\s?#/]*%s/?[^\s]*`, regexReplacedHost)
	jsRegexPattern := fmt.Sprintf(`(https?)://[^\s?#/]*%s/?[^\s]*(\.js[^\s/son]*$)`, regexReplacedHost)

	log.Debugf("Regex: %s", pageRegexPattern)

	pageCollector = colly.NewCollector(
		colly.Async(true),
		colly.IgnoreRobotsTxt(),
		colly.MaxDepth(depth),
		colly.URLFilters(regexp.MustCompile(pageRegexPattern)),
	)

	jsCollector = colly.NewCollector(
		colly.Async(true),
		colly.IgnoreRobotsTxt(),
		colly.MaxDepth(depth),
		colly.URLFilters(regexp.MustCompile(jsRegexPattern)),
	)

	// Specify if we should send HEAD requests before the GET requests
	pageCollector.CheckHead = noHeadRequest
	jsCollector.CheckHead = noHeadRequest

	// Specify the max response body size we'll allow
	pageCollector.MaxBodySize = maxResponseBodySize
	jsCollector.MaxBodySize = maxResponseBodySize

	// Set the timeouts for each collector
	pageCollector.SetRequestTimeout(time.Duration(timeout) * time.Second)
	jsCollector.SetRequestTimeout(time.Duration(timeout) * time.Second)

	// Compile the JS parsing regex
	// Shamelessly stolen/ported from https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py
	urlParsingPattern := `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`
	urlParsingRegex, err := regexp.Compile(urlParsingPattern)

	if err != nil {
		panic(err)
	}

	// The DomainGlob should be a wildcard so it globally applies
	domainGlob := fmt.Sprintf("*%s*", rootDomain)
	pageCollector.Limit(&colly.LimitRule{
		DomainGlob:  domainGlob,
		Parallelism: threadCount,
		RandomDelay: time.Duration(randomDelay) * time.Millisecond,
	})

	// If debug setup the debugger
	if debugFlag {
		pageCollector.SetDebugger(&debug.LogDebugger{})
	}

	// Setup proxy if supplied
	if suppliedProxy != "" {
		var proxySwitcher colly.ProxyFunc

		// If more than one proxy was supplied
		if strings.Contains(suppliedProxy, ",") {
			proxies := strings.Split(suppliedProxy, ",")
			log.Infof("Proxies loaded: %v", len(proxies))
			rrps, err := proxy.RoundRobinProxySwitcher(proxies...)
			if err != nil {
				log.Fatal(err)
			}

			proxySwitcher = rrps
		} else {
			log.Infof("Proxy set to: %s", suppliedProxy)
			rrps, err := proxy.RoundRobinProxySwitcher(suppliedProxy, suppliedProxy)

			if err != nil {
				log.Fatal(err)
			}

			proxySwitcher = rrps
		}

		pageCollector.SetProxyFunc(proxySwitcher)
		jsCollector.SetProxyFunc(proxySwitcher)
	}

	// Use random user-agent if requested
	if useRandomAgent {
		extensions.RandomUserAgent(pageCollector)
	}

	// Use the referer if requested
	if useReferer {
		extensions.Referer(pageCollector)
		extensions.Referer(jsCollector)
		// Won't work on the JS collector as you have the od the relevative .Visit()
	}

	// Setup the default transport we'll use for the collectors
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: time.Duration(timeout) * time.Second,
		}).DialContext,
		MaxIdleConns:          100, // Golang default is 100
		IdleConnTimeout:       time.Duration(timeout) * time.Second,
		TLSHandshakeTimeout:   time.Duration(timeout) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// If we ignore SSL certs set the default transport
	// https://github.com/gocolly/colly/issues/422#issuecomment-573483601
	if ignoreSSL {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Setup the client with our transport to pass to the collectors
	client := &http.Client{Transport: tr}

	pageCollector.SetClient(client)
	jsCollector.SetClient(client)

	// On every a element which has href attribute call callback
	// Wildcard to match everything - not only <a> tags
	pageCollector.OnHTML("*[href]", func(e *colly.HTMLElement) {

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
		// Trim the spaces on either end (if any)
		urlToVisit = strings.Trim(urlToVisit, " ")

		// Add only if we do not have it already
		if !arrayContains(foundUrls, urlToVisit) {
			foundUrls = append(foundUrls, urlToVisit)
		}

		if useReferer {
			e.Request.Visit(urlToVisit)
		} else {
			pageCollector.Visit(urlToVisit)
		}

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
		// Trim the spaces on either end (if any)
		urlToVisit = strings.Trim(urlToVisit, " ")

		// Add only if we do not have it already
		if !arrayContains(foundUrls, urlToVisit) {
			foundUrls = append(foundUrls, urlToVisit)
			// Pass it to the JS collector

			if useReferer {
				e.Request.Visit(urlToVisit)
			} else {
				pageCollector.Visit(urlToVisit)
			}
		}

	})

	// These are the pages that were visited completely.
	pageCollector.OnScraped(func(r *colly.Response) {
		// Scraped a page

		// Trim trailing slash in the URL
		u := strings.TrimRight(r.Request.URL.String(), "/")
		visitedUrls = append(visitedUrls, u)

		// Find a matching host in our results array otherwise crate it
		idx := sort.Search(len(results), func(i int) bool {
			return results[i].Host == r.Request.URL.Host
		})

		if idx < len(results) && results[idx].Host == r.Request.URL.Host {
			results[idx].Urls = append(results[idx].Urls, r.Request.URL.String())
			results[idx].Count = len(results[idx].Urls)
		} else {
			// We didn't find the match, so let's make it and add it to results
			di := DomainInfo{
				Host: r.Request.URL.Host,
			}
			di.Urls = append(di.Urls, r.Request.URL.String())
			di.Count = len(di.Urls)

			results = append(results, di)

		}

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
	if outputAllDirPath != "" {
		if _, err := os.Stat(outputAllDirPath); os.IsNotExist(err) {
			log.Fatal(err)
			os.Exit(1)
		}
	}

	// Start scraping on our start URL
	pageCollector.Visit(startUrl)

	// Async means we must .Wait() on each Collector
	pageCollector.Wait()
	jsCollector.Wait()

	// Output
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
	if outputAllDirPath != "" {
		uniqueVisitedPath := fmt.Sprintf("%s/unique_visited.txt", outputAllDirPath)
		uniqueFoundPath := fmt.Sprintf("%s/unique_found.txt", outputAllDirPath)
		writeLines(uniqueVisitedPath, uniqueVisitedUrls)
		writeLines(uniqueFoundPath, uniqueFoundUrls)

	} else if outputJsonFilePath != "" {
		// Don't output an empty file
		if len(results) > 0 {
			writeToJsonFile(outputJsonFilePath, results)
			log.Infof("Output saved to %s", outputJsonFilePath)
		}
	}

}

func setupLogging(verbose bool) {
	formatter := logging.MustStringFormatter(
		`%{color}%{shortfunc} ▶ %{level:.5s}%{color:reset} %{message}`,
	)
	// Create backend for os.Stderr.
	loggingBackend1 := logging.NewLogBackend(os.Stdout, "", 0)

	//backendFormatter := logging.NewBackendFormatter(loggingBackend1, formatter)
	backendLeveled := logging.AddModuleLevel(loggingBackend1)

	if verbose == true {
		backendLeveled.SetLevel(logging.DEBUG, "")
	} else {
		backendLeveled.SetLevel(logging.INFO, "")
	}

	logging.SetFormatter(formatter)
	log.SetBackend(backendLeveled)

	log.Debug("Logger instantiated and configured!")
}

func stripQueryFromUrl(u *url.URL) string {
	// Ignoring the query portion on the query. Stripping it from the URL
	var strippedUrl = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
	strippedUrl = strings.TrimRight(strippedUrl, "/")
	return strippedUrl
}

func writeToJsonFile(outputPath string, data interface{}) {
	f, err := os.Create(outputPath)
	if nil != err {
		panic(err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}

	_, err = f.WriteString(string(jsonData))
	if err != nil {
		panic(err)
		f.Close()
		return
	}

	err = f.Close()
	if err != nil {
		panic(err)
		return
	}
}

func writeLines(outputPath string, data []string) {
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
