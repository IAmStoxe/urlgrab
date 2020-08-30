package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/debug"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/gocolly/colly/v2/proxy"
	"github.com/mpvl/unique"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"github.com/IAmStoxe/urlgrab/browser"
	. "github.com/IAmStoxe/urlgrab/utilities"
)

type DomainInfo struct {
	Host  string   `json:"host"`
	Count int      `json:"count"`
	Urls  []string `json:"urls"`
}

func main() {
	var foundUrls []string
	var visitedUrls []string
	var results []DomainInfo

	const (
		// Default values for flags
		defaultHttpTimeout     = 10
		defaultJsTimeout       = 10
		defaultMaxBodySizeInKb = 10 * 1024
		defaultMaxDepth        = 2
		defaultRandomDelay     = 2000
		defaultThreadCount     = 5
		defaultUserAgent       = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36"
	)

	// Params
	var (
		cacheDirectory          string
		debugFlag               bool
		depth                   int
		headlessBrowser         bool
		ignoreQuery             bool
		ignoreSSL               bool
		maxResponseBodySizeInKb int
		noHeadRequest           bool
		outputAllDirPath        string
		outputJsonFilePath      string
		randomDelay             int64
		renderJavaScript        bool
		renderTimeout           int
		rootDomain              string
		startUrl                string
		suppliedProxy           string
		threadCount             int
		timeout                 int
		urlsPath                string
		useRandomAgent          bool
		userAgent               string
		verbose                 bool
	)

	flag.BoolVar(&debugFlag, "debug", false, "Extremely verbose debugging output. Useful mainly for development.")
	flag.BoolVar(&headlessBrowser, "headless", true, "If true the browser will be displayed while crawling.\nNote: Requires render-js flag\nNote: Usage to show browser: --headless=false")
	flag.BoolVar(&ignoreQuery, "ignore-query", false, "Strip the query portion of the URL before determining if we've visited it yet.")
	flag.BoolVar(&ignoreSSL, "ignore-ssl", false, "Scrape pages with invalid SSL certificates")
	flag.BoolVar(&noHeadRequest, "no-head", false, "Do not send HEAD requests prior to GET for pre-validation.")
	flag.BoolVar(&renderJavaScript, "render-js", false, "Determines if we utilize a headless chrome instance to render javascript.")
	flag.BoolVar(&useRandomAgent, "random-agent", false, "Utilize a random user agent string.")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.Int64Var(&randomDelay, "delay", defaultRandomDelay, "Milliseconds to randomly apply as a delay between requests.")
	flag.IntVar(&depth, "depth", defaultMaxDepth, "The maximum limit on the recursion depth of visited URLs. ")
	flag.IntVar(&maxResponseBodySizeInKb, "max-body", defaultMaxBodySizeInKb, "The limit of the retrieved response body in kilobytes.\n0 means unlimited.\nSupply this value in kilobytes. (i.e. 10 * 1024kb = 10MB)")
	flag.IntVar(&renderTimeout, "js-timeout", defaultJsTimeout, "The amount of seconds before a request to render javascript should timeout.")
	flag.IntVar(&threadCount, "threads", defaultThreadCount, "The number of threads to utilize.")
	flag.IntVar(&timeout, "timeout", defaultHttpTimeout, "The amount of seconds before a request should timeout.")
	flag.StringVar(&cacheDirectory, "cache-dir", "", "Specify a directory to utilize caching. Works between sessions as well.")
	flag.StringVar(&outputAllDirPath, "output-all", "", "The directory where we should store the output files.")
	flag.StringVar(&outputJsonFilePath, "json", "", "The filename where we should store the output JSON file.")
	flag.StringVar(&rootDomain, "root-domain", "", "The root domain we should match links against.\nIf not specified it will default to the host of --url.\nExample: --root-domain google.com")
	flag.StringVar(&startUrl, "url", "", "The URL where we should start crawling.")
	flag.StringVar(&suppliedProxy, "proxy", "", "The SOCKS5 proxy to utilize (format: socks5://127.0.0.1:8080 OR http://127.0.0.1:8080).\nSupply multiple proxies by separating them with a comma.")
	flag.StringVar(&urlsPath, "urls", "", "A file path that contains a list of urls to supply as starting urls.\nRequires --root-domain flag.")
	flag.StringVar(&userAgent, "user-agent", defaultUserAgent, "A user agent.")

	flag.Parse()

	SetupLogging(verbose)

	if len(os.Args) <= 1 {
		Logger.Fatal("No arguments supplied. Supply --help for help.")
	}

	if urlsPath != "" && rootDomain == "" {
		// If loading a bulk file you must provide the rootDomain flag
		Logger.Fatal("If using bulk loading you must manually supply the root-domain flag!")
	}
	// Ensure that a protocol is specified
	if !strings.HasPrefix(strings.ToUpper(startUrl), strings.ToUpper("HTTP")) {
		startUrl = "https://" + startUrl
	}

	// Validate the user passed URL
	parsedUrl, err := url.Parse(startUrl)

	if err != nil {
		Logger.Fatalf("Error parsing URL: %s", startUrl)
		panic(err)
	}

	Logger.Infof("Domain: %v", parsedUrl.Host)

	// Handle pageCollector instantiation with option debugging.
	var pageCollector *colly.Collector = nil
	var jsCollector *colly.Collector = nil

	var regexReplacedHost = ""

	// If root domain is specified use it, otherwise use the host from --url
	if rootDomain != "" {
		regexReplacedHost = strings.Replace(rootDomain, ".", `\.`, -1)
	} else {
		// rootDomain wasn't supplied so use the root domain as the filter
		// i.e. if abc.xyz.com is supplied, xyz.com will be the root domain
		splitHost := strings.Split(parsedUrl.Host, ".")
		if len(splitHost) == 0 {
			// Failed to parse
			Logger.Fatal("Failed to splitHost from %s", parsedUrl.Host)
		}
		rootDomainNameTld := splitHost[len(splitHost)-1]
		rootDomainNameWithoutTld := splitHost[len(splitHost)-2]
		rootDomainNameWithTld := fmt.Sprintf("%s.%s", rootDomainNameWithoutTld, rootDomainNameTld)

		rootDomain = rootDomainNameWithTld

		regexReplacedHost = strings.Replace(rootDomainNameWithTld, ".", `\.`, -1)
	}

	pageRegexPattern := fmt.Sprintf(`(https?)://[^\s?#\/]*%s/?[^\s]*`, regexReplacedHost)
	jsRegexPattern := fmt.Sprintf(`(https?)://[^\s?#\/]*%s/?[^\s]*(\.js)[^\s/]*$`, regexReplacedHost)

	Logger.Debugf("Regex: %s", pageRegexPattern)

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

	// Set the timeouts for each collector
	pageCollector.SetRequestTimeout(time.Duration(timeout) * time.Second)
	jsCollector.SetRequestTimeout(time.Duration(timeout) * time.Second)

	// Compile the JS parsing regex
	// Shamelessly stolen/ported from https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py
	var urlParsingPattern = `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`
	urlParsingRegex, _ := regexp.Compile(urlParsingPattern)

	ignoredFileTypesPattern := `(?m).*?\.*(jpg|png|gif|webp|tiff|psd|raw|bmp|heif|ico|css|pdf)(\?.*?|)$`
	ignoredFileTypesRegex := regexp.MustCompile(ignoredFileTypesPattern)

	// The DomainGlob should be a wildcard so it globally applies
	domainGlob := fmt.Sprintf("*%s", rootDomain)

	pageCollector.Limit(&colly.LimitRule{
		DomainGlob:  domainGlob,
		Parallelism: threadCount,
		RandomDelay: time.Duration(randomDelay) * time.Millisecond,
	})

	jsCollector.Limit(&colly.LimitRule{
		DomainGlob:  domainGlob,
		Parallelism: threadCount,
		RandomDelay: time.Duration(randomDelay) * time.Millisecond,
	})

	pageCollector.ID = 1
	jsCollector.ID = 2

	if cacheDirectory != "" {
		pageCollector.CacheDir = cacheDirectory
	}

	// Specify if we should send HEAD requests before the GET requests
	if noHeadRequest {
		pageCollector.CheckHead = false
		jsCollector.CheckHead = false
	}

	// If maxResponseBodySizeInKb is anything but default apply it to the collectors
	// Multiply by 1024 as our flag uses kilobytes and .MaxBodySize uses bytes
	if maxResponseBodySizeInKb != defaultMaxBodySizeInKb {
		pageCollector.MaxBodySize = maxResponseBodySizeInKb * 1024
		jsCollector.MaxBodySize = maxResponseBodySizeInKb * 1024
	}

	// If debug setup the debugger
	if debugFlag {
		pageCollector.SetDebugger(&debug.LogDebugger{})
	}

	// If userAgent is supplied, apply it
	if userAgent != "" {
		pageCollector.UserAgent = userAgent
		jsCollector.UserAgent = userAgent
	}

	// Use random user-agent if requested
	if useRandomAgent {
		extensions.RandomUserAgent(pageCollector)
	}

	client := getConfiguredHttpClient(timeout, ignoreSSL)

	// NOTE: Must come BEFORE .SetClient calls
	pageCollector.SetClient(client)
	jsCollector.SetClient(client)

	// Setup proxy if supplied
	// NOTE: Must come AFTER .SetClient calls
	if suppliedProxy != "" {

		proxies := strings.Split(suppliedProxy, ",")
		Logger.Infof("Proxies loaded: %v", len(proxies))
		rrps, err := proxy.RoundRobinProxySwitcher(proxies...)
		if err != nil {
			Logger.Fatal(err)
		}

		pageCollector.SetProxyFunc(rrps)
		jsCollector.SetProxyFunc(rrps)

	}

	if renderJavaScript {
		// If we're using a proxy send it to the chrome instance
		browser.GlobalContext, browser.GlobalCancel = browser.GetGlobalContext(headlessBrowser, suppliedProxy)

		// Close the main tab when we end the main() function
		defer browser.GlobalCancel()

		// If renderJavascript, pass the response's body to the renderer and then replace the body for .OnHTML to handle.

		pageCollector.OnResponse(func(r *colly.Response) {
			// Strictly for benchmarking
			startTime := time.Now()

			u := r.Request.URL.String()
			html := browser.GetRenderedSource(u)

			endTime := time.Now()
			totalSeconds := endTime.Sub(startTime).Seconds()
			Logger.Debugf("Loading/Rendering of %s took %v seconds", u, totalSeconds)

			r.Body = []byte(html)
		})
	}

	// Before making a request print "Visiting ..."
	pageCollector.OnRequest(func(r *colly.Request) {
		// If it's a javascript file, ensure we pass it to the proper connector
		// And it matches our rootDomain
		if strings.HasSuffix(r.URL.Path, ".js") && StringsMatch(r.URL.Host, rootDomain) {
			err2 := jsCollector.Visit(r.URL.String())
			if err2 != nil {
				Logger.Errorf("Failed to submit (%s) file to jsCollector!", r.URL.String())
			}
			// Cancel the request to ensure we don't process it on this collector
			r.Abort()
			return
		}

		// Is it an image or similar? Don't request it.
		matchString := ignoredFileTypesRegex.MatchString(r.URL.Path)
		if matchString {
			// We don't need to call those items
			Logger.Debugf("[Page Collector] Aborting request due to blacklisted file type.")
			r.Abort()
			return
		}

		//// It's a valid URL as it's on the request item - no error check needed
		//parsedUrl, _ := url.Parse(r.URL.String())
		//parsedUrlDomainContainsRootDomain := StringContains(parsedUrl.Host, rootDomain)
		//if !parsedUrlDomainContainsRootDomain {
		//	// Likely a twitter or facebook url - skipping.
		//	r.Abort()
		//	return
		//}

		Logger.Debugf("[Page Collector] Visiting %s", r.URL.String())
	})

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
		if !ArrayContains(foundUrls, urlToVisit) {
			foundUrls = append(foundUrls, urlToVisit)

			parsedUrl, err2 := url.Parse(urlToVisit)
			if err2 != nil {
				Logger.Errorf("[Page Collector] Failed to parse %s.", urlToVisit)
				Logger.Error(err2)
			}

			// Does the URL match our rootDomain?
			if !StringContains(parsedUrl.Host, rootDomain) {
				// If not then return
				return
			}

			//underMaxDepthLimit := e.Request.Depth <= pageCollector.MaxDepth
			//
			//// If we've hit max depth don't submit any more links.
			//if !underMaxDepthLimit {
			//	return
			//}
			pageCollectorVisitErr := e.Request.Visit(parsedUrl.String())

			if pageCollectorVisitErr != nil {
				switch pageCollectorVisitErr.Error() {
				case "URL already visited":
					//
				case "No URLFilters match":
					//
				case "Max depth limit reached":
					Logger.Error("[Page Collector] Max Depth Reached")
				default:
					Logger.Errorf("[Page Collector] Failed to visit %s.", urlToVisit)
					Logger.Error(pageCollectorVisitErr)
				}

			}
		}
	})

	// Scrape all found js files via src attribute
	pageCollector.OnHTML("script[src]", func(e *colly.HTMLElement) {

		link := e.Attr("src")
		// Parse the absolute URL from the (potentially) relative link
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
		// Since we're filtering to script tags we send everything to jsQeue
		// And it contains our rootDomain
		if !ArrayContains(foundUrls, urlToVisit) &&
			StringContains(urlToVisit, rootDomain) {

			foundUrls = append(foundUrls, urlToVisit)
			err2 := jsCollector.Visit(urlToVisit)
			if err2 != nil {
				Logger.Errorf("[JS Collector] Failed to visit %s", urlToVisit)
				Logger.Error(err2.Error())
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

	// On error execute the callback
	pageCollector.OnError(func(r *colly.Response, err error) {
		if r.StatusCode == 0 {
			Logger.Error(err)
		}
		if err.Error() == "remote error: tls: user canceled" {
			Logger.Debug("[Page Collector ERROR] Assumed Timeout (tls: user canceled)")
		} else {
			// Can handle individual status codes here if chosen
			switch r.StatusCode {
			case http.StatusForbidden:
				Logger.Debugf("[Page Collector] Forbidden")
			default:
				// Print the status code and http libs name for the status code
				Logger.Debugf("[Page Collector] Returned Status Code %v (%s)", r.StatusCode, http.StatusText(r.StatusCode))
			}
		}
	})

	// Before making a request print "Visiting ..."
	jsCollector.OnRequest(func(r *colly.Request) {
		Logger.Debugf("[JS Collector] (Depth: %v) Visiting %s", r.Depth, r.URL.String())
	})

	// On initial response execute the callback
	// jsCollector won't need to parse HTML
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
			parsedAbsoluteUrl, _ := url.Parse(absoluteURL)

			// We submit all links we find and the collector will handle the parsing based on our URL filter
			// We submit them back to the main collector so it's parsed like any other page
			visited, _ := pageCollector.HasVisited(absoluteURL)

			host := parsedAbsoluteUrl.Host
			domainMatchesRoot := StringsMatch(host, rootDomain)

			//underMaxDepthLimit := r.Request.Depth <= pageCollector.MaxDepth
			if !visited && domainMatchesRoot {
				// Request it with the pageCollector with current response context following convention
				// http://go-colly.org/docs/best_practices/multi_collector/

				err2 := pageCollector.Request("GET", absoluteURL, nil, r.Ctx, nil)
				if err2 != nil {
					// ignore the filter error

					Logger.Errorf("[JS Collector] Failed send %s to Page Collector", absoluteURL)
					Logger.Error(err2.Error())
					Logger.Error(pageCollector.String())

				}
			}

		}

		Logger.Debugf("[JS Parser] Parsed %v urls from %s", len(regexLinks), r.Request.URL.String())

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
			Logger.Errorf("[JS Collector ERROR] %s", err.Error())
			break
		}
	})

	// If outputting files, verify the directory exists:
	if outputAllDirPath != "" {
		if _, err := os.Stat(outputAllDirPath); os.IsNotExist(err) {
			Logger.Fatal(err)
			os.Exit(1)
		}
	}

	// If a file path to load urls was supplied load them and visit each
	// otherwise just visit the given start url
	if urlsPath != "" {
		lines, err := ReadLines(urlsPath)
		if err != nil {
			Logger.Fatal(err)
		}

		loadedUrls, totalUrls := 0, 0

		for i, line := range lines {
			totalUrls++
			u, err := url.Parse(line)
			if err != nil {
				Logger.Errorf("Failed to parse line #%v as a url: %s", i, line)
				continue
			}
			loadedUrls++
			//pageQueueAddUrlErr := pageQueue.AddURL(u.String())
			err = pageCollector.Visit(u.String())
			if err != nil {
				Logger.Errorf("[Page Collector] Failed to visit %s", u.String())
				Logger.Error(err)
				continue
			}

			// Wait when we hit a max of threadCount visits before waiting.
			// We do this to not overload colly and the stack
			if i%threadCount == 0 {
				pageCollector.Wait()
			}
		}

		Logger.Debugf("Loaded %v valid urls out of a total %v from the supplied file.", loadedUrls, totalUrls)

	} else if startUrl != "" {
		pageCollectorVisitErr := pageCollector.Visit(startUrl)
		if pageCollectorVisitErr != nil {
			Logger.Errorf("[PageCollector] Failed to visit %s", startUrl)
		}
	} else {
		// Neither startUrl or urlsPath were supplied.
		Logger.Fatal("You must supply either a starting url or a file path!")
	}

	// Async means we must .Wait() on each Collector
	pageCollector.Wait()

	// Output
	var uniqueFoundUrls = foundUrls
	var uniqueVisitedUrls = visitedUrls

	// Sort and removes duplicate entries
	unique.Sort(unique.StringSlice{P: &uniqueFoundUrls})
	unique.Sort(unique.StringSlice{P: &uniqueVisitedUrls})

	Logger.Infof("[~] Total found URLs: %v", len(foundUrls))
	Logger.Infof("[~] Unique found URLs: %v", len(uniqueFoundUrls))
	Logger.Infof("[~] Total visited URLs: %v", len(visitedUrls))
	Logger.Infof("[~] Unique visited URLs: %v", len(visitedUrls))

	// If and output path is specified, save the file in that directory.
	if outputAllDirPath != "" {
		uniqueVisitedPath := fmt.Sprintf("%s/unique_visited.txt", outputAllDirPath)
		uniqueFoundPath := fmt.Sprintf("%s/unique_found.txt", outputAllDirPath)
		WriteLines(uniqueVisitedPath, uniqueVisitedUrls)
		WriteLines(uniqueFoundPath, uniqueFoundUrls)

	} else if outputJsonFilePath != "" {
		// Don't output an empty file
		if len(results) > 0 {
			WriteToJsonFile(outputJsonFilePath, results)
			Logger.Infof("Output saved to %s", outputJsonFilePath)
		}
	}

}

func getConfiguredHttpClient(timeout int, ignoreSSL bool) *http.Client {
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
	return client
}

func stripQueryFromUrl(u *url.URL) string {
	// Ignoring the query portion on the query. Stripping it from the URL
	var strippedUrl = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
	strippedUrl = strings.TrimRight(strippedUrl, "/")
	return strippedUrl
}
