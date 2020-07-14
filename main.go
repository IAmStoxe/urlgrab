package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/chromedp/chromedp"
	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/debug"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/gocolly/colly/v2/proxy"
	"github.com/gocolly/colly/v2/queue"
	"github.com/mpvl/unique"
	"github.com/op/go-logging"
	"io"
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
var log = logging.MustGetLogger("urlgrab")

var globalContext context.Context
var globalCancel context.CancelFunc

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
		defaultHttpTimeout = 10
		defaultJsTimeout   = 10
		defaultMaxBodySize = 10 * 1024
		defaultMaxDepth    = 2
		defaultRandomDelay = 2000
		defaultThreadCount = 5
	)

	// Params
	var (
		cacheDirectory      string
		debugFlag           bool
		depth               int
		headlessBrowser     bool
		ignoreQuery         bool
		ignoreSSL           bool
		maxResponseBodySize int
		noHeadRequest       bool
		outputAllDirPath    string
		outputJsonFilePath  string
		randomDelay         int64
		renderJavaScript    bool
		renderTimeout       int
		rootDomain          string
		startUrl            string
		suppliedProxy       string
		threadCount         int
		timeout             int
		urlsPath            string
		useRandomAgent      bool
		userAgent           string
		verbose             bool
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
	flag.IntVar(&maxResponseBodySize, "max-body", defaultMaxBodySize, "The limit of the retrieved response body in kilobytes.\n0 means unlimited.\nSupply this value in kilobytes. (i.e. 10 * 1024kb = 10MB)")
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
	flag.StringVar(&userAgent, "user-agent", "", "A user agent such as (Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0).")

	flag.Parse()

	setupLogging(verbose)

	if urlsPath != "" && rootDomain == "" {
		// If loading a bulk file you must provide the rootDomain flag
		log.Fatal("If using bulk loading you must manually supply the root-domain flag!")
	}
	// Ensure that a protocol is specified
	if !strings.HasPrefix(strings.ToUpper(startUrl), strings.ToUpper("HTTP")) {
		startUrl = "https://" + startUrl
	}

	// Validate the user passed URL
	parsedUrl, err := url.Parse(startUrl)

	if err != nil {
		log.Fatalf("Error parsing URL: %s", startUrl)
		panic(err)
	}

	log.Infof("Domain: %v", parsedUrl.Host)

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
			log.Fatal("Failed to splitHost from %s", parsedUrl.Host)
		}
		rootDomainNameTld := splitHost[len(splitHost)-1]
		rootDomainNameWithoutTld := splitHost[len(splitHost)-2]
		rootDomainNameWithTld := fmt.Sprintf("%s.%s", rootDomainNameWithoutTld, rootDomainNameTld)

		rootDomain = rootDomainNameWithTld

		regexReplacedHost = strings.Replace(rootDomainNameWithTld, ".", `\.`, -1)
	}

	pageRegexPattern := fmt.Sprintf(`(https?)://[^\s?#\/]*%s/?[^\s]*`, regexReplacedHost)
	jsRegexPattern := fmt.Sprintf(`(https?)://[^\s?#\/]*%s/?[^\s]*(\.js[^\s/son]*$)`, regexReplacedHost)

	log.Debugf("Regex: %s", pageRegexPattern)

	// create a page request queue with threadCount consumer threads
	pageQueue, _ := queue.New(
		threadCount, // Number of consumer threads
		&queue.InMemoryQueueStorage{MaxSize: 10000}, // Use default queue storage
	)

	pageCollector = colly.NewCollector(
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
	var urlParsingRegex *regexp.Regexp

	urlParsingRegex, err = regexp.Compile(urlParsingPattern)

	if err != nil {
		log.Fatal(err)
	}

	// The DomainGlob should be a wildcard so it globally applies
	domainGlob := fmt.Sprintf("*%s*", rootDomain)

	pageCollector.Limit(&colly.LimitRule{
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

	// If maxResponseBodySize is anything but default apply it to the collectors
	if maxResponseBodySize != defaultMaxBodySize {
		pageCollector.MaxBodySize = maxResponseBodySize
		jsCollector.MaxBodySize = maxResponseBodySize
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

	pageCollector.SetClient(client)
	jsCollector.SetClient(client)

	// Setup proxy if supplied
	// NOTE: Must come after .SetClient calls
	if suppliedProxy != "" {

		proxies := strings.Split(suppliedProxy, ",")
		log.Infof("Proxies loaded: %v", len(proxies))
		rrps, err := proxy.RoundRobinProxySwitcher(proxies...)
		if err != nil {
			log.Fatal(err)
		}

		pageCollector.SetProxyFunc(rrps)
		jsCollector.SetProxyFunc(rrps)

	}

	if renderJavaScript {
		// If we're using a proxy send it to the chrome instance
		globalContext, globalCancel = getGlobalContext(headlessBrowser, suppliedProxy)

		// Close the main tab when we end the main() function
		defer globalCancel()

		// If renderJavascript, pass the response's body to the renderer and then replace the body for .OnHTML to handle.

		pageCollector.OnResponse(func(r *colly.Response) {
			// Strictly for benchmarking
			startTime := time.Now()

			u := r.Request.URL.String()
			html := getRenderedSource(u)

			endTime := time.Now()
			totalSeconds := endTime.Sub(startTime).Seconds()
			log.Debugf("Loading/Rendering of %s took %v seconds", u, totalSeconds)

			r.Body = []byte(html)
		})
	}

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

		pageQueue.AddURL(urlToVisit)

	})

	// Scrape all found js files via src attribute
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
		}
		// Add all pages to the queue as the queue handles filtering
		// Since we're filtering to script tags we send everything to jsQeue

		_ = jsCollector.Visit(urlToVisit)

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
		// If it's a javascript file, ensure we pass it to the proper connector
		if strings.HasSuffix(r.URL.Path, ".js") {
			err2 := jsCollector.Visit(r.URL.String())
			if err2 != nil {
				log.Errorf("Failed to submit (%s) file to jsCollector!", r.URL.String())
			}

			// Send to jsCollector
			jsCollector.Visit(r.URL.String())

			// Cancel the request to ensure we don't process it on this collecotr
			r.Abort()
			return
		} else {
			// Is it an image or similar? Don't request it.
			var re = regexp.MustCompile(`(?m).*?\.*(jpg|png|gif|webp|tiff|psd|raw|bmp|heif|ico|css|pdf)(\?.*?|)$`)
			matchString := re.MatchString(r.URL.Path)
			if matchString {
				// We don't need to call those items
				log.Debug("[Page Collector] Aborting request due to blacklisted file type.")
				r.Abort()
				return
			}

		}

		log.Debugf("[Page Collector] Visiting %s", r.URL.String())
	})

	// Page is completely done getting scraped
	pageCollector.OnScraped(func(r *colly.Response) {
		//
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

			// We submit all links we find and the collector will handle the parsing based on our URL filter
			// We submit them back to the main collector so it's parsed like any other page
			pageQueue.AddURL(absoluteURL)
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

	// If a file path to load urls was supplied load them and visit each
	// otherwise just visit the given start url
	if urlsPath != "" {
		lines, err := readLines(urlsPath)
		if err != nil {
			log.Fatal(err)
		}

		loadedUrls, totalUrls := 0, 0

		for _, line := range lines {
			totalUrls++
			u, err := url.Parse(line)
			if err != nil {
				log.Errorf("Failed to parse %s as a url", line)
				continue
			}
			loadedUrls++
			pageCollector.Visit(u.String())
		}
		log.Debugf("Loaded %v valid urls out of a total %v from the supplied file.", loadedUrls, totalUrls)

	} else if startUrl != "" {
		pageCollector.Visit(startUrl)
	} else {
		// Neither startUrl or urlsPath were supplied.
		log.Fatal("You must supply either a starting url or a file path!")
	}

	// Start both queues
	pageQueue.Run(pageCollector)

	// Async means we must .Wait() on each Collector
	//pageCollector.Wait()
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
		f.Close()
		panic(err)
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
			f.Close()
			panic(err)
			return
		}
	}

	err = f.Close()
	if err != nil {
		panic(err)
		return
	}
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func arrayContains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func writeHTML(content string, baseUrl string) http.Handler {
	// This is so we can detect the page load universally
	var doneLoadingJs = fmt.Sprintf(`
<script>
function onLoaded() {
        var element = document.createElement("div");
        element.id = "ShouldOnlyBeHereAfterLoadingCompletely"
        document.getElementsByTagName('body')[0].appendChild(element);
    }
    window.onload = onLoaded();

	document.write("<base href='%s' />");
</script>`, baseUrl)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		html := fmt.Sprintf("%s\n%s", strings.TrimSpace(content), doneLoadingJs)
		io.WriteString(w, html)
	})
}

func getRenderedSource(url string) string {

	// same browser, second tab
	newCtx, newCtxCancel := chromedp.NewContext(globalContext)
	defer newCtxCancel()

	// ensure the second tab is created
	if err := chromedp.Run(newCtx); err != nil {
		newCtxCancel()
		log.Fatal(err)
	}

	// navigate to a page, and get it's entire HTML
	var outerHtml string

	if err := chromedp.Run(newCtx,
		chromedp.Navigate(url),
		chromedp.OuterHTML("html", &outerHtml),
	); err != nil {
		log.Error(err)
	}

	return outerHtml
}

func getGlobalContext(headless bool, proxy string) (context.Context, context.CancelFunc) {
	var (
		allocCtx context.Context
		cancel   context.CancelFunc
	)
	if proxy == "" {
		allocCtx, cancel = chromedp.NewExecAllocator(context.Background(),
			chromedp.Flag("headless", headless),
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("no-first-run", true),
			chromedp.Flag("no-default-browser-check", true),
		)
	} else {
		allocCtx, cancel = chromedp.NewExecAllocator(context.Background(),
			chromedp.Flag("headless", headless),
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("no-first-run", true),
			chromedp.Flag("no-default-browser-check", true),
			chromedp.Flag("no-default-browser-check", true),
			chromedp.Flag("proxy-server", proxy),
		)
	}

	// create chrome instance
	ctx, cancel := chromedp.NewContext(allocCtx,
		chromedp.WithErrorf(log.Errorf),
		chromedp.WithBrowserOption(),
	)

	// ensure the first tab is created
	if err := chromedp.Run(ctx); err != nil {
		log.Fatal(err)
	}

	return ctx, cancel
}
