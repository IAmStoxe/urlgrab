# urlgrab


A golang utility to spider through a website searching for additional links. 


## Installation

###### Options
1. Clone this repository and build
2. Download the latest available release from the releases page (if available).
3. Execute the below go get command

```bash
go get -u github.com/iamstoxe/urlgrab
```

## Usage

```bash
urlgrab.exe -h

Usage of urlgrab.exe:
  -delay int
        Milliseconds to randomly apply as a delay between requests. (default 2000)
  -depth int
        The  maximum depth to crawl. (default 100)
  -ignore-query
        Strip the query portion of the URL before determining if we've visited it yet.
  -ignore-ssl
        Scrape pages with invalid SSL certificates
  -output string
        The directory where we should store the output files.
  -proxy string
        The SOCKS5 proxy to utilize (format: socks5://127.0.0.1:8080 OR http://127.0.0.1:8080).
  -random-agent
        Utilize a random user agent string.
  -threads int
        The number of threads to utilize. (default 5)
  -timeout int
        The amount of seconds before a request should timeout. (default 10)
  -url string
        The URL where we should start crawling.
  -verbose
        Verbose output


```

###### Note
urlgrab will only visits links that either share same domain as the specified starting url or are a subdomain of the starting url.


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)