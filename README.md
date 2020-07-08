<h1 align="center">Welcome to urlgrab 👋</h1>
<p>
  <a href="https://twitter.com/DevinStokes" target="_blank">
    <img alt="Twitter: DevinStokes" src="https://img.shields.io/twitter/follow/DevinStokes.svg?style=social" />
  </a>
</p>

> A golang utility to spider through a website searching for additional links.

## Install

```sh
go get -u github.com/iamstoxe/urlgrab
```

## Usage

```sh
Usage of urlgrab.exe:
  -delay int
        Milliseconds to randomly apply as a delay between requests. (default 2000)
  -depth int
        The maximum limit on the recursion depth of visited URLs.  (default 2)
  -ignore-query
        Strip the query portion of the URL before determining if we've visited it yet.
  -ignore-ssl
        Scrape pages with invalid SSL certificates
  -json string
        The filename where we should store the output JSON file.
  -output-all string
        The directory where we should store the output files.
  -proxy string
        The SOCKS5 proxy to utilize (format: socks5://127.0.0.1:8080 OR http://127.0.0.1:8080). Supply multiple proxies by separating them with a comma.
  -random-agent
        Utilize a random user agent string.
  -threads int
        The number of threads to utilize. (default 5)
  -timeout int
        The amount of seconds before a request should timeout. (default 10)
  -url string
        The URL where we should start crawling.
  -use-referer
        Referer sets valid Referer HTTP header to requests from the crawled URL.
  -verbose
        Verbose output

```

## Author

👤 **Devin Stokes**

* Twitter: [@DevinStokes](https://twitter.com/DevinStokes)
* Github: [@IAmStoxe](https://github.com/IAmStoxe)

## 🤝 Contributing

Contributions, issues and feature requests are welcome!<br />Feel free to check [issues page](https://github.com/IAmStoxe/urlgrab/issue). 

## Show your support

Give a ⭐ if this project helped you!

<a href="https://www.buymeacoffee.com/stoxe" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-white.png" alt="Buy Me A Coffee" style="height: 51px !important;width: 217px !important;" ></a>
