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
urlgrab --url=https://httpbin.org/links/200/0 \
        --depth=3 \ # Go 3 levels deep
        --threads=10 \ # Utilize 10 threads
        --delay=2000 \ # Randomly apply a 2000ms delay
        --ignore-query \ # Ignore the query portion of urls
        --random-agent # Utilize a random user-agent
```

###### Note
urlgrab will only visit links that at either the same domain as the specified starting url or a subdomain of the starting url.


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)