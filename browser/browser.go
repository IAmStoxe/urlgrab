package browser

import (
	"context"
	"github.com/chromedp/chromedp"
	"github.com/IAmStoxe/urlgrab/utilities"
)

var GlobalContext context.Context
var GlobalCancel context.CancelFunc

func GetRenderedSource(url string) string {

	// same browser, second tab
	newCtx, newCtxCancel := chromedp.NewContext(GlobalContext)
	defer newCtxCancel()

	// ensure the second tab is created
	if err := chromedp.Run(newCtx); err != nil {
		newCtxCancel()
		utilities.Logger.Fatal(err)
	}

	// navigate to a page, and get it's entire HTML
	var outerHtml string

	if err := chromedp.Run(newCtx,
		chromedp.Navigate(url),
		chromedp.OuterHTML("html", &outerHtml),
	); err != nil {
		utilities.Logger.Error(err)
	}

	return outerHtml
}

func GetGlobalContext(headless bool, proxy string) (context.Context, context.CancelFunc) {
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
		chromedp.WithErrorf(utilities.Logger.Errorf),
		chromedp.WithBrowserOption(),
	)

	// ensure the first tab is created
	if err := chromedp.Run(ctx); err != nil {
		utilities.Logger.Fatal(err)
	}

	return ctx, cancel
}
