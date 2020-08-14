package utilities

import (
	"github.com/op/go-logging"
	"os"
)

// Setup the logging instance
var Logger = logging.MustGetLogger("urlgrab")

func SetupLogging(verbose bool) {
	formatter := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} ■ %{shortfunc} ▶ %{level:.5s}%{color:reset} %{message}`,
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
	Logger.SetBackend(backendLeveled)

	Logger.Debug("Logger instantiated and configured!")
}
