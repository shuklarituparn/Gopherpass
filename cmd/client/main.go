
package main

import (
	"github.com/shuklarituparn/Gopherpass/internal/client/commands"
)

var (
	buildVersion = "dev"
	buildDate    = "unknown"
	buildCommit  = "unknown"
)

func init() {
	commands.BuildVersion = buildVersion
	commands.BuildDate = buildDate
	commands.BuildCommit = buildCommit
}

func main() {
	commands.Execute()
}
