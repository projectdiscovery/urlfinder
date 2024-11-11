package runner

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
)

const banner = `
  __  _____  __   _____         __       
 / / / / _ \/ /  / __(_)__  ___/ /__ ____
/ /_/ / , _/ /__/ _// / _ \/ _  / -_) __/
\____/_/|_/____/_/ /_/_//_/\_,_/\__/_/    										
`

// Name
const ToolName = `urlfinder`

// Version is the current version of urlfinder
const version = `v0.0.1`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates urlfinder
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("urlfinder", version)()
	}
}
