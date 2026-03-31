package registry

import (
	_ "embed"
	"strings"

	"github.com/projectdiscovery/tldfinder/pkg/utils"
)

//go:embed tlds.txt
var tldData string

//go:embed private_tlds.txt
var privateTldData string

//go:embed subdomains.txt
var subdomainData string

var (
	TLDs        = processTLDData(tldData)
	PrivateTLDs = processTLDData(privateTldData)
	Subdomains  = processTLDData(subdomainData)
)

func processTLDData(data string) []string {
	lines := strings.Split(data, "\n")
	for i, line := range lines {
		lines[i], _ = utils.Sanitize(line)
	}
	return lines
}
