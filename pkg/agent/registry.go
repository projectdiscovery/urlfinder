package agent

import (
	"github.com/projectdiscovery/urlfinder/pkg/source"
	"github.com/projectdiscovery/urlfinder/pkg/source/alienvault"
	"github.com/projectdiscovery/urlfinder/pkg/source/commoncrawl"
	"github.com/projectdiscovery/urlfinder/pkg/source/urlscan"
	"github.com/projectdiscovery/urlfinder/pkg/source/virustotal"
	"github.com/projectdiscovery/urlfinder/pkg/source/waybackarchive"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var AllSources = map[string]source.Source{
	"alienvault":     &alienvault.Source{},
	"commoncrawl":    &commoncrawl.Source{},
	"urlscan":        &urlscan.Source{},
	"waybackarchive": &waybackarchive.Source{},
	"virustotal":     &virustotal.Source{},
}

var sourceWarnings = mapsutil.NewSyncLockMap[string, string](
	mapsutil.WithMap(mapsutil.Map[string, string]{}))
