package runner

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"
	"golang.org/x/net/publicsuffix"

	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/tldfinder/pkg/agent"
	"github.com/projectdiscovery/tldfinder/pkg/resolve"
	"github.com/projectdiscovery/tldfinder/pkg/source"
)

const maxNumCount = 2

// EnumerateSingleQuery wraps EnumerateSingleQuerynWithCtx with an empty context
func (r *Runner) EnumerateSingleQuery(query string, writers []io.Writer) error {
	return r.EnumerateSingleQueryWithCtx(context.Background(), query, writers)
}

// EnumerateSingleQueryWithCtx performs domain enumeration against a single query
func (r *Runner) EnumerateSingleQueryWithCtx(ctx context.Context, query string, writers []io.Writer) error {
	switch r.options.DiscoveryMode {
	case source.DNSMode:
		gologger.Info().Msgf("Enumerating sub(domains) for \"%s\" TLD\n", query)
	case source.TLDMode:
		gologger.Info().Msgf("Enumerating TLDs for \"%s\"\n", query)
	case source.DomainMode:
		gologger.Info().Msgf("Enumerating related domains for \"%s\"\n", query)
	case source.SubdomainMode:
		gologger.Info().Msgf("Enumerating subdomains for \"%s\"\n", query)
	case source.FullMode:
		gologger.Info().Msgf("Running full enumeration for \"%s\"\n", query)
	}

	// Check if the user has asked to remove wildcards explicitly.
	// If yes, create the resolution pool and get the wildcards for the current domain
	var resolutionPool *resolve.ResolutionPool
	if r.options.RemoveWildcard {
		resolutionPool = r.resolverClient.NewResolutionPool(r.options.Threads, r.options.RemoveWildcard, r.options.IncludeASN)
		err := resolutionPool.InitWildcards(query)
		if err != nil {
			// Log the error but don't quit.
			gologger.Warning().Msgf("Could not get wildcards for domain %s: %s\n", query, err)
		}
	}

	// Run the domain enumeration
	now := time.Now()
	results := r.agent.EnumerateQueriesWithCtx(ctx, query, r.options.Proxy, r.options.RateLimit, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute, agent.WithCustomRateLimit(r.rateLimit))

	outputWriter := NewOutputWriter(r.options.JSON)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	// Create a unique map for filtering duplicate domains out
	uniqueMap := make(map[string]resolve.HostEntry)
	// Create a map to track sources for each host
	sourceMap := make(map[string]map[string]struct{})
	// Process the results in a separate goroutine
	go func() {
		for result := range results {
			switch result.Type {
			case source.Error:
				gologger.Warning().Msgf("Could not run source %s: %s\n", result.Source, result.Error)
			case source.Domain:
				// Validate the domain found and remove wildcards from
				if (r.options.DiscoveryMode == source.DNSMode || r.options.DiscoveryMode == source.SubdomainMode) && !strings.HasSuffix(result.Value, "."+query) {
					continue
				}

				domain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")
				publicSuffix, icann := publicsuffix.PublicSuffix(domain)
				if !icann {
					domain = publicSuffix
				}

				if matchDomain := r.filterAndMatchDomain(domain); matchDomain {
					if _, ok := uniqueMap[domain]; !ok {
						sourceMap[domain] = make(map[string]struct{})
					}

					// Log the verbose message about the found domain per source
					if _, ok := sourceMap[domain][result.Source]; !ok {
						if r.options.Verbose {
							gologger.Verbose().Label(result.Source).Msg(domain)
						}
					}

					sourceMap[domain][result.Source] = struct{}{}

					// Check if the domain is a duplicate. If not,
					// send the domain for resolution.
					if _, ok := uniqueMap[domain]; ok {
						continue
					}

					hostEntry := resolve.HostEntry{Query: query, Host: domain, Source: result.Source}

					uniqueMap[domain] = hostEntry
					// If the user asked to remove wildcard then send on the resolve
					// queue. Otherwise, output results immediately as they are discovered.
					if r.options.RemoveWildcard {
						resolutionPool.Tasks <- hostEntry
					} else {
						for _, writer := range writers {
							var err error
							if r.options.CaptureSources {
								hostSourceMap := map[string]map[string]struct{}{domain: sourceMap[domain]}
								err = outputWriter.WriteSourceHost(query, hostSourceMap, writer)
							} else {
								hostMap := map[string]resolve.HostEntry{domain: hostEntry}
								err = outputWriter.WriteHost(query, hostMap, writer)
							}
							if err != nil {
								gologger.Error().Msgf("Could not write result for %s: %s\n", domain, err)
							}
						}
						// Call result callback if set
						if r.options.ResultCallback != nil {
							r.options.ResultCallback(&hostEntry)
						}
					}
				}
			}
		}
		// Close the task channel only if wildcards are asked to be removed
		if r.options.RemoveWildcard {
			close(resolutionPool.Tasks)
		}
		wg.Done()
	}()

	// If the user asked to remove wildcards, listen from the results
	// queue and write results in real-time
	foundResults := make(map[string]resolve.Result)
	if r.options.RemoveWildcard {
		// Process the results coming from the resolutions pool
		for result := range resolutionPool.Results {
			switch result.Type {
			case resolve.Error:
				gologger.Warning().Msgf("Could not resolve host: %s\n", result.Error)
			case resolve.Subdomain:
				// Add the found domain to a map and output immediately
				if _, ok := foundResults[result.Host]; !ok {
					foundResults[result.Host] = result
					for _, writer := range writers {
						var err error
						if r.options.HostIP {
							resultMap := map[string]resolve.Result{result.Host: result}
							err = outputWriter.WriteHostIP(query, resultMap, writer)
						} else {
							resultMap := map[string]resolve.Result{result.Host: result}
							err = outputWriter.WriteHostNoWildcard(query, resultMap, writer)
						}
						if err != nil {
							gologger.Error().Msgf("Could not write result for %s: %s\n", result.Host, err)
						}
					}
					if r.options.ResultCallback != nil {
						r.options.ResultCallback(&resolve.HostEntry{Query: query, Host: result.Host, Source: result.Source})
					}
				}
			}
		}
	}
	wg.Wait()

	// Show found domain count in any case.
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()
	var numberOfDomains int
	if r.options.RemoveWildcard {
		numberOfDomains = len(foundResults)
	} else {
		numberOfDomains = len(uniqueMap)
	}
	gologger.Info().Msgf("Found %d domains for %s in %s\n", numberOfDomains, query, duration)

	if r.options.Statistics {
		gologger.Info().Msgf("Printing source statistics for %s", query)
		printStatistics(r.agent.GetStatistics())
	}

	return nil
}

// EnumerateFullModeWithCtx runs TLD discovery first, then subdomain brute-force on each found TLD domain
func (r *Runner) EnumerateFullModeWithCtx(ctx context.Context, query string, writers []io.Writer) error {
	gologger.Info().Msgf("Phase 1: Enumerating TLDs for \"%s\"\n", query)

	// Phase 1: TLD enumeration (agent is already initialized for TLDMode)
	now := time.Now()
	results := r.agent.EnumerateQueriesWithCtx(ctx, query, r.options.Proxy, r.options.RateLimit, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute, agent.WithCustomRateLimit(r.rateLimit))

	// Collect all unique TLD domains
	tldDomains := make(map[string]struct{})
	for result := range results {
		switch result.Type {
		case source.Error:
			gologger.Warning().Msgf("Could not run source %s: %s\n", result.Source, result.Error)
		case source.Domain:
			domain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")
			if matchDomain := r.filterAndMatchDomain(domain); matchDomain {
				if _, ok := tldDomains[domain]; !ok {
					tldDomains[domain] = struct{}{}
					gologger.Info().Msgf("Found TLD: %s\n", domain)
				}
			}
		}
	}

	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()
	gologger.Info().Msgf("Found %d TLD domains for %s in %s\n", len(tldDomains), query, duration)

	if len(tldDomains) == 0 {
		return nil
	}

	// Phase 2: Subdomain brute-force against each found TLD domain
	gologger.Info().Msgf("Phase 2: Enumerating subdomains for %d discovered TLD domains\n", len(tldDomains))

	// Create a subdomain agent
	subAgent := agent.New(r.options.Sources, r.options.ExcludeSources, r.options.All, source.SubdomainMode)
	origAgent := r.agent
	r.agent = subAgent
	// Temporarily switch mode for the enumeration logic
	origMode := r.options.DiscoveryMode
	r.options.DiscoveryMode = source.SubdomainMode

	for domain := range tldDomains {
		gologger.Info().Msgf("Enumerating subdomains for \"%s\"\n", domain)
		if err := r.EnumerateSingleQueryWithCtx(ctx, domain, writers); err != nil {
			gologger.Error().Msgf("Error enumerating subdomains for %s: %s\n", domain, err)
		}
	}

	// Restore original agent and mode
	r.agent = origAgent
	r.options.DiscoveryMode = origMode

	return nil
}

func (r *Runner) filterAndMatchDomain(domain string) bool {
	if r.options.filterRegexes != nil {
		for _, filter := range r.options.filterRegexes {
			if m := filter.MatchString(domain); m {
				return false
			}
		}
	}
	if r.options.matchRegexes != nil {
		for _, match := range r.options.matchRegexes {
			if m := match.MatchString(domain); m {
				return true
			}
		}
		return false
	}
	return true
}
