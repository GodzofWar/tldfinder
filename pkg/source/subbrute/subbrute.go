package subbrute

import (
	"context"
	"math"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/tldfinder/pkg/registry"
	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	syncutil "github.com/projectdiscovery/utils/sync"
)

type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
}

func (s *Source) Run(ctx context.Context, query string, sess *session.Session) <-chan source.Result {
	results := make(chan source.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		dnsxOptions := dnsx.DefaultOptions
		dnsxOptions.MaxRetries = 2
		dnsxOptions.TraceMaxRecursion = math.MaxInt16
		dnsxOptions.QuestionTypes = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME}
		dnsX, err := dnsx.New(dnsxOptions)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			return
		}

		var candidates []string
		for _, sub := range registry.Subdomains {
			if sub == "" {
				continue
			}
			candidates = append(candidates, sub+"."+query)
		}

		wg, err := syncutil.New(syncutil.WithSize(100))
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			return
		}

		for _, domain := range candidates {
			wg.Add()
			go func(domain string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					return
				default:
				}

				sourceName, ok := ctx.Value(session.CtxSourceArg).(string)
				if !ok {
					sourceName = s.Name()
				}
				if err := sess.MultiRateLimiter.Take(sourceName); err != nil {
					return
				}

				dnsData := dnsx.ResponseData{}
				dnsData.DNSData, _ = dnsX.QueryMultiple(domain)
				if dnsData.DNSData == nil || dnsData.DNSData.StatusCode == "NXDOMAIN" {
					return
				}
				// Verify we got actual records
				if len(dnsData.DNSData.A) == 0 && len(dnsData.DNSData.AAAA) == 0 && len(dnsData.DNSData.CNAME) == 0 {
					return
				}

				results <- source.Result{Source: s.Name(), Type: source.Domain, Value: domain}
				s.results++
			}(domain)
		}

		wg.Wait()
	}()

	return results
}

func (s *Source) Name() string {
	return "subbrute"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) SupportedDiscoveryModes() []source.DiscoveryMode {
	return []source.DiscoveryMode{source.SubdomainMode}
}

func (s *Source) DiscoveryType() source.DiscoveryType {
	return source.Active
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() source.Statistics {
	return source.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}
