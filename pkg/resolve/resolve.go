package resolve

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/rs/xid"
)

const (
	maxWildcardChecks = 3
)

// ResolutionPool is a pool of resolvers created for resolving domains
// for a given host.
type ResolutionPool struct {
	*Resolver
	Tasks          chan HostEntry
	Results        chan Result
	wg             *sync.WaitGroup
	removeWildcard bool
	includeASN     bool

	wildcardIPs map[string]struct{}
}

// HostEntry defines a host with the source
type HostEntry struct {
	Query  string
	Host   string
	Source string
}

// Result contains the result for a host resolution
type Result struct {
	Type   ResultType
	Host   string
	IP     string
	ASN    string
	Org    string
	Error  error
	Source string
}

// ResultType is the type of result found
type ResultType int

// Types of data result can return
const (
	Subdomain ResultType = iota
	Error
)

// NewResolutionPool creates a pool of resolvers for resolving domain
func (r *Resolver) NewResolutionPool(workers int, removeWildcard bool, includeASN bool) *ResolutionPool {
	resolutionPool := &ResolutionPool{
		Resolver:       r,
		Tasks:          make(chan HostEntry),
		Results:        make(chan Result),
		wg:             &sync.WaitGroup{},
		removeWildcard: removeWildcard,
		includeASN:     includeASN,
		wildcardIPs:    make(map[string]struct{}),
	}

	go func() {
		for i := 0; i < workers; i++ {
			resolutionPool.wg.Add(1)
			go resolutionPool.resolveWorker()
		}
		resolutionPool.wg.Wait()
		close(resolutionPool.Results)
	}()

	return resolutionPool
}

// InitWildcards inits the wildcard ips array
func (r *ResolutionPool) InitWildcards(domain string) error {
	for i := 0; i < maxWildcardChecks; i++ {
		uid := xid.New().String()

		hosts, _ := r.DNSClient.Lookup(uid + "." + domain)
		if len(hosts) == 0 {
			return fmt.Errorf("%s is not a wildcard domain", domain)
		}

		// Append all wildcard ips found for domains
		for _, host := range hosts {
			r.wildcardIPs[host] = struct{}{}
		}
	}
	return nil
}

func (r *ResolutionPool) resolveWorker() {
	for task := range r.Tasks {
		if !r.removeWildcard {
			r.Results <- Result{Type: Subdomain, Host: task.Host, IP: "", Source: task.Source}
			continue
		}

		hosts, err := r.DNSClient.Lookup(task.Host)
		if err != nil {
			r.Results <- Result{Type: Error, Host: task.Host, Source: task.Source, Error: err}
			continue
		}

		if len(hosts) == 0 {
			continue
		}

		var skip bool
		for _, host := range hosts {
			// Ignore the host if it exists in wildcard ips map
			if _, ok := r.wildcardIPs[host]; ok {
				skip = true
				break
			}
		}

		if !skip {
			result := Result{Type: Subdomain, Host: task.Host, IP: hosts[0], Source: task.Source}
			if r.includeASN {
				result.ASN, result.Org = lookupASN(hosts[0])
			}
			r.Results <- result
		}
	}
	r.wg.Done()
}

// lookupASN queries Team Cymru's DNS service for ASN information.
// It reverses the IP octets and queries <reversed>.origin.asn.cymru.com TXT.
// The TXT record format is: "ASN | IP/Prefix | CC | Registry | Allocated"
func lookupASN(ip string) (asn string, org string) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", ""
	}

	octets := strings.Split(parsed.To4().String(), ".")
	reversed := octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0]

	// Query origin.asn.cymru.com for ASN + prefix
	msg := new(dns.Msg)
	msg.SetQuestion(reversed+".origin.asn.cymru.com.", dns.TypeTXT)
	msg.RecursionDesired = true

	client := &dns.Client{}
	resp, _, err := client.Exchange(msg, "1.1.1.1:53")
	if err != nil || len(resp.Answer) == 0 {
		return "", ""
	}

	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok || len(txt.Txt) == 0 {
		return "", ""
	}

	// Format: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
	parts := strings.Split(txt.Txt[0], " | ")
	if len(parts) < 1 {
		return "", ""
	}
	asn = strings.TrimSpace(parts[0])

	// Query peer.asn.cymru.com for org name
	orgMsg := new(dns.Msg)
	orgMsg.SetQuestion("AS"+asn+".asn.cymru.com.", dns.TypeTXT)
	orgMsg.RecursionDesired = true

	orgResp, _, err := client.Exchange(orgMsg, "1.1.1.1:53")
	if err != nil || len(orgResp.Answer) == 0 {
		return "AS" + asn, ""
	}

	orgTxt, ok := orgResp.Answer[0].(*dns.TXT)
	if !ok || len(orgTxt.Txt) == 0 {
		return "AS" + asn, ""
	}

	// Format: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
	orgParts := strings.Split(orgTxt.Txt[0], " | ")
	if len(orgParts) >= 5 {
		org = strings.TrimSpace(orgParts[4])
	}

	return "AS" + asn, org
}
