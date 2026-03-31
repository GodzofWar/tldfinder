package resolve

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// WhoisInfo holds extracted WHOIS registration data
type WhoisInfo struct {
	Registrar   string `json:"registrar,omitempty"`
	CreatedDate string `json:"created_date,omitempty"`
	ExpiryDate  string `json:"expiry_date,omitempty"`
	UpdatedDate string `json:"updated_date,omitempty"`
	NameServers string `json:"name_servers,omitempty"`
	DomainStatus string `json:"domain_status,omitempty"`
	Registrant  string `json:"registrant,omitempty"`
}

// whoisCache caches WHOIS results per base domain to avoid redundant lookups
// (e.g., multiple subdomains of the same domain share WHOIS data)
var (
	whoisCache   = make(map[string]*WhoisInfo)
	whoisCacheMu sync.RWMutex
)

// lookupWhois performs a WHOIS lookup for the base domain of the given hostname.
// It first queries whois.iana.org to find the authoritative WHOIS server for the TLD,
// then queries that server for the domain's registration data.
func lookupWhois(hostname string) *WhoisInfo {
	// Extract base domain (e.g., "mail.google.com" → "google.com")
	baseDomain := extractBaseDomain(hostname)
	if baseDomain == "" {
		return nil
	}

	// Check cache
	whoisCacheMu.RLock()
	if cached, ok := whoisCache[baseDomain]; ok {
		whoisCacheMu.RUnlock()
		return cached
	}
	whoisCacheMu.RUnlock()

	// Find the WHOIS server for this TLD via IANA
	whoisServer := getWhoisServer(baseDomain)
	if whoisServer == "" {
		return nil
	}

	// Query the WHOIS server
	raw := queryWhois(whoisServer, baseDomain)
	if raw == "" {
		return nil
	}

	info := parseWhoisResponse(raw)

	// Cache the result
	whoisCacheMu.Lock()
	whoisCache[baseDomain] = info
	whoisCacheMu.Unlock()

	return info
}

// extractBaseDomain extracts the registrable domain from a hostname.
// "www.sub.example.com" → "example.com", "test.co.uk" → "test.co.uk"
func extractBaseDomain(hostname string) string {
	parts := strings.Split(strings.TrimRight(hostname, "."), ".")
	if len(parts) < 2 {
		return hostname
	}

	// Handle common two-part TLDs
	twoPartTLDs := map[string]bool{
		"co.uk": true, "co.jp": true, "co.kr": true, "co.in": true,
		"co.nz": true, "co.za": true, "co.id": true, "co.il": true,
		"com.au": true, "com.br": true, "com.cn": true, "com.mx": true,
		"com.tr": true, "com.ar": true, "com.co": true, "com.vn": true,
		"com.sg": true, "com.hk": true, "com.tw": true, "com.my": true,
		"org.uk": true, "net.au": true, "org.au": true, "ac.uk": true,
	}

	if len(parts) >= 3 {
		possibleTwoPartTLD := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if twoPartTLDs[possibleTwoPartTLD] {
			if len(parts) >= 3 {
				return parts[len(parts)-3] + "." + possibleTwoPartTLD
			}
			return possibleTwoPartTLD
		}
	}

	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// getWhoisServer queries whois.iana.org to find the authoritative WHOIS server for a domain's TLD.
func getWhoisServer(domain string) string {
	parts := strings.Split(domain, ".")
	tld := parts[len(parts)-1]

	raw := queryWhois("whois.iana.org", tld)
	if raw == "" {
		return ""
	}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "whois:") {
			server := strings.TrimSpace(strings.TrimPrefix(line, "whois:"))
			server = strings.TrimSpace(strings.TrimPrefix(server, "Whois:"))
			if server != "" {
				return server
			}
		}
	}

	// Fallback: try common WHOIS servers
	commonServers := map[string]string{
		"com": "whois.verisign-grs.com",
		"net": "whois.verisign-grs.com",
		"org": "whois.pir.org",
		"io":  "whois.nic.io",
		"co":  "whois.nic.co",
		"app": "whois.nic.google",
		"dev": "whois.nic.google",
	}

	if server, ok := commonServers[tld]; ok {
		return server
	}

	return ""
}

// queryWhois sends a raw WHOIS query to the given server and returns the response.
func queryWhois(server, query string) string {
	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	_, err = fmt.Fprintf(conn, "%s\r\n", query)
	if err != nil {
		return ""
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteString("\n")
	}

	return sb.String()
}

// parseWhoisResponse extracts key fields from a WHOIS response.
// WHOIS responses vary by registrar, so we check multiple field name variants.
func parseWhoisResponse(raw string) *WhoisInfo {
	info := &WhoisInfo{}

	var nameServers []string

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		if value == "" {
			continue
		}

		switch key {
		case "registrar", "sponsoring registrar", "registrar name":
			if info.Registrar == "" {
				info.Registrar = value
			}
		case "creation date", "created", "registration date", "created date",
			"domain registration date", "registered on", "registered":
			if info.CreatedDate == "" {
				info.CreatedDate = value
			}
		case "registry expiry date", "expiration date", "expires", "expiry date",
			"domain expiration date", "expire date", "paid-till":
			if info.ExpiryDate == "" {
				info.ExpiryDate = value
			}
		case "updated date", "last updated", "last modified", "changed":
			if info.UpdatedDate == "" {
				info.UpdatedDate = value
			}
		case "name server", "nserver", "nameserver":
			nameServers = append(nameServers, strings.ToLower(value))
		case "domain status", "status":
			if info.DomainStatus == "" {
				// Take just the status keyword, strip the URL
				parts := strings.Fields(value)
				info.DomainStatus = parts[0]
			}
		case "registrant organization", "registrant org", "registrant",
			"registrant name", "org":
			if info.Registrant == "" {
				info.Registrant = value
			}
		}
	}

	if len(nameServers) > 0 {
		info.NameServers = strings.Join(nameServers, ",")
	}

	return info
}
