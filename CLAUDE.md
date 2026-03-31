# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

tldfinder is a Go tool for domain discovery and reconnaissance. It finds private TLDs, enumerates subdomains via DNS brute-force, and enriches results with IP, ASN, TLS certificate, and WHOIS data. Part of the ProjectDiscovery ecosystem.

## Build & Test Commands

```bash
make build          # Build binary (output: ./tldfinder)
make test           # Run all tests (go test -v ./...)
make tidy           # go mod tidy
make verify         # go mod tidy + go mod verify
```

Run a single test:
```bash
go test -v -run TestName ./pkg/source/crtsh/
```

Docker:
```bash
docker compose build
docker compose run --rm tldfinder -d google.com -dm subdomain -nW -oI -oA -oC -oW -rL /resolvers.txt -o /output/results.txt
```

## Discovery Modes

Five modes via `-dm` flag:

| Mode | Flag | Input | What it does |
|------|------|-------|-------------|
| DNS | `-dm dns` | Private TLD (e.g., `google`) | Find subdomains of private TLDs via passive sources |
| TLD | `-dm tld` | Domain name (e.g., `tesla`) | Find which TLDs a domain exists on via DNS brute-force |
| Domain | `-dm domain` | Domain | Find related domains via WHOIS reverse lookup |
| Subdomain | `-dm subdomain` | Full domain (e.g., `google.com`) | Brute-force subdomains using embedded wordlist |
| Full | `-dm full` | Domain name (e.g., `tesla`) | Pipeline: TLD discovery → subdomain brute-force on each found TLD |

## Enrichment Flags

All require `-nW` (active resolution mode):

| Flag | What it adds | Implementation |
|------|-------------|----------------|
| `-oI` | Resolved IP address | DNS A record lookup |
| `-oA` | ASN number + org name | Team Cymru DNS (`origin.asn.cymru.com`) |
| `-oC` | TLS cert: subject CN, fingerprint (SHA256), issuer, SANs, validity | TLS connection to port 443 |
| `-oW` | WHOIS: registrar, dates, nameservers, status, registrant | Raw TCP to WHOIS port 43 via IANA referral |

## Architecture

**Entry point**: `cmd/tldfinder/main.go` → parses options → creates Runner → runs enumeration.

**Core flow**: Runner (`internal/runner/`) → Agent (`pkg/agent/`) → Sources (`pkg/source/`) → Results → Resolution/Enrichment (`pkg/resolve/`) → Output

- **Runner** (`internal/runner/`): CLI orchestrator. Key files: `runner.go` (orchestration + mode dispatch), `options.go` (CLI flags), `enumerate.go` (enumeration loop + full mode pipeline), `outputter.go` (JSON/plain text output formatting), `validate.go` (flag validation).

- **Agent** (`pkg/agent/`): Manages source registry and parallel execution of data sources with rate limiting. `registry.go` maps source names to constructors. Sources are filtered by discovery mode at agent creation time.

- **Source interface** (`pkg/source/source.go`): All data sources implement this interface. Each source returns results via a channel. Sources live in `pkg/source/<name>/`. Five discovery modes: `DNSMode`, `TLDMode`, `DomainMode`, `SubdomainMode`, `FullMode`. Two discovery types: `Passive` (HTTP only) and `Active` (DNS lookups).

- **Resolve** (`pkg/resolve/`): Worker pool for DNS resolution and enrichment. `resolve.go` has the resolution pool, ASN lookup (Team Cymru DNS), and TLS cert grabbing. `whois.go` has raw WHOIS lookups with IANA referral and per-domain caching. Configured via `ResolutionPoolOptions` struct.

- **Session** (`pkg/session/`): HTTP client wrapper with random User-Agent, proxy support, rate limiting, and domain extraction.

- **Registry** (`pkg/registry/`): Embedded data files — `tlds.txt` (IANA TLDs), `private_tlds.txt` (corporate TLDs), `subdomains.txt` (brute-force wordlist).

## Adding a New Source

1. Create `pkg/source/<name>/<name>.go` implementing the `source.Source` interface
2. Register it in `pkg/agent/registry.go` in the `AllSources` map
3. Set `SupportedDiscoveryModes()` to the modes it should run in

## Adding a New Enrichment

1. Add field(s) to `resolve.Result` struct in `pkg/resolve/resolve.go`
2. Add option to `ResolutionPoolOptions` and `ResolutionPool` structs
3. Add lookup call in `resolveWorker()` (gated by the new option flag)
4. Add CLI flag in `internal/runner/options.go` and validation in `validate.go`
5. Wire the option through `enumerate.go` where `NewResolutionPool` is called
6. Update output structs and writers in `internal/runner/outputter.go`

## Docker Setup

- `docker-compose.yml` — builds from Dockerfile, mounts `provider-config.yaml`, `resolvers.txt`, and `./output`
- `resolvers.txt` — 28 public DNS resolvers (Cloudflare, Google, Quad9, OpenDNS, etc.)
- `provider-config.yaml` — API key template for sources that need keys (censys, bufferover, netlas, whoisxmlapi, whoxy, dnsrepo)
- `Dockerfile` — multi-stage build with Go 1.24 builder and Alpine runtime

## Key Dependencies

- `github.com/projectdiscovery/goflags` - CLI flag parsing
- `github.com/projectdiscovery/gologger` - Logging
- `github.com/projectdiscovery/ratelimit` - Rate limiting
- `github.com/projectdiscovery/dnsx` - DNS enumeration (active sources)
- `github.com/lib/pq` - PostgreSQL driver (crtsh source)
- `github.com/miekg/dns` - DNS protocol (ASN lookups, resolution)
