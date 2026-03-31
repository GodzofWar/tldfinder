# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

tldfinder is a Go tool for discovering private TLDs (Top-Level Domains) using passive and active enumeration across multiple data sources (crtsh, censys, wayback, dnsx, etc.). Part of the ProjectDiscovery ecosystem.

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

## Architecture

**Entry point**: `cmd/tldfinder/main.go` → parses options → creates Runner → runs enumeration.

**Core flow**: Runner (`internal/runner/`) → Agent (`pkg/agent/`) → Sources (`pkg/source/`) → Results

- **Runner** (`internal/runner/`): CLI orchestrator. Handles input parsing, output formatting, wildcard filtering, match/filter regexes, and statistics. Key files: `runner.go` (orchestration), `options.go` (CLI flags), `enumerate.go` (enumeration loop), `outputter.go` (output formatting).

- **Agent** (`pkg/agent/`): Manages source registry and parallel execution of data sources with rate limiting. `registry.go` maps source names to constructors.

- **Source interface** (`pkg/source/source.go`): All data sources implement this interface. Each source returns results via a channel. Sources live in `pkg/source/<name>/`. Three discovery modes: `DNSMode`, `TLDMode`, `DomainMode`. Two discovery types: `Passive` (HTTP only) and `Active` (DNS lookups).

- **Session** (`pkg/session/`): HTTP client wrapper with random User-Agent, proxy support, rate limiting, and domain extraction.

- **Resolve** (`pkg/resolve/`): DNS resolution pool for wildcard filtering when `-nW` flag is used. Uses worker pool pattern.

- **Extractor** (`pkg/extractor/`): Regex-based domain extraction from source responses.

- **Registry** (`pkg/registry/`): Embedded TLD lists (`tlds.txt`, `private_tlds.txt`) for validation.

## Adding a New Source

1. Create `pkg/source/<name>/<name>.go` implementing the `source.Source` interface
2. Register it in `pkg/agent/registry.go` in the `AllSources` map

## Key Dependencies

- `github.com/projectdiscovery/goflags` - CLI flag parsing
- `github.com/projectdiscovery/gologger` - Logging
- `github.com/projectdiscovery/ratelimit` - Rate limiting
- `github.com/projectdiscovery/dnsx` - DNS enumeration (active source)
- `github.com/lib/pq` - PostgreSQL driver (crtsh source)
- `github.com/miekg/dns` - DNS protocol
