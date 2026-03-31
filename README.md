<h1 align="center">
TLDFinder
<br>
</h1>


<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/tldfinder"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/tldfinder"></a>
<a href="https://pkg.go.dev/github.com/projectdiscovery/tldfinder/pkg/tldfinder"><img src="https://img.shields.io/badge/go-reference-blue"></a>
<a href="https://github.com/projectdiscovery/tldfinder/releases"><img src="https://img.shields.io/github/release/projectdiscovery/tldfinder"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-tldfinder">Running tldfinder</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

A streamlined tool for discovering private TLDs, enumerating subdomains, and enriching results with IP, ASN, TLS certificate, and WHOIS data for security research.

# Features

![image](https://github.com/user-attachments/assets/f9c96de5-9a14-4861-a85a-21df8c848e76)

 - **5 discovery modes**: DNS (private TLD), TLD brute-force, domain, subdomain brute-force, and full pipeline
 - **Enrichment**: IP resolution, ASN lookup, TLS certificate extraction, WHOIS registration data
 - **No API keys required** for core functionality (crtsh, dnsx, wayback, subbrute sources)
 - **Full pipeline mode**: automatically chains TLD discovery → subdomain brute-force
 - STD **IN/OUT** and **TXT/JSON** output
 - Docker Compose support with bundled resolvers

## Installation

tldfinder requires **Go 1.24** to install successfully. To install, just run the below command or download pre-compiled binary from [release page](https://github.com/projectdiscovery/tldfinder/releases).

```console
go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest
```

### Docker

```console
docker compose build
docker compose run --rm tldfinder -d google.com -dm subdomain -nW -oI -oA -oC -oW -rL /resolvers.txt -o /output/results.txt
```

## Usage

```console
tldfinder -h
```

This will display help for the tool. Here are all the switches it supports.

```console
A streamlined tool for discovering private TLDs for security research.

Usage:
  ./tldfinder [flags]

Flags:
INPUT:
   -d, -domain string[]  domain or list of domains for discovery (file or comma separated)

SOURCE:
   -s, -sources string[]           specific sources to use for discovery (-s censys,dnsrepo). Use -ls to display all available sources.
   -es, -exclude-sources string[]  sources to exclude from enumeration (-es censys,dnsrepo)
   -dm, -discovery-mode value      discovery mode (dns,tld,domain,subdomain,full) (default dns)
   -all                            use all sources for enumeration (slow)

FILTER:
   -m, -match string[]   domain or list of domain to match (file or comma separated)
   -f, -filter string[]   domain or list of domain to filter (file or comma separated)

RATE-LIMIT:
   -rl, -rate-limit int      maximum number of http requests to send per second (global)
   -rls, -rate-limits value  maximum number of http requests to send per second four providers in key=value format (-rls hackertarget=10/m) (default ["waybackarchive=15/m", "whoisxmlapi=50/s", "whoisxmlapi=30/s"])
   -t int                    number of concurrent goroutines for resolving (-active only) (default 10)

UPDATE:
   -up, -update                 update tldfinder to latest version
   -duc, -disable-update-check  disable automatic tldfinder update check

OUTPUT:
   -o, -output string       file to write output to
   -oJ, -json               write output in JSONL(ines) format
   -oD, -output-dir string  directory to write output (-dL only)
   -cs, -collect-sources    include all sources in the output (-json only)
   -oI, -ip                 include host IP in output (-active only)
   -oA, -asn                include host ASN in output (-active only)
   -oC, -cert               include TLS certificate info in output (-active only)
   -oW, -whois              include WHOIS registration data in output (-active only)

CONFIGURATION:
   -config string                flag config file (default "/Users/user/Library/Application Support/tldfinder/config.yaml")
   -pc, -provider-config string  provider config file (default "/Users/user/Library/Application Support/tldfinder/provider-config.yaml")
   -r string[]                   comma separated list of resolvers to use
   -rL, -rlist string            file containing list of resolvers to use
   -nW, -active                  display active domains only
   -proxy string                 http proxy to use with tldfinder
   -ei, -exclude-ip              exclude IPs from the list of domains

DEBUG:
   -silent             show only domains in output
   -version            show version of tldfinder
   -v                  show verbose output
   -nc, -no-color      disable color in output
   -ls, -list-sources  list all available sources
   -stats              report source statistics

OPTIMIZATION:
   -timeout int   seconds to wait before timing out (default 30)
   -max-time int  minutes to wait for enumeration results (default 10)
```

## Discovery Modes

### DNS Mode (default)
Discover subdomains of private TLDs via passive sources:
```console
tldfinder -d google
```

### TLD Mode
Find which TLDs a domain exists on via DNS brute-force:
```console
tldfinder -d tesla -dm tld -nW -oI -oA
```

### Subdomain Mode
Brute-force subdomains of any domain using an embedded wordlist:
```console
tldfinder -d google.com -dm subdomain -nW -oI -oA -oC -oW
```

### Full Pipeline Mode
Chains TLD discovery → subdomain brute-force on every found TLD domain:
```console
tldfinder -d tesla -dm full -nW -oI -oA -oC -oW -rL resolvers.txt -o results.txt
```

## Running tldfinder

tldfinder is designed for security research. It supports multiple input types depending on the discovery mode:

| Mode | Input | Example |
|------|-------|---------|
| dns | Private TLD or domain with private TLD | `google`, `example.google` |
| tld | Domain name (SLD extracted) | `tesla`, `tesla.com` |
| subdomain | Full domain | `google.com`, `tesla.ai` |
| full | Domain name (SLD extracted) | `tesla` |
| domain | Domain | `paypal.com` |

Use `-domain` or `-d` to specify input, and provide multiple values as comma-separated input.

### Enrichment

When using active mode (`-nW`), results can be enriched with:

```console
# IP + ASN + TLS cert + WHOIS, all at once
tldfinder -d google.com -dm subdomain -nW -oI -oA -oC -oW -rL resolvers.txt
```

**Plain text output** (comma-separated):
```
host,ip,asn,org,subject_cn,fingerprint,issuer,not_after,registrar,created,expiry,registrant,source
```

**JSON output** (`-oJ`) includes full nested objects for cert (with SANs array), WHOIS (with nameservers, domain status), etc.

### Example: Full Pipeline with All Enrichment

```console
$ tldfinder -d tesla -dm full -nW -oI -oA -oC -oW -rL resolvers.txt -oJ -o tesla-full.json

[INF] Phase 1: Enumerating TLDs for "tesla"
[INF] Found TLD: tesla.com
[INF] Found TLD: tesla.app
[INF] Found TLD: tesla.ai
...
[INF] Found 425 TLD domains for tesla in 1 minute 30 seconds
[INF] Phase 2: Enumerating subdomains for 425 discovered TLD domains
[INF] Enumerating subdomains for "tesla.com"
www.tesla.com,23.9.66.49,AS20940,AKAMAI-ASN1 - Akamai...,*.tesla.com,abc123...,DigiCert,2026-...,CSC Corporate Domains,2003-...,2026-...,Tesla Inc.,subbrute
...
```

## Reference

- [Hacking Beyond.com — Enumerating Private TLDs
](https://cloud.google.com/blog/topics/threat-intelligence/enumerating-private-tlds/)


## Acknowledgements

- [N7WEra](https://github.com/N7WEra) for coming up with idea for this project.

--------

<div align="center">

tldfinder is made with ❤️ by the [projectdiscovery](https://projectdiscovery.io) team and distributed under [MIT License](LICENSE).


<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="300" alt="Join Discord"></a>

</div>