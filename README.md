<div align="center">
  <img src="logo.png" alt="Magpie Logo" width="200"/>

  # Magpie

  **Fast, concurrent blocklist aggregation and validation tool**

  [![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev/)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
  [![Built with Go](https://img.shields.io/badge/built%20with-Go-00ADD8.svg)](https://golang.org)
  [![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-success.svg)](go.mod)

</div>

---

## Overview

Magpie is a high-performance blocklist aggregator that fetches, validates, and combines domain blocklists from multiple sources. Built in pure Go with zero external dependencies, it's designed for speed and reliability.

## Features

- **Multi-Source Fetching** - Download blocklists from multiple HTTP/HTTPS sources concurrently
- **Format Support** - Parses hosts files, plain domain lists, and various blocklist formats
- **DNS Validation** - Validates domains have A, AAAA, or CNAME records
- **HTTP Validation** - Optional HTTP/HTTPS connectivity checks
- **Deduplication** - Automatically removes duplicate domains
- **Concurrent Processing** - Multi-threaded validation for maximum speed
- **Zero Dependencies** - Pure Go, no external dependencies required

## Installation

### From Source

```bash
git clone https://github.com/pigeonsec/magpie.git
cd magpie
go build -o magpie ./cmd/aggregator
```

### Quick Install

```bash
go install github.com/pigeonsec/magpie/cmd/aggregator@latest
```

## Usage

### Basic Usage

```bash
# Aggregate with DNS validation (default)
./magpie -source-file sources.txt -output aggregated.txt

# Aggregate without validation
./magpie -source-file sources.txt -output aggregated.txt -dns=false

# Aggregate with full validation (DNS + HTTP)
./magpie -source-file sources.txt -output aggregated.txt -http

# Use more workers for faster validation
./magpie -source-file sources.txt -workers 20

# Quiet mode
./magpie -source-file sources.txt -quiet
```

### Source File Format

Create a text file with one URL per line:

```text
# sources.txt - List of blocklist URLs
# Lines starting with # are comments

https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://www.malwaredomainlist.com/hostslist/hosts.txt
https://somecdn.somewhere.com/badlist.txt
```

### Supported Blocklist Formats

Magpie automatically parses various formats:

```text
# Plain domains
example.com
malicious-site.net

# Hosts file format
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com

# With IP addresses
192.168.1.1 blocked-domain.com

# Comments are ignored
# This is a comment
! This is also a comment (AdBlock format)
example.com # inline comments work too
```

## Validation Modes

### DNS Validation (default)

Checks if domain has:
- A records (IPv4)
- AAAA records (IPv6)
- CNAME records

```bash
./magpie -source-file sources.txt -dns
```

### HTTP Validation

Attempts to connect via HTTP/HTTPS:

```bash
./magpie -source-file sources.txt -http
```

This performs DNS validation first, then checks HTTP connectivity.

### No Validation

Skip validation for faster aggregation:

```bash
./magpie -source-file sources.txt -dns=false
```

## CLI Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-source-file` | string | *required* | File containing URLs to fetch (one per line) |
| `-output` | string | `aggregated.txt` | Output file for aggregated domains |
| `-dns` | bool | `true` | Enable DNS validation (A, AAAA, CNAME) |
| `-http` | bool | `false` | Enable HTTP validation (in addition to DNS) |
| `-workers` | int | `10` | Number of concurrent validation workers |
| `-quiet` | bool | `false` | Quiet mode - minimal output |
| `-version` | bool | `false` | Show version information |

## Examples

### Example 1: Quick Aggregation

```bash
# Create source file
cat > sources.txt << EOF
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://www.malwaredomainlist.com/hostslist/hosts.txt
EOF

# Run aggregator
./magpie -source-file sources.txt -output blocklist.txt

# Output:
# URLs fetched:        2
# Domains found:       150000
# Duplicates removed:  5000
# Domains validated:   145000 valid, 5000 invalid
# Output file:         blocklist.txt
```

### Example 2: Maximum Validation

```bash
# Validate with both DNS and HTTP
./magpie -source-file sources.txt \
  -output validated.txt \
  -http \
  -workers 50
```

### Example 3: Fast Aggregation (No Validation)

```bash
# Skip validation for speed
./magpie -source-file sources.txt \
  -output quick-list.txt \
  -dns=false
```

## Output Format

The output file contains one domain per line:

```text
example.com
malicious-site.net
ads.tracking.com
```

This format is compatible with:
- [Pi-hole](https://pi-hole.net/)
- [AdGuard Home](https://adguard.com/en/adguard-home/overview.html)
- DNS sinkholes
- Firewalls
- Proxy servers

## Performance

| Metric | Performance |
|--------|-------------|
| **Fetching** | Parallel with retry logic |
| **Validation** | Concurrent workers (configurable) |
| **Memory** | Efficient deduplication using maps |
| **Speed** | ~1,000-5,000 domains/second (DNS only) |

## Use Cases

### Pi-hole / AdGuard

Aggregate multiple blocklists into one:

```bash
./magpie -source-file pihole-sources.txt -output pihole-combined.txt
```

### Enterprise DNS Filtering

Create validated, production-ready blocklists:

```bash
./magpie -source-file enterprise-sources.txt \
  -output enterprise-blocklist.txt \
  -http \
  -workers 50
```

### Research & Analysis

Collect domains without validation:

```bash
./magpie -source-file research-sources.txt \
  -output all-domains.txt \
  -dns=false
```

## Integration with Kestrel

Use Magpie output with [Kestrel](https://github.com/pigeonsec/kestrel) threat intelligence server:

```bash
# 1. Aggregate blocklists
./magpie -source-file sources.txt -output aggregated.txt

# 2. Ingest into Kestrel
while read domain; do
  curl -X POST http://localhost:8080/api/ioc \
    -H "X-API-Key: kestrel_admin_key" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$domain\",\"category\":\"Aggregated\",\"feed\":\"community\",\"access_level\":\"free\"}"
done < aggregated.txt
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the same license as the [Kestrel](https://github.com/pigeonsec/kestrel) project.

---

<div align="center">

  Made with :bird: by [PigeonSec](https://github.com/pigeonsec)

</div>
