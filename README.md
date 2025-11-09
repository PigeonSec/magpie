# Kestrel Aggregator

Fast, concurrent blocklist aggregation and validation tool.

## Features

- **Multi-Source Fetching** - Download blocklists from multiple HTTP/HTTPS sources
- **Format Support** - Parses hosts files, plain domain lists, and various blocklist formats
- **DNS Validation** - Validates domains have A, AAAA, or CNAME records
- **HTTP Validation** - Optional HTTP/HTTPS connectivity checks
- **Deduplication** - Automatically removes duplicate domains
- **Concurrent Processing** - Multi-threaded validation for speed
- **Zero Dependencies** - Pure Go, no external dependencies

## Installation

```bash
go build -o aggregator ./cmd/aggregator
```

## Usage

### Basic Usage

```bash
# Aggregate with DNS validation (default)
./aggregator -source-file sources.txt -output aggregated.txt

# Aggregate without validation
./aggregator -source-file sources.txt -output aggregated.txt -dns=false

# Aggregate with full validation (DNS + HTTP)
./aggregator -source-file sources.txt -output aggregated.txt -http

# Use more workers for faster validation
./aggregator -source-file sources.txt -workers 20

# Quiet mode
./aggregator -source-file sources.txt -quiet
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

The aggregator automatically parses various formats:

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
./aggregator -source-file sources.txt -dns
```

### HTTP Validation

Attempts to connect via HTTP/HTTPS:

```bash
./aggregator -source-file sources.txt -http
```

This performs DNS validation first, then checks HTTP connectivity.

### No Validation

Skip validation for faster aggregation:

```bash
./aggregator -source-file sources.txt -dns=false
```

## CLI Options

```
-source-file string
    File containing URLs to fetch (one per line) [REQUIRED]

-output string
    Output file for aggregated domains (default "aggregated.txt")

-dns
    Enable DNS validation (A, AAAA, CNAME) (default true)

-http
    Enable HTTP validation (in addition to DNS)

-workers int
    Number of concurrent validation workers (default 10)

-quiet
    Quiet mode - minimal output

-version
    Show version information
```

## Examples

### Example 1: Quick Aggregation

```bash
# Create source file
cat > sources.txt << EOF
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://www.malwaredomainlist.com/hostslist/hosts.txt
EOF

# Run aggregator
./aggregator -source-file sources.txt -output blocklist.txt

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
./aggregator -source-file sources.txt \
  -output validated.txt \
  -http \
  -workers 50
```

### Example 3: Fast Aggregation (No Validation)

```bash
# Skip validation for speed
./aggregator -source-file sources.txt \
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
- Pi-hole
- AdGuard Home
- DNS sinkholes
- Firewalls
- Proxy servers

## Performance

- **Fetching**: Parallel with retry logic
- **Validation**: Concurrent workers (configurable)
- **Memory**: Efficient deduplication using maps
- **Speed**: ~1000-5000 domains/second validation (DNS only)

## Use Cases

### Pi-hole / AdGuard

Aggregate multiple blocklists into one:

```bash
./aggregator -source-file pihole-sources.txt -output pihole-combined.txt
```

### Enterprise DNS Filtering

Create validated, production-ready blocklists:

```bash
./aggregator -source-file enterprise-sources.txt \
  -output enterprise-blocklist.txt \
  -http \
  -workers 50
```

### Research & Analysis

Collect domains without validation:

```bash
./aggregator -source-file research-sources.txt \
  -output all-domains.txt \
  -dns=false
```

## Integration with Kestrel

Use the aggregator output with Kestrel threat intelligence server:

```bash
# 1. Aggregate blocklists
./aggregator -source-file sources.txt -output aggregated.txt

# 2. Ingest into Kestrel
while read domain; do
  curl -X POST http://localhost:8080/api/ioc \
    -H "X-API-Key: kestrel_admin_key" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$domain\",\"category\":\"Aggregated\",\"feed\":\"community\",\"access_level\":\"free\"}"
done < aggregated.txt
```

## License

Same license as Kestrel project.
# magpie
