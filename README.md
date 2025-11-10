<div align="center">
  <img src="docs/magpie.webp" alt="Magpie Logo" width="200"/>

  # Magpie

  **High-performance blocklist aggregator with smart filtering and DNS validation**

  [![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev/)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
  [![Minimal Dependencies](https://img.shields.io/badge/dependencies-2-success.svg)](go.mod)

</div>

---

## Overview

Magpie is a high-performance blocklist aggregator that fetches, validates, and combines domain blocklists from multiple sources. Built in pure Go with minimal dependencies (color output and progress bars), it's optimized for speed and reliability.

**Key Features:**
- 🚀 **Parallel fetching** with 6 DNS resolvers (bypasses Pi-hole)
- 🎯 **Smart filtering** auto-blacklists failing URLs after 3 attempts
- 📊 **Stats tracking** persistent health monitoring in `data/stats.json`
- ⚡ **High performance** 100 workers, DNS caching, connection pooling
- 🔧 **Format support** hosts files, plain lists, AdBlock, URLs, wildcards

## Installation

```bash
# From source
git clone https://github.com/pigeonsec/magpie.git
cd magpie
go build -o magpie ./cmd/aggregator

# Quick install
go install github.com/pigeonsec/magpie/cmd/aggregator@latest
```

## Quick Start

```bash
# Create source file with blocklist URLs
cat > sources.txt << EOF
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://v.firebog.net/hosts/static/w3kbl.txt
EOF

# Aggregate with DNS validation (long form)
./magpie -source sources.txt -output blocklist.txt

# Or use short flags
./magpie -s sources.txt -o blocklist.txt

# Fast mode (no validation)
./magpie -s sources.txt -o blocklist.txt -dns=false

# View statistics
./magpie --stats
```

## CLI Options

### Input/Output
| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `-source` | `-s` | *required* | Source file containing URLs to fetch (one per line) |
| `-output` | `-o` | `aggregated.txt` | Output file for aggregated domains |

### Validation
| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `-dns` | `-d` | `true` | Enable DNS validation (A, AAAA, CNAME) |
| `-http` | `-H` | `false` | Enable HTTP validation (in addition to DNS) |
| `-workers` | `-w` | `100` | Number of concurrent validation workers |
| `-resolvers` | `-r` | `1.1.1.1:53,...` | Comma-separated DNS resolvers (Cloudflare, Google, Quad9) |

### Performance
| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `-fetch-workers` | `-f` | `5` | Number of concurrent URL fetchers |
| `-cache` | `-c` | `true` | Enable DNS result caching (5min TTL) |

### Stats & Filtering
| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--data-dir` | - | `./data` | Directory for stats.json and persistent data |
| `--no-tracking` | - | `false` | Disable URL health tracking and auto-filtering |

### General Options
| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `-quiet` | `-q` | `false` | Quiet mode - minimal output |
| `-version` | `-v` | `false` | Show version information |
| `--stats` | - | `false` | Display stats table and exit |
| `--help` | `-h` | `false` | Show help message |

## Performance

Real-world benchmarks on **M1 MacBook Pro with 100 Mbit connection** using test dataset (5 URLs, 117k domains):

### Benchmark Results

| Validation Method | Workers | Time | Speed | Valid Domains | Notes |
|-------------------|---------|------|-------|---------------|-------|
| **No validation** | N/A | ~5 sec | N/A | 117,160 (100%) | Fastest, no filtering |
| **DNS only** | 50 | 13 min | 151/sec | 15,584 (13.3%) | ✅ **Recommended** |
| **HTTP only** | 10 | ~140 min | 14/sec | ~45,000 (38.3%) | ⚠️ Very slow, impractical |
| **DNS + HTTP** | 50 + 10 | ~32 min | Varies | ~6,000 (5%) | Most aggressive filtering |

### Performance Analysis

**DNS Validation (Recommended):**
- ✅ Fast and efficient (~151 domains/sec with 50 workers)
- ✅ Filters out 86.7% of invalid domains
- ✅ Low resource usage
- ⚡ **13 minutes** for 117k domains

**HTTP Validation (Not Recommended):**
- ⚠️ 10x slower than DNS (~14 domains/sec)
- ⚠️ High resource usage (HTTP/2 connections, TLS handshakes)
- ⚠️ Many protocol errors from malformed responses (tracking pixels, broken servers)
- ⏱️ **2+ hours** for 117k domains - impractical for large blocklists

**DNS + HTTP (Maximum Filtering):**
- First pass with DNS (fast)
- Second pass with HTTP on DNS-valid domains only
- Achieves highest filtering rate but takes longer
- ⏱️ **~32 minutes** for 117k domains

### Test Configuration

- **Hardware**: M1 MacBook Pro, 100 Mbit internet
- **Dataset**: 5 URLs, 117,160 unique domains
- **DNS Resolvers**: 6 public resolvers (Cloudflare, Google, Quad9)
- **Parallel DNS lookups**: A, AAAA, CNAME checked simultaneously (500ms timeout)
- **DNS caching**: Enabled (5min TTL)
- **Fetch time**: ~5 seconds for all URLs

### Why is DNS validation so fast?

1. **Parallel lookups**: Checks A, AAAA, and CNAME records simultaneously, not sequentially
2. **Round-robin DNS**: Distributes load across 6 DNS resolvers
3. **Early exit**: Stops checking once any record type validates
4. **Result caching**: 5-minute TTL reduces redundant queries
5. **High concurrency**: 50 workers process domains in parallel

### Recommendations

| Use Case | Recommended Settings |
|----------|---------------------|
| **Daily aggregation** | `-dns` (default) with 50+ workers |
| **Maximum speed** | `-dns=false` (no validation, 5 sec) |
| **Maximum filtering** | `-dns -http` with 50+ workers (~30-60 min) |
| **CI/CD pipelines** | `-dns` with `-workers 100` for faster builds |
| **Resource-constrained** | `-dns` with `-workers 20-30` |

**⚡ Pro tip**: DNS validation provides 86.7% filtering in just 13 minutes. HTTP validation is rarely worth the 10x slowdown.

## Supported Formats

Magpie automatically parses various blocklist formats:

```text
# Plain domains
example.com

# Hosts file (IPv4/IPv6)
0.0.0.0 ads.example.com
127.0.0.1 tracker.com
::1 blocked.net

# AdBlock/uBlock
||domain.com^
||ads.example.com^$third-party

# URLs
https://example.com/path

# Wildcards
*.ads.example.com

# Comments (ignored)
# This is a comment
! AdBlock comment
; Hosts comment
```

## Smart URL Filtering

Magpie automatically tracks URL health and filters broken sources:

```bash
# View statistics
./magpie --show-stats
```

**How it works:**
- Every fetch is tracked in `data/stats.json`
- URLs failing 3+ times are automatically blacklisted
- Blacklisted URLs are skipped on future runs
- Auto-recovery when URLs come back online

**Stats include:**
- Success/failure counts
- Last fetch time
- Total domains retrieved
- Error messages
- Blacklist status

## DNS Validation

Magpie uses 6 public DNS resolvers in round-robin to bypass Pi-hole and ensure accurate validation:

**Resolvers:**
- Cloudflare: `1.1.1.1:53`, `1.0.0.1:53`
- Google: `8.8.8.8:53`, `8.8.4.4:53`
- Quad9: `9.9.9.9:53`, `149.112.112.112:53`

**Validation logic:**
1. Check A record (IPv4) - most common, checked first
2. If no A → check AAAA record (IPv6)
3. If no AAAA → check CNAME record
4. Cache result for 5 minutes

## Examples

### Basic Aggregation
```bash
# Long form
./magpie -source sources.txt -output blocklist.txt

# Short form
./magpie -s sources.txt -o blocklist.txt
```

### Maximum Performance
```bash
# Using short flags for brevity
./magpie -s sources.txt -o blocklist.txt -w 150 -f 10
```

### No Validation (Fastest)
```bash
./magpie -s sources.txt -o blocklist.txt -dns=false
```

### Full HTTP Validation
```bash
./magpie -s sources.txt -o blocklist.txt -H -w 50
```

### Custom DNS Resolvers
```bash
./magpie -s sources.txt -o blocklist.txt -r "1.1.1.1:53,8.8.8.8:53"
```

### Quiet Mode (for Scripts)
```bash
./magpie -s sources.txt -o blocklist.txt -q
```

## Integration with Kestrel

Use Magpie output with [Kestrel](https://github.com/pigeonsec/kestrel) threat intelligence server:

```bash
# Aggregate blocklists with short flags
./magpie -s sources.txt -o aggregated.txt

# Ingest into Kestrel
while read domain; do
  curl -X POST http://localhost:8080/api/ioc \
    -H "X-API-Key: kestrel_admin_key" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$domain\",\"category\":\"Aggregated\",\"feed\":\"community\"}"
done < aggregated.txt
```

## Output Format

Plain text, one domain per line:

```text
example.com
malicious-site.net
ads.tracking.com
```

Compatible with:
- [Pi-hole](https://pi-hole.net/)
- [AdGuard Home](https://adguard.com/en/adguard-home/overview.html)
- DNS sinkholes
- Firewalls

## Contributing

Contributions are welcome! Please submit a Pull Request.

---

<!-- BEGIN_STATS -->

## 📊 Blocklist Statistics

| URL | Domains | Status | Success | Failures | Last Checked |
|-----|---------|--------|---------|----------|--------------|
| https://raw.githubusercontent.com/RooneyMcNibNu... | 67.2K | ✅ Active | 1 | 0 | 1m ago |
| https://raw.githubusercontent.com/PolishFilters... | 39.3K | ✅ Active | 1 | 0 | 1m ago |
| https://winhelp2002.mvps.org/hosts.txt | 8.6K | ✅ Active | 1 | 0 | 1m ago |
| https://v.firebog.net/hosts/neohostsbasic.txt | 2.4K | ✅ Active | 1 | 0 | 1m ago |
| https://raw.githubusercontent.com/FadeMind/host... | 31 | ✅ Active | 1 | 0 | 1m ago |

**Summary:** 5 total URLs | 5 active | 0 filtered | ~117.6K total domains

*Last updated: 2025-11-10 21:23 UTC*

<!-- END_STATS -->

---

## License

This project is licensed under the same license as the [Kestrel](https://github.com/pigeonsec/kestrel) project.

---

<div align="center">
  Made with ❤️ by [PigeonSec](https://github.com/pigeonsec)
</div>
