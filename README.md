# Proxy Checker API

A fast and accurate proxy/VPN/datacenter IP detection API written in Rust. This tool performs comprehensive analysis of IP addresses to determine if they are proxies, VPNs, or belong to datacenters.

## Features

- **No External API Dependencies**: Works completely without paid third-party services
- **Multiple Detection Methods**:
  - Datacenter IP range detection (AWS, DigitalOcean, Vultr, OVH, Hetzner, Linode, Contabo, etc.)
  - Port scanning for common proxy/VPN ports (SOCKS, HTTP proxy, Tor, etc.)
  - DNS blacklist (DNSBL) checking (Spamhaus, SORBS, DroneRL, etc.)
  - Reverse DNS pattern analysis
  - WHOIS lookup and analysis
  - ASN-based datacenter detection
- **Risk Scoring**: 0-100 risk score with detailed breakdown
- **REST API**: Easy-to-use HTTP endpoints
- **CLI Support**: Check IPs directly from command line

## Quick Start

### Build

```bash
cargo build --release
```

### CLI Usage

Check IPs directly from command line:

```bash
# Check single IP
cargo run --release -- 123.123.123.123

# Check multiple IPs
cargo run --release -- 123.123.123.123 124.124.124.124 8.8.8.8
```

### API Usage

Start the API server:

```bash
cargo run --release
```

The server starts on `http://0.0.0.0:3000`

#### Endpoints

**Health Check:**
```bash
curl http://localhost:3000/
```

**Check IP (GET):**
```bash
curl http://localhost:3000/check/123.123.123.123
```

**Check IP (POST):**
```bash
curl -X POST http://localhost:3000/check \
  -H "Content-Type: application/json" \
  -d '{"ip": "123.123.123.123"}'
```

### Example Response

```json
{
  "ip": "123.123.123.123",
  "is_proxy": true,
  "is_vpn": false,
  "is_datacenter": true,
  "is_residential": false,
  "risk_score": 100,
  "details": {
    "reverse_dns": null,
    "rdns_suspicious": false,
    "open_proxy_ports": [1080, 80, 443, 22],
    "blacklisted": true,
    "blacklist_entries": ["zen.spamhaus.org", "dnsbl.dronebl.org"],
    "datacenter_cidr": "123.123.0.0/16",
    "whois_organization": "Proxy ISP, LLC",
    "whois_country": "US",
    "risk_factors": [
      "IP belongs to known datacenter IP range",
      "Open proxy/VPN ports detected: [1080]",
      "High-risk port 1080 (SOCKS/Tor)",
      "Listed in 6 DNS blacklists"
    ]
  }
}
```

## Detection Methods

### 1. Datacenter CIDR Ranges
Detects IPs belonging to known cloud/hosting providers:
- AWS, Google Cloud, Microsoft Azure
- DigitalOcean, Vultr, Linode
- OVH, Hetzner, Contabo, Scaleway
- And many more...

### 2. Port Scanning
Scans for common proxy/VPN ports:
- SOCKS proxies (1080, etc.)
- HTTP proxies (3128, 8080, 8888)
- Tor (9050, 9051)
- VPN ports (1194, 1723, 500)

### 3. DNS Blacklists
Checks against 25+ DNS blacklists including:
- Spamhaus (SBL, XBL, PBL)
- SORBS, SpamCop
- DroneRL, abuse.ch
- Tor exit node lists

### 4. WHOIS Analysis
Parses WHOIS data for:
- Organization names with VPN/hosting keywords
- Known datacenter ASNs
- Network registration details

### 5. Reverse DNS
Analyzes PTR records for suspicious patterns:
- VPN/proxy keywords
- Datacenter hostnames
- Suspicious formatting

## Risk Score

The risk score (0-100) is calculated by combining signals from all detection methods:
- 0-29: Likely residential
- 30-49: Suspicious, needs review
- 50-74: Likely proxy/datacenter
- 75-100: Highly likely proxy/VPN/datacenter
