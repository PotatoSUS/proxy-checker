use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use regex::Regex;

/**
 * @Author PotatoSUS
 * @Date 2/8/2026
 */

// Hardcoded asf, i need to @Rewrite this, but just works :trollface:


// Common proxy/vpn ports to scan
pub const PROXY_PORTS: &[u16] = &[
    // SOCKS proxies
    1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089,
    // HTTP proxies
    80, 8080, 8081, 8888, 3128, 8000, 8001, 8002, 8118,
    // HTTPS proxies
    443, 8443,
    // Squid
    3129,
    // VPN common ports
    1194, 1723, 500, 4500,
    // SSH tunneling
    22, 2222,
    // Tor
    9050, 9051,
    // Other proxy ports
    3127, 8123, 9000, 9090, 9091, 9999,
    // Minecraft proxies
    25565, 25566, 25567,
];

// Known datacenter/hosting provider ASN numbers (i guess)
pub const DATACENTER_ASNS: &[&str] = &[
    // Major cloud providers
    "AS16509",  // Amazon
    "AS14618",  // Amazon
    "AS15169",  // Google
    "AS396982", // Google Cloud
    "AS8075",   // Microsoft Azure
    "AS13335",  // Cloudflare
    "AS20940",  // Akamai
    "AS16276",  // OVH
    "AS63949",  // Linode
    "AS14061",  // DigitalOcean
    "AS20473",  // Vultr/Choopa
    "AS46652",  // Serverius
    "AS45102",  // Alibaba
    "AS24940",  // Hetzner
    "AS51167",  // Contabo
    "AS12876",  // Scaleway
    "AS62567",  // DigitalOcean
    "AS36352",  // ColoCrossing
    "AS21740",  // eNET
    "AS46261",  // QuadraNet
    "AS19531",  // DataCamp
    "AS55286",  // B2 Net Solutions (Servermania)
    "AS29802",  // HIVELOCITY
    "AS25369",  // Hydra Communications
    "AS50304",  // Blix Solutions
    "AS200019", // AlexHost
    "AS42831",  // UK Dedicated Servers
    "AS35916",  // MultaHost
    "AS49981",  // WorldStream
    "AS60781",  // LeaseWeb
    "AS30083",  // HEG US
    "AS174",    // Cogent
    "AS3356",   // Level3/Lumen
    "AS6939",   // Hurricane Electric
    "AS3257",   // GTT
    "AS1299",   // Telia
    "AS36692",  // OpenDNS/Cisco Umbrella
    "AS394711", // Limenet
    "AS50613",  // Advania
    "AS51765",  // ITL LLC
    "AS198610", // ITL LLC
    "AS56630",  // Melbikomas
    "AS9009",   // M247
    "AS60068",  // DataCamp Limited
    "AS202425", // IP Volume
    "AS35913",  // DediPath
    "AS396356", // Maxihost
    "AS31898"   // Oracle Corporation
];

// Common vpn/proxy provider names in whois data
pub const VPN_PROVIDER_KEYWORDS: &[&str] = &[
    "vpn", "proxy", "anonymous", "privacy", "hide", "mask", "tunnel",
    "express", "nord", "surfshark", "cyberghost", "private internet access",
    "mullvad", "proton", "ipvanish", "hotspot shield", "purevpn",
    "windscribe", "zenmate", "ivacy", "torguard", "vypr",
    "hideme", "hidemyass", "strongvpn", "perfect privacy",
    "air vpn", "privatevpn", "astrill", "azire",
    "hosting", "datacenter", "data center", "data-center",
    "cloud", "server", "dedicated", "colocation", "colo",
    "vps", "virtual private", "vserver",
    "ovh", "digitalocean", "linode", "vultr", "aws", "amazon",
    "google cloud", "azure", "hetzner", "contabo", "scaleway",
    "choopa", "gameserver", "game server",
];

// DNS based blacklists (DNSBLs) for checking if ip is listed
pub const DNS_BLACKLISTS: &[&str] = &[
    "zen.spamhaus.org",
    "dnsbl.sorbs.net",
    "bl.spamcop.net",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "spam.dnsbl.sorbs.net",
    "dul.dnsbl.sorbs.net",
    "http.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "misc.dnsbl.sorbs.net",
    "zombie.dnsbl.sorbs.net",
    "sbl.spamhaus.org",
    "xbl.spamhaus.org",
    "pbl.spamhaus.org",
    "cbl.abuseat.org",
    "dnsbl.dronebl.org",
    "drone.abuse.ch",
    "httpbl.abuse.ch",
    "tor.dan.me.uk",
    "torexit.dan.me.uk",
    "exitnodes.tor.dnsbl.sectoor.de",
    "rbl.megarbl.net",
    "all.s5h.net",
    "dnsbl.justspam.org",
    "spamtrap.drbl.drand.net",
];

// Reverse dns patterns that indicate proxy/dns/datacenter
pub const SUSPICIOUS_RDNS_PATTERNS: &[&str] = &[
    r"vpn", r"proxy", r"vps", r"dedicated", r"cloud",
    r"server\d*\.", r"srv\d*\.", r"node\d*\.",
    r"client\d+\.", r"host\d+\.", r"pool-",
    r"static[-\.]", r"dynamic[-\.]",
    r"^ip[-\.]?\d+", r"^\d+[-\.]\d+[-\.]\d+[-\.]\d+",
    r"ovh\.", r"amazonaws\.", r"googlecloud\.", r"azure\.",
    r"linode\.", r"digitalocean\.", r"vultr\.", r"hetzner\.",
    r"contabo\.", r"scaleway\.", r"choopa\.", r"datacamp\.",
    r"hurricane\.", r"cogent\.", r"lumen\.",
    r"tor[-\.]?exit", r"tor[-\.]?node", r"onion\.",
    r"unassigned", r"unknown", r"no[-\.]?ptr",
    r"\.ru$", r"\.cn$",  // Often associated with proxy services
    r"game[-\.]?server", r"minecraft", r"mc\d*\.",
    r"bot\d*\.", r"crawler", r"spider",
];


// Known datacenter CIDR`S (i guess 2x)
pub const DATACENTER_CIDR_RANGES: &[&str] = &[
    // AWS ranges (specific known ranges)
    "3.0.0.0/16",
    "3.5.0.0/16",
    "3.8.0.0/14",
    "13.32.0.0/15",
    "13.48.0.0/15",
    "13.56.0.0/16",
    "18.144.0.0/15",
    "18.188.0.0/16",
    "18.204.0.0/16",
    "52.0.0.0/15",
    "52.44.0.0/15",
    "52.64.0.0/17",
    "54.64.0.0/15",
    "54.144.0.0/14",
    "54.172.0.0/15",
    "54.208.0.0/15",
    // DigitalOcean
    "104.131.0.0/16",
    "104.236.0.0/16",
    "107.170.0.0/16",
    "159.65.0.0/16",
    "167.71.0.0/16",
    "167.99.0.0/16",
    "174.138.0.0/16",
    "178.62.0.0/16",
    "188.166.0.0/16",
    "206.189.0.0/16",
    "209.97.0.0/16",
    "138.68.0.0/16",
    "139.59.0.0/16",
    "142.93.0.0/16",
    "157.230.0.0/16",
    "161.35.0.0/16",
    "143.198.0.0/16",
    // Vultr/Choopa
    "45.32.0.0/16",
    "45.63.0.0/16",
    "45.76.0.0/16",
    "45.77.0.0/16",
    "64.156.0.0/16",
    "66.42.0.0/16",
    "78.141.0.0/16",
    "108.61.0.0/16",
    "136.244.0.0/16",
    "140.82.0.0/16",
    "144.202.0.0/16",
    "149.28.0.0/16",
    "155.138.0.0/16",
    // OVH
    "51.38.0.0/16",
    "51.68.0.0/16",
    "51.75.0.0/16",
    "51.77.0.0/16",
    "51.79.0.0/16",
    "51.81.0.0/16",
    "51.83.0.0/16",
    "51.89.0.0/16",
    "51.91.0.0/16",
    "54.36.0.0/16",
    "54.37.0.0/16",
    "54.38.0.0/16",
    "54.39.0.0/16",
    "135.125.0.0/16",
    "137.74.0.0/16",
    "145.239.0.0/16",
    "147.135.0.0/16",
    "149.56.0.0/16",
    "158.69.0.0/16",
    "162.19.0.0/16",
    "164.132.0.0/16",
    "176.31.0.0/16",
    "178.32.0.0/16",
    "185.45.0.0/16",
    "188.165.0.0/16",
    "192.99.0.0/16",
    "193.70.0.0/16",
    "198.27.0.0/16",
    "198.50.0.0/16",
    "198.100.0.0/16",
    "213.186.0.0/16",
    "213.251.0.0/16",
    // Hetzner
    "5.9.0.0/16",
    "23.88.0.0/16",
    "46.4.0.0/16",
    "49.12.0.0/16",
    "78.46.0.0/16",
    "78.47.0.0/16",
    "88.99.0.0/16",
    "88.198.0.0/16",
    "94.130.0.0/16",
    "95.216.0.0/16",
    "116.202.0.0/16",
    "116.203.0.0/16",
    "128.140.0.0/16",
    "135.181.0.0/16",
    "136.243.0.0/16",
    "138.201.0.0/16",
    "142.132.0.0/16",
    "144.76.0.0/16",
    "148.251.0.0/16",
    "157.90.0.0/16",
    "159.69.0.0/16",
    "162.55.0.0/16",
    "168.119.0.0/16",
    "176.9.0.0/16",
    "178.63.0.0/16",
    "188.40.0.0/16",
    "195.201.0.0/16",
    "213.133.0.0/16",
    "213.239.0.0/16",
    // Linode
    "45.33.0.0/16",
    "45.56.0.0/16",
    "45.79.0.0/16",
    "50.116.0.0/16",
    "66.175.0.0/16",
    "69.164.0.0/16",
    "72.14.0.0/16",
    "96.126.0.0/16",
    "97.107.0.0/16",
    "139.144.0.0/16",
    "139.162.0.0/16",
    "143.42.0.0/16",
    "172.104.0.0/16",
    "172.105.0.0/16",
    "173.255.0.0/16",
    "178.79.0.0/16",
    "192.155.0.0/16",
    "198.58.0.0/16",
    // Contabo
    "38.54.0.0/16",
    "45.136.0.0/16",
    "45.142.0.0/16",
    "62.171.0.0/16",
    "79.143.0.0/16",
    "144.91.0.0/16",
    "161.97.0.0/16",
    "167.86.0.0/16",
    "173.249.0.0/16",
    "178.238.0.0/16",
    "193.26.0.0/16",
    "193.104.0.0/16",
    "193.188.0.0/16",
    // Google Cloud (specific ranges)
    "34.64.0.0/14",
    "34.80.0.0/15",
    "34.96.0.0/14",
    "34.104.0.0/14",
    "34.120.0.0/14",
    "35.184.0.0/14",
    "35.188.0.0/14",
    "35.192.0.0/14",
    "35.200.0.0/14",
    "35.208.0.0/14",
    "35.220.0.0/14",
    "35.228.0.0/14",
    "35.240.0.0/14",
    // Microsoft Azure (specific ranges)
    "13.64.0.0/16",
    "13.65.0.0/16",
    "13.66.0.0/16",
    "13.67.0.0/16",
    "20.36.0.0/14",
    "20.40.0.0/14",
    "20.44.0.0/14",
    "20.48.0.0/14",
    "20.52.0.0/14",
    "40.64.0.0/14",
    "40.68.0.0/14",
    "40.74.0.0/15",
    "40.76.0.0/14",
    "52.224.0.0/14",
    "52.228.0.0/14",
    "52.232.0.0/14",
    // Common proxy/vpn provider ranges
    "193.233.0.0/16",  // Various hosting
    "37.200.0.0/16",   // Various hosting
    // 185.x.x.x ranges (specific datacenter allocations)
    "185.45.0.0/16",
    "185.110.0.0/16",
    "185.156.0.0/16",
    "185.180.0.0/16",
    "185.220.0.0/16",
    "185.234.0.0/16",
];

// Scan a single port with timeout
// Note: Connection is dropped (RST sent) after detection which is standard for port scanning
pub async fn scan_port(ip: &IpAddr, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", ip, port);
    match timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr)
    ).await {
        Ok(Ok(stream)) => {
            // Attempt graceful shutdown, ignore errors
            let _ = stream.into_std().map(|s| {
                let _ = s.shutdown(std::net::Shutdown::Both);
            });
            true
        }
        _ => false,
    }
}

// Scan multiple ports and return list of open ones
pub async fn scan_proxy_ports(ip: &IpAddr) -> Vec<u16> {
    let mut open_ports = Vec::new();
    
    // Use a timeout for network operations
    let timeout_ms = 500;
    
    // Scan ports in batches 
    let batch_size = 20;
    for chunk in PROXY_PORTS.chunks(batch_size) {
        let futures: Vec<_> = chunk.iter()
            .map(|&port| {
                let ip = *ip;
                async move {
                    if scan_port(&ip, port, timeout_ms).await {
                        Some(port)
                    } else {
                        None
                    }
                }
            })
            .collect();
        
        let results = futures::future::join_all(futures).await;
        for result in results {
            if let Some(port) = result {
                open_ports.push(port);
            }
        }
    }
    
    open_ports
}

// Perform reverse dns lookup
pub async fn reverse_dns_lookup(ip: &IpAddr) -> Option<String> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default()
    );
    
    match resolver.reverse_lookup(*ip).await {
        Ok(lookup) => {
            lookup.iter().next().map(|name| name.to_string())
        }
        Err(_) => None,
    }
}

// Check if IP is listed in DNS blacklists
pub async fn check_dns_blacklists(ip: &IpAddr) -> Vec<String> {
    let mut listed_in = Vec::new();
    
    if let IpAddr::V4(ipv4) = ip {
        let octets = ipv4.octets();
        let reversed = format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]);
        
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default()
        );
        
        for blacklist in DNS_BLACKLISTS {
            let query = format!("{}.{}", reversed, blacklist);
            if let Ok(response) = timeout(
                Duration::from_secs(2),
                resolver.lookup_ip(&query)
            ).await {
                if response.is_ok() {
                    listed_in.push(blacklist.to_string());
                }
            }
        }
    }
    
    listed_in
}

// Check if reverse DNS matches suspicious patterns
pub fn check_rdns_patterns(rdns: &str) -> Vec<String> {
    let mut matches = Vec::new();
    let rdns_lower = rdns.to_lowercase();
    
    for pattern in SUSPICIOUS_RDNS_PATTERNS {
        if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
            if re.is_match(&rdns_lower) {
                matches.push(pattern.to_string());
            }
        }
    }
    
    matches
}

// Check if IP belongs to a known datacenter CIDR range
pub fn check_datacenter_cidr(ip: &IpAddr) -> Option<String> {
    use std::str::FromStr;
    use cidr::IpCidr;
    
    for range in DATACENTER_CIDR_RANGES {
        if let Ok(cidr) = IpCidr::from_str(range) {
            if cidr.contains(ip) {
                return Some(range.to_string());
            }
        }
    }
    
    None
}

// whois lookup 
pub async fn whois_lookup(ip: &IpAddr) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcpStream;
    
    let whois_servers = [
        "whois.arin.net",
        "whois.ripe.net",
        "whois.apnic.net",
        "whois.lacnic.net",
        "whois.afrinic.net",
    ];
    
    for server in whois_servers {
        if let Ok(mut stream) = StdTcpStream::connect(format!("{}:43", server)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            
            let query = format!("{}\r\n", ip);
            if stream.write_all(query.as_bytes()).is_ok() {
                let mut response = String::new();
                if stream.read_to_string(&mut response).is_ok() && !response.is_empty() {
                    return Some(response);
                }
            }
        }
    }
    
    None
}

// Parse whois response
pub fn parse_whois_response(whois_data: &str) -> WhoisInfo {
    let mut info = WhoisInfo::default();
    let whois_lower = whois_data.to_lowercase();
    
    // Extract isp/company name
    for line in whois_data.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.contains("orgname:") || line_lower.contains("org-name:") || 
           line_lower.contains("organization:") || line_lower.contains("descr:") {
            if let Some(value) = line.split(':').nth(1) {
                let value = value.trim();
                if !value.is_empty() && info.organization.is_none() {
                    info.organization = Some(value.to_string());
                }
            }
        }
        
        if line_lower.contains("netname:") {
            if let Some(value) = line.split(':').nth(1) {
                let value = value.trim();
                if !value.is_empty() {
                    info.netname = Some(value.to_string());
                }
            }
        }
        
        if line_lower.contains("origin:") || line_lower.contains("originas:") {
            if let Some(value) = line.split(':').nth(1) {
                let value = value.trim().to_uppercase();
                if value.starts_with("AS") {
                    info.asn = Some(value);
                }
            }
        }
        
        if line_lower.contains("country:") {
            if let Some(value) = line.split(':').nth(1) {
                let value = value.trim().to_uppercase();
                if value.len() == 2 && info.country.is_none() {
                    info.country = Some(value);
                }
            }
        }
    }
    
    // Check for vpn/proxy keywords
    for keyword in VPN_PROVIDER_KEYWORDS {
        if whois_lower.contains(keyword) {
            info.has_vpn_keywords = true;
            info.matched_keywords.push(keyword.to_string());
        }
    }
    
    // Check for datacenter ASN
    if let Some(ref asn) = info.asn {
        for dc_asn in DATACENTER_ASNS {
            if asn == *dc_asn {
                info.is_datacenter_asn = true;
                break;
            }
        }
    }
    
    info
}

#[derive(Debug, Default, Clone)]
pub struct WhoisInfo {
    pub organization: Option<String>,
    pub netname: Option<String>,
    pub asn: Option<String>,
    pub country: Option<String>,
    pub has_vpn_keywords: bool,
    pub matched_keywords: Vec<String>,
    pub is_datacenter_asn: bool,
}
