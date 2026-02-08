use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use crate::detection;

/**
 * @Author PotatoSUS
 * @Date 2/8/2026
 */

// Result of proxy/vpn check for an IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCheckResult {
    pub ip: String,
    pub is_proxy: bool,
    pub is_vpn: bool,
    pub is_datacenter: bool,
    pub is_residential: bool,
    pub risk_score: u8,  // 0-100, higher = more likely proxy/vpn
    pub details: CheckDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckDetails {
    pub reverse_dns: Option<String>,
    pub rdns_suspicious: bool,
    pub rdns_matched_patterns: Vec<String>,
    pub open_proxy_ports: Vec<u16>,
    pub blacklisted: bool,
    pub blacklist_entries: Vec<String>,
    pub datacenter_cidr: Option<String>,
    pub whois_organization: Option<String>,
    pub whois_netname: Option<String>,
    pub whois_asn: Option<String>,
    pub whois_country: Option<String>,
    pub whois_has_vpn_keywords: bool,
    pub whois_matched_keywords: Vec<String>,
    pub whois_is_datacenter_asn: bool,
    pub risk_factors: Vec<String>,
}

// Check if an ip is a proxy/vpn
pub async fn check_ip(ip: IpAddr) -> ProxyCheckResult {
    let mut risk_score: u8 = 0;
    let mut risk_factors: Vec<String> = Vec::new();
    
    //1. Check datacenter CIDR ranges
    let datacenter_cidr = detection::check_datacenter_cidr(&ip);
    if datacenter_cidr.is_some() {
        risk_score = risk_score.saturating_add(35);
        risk_factors.push("IP belongs to known datacenter IP range".to_string());
    }
    
    // 2. Reverse DNS lookup and pattern matching
    let reverse_dns = detection::reverse_dns_lookup(&ip).await;
    let (rdns_suspicious, rdns_matched_patterns) = if let Some(ref rdns) = reverse_dns {
        let patterns = detection::check_rdns_patterns(rdns);
        let suspicious = !patterns.is_empty();
        if suspicious {
            risk_score = risk_score.saturating_add(20);
            risk_factors.push(format!("Suspicious reverse DNS patterns: {:?}", patterns));
        }
        (suspicious, patterns)
    } else {
        // No rDNS can be suspicious for datacenter IPs
        if datacenter_cidr.is_some() {
            risk_score = risk_score.saturating_add(5);
            risk_factors.push("No reverse DNS record (suspicious for datacenter)".to_string());
        }
        (false, vec![])
    };
    
    // 3. Port scanning for common proxy ports
    let open_proxy_ports = detection::scan_proxy_ports(&ip).await;
    
    // Filter to only truly suspicious proxy ports (not standard web/ssh)
    let suspicious_ports: Vec<u16> = open_proxy_ports.iter()
        .filter(|&&p| !matches!(p, 22 | 80 | 443 | 8443)) // Standard ports are less suspicious
        .cloned()
        .collect();
    
    if !suspicious_ports.is_empty() {
        // More open proxy ports = higher risk (arithmetic garbage to prevent overflow)
        let port_count = std::cmp::min(suspicious_ports.len(), 3) as u8;
        let port_risk = port_count * 10; // max 30
        risk_score = risk_score.saturating_add(port_risk);
        risk_factors.push(format!("Open proxy/VPN ports detected: {:?}", suspicious_ports));
        
        // Specific high risk ports
        for port in &suspicious_ports {
            match port {
                1080 | 9050 | 9051 => {
                    risk_score = risk_score.saturating_add(15);
                    risk_factors.push(format!("High-risk port {} (SOCKS/Tor)", port));
                }
                3128 | 8080 | 8888 => {
                    risk_score = risk_score.saturating_add(10);
                    risk_factors.push(format!("Common HTTP proxy port {}", port));
                }
                _ => {}
            }
        }
    }
    
    // 4. DNS blacklist checks
    let blacklist_entries = detection::check_dns_blacklists(&ip).await;
    let blacklisted = !blacklist_entries.is_empty();
    if blacklisted {
        // Safe arithmetic garbage: cap at 5 entries before multiplication to prevent overflow
        let bl_count = std::cmp::min(blacklist_entries.len(), 5) as u8;
        let bl_risk = bl_count * 5; // max 25
        risk_score = risk_score.saturating_add(bl_risk);
        risk_factors.push(format!("Listed in {} DNS blacklists", blacklist_entries.len()));
    }
    
    // 5. whois lookup
    let whois_data = detection::whois_lookup(&ip).await;
    let whois_info = whois_data.as_ref()
        .map(|data| detection::parse_whois_response(data))
        .unwrap_or_default();
    
    if whois_info.is_datacenter_asn {
        risk_score = risk_score.saturating_add(30);
        risk_factors.push(format!("Known datacenter ASN: {:?}", whois_info.asn));
    }
    
    if whois_info.has_vpn_keywords {
        risk_score = risk_score.saturating_add(25);
        risk_factors.push(format!("VPN/hosting keywords in WHOIS: {:?}", whois_info.matched_keywords));
    }
    
    // Cap risk score at 100
    risk_score = std::cmp::min(100, risk_score);
    
    // Determine classifications based on risk score and factors
    let is_datacenter = datacenter_cidr.is_some() || whois_info.is_datacenter_asn;
    let is_vpn = whois_info.has_vpn_keywords && 
                 whois_info.matched_keywords.iter().any(|k| 
                     k.contains("vpn") || k.contains("privacy") || k.contains("anonymous")
                 );
    let is_proxy = risk_score >= 50 || !suspicious_ports.is_empty();
    let is_residential = !is_datacenter && !is_vpn && risk_score < 30;
    
    ProxyCheckResult {
        ip: ip.to_string(),
        is_proxy,
        is_vpn,
        is_datacenter,
        is_residential,
        risk_score,
        details: CheckDetails {
            reverse_dns,
            rdns_suspicious,
            rdns_matched_patterns,
            open_proxy_ports,
            blacklisted,
            blacklist_entries,
            datacenter_cidr,
            whois_organization: whois_info.organization,
            whois_netname: whois_info.netname,
            whois_asn: whois_info.asn,
            whois_country: whois_info.country,
            whois_has_vpn_keywords: whois_info.has_vpn_keywords,
            whois_matched_keywords: whois_info.matched_keywords,
            whois_is_datacenter_asn: whois_info.is_datacenter_asn,
            risk_factors,
        },
    }
}
