mod checker;
mod api;
mod detection;

use std::net::{IpAddr, SocketAddr};
use std::env;
use axum::{Router, routing::{get, post}};
use tracing_subscriber;

/**
 * @Author PotatoSUS
 * @Date 2/8/2026
 * @TODO: Rewrite the hardcoded codes (please), place into a yml config file or other thing
 * @TODO: Optimize the response time. Actual: (~10-15s on localhost). Target: (~3-5s on localhost)
 * @TODO: Improve checks!
 */

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    let args: Vec<String> = env::args().collect();
    
    // if ip addresses provided as arguments, check them directly
    if args.len() > 1 {
        for arg in &args[1..] {
            let cleaned = clean_ip_arg(arg);
            match cleaned.parse::<IpAddr>() {
                Ok(ip) => {
                    println!("\n=== Checking IP: {} ===", ip);
                    let result = checker::check_ip(ip).await;
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    
                    // Summary
                    println!("\n--- SUMMARY ---");
                    println!("IP: {}", result.ip);
                    println!("Is Proxy: {}", result.is_proxy);
                    println!("Is VPN: {}", result.is_vpn);
                    println!("Is Datacenter: {}", result.is_datacenter);
                    println!("Is Residential: {}", result.is_residential);
                    println!("Risk Score: {}/100", result.risk_score);
                    println!("---------------\n");
                }
                Err(e) => {
                    eprintln!("Invalid IP '{}': {}", arg, e);
                }
            }
        }
        return;
    }
    
    // start the API server
    let app = Router::new()
        .route("/", get(api::health))
        .route("/check", post(api::check_ip))
        .route("/check/:ip", get(api::check_ip_get));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Starting proxy checker API on http://{}", addr);
    println!("Usage:");
    println!("  - GET  /check/:ip - Check an IP address");
    println!("  - POST /check with JSON body {{\"ip\": \"1.2.3.4\"}}");
    println!("\nOr run with IP arguments: cargo run -- 1.2.3.4 5.6.7.8");
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// clean up ip argument by removing common formatting issues
fn clean_ip_arg(s: &str) -> String {
    let mut cleaned = s.trim().to_string();
    
    // Remove name prefix like "afk1[/"
    if let Some(bracket_pos) = cleaned.find('[') {
        cleaned = cleaned[bracket_pos..].to_string();
    }
    
    // Remove leading/trailing brackets and slashes
    cleaned = cleaned.trim_start_matches('[')
        .trim_start_matches('/')
        .trim_end_matches(']')
        .to_string();
    
    // Remove port if present (IPv4 format: 1.2.3.4:8080)
    if let Some(colon_pos) = cleaned.rfind(':') {
        // Check if this is IPv4 with port (not IPv6)
        if cleaned.matches(':').count() == 1 {
            cleaned = cleaned[..colon_pos].to_string();
        }
    }
    
    cleaned
}
