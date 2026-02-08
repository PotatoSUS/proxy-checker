use std::net::IpAddr;
use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use crate::checker;

/**
 * @Author PotatoSUS
 * @Date 2/8/2026
 */

// Health check endpoint
pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "proxy-checker",
        "version": "0.1.0"
    }))
}

#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    pub ip: String,
}


// Check ip via POST request
pub async fn check_ip(Json(payload): Json<CheckRequest>) -> impl IntoResponse {
    match parse_and_check_ip(&payload.ip).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(result).unwrap())),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e }))
        ),
    }
}

    // Check ip via GET request with path parameter
pub async fn check_ip_get(Path(ip): Path<String>) -> impl IntoResponse {
    match parse_and_check_ip(&ip).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(result).unwrap())),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e }))
        ),
    }
}

async fn parse_and_check_ip(ip_str: &str) -> Result<checker::ProxyCheckResult, String> {
    // Clean up the IP string (remove brackets, ports, etc.)
    let cleaned = clean_ip_string(ip_str);
    
    let ip: IpAddr = cleaned.parse()
        .map_err(|e| format!("Invalid IP address '{}': {}", ip_str, e))?;
    
    Ok(checker::check_ip(ip).await)
}

// Clean up IP string by removing common formatting issues
fn clean_ip_string(s: &str) -> String {
    let mut cleaned = s.trim().to_string();
    
    // Remove leading/trailing brackets
    if cleaned.starts_with('/') {
        cleaned = cleaned[1..].to_string();
    }
    if cleaned.starts_with('[') {
        cleaned = cleaned[1..].to_string();
    }
    if cleaned.ends_with(']') {
        cleaned = cleaned[..cleaned.len()-1].to_string();
    }
    
    // Remove port if present (IPv4 format: 1.2.3.4:8080)
    if let Some(colon_pos) = cleaned.rfind(':') {
        // Check if this is IPv4 with port (not IPv6)
        if cleaned.matches(':').count() == 1 {
            cleaned = cleaned[..colon_pos].to_string();
        }
    }
    
    cleaned
}
