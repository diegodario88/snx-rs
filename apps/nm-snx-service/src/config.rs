use anyhow::Result;
use snxcore::model::params::TunnelParams;
use snxcore::util::parse_ipv4_or_subnet;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};
use zbus::zvariant::{Dict, OwnedValue, Str};

/// Maximum length for Linux interface names (including null terminator)
const IFNAMSIZ: usize = 16;
/// Prefix for all SNX interface names
const IF_PREFIX: &str = "snx-";

/// Sanitize a connection name for use as interface name suffix
/// - Converts to lowercase
/// - Removes non-alphanumeric characters
/// - Truncates to fit within IFNAMSIZ limit (15 - 4 for "snx-" = 11 chars max)
fn sanitize_if_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .take(IFNAMSIZ - 1 - IF_PREFIX.len()) // 15 - 4 = 11 chars max
        .collect::<String>()
        .to_lowercase()
}

/// Generate interface name from connection name (preferred) or UUID (fallback)
///
/// Examples:
/// - "VPN Corp" → "snx-corp"
/// - "My VPN Connection" → "snx-myvpnconnec" (truncated to 11 chars)
/// - UUID fallback: "a1b2c3d4-..." → "snx-a1b2c3d4"
fn generate_if_name(connection_name: Option<&str>, uuid: &str) -> String {
    let suffix = if let Some(name) = connection_name {
        let sanitized = sanitize_if_name(name);
        if sanitized.is_empty() {
            // Fallback to UUID if name sanitizes to empty string
            sanitize_if_name(uuid)
        } else {
            sanitized
        }
    } else {
        sanitize_if_name(uuid)
    };

    format!("{}{}", IF_PREFIX, suffix)
}

pub fn params_from_connection(connection: &HashMap<String, HashMap<String, OwnedValue>>) -> Result<TunnelParams> {
    let mut params = TunnelParams::default();

    // Extract connection UUID for generating unique interface name
    let mut connection_uuid: Option<String> = None;
    let mut connection_id: Option<String> = None;

    if let Some(conn_settings) = connection.get("connection") {
        if let Some(uuid) = conn_settings.get("uuid")
            && let Ok(s) = uuid.downcast_ref::<Str>()
        {
            connection_uuid = Some(s.as_str().to_string());
        }
        if let Some(id) = conn_settings.get("id")
            && let Ok(s) = id.downcast_ref::<Str>()
        {
            connection_id = Some(s.as_str().to_string());
        }
    }

    debug!("Connection UUID: {:?}, ID: {:?}", connection_uuid, connection_id);

    if let Some(vpn_settings) = connection.get("vpn") {
        debug!("vpn_settings keys: {:?}", vpn_settings.keys().collect::<Vec<_>>());

        if let Some(data) = vpn_settings.get("data") {
            debug!("Processing vpn.data: {:?}", data);
            extract_and_apply(data, &mut params)?;
            debug!("After vpn.data: user_name={:?}", params.user_name);
        }

        if let Some(secrets) = vpn_settings.get("secrets") {
            debug!("Processing vpn.secrets: {:?}", secrets);
            extract_and_apply(secrets, &mut params)?;
            debug!("After vpn.secrets: user_name={:?}", params.user_name);
        }

        // Also check for top-level keys in the 'vpn' map (e.g. user-name)
        // NetworkManager stores username in vpn.user-name property, not in vpn.data
        if let Some(username) = vpn_settings.get("user-name")
            && let Ok(s) = username.downcast_ref::<Str>()
        {
            debug!("Found top-level 'user-name' in vpn: {}", s.as_str());
            params.user_name = s.as_str().to_string();
        }
        if let Some(username) = vpn_settings.get("username")
            && let Ok(s) = username.downcast_ref::<Str>()
        {
            debug!("Found top-level 'username' in vpn: {}", s.as_str());
            params.user_name = s.as_str().to_string();
        }
    }

    debug!(
        "Final parsed params: user_name={:?}, server={:?}, password_len={}",
        params.user_name,
        params.server_name,
        params.password.len()
    );

    // Generate unique interface name if not explicitly set
    // Prefer connection name (e.g., "VPN Corp" → "snx-corp") over UUID
    if params.if_name.is_none()
        && let Some(uuid) = &connection_uuid
    {
        let generated_name = generate_if_name(connection_id.as_deref(), uuid);
        debug!("Generated interface name: {}", generated_name);
        params.if_name = Some(generated_name);
    }

    // For NetworkManager plugin:
    // - snxcore handles routing (NM doesn't know about VPN-specific routes)
    // - NetworkManager handles DNS via Ip4Config signals (cleaner integration)
    params.no_routing = false; // snxcore manages routing
    params.no_dns = true; // NetworkManager manages DNS via Ip4Config signal
    params.set_routing_domains = true; // Enable split DNS with ~ prefix for routing domains

    Ok(params)
}

fn extract_and_apply(value: &OwnedValue, params: &mut TunnelParams) -> Result<()> {
    // Try to extract as a Dict
    if let Ok(dict) = value.downcast_ref::<Dict<'_, '_>>() {
        let mut map = HashMap::new();
        // Dict::iter returns (&Value, &Value).
        for (k, v) in dict.iter() {
            // Keys must be strings (zbus::zvariant::Str)
            if let Ok(key_str) = k.downcast_ref::<Str>() {
                // Values must be strings too for our simple config
                if let Ok(val_str) = v.downcast_ref::<Str>() {
                    map.insert(key_str.as_str().to_string(), val_str.as_str().to_string());
                }
            }
        }
        apply_string_map(&map, params)?;
        return Ok(());
    }

    warn!("Could not extract string map from value: {:?}", value);
    Ok(())
}

fn apply_string_map(map: &HashMap<String, String>, params: &mut TunnelParams) -> Result<()> {
    debug!(
        "apply_string_map called with keys: {:?}",
        map.keys().collect::<Vec<_>>()
    );
    for (k, v) in map {
        match k.as_str() {
            "server" | "server-name" => params.server_name = v.clone(),
            "username" | "user-name" => {
                debug!("Setting user_name from key '{}' to '{}'", k, v);
                params.user_name = v.clone();
            }
            "password" => params.password = v.clone(),
            "password-factor" => params.password_factor = v.parse().unwrap_or(1),
            "mfa_token" | "mfa-token" => params.mfa_code = Some(v.clone()),
            "log-level" => params.log_level = v.clone(),
            "search-domains" => params.search_domains = v.split(',').map(|s| s.trim().to_owned()).collect(),
            "ignore-search-domains" => {
                params.ignore_search_domains = v.split(',').map(|s| s.trim().to_owned()).collect()
            }
            "dns-servers" => params.dns_servers = v.split(',').flat_map(|s| s.trim().parse().ok()).collect(),
            "ignore-dns-servers" => {
                params.ignore_dns_servers = v.split(',').flat_map(|s| s.trim().parse().ok()).collect()
            }
            "default-route" => params.default_route = v.parse().unwrap_or_default(),
            "add-routes" => {
                params.add_routes = v.split(',').flat_map(|s| parse_ipv4_or_subnet(s.trim()).ok()).collect()
            }
            "ignore-routes" => {
                params.ignore_routes = v.split(',').flat_map(|s| parse_ipv4_or_subnet(s.trim()).ok()).collect()
            }
            "ignore-server-cert" => params.ignore_server_cert = v.parse().unwrap_or_default(),
            "tunnel-type" => params.tunnel_type = v.parse().unwrap_or_default(),
            "ca-cert" => params.ca_cert = v.split(',').map(|s| s.trim().into()).collect(),
            "login-type" => params.login_type = v.clone(),
            "cert-type" => params.cert_type = v.parse().unwrap_or_default(),
            "cert-path" => params.cert_path = Some(v.into()),
            "cert-password" => params.cert_password = Some(v.clone()),
            "cert-id" => params.cert_id = Some(v.clone()),
            "if-name" => params.if_name = Some(v.clone()),
            "ike-lifetime" => {
                params.ike_lifetime = v
                    .parse::<u64>()
                    .ok()
                    .map_or(Duration::from_secs(28800), Duration::from_secs);
            }
            "ike-persist" => params.ike_persist = v.parse().unwrap_or_default(),
            "no-keepalive" => params.no_keepalive = v.parse().unwrap_or_default(),
            "client-mode" => params.client_mode = v.clone(),
            "port-knock" => params.port_knock = v.parse().unwrap_or_default(),
            "ip-lease-time" => params.ip_lease_time = v.parse::<u64>().ok().map(Duration::from_secs),
            "disable-ipv6" => params.disable_ipv6 = v.parse().unwrap_or_default(),
            "mtu" => params.mtu = v.parse().unwrap_or(1350),
            "transport-type" => params.transport_type = v.parse().unwrap_or_default(),
            _ => {
                // Ignore unknown keys
            }
        }
    }
    Ok(())
}
