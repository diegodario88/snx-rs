use anyhow::Result;
use snxcore::model::params::TunnelParams;
use snxcore::util::parse_ipv4_or_subnet;
use std::collections::HashMap;
use std::time::Duration;
use zbus::zvariant::{Dict, OwnedValue, Str};
use tracing::warn;

pub fn params_from_connection(
    connection: &HashMap<String, HashMap<String, OwnedValue>>,
) -> Result<TunnelParams> {
    let mut params = TunnelParams::default();

    if let Some(vpn_settings) = connection.get("vpn") {
        if let Some(data) = vpn_settings.get("data") {
            extract_and_apply(data, &mut params)?;
        }

        if let Some(secrets) = vpn_settings.get("secrets") {
            extract_and_apply(secrets, &mut params)?;
        }

        // Also check for top-level keys in the 'vpn' map (e.g. user-name)
        if let Some(username) = vpn_settings.get("user-name") {
            if let Ok(s) = username.downcast_ref::<Str>() {
                params.user_name = s.as_str().to_string();
            }
        }
        if let Some(username) = vpn_settings.get("username") {
            if let Ok(s) = username.downcast_ref::<Str>() {
                params.user_name = s.as_str().to_string();
            }
        }
    }

    // For NetworkManager plugin, snxcore handles all networking
    // We'll emit signals but NM won't manage the interface
    params.no_routing = false;  // snxcore manages routing
    params.no_dns = false;      // snxcore manages DNS

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
    for (k, v) in map {
        match k.as_str() {
            "server" | "server-name" => params.server_name = v.clone(),
            "username" | "user-name" => params.user_name = v.clone(),
            "password" => params.password = v.clone(),
            "password-factor" => params.password_factor = v.parse().unwrap_or(1),
            "mfa_token" | "mfa-token" => params.mfa_code = Some(v.clone()),
            "log-level" => params.log_level = v.clone(),
            "search-domains" => {
                params.search_domains = v.split(',').map(|s| s.trim().to_owned()).collect()
            }
            "ignore-search-domains" => {
                params.ignore_search_domains = v.split(',').map(|s| s.trim().to_owned()).collect()
            }
            "dns-servers" => {
                params.dns_servers = v
                    .split(',')
                    .flat_map(|s| s.trim().parse().ok())
                    .collect()
            }
            "ignore-dns-servers" => {
                params.ignore_dns_servers = v
                    .split(',')
                    .flat_map(|s| s.trim().parse().ok())
                    .collect()
            }
            "default-route" => params.default_route = v.parse().unwrap_or_default(),
            "no-routing" => params.no_routing = v.parse().unwrap_or_default(),
            "add-routes" => {
                params.add_routes = v
                    .split(',')
                    .flat_map(|s| parse_ipv4_or_subnet(s.trim()).ok())
                    .collect()
            }
            "ignore-routes" => {
                params.ignore_routes = v
                    .split(',')
                    .flat_map(|s| parse_ipv4_or_subnet(s.trim()).ok())
                    .collect()
            }
            "no-dns" => params.no_dns = v.parse().unwrap_or_default(),
            "ignore-server-cert" => params.ignore_server_cert = v.parse().unwrap_or_default(),
            "tunnel-type" => params.tunnel_type = v.parse().unwrap_or_default(),
            "ca-cert" => params.ca_cert = v.split(',').map(|s| s.trim().into()).collect(),
            "login-type" => params.login_type = v.clone(),
            "cert-type" => params.cert_type = v.parse().unwrap_or_default(),
            "cert-path" => params.cert_path = Some(v.into()),
            "cert-password" => params.cert_password = Some(v.clone()),
            "cert-id" => params.cert_id = Some(v.clone()),
            "if-name" => params.if_name = Some(v.clone()),
            "no-keychain" => params.no_keychain = v.parse().unwrap_or_default(),
            "ike-lifetime" => {
                params.ike_lifetime = v
                    .parse::<u64>()
                    .ok()
                    .map_or(Duration::from_secs(28800), Duration::from_secs);
            }
            "ike-persist" => params.ike_persist = v.parse().unwrap_or_default(),
            "no-keepalive" => params.no_keepalive = v.parse().unwrap_or_default(),
            "client-mode" => params.client_mode = v.clone(),
            "set-routing-domains" => params.set_routing_domains = v.parse().unwrap_or_default(),
            "port-knock" => params.port_knock = v.parse().unwrap_or_default(),
            "ip-lease-time" => {
                params.ip_lease_time = v.parse::<u64>().ok().map(Duration::from_secs)
            }
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
