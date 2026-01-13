use std::{collections::HashSet, net::Ipv4Addr};

use async_trait::async_trait;
use ipnet::Ipv4Net;
use tracing::{debug, warn};

use crate::platform::RoutingConfigurator;

/// Shared iptables chain for all SNX VPN routing marks.
/// All VPNs share this chain, with rules ordered by prefix specificity.
const SNX_CHAIN: &str = "SNX_ROUTES";

/// Generate a unique routing table ID and fwmark from device name
/// Uses a simple hash to get a number in range 100-65000
fn generate_table_id(device: &str) -> u32 {
    let hash: u32 = device
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_add(b as u32).wrapping_mul(31));
    100 + (hash % 64900) // Range: 100-65000
}

/// Ensure the shared SNX_ROUTES chain exists and is linked from OUTPUT/PREROUTING.
/// This is idempotent - safe to call multiple times.
async fn ensure_snx_chain_exists() {
    // Try to create chain (ignore error if already exists)
    let _ = crate::util::run_command("iptables", ["-t", "mangle", "-N", SNX_CHAIN]).await;

    // Check if jump from OUTPUT exists
    let output_jump_exists = crate::util::run_command("iptables", ["-t", "mangle", "-C", "OUTPUT", "-j", SNX_CHAIN])
        .await
        .is_ok();

    if !output_jump_exists {
        debug!("Adding jump from OUTPUT to {}", SNX_CHAIN);
        let _ = crate::util::run_command("iptables", ["-t", "mangle", "-I", "OUTPUT", "-j", SNX_CHAIN]).await;
    }

    // Check if jump from PREROUTING exists
    let prerouting_jump_exists =
        crate::util::run_command("iptables", ["-t", "mangle", "-C", "PREROUTING", "-j", SNX_CHAIN])
            .await
            .is_ok();

    if !prerouting_jump_exists {
        debug!("Adding jump from PREROUTING to {}", SNX_CHAIN);
        let _ = crate::util::run_command("iptables", ["-t", "mangle", "-I", "PREROUTING", "-j", SNX_CHAIN]).await;
    }
}

/// Check if a MARK rule for this subnet/mark already exists in SNX_ROUTES
async fn mark_rule_exists(subnet_str: &str, mark: &str) -> bool {
    crate::util::run_command(
        "iptables",
        [
            "-t",
            "mangle",
            "-C",
            SNX_CHAIN,
            "-d",
            subnet_str,
            "-j",
            "MARK",
            "--set-mark",
            mark,
        ],
    )
    .await
    .is_ok()
}

/// Check if a RETURN rule for this subnet/mark already exists in SNX_ROUTES
async fn return_rule_exists(subnet_str: &str, mark: &str) -> bool {
    crate::util::run_command(
        "iptables",
        [
            "-t", "mangle", "-C", SNX_CHAIN, "-d", subnet_str, "-m", "mark", "--mark", mark, "-j", "RETURN",
        ],
    )
    .await
    .is_ok()
}

/// Extract prefix length from a CIDR string like "172.16.0.0/16"
fn parse_prefix_len(cidr: &str) -> Option<u8> {
    cidr.split('/').nth(1).and_then(|s| s.parse().ok())
}

/// Extract the destination CIDR from an iptables rule line.
/// Example line: "MARK       all  --  0.0.0.0/0            172.16.0.0/16        MARK set 0x6f"
/// The format with `iptables -L CHAIN -n` (no -v) and split_whitespace is:
///   TARGET(0) PROT(1) OPT(2) SOURCE(3) DESTINATION(4) ...
/// Returns the destination (e.g., "172.16.0.0/16" or "200.201.213.46") if found.
fn extract_destination_from_rule(line: &str) -> Option<&str> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    // Format: TARGET(0) PROT(1) OPT(2) SOURCE(3) DESTINATION(4) ...
    if parts.len() >= 5 {
        let dest = parts[4];
        // Skip if it's the wildcard "0.0.0.0/0"
        if dest != "0.0.0.0/0" && dest.contains('/') {
            return Some(dest);
        }
        // Also handle single IPs without prefix (treated as /32)
        if dest != "0.0.0.0/0" && !dest.contains('/') && dest.contains('.') {
            return Some(dest);
        }
    }
    None
}

/// Check if adding a rule for `subnet` would conflict with an existing rule
/// from a DIFFERENT VPN (different fwmark) that has the EXACT SAME subnet.
///
/// Strategy: Only skip if exact same subnet exists with different mark.
/// Different prefix lengths can coexist - iptables processes rules in order,
/// so more specific rules (added first via find_insert_position) will match first.
///
/// Returns true if we should skip adding our rule.
async fn check_exact_duplicate_rule(subnet: Ipv4Net, our_mark: &str) -> bool {
    let output = crate::util::run_command("iptables", ["-t", "mangle", "-L", SNX_CHAIN, "-n"])
        .await
        .unwrap_or_default();

    for line in output.lines().skip(2) {
        // Only check MARK rules
        if !line.trim_start().starts_with("MARK") {
            continue;
        }

        // Skip rules with our own mark
        if line.contains(our_mark) {
            continue;
        }

        if let Some(dest) = extract_destination_from_rule(line) {
            // Parse the existing rule's destination
            let existing_subnet: Ipv4Net = if dest.contains('/') {
                match dest.parse() {
                    Ok(net) => net,
                    Err(_) => continue,
                }
            } else {
                // Single IP, treat as /32
                match dest.parse::<std::net::Ipv4Addr>() {
                    Ok(ip) => Ipv4Net::new(ip, 32).unwrap(),
                    Err(_) => continue,
                }
            };

            // Only skip if EXACT same subnet (same network AND same prefix length)
            if existing_subnet == subnet {
                debug!(
                    "Skipping iptables rule for {} (mark {}): exact same subnet exists from another VPN",
                    subnet, our_mark
                );
                return true;
            }
        }
    }

    false
}

/// Find all subnets in SNX_ROUTES that have MARK rules with the specified fwmark.
/// This is used during cleanup to discover which rules belong to this VPN instance,
/// without relying on in-memory state (which is lost when the configurator is dropped).
async fn find_subnets_for_mark(mark: &str) -> Vec<Ipv4Net> {
    let output = crate::util::run_command("iptables", ["-t", "mangle", "-L", SNX_CHAIN, "-n"])
        .await
        .unwrap_or_default();

    debug!("iptables -L {} output ({} bytes):\n{}", SNX_CHAIN, output.len(), output);

    let mut subnets = Vec::new();
    for line in output.lines().skip(2) {
        // Look for MARK rules with our specific mark value
        // Example: "MARK       all  --  0.0.0.0/0            172.16.0.0/16        MARK set 0x6f"
        if line.trim_start().starts_with("MARK") && line.contains(mark) {
            if let Some(dest) = extract_destination_from_rule(line) {
                if let Ok(subnet) = dest.parse::<Ipv4Net>() {
                    subnets.push(subnet);
                }
            }
        }
    }

    if !subnets.is_empty() {
        debug!(
            "Found {} subnet(s) in {} for mark {}: {:?}",
            subnets.len(),
            SNX_CHAIN,
            mark,
            subnets
        );
    }

    subnets
}

/// Find the correct position to insert a rule based on prefix length.
/// Rules with larger prefix (more specific) should come FIRST.
/// Returns the 1-based position for iptables -I.
async fn find_insert_position(prefix_len: u8) -> u32 {
    let output = crate::util::run_command("iptables", ["-t", "mangle", "-L", SNX_CHAIN, "-n"])
        .await
        .unwrap_or_default();

    let lines: Vec<&str> = output.lines().skip(2).filter(|l| !l.is_empty()).collect();
    let rule_count = lines.len();

    debug!(
        "find_insert_position: looking for position for /{}, chain has {} rules",
        prefix_len, rule_count
    );

    // If chain is empty, insert at position 1
    if rule_count == 0 {
        debug!("find_insert_position: chain is empty, returning position 1");
        return 1;
    }

    let mut position = 1u32;
    let mut i = 0;

    // Process rules in pairs (MARK + RETURN)
    while i < lines.len() {
        let line = lines[i];

        // Only process MARK rules
        if !line.trim_start().starts_with("MARK") {
            // Skip non-MARK rules (shouldn't happen in a well-formed chain)
            position += 1;
            i += 1;
            continue;
        }

        if let Some(dest) = extract_destination_from_rule(line) {
            // Get prefix length, treating single IPs as /32
            let existing_prefix = if dest.contains('/') {
                parse_prefix_len(dest).unwrap_or(0)
            } else {
                32 // Single IP
            };

            debug!(
                "find_insert_position: rule at pos {}: dest={}, existing_prefix={}, our_prefix={}",
                position, dest, existing_prefix, prefix_len
            );

            if existing_prefix >= prefix_len {
                // Existing rule is more specific or equal, insert after this MARK+RETURN pair
                position += 2; // Skip MARK + RETURN pair
                i += 2; // Move past both MARK and RETURN in our iteration
            } else {
                // Found a less specific rule, insert before it
                debug!(
                    "find_insert_position: found less specific rule, inserting at position {}",
                    position
                );
                break;
            }
        } else {
            // Couldn't parse destination, log the line for debugging
            debug!(
                "find_insert_position: couldn't parse destination from MARK rule: '{}'",
                line
            );
            position += 1;
            i += 1;
        }
    }

    debug!(
        "find_insert_position: returning position {} for /{}",
        position, prefix_len
    );
    position
}

/// Remove the SNX_ROUTES chain if it's empty (no more VPNs connected)
async fn maybe_cleanup_empty_chain() {
    let output = crate::util::run_command("iptables", ["-t", "mangle", "-L", SNX_CHAIN, "-n"])
        .await
        .unwrap_or_default();

    // Count rules (skip 2 header lines)
    let rule_count = output.lines().skip(2).filter(|l| !l.is_empty()).count();

    if rule_count == 0 {
        debug!("{} chain is empty, removing it", SNX_CHAIN);

        // Remove jumps from OUTPUT and PREROUTING
        let _ = crate::util::run_command("iptables", ["-t", "mangle", "-D", "OUTPUT", "-j", SNX_CHAIN]).await;
        let _ = crate::util::run_command("iptables", ["-t", "mangle", "-D", "PREROUTING", "-j", SNX_CHAIN]).await;

        // Delete the chain (must be empty and not referenced)
        let _ = crate::util::run_command("iptables", ["-t", "mangle", "-X", SNX_CHAIN]).await;
    }
}

pub struct LinuxRoutingConfigurator {
    device: String,
    address: Ipv4Addr,
    table_id: u32,
    fwmark: u32,
}

impl LinuxRoutingConfigurator {
    pub fn new<S: AsRef<str>>(device: S, address: Ipv4Addr) -> Self {
        let device_str = device.as_ref().to_string();
        let table_id = generate_table_id(&device_str);
        // Use same value for fwmark (keeps it simple and unique per device)
        let fwmark = table_id;
        debug!(
            "Routing config for '{}': table_id={}, fwmark=0x{:x}",
            device_str, table_id, fwmark
        );
        Self {
            device: device_str,
            address,
            table_id,
            fwmark,
        }
    }

    fn table_id_str(&self) -> String {
        self.table_id.to_string()
    }

    fn fwmark_hex(&self) -> String {
        format!("0x{:x}", self.fwmark)
    }

    /// Add a route ONLY to VPN-specific table (NOT to main table)
    /// This avoids conflicts between different VPN types (SSL vs IPSec)
    async fn add_route_to_table(&self, route: Ipv4Net) -> anyhow::Result<()> {
        let route_str = route.to_string();

        debug!("Adding route to table {}: {} dev {}", self.table_id, route, self.device);
        let _ = crate::util::run_command(
            "ip",
            [
                "route",
                "add",
                &route_str,
                "dev",
                &self.device,
                "table",
                &self.table_id_str(),
            ],
        )
        .await;

        Ok(())
    }

    /// Remove iptables mangle rules for a specific subnet from SNX_ROUTES chain.
    async fn remove_mark_for_subnet(&self, subnet: Ipv4Net) {
        let mark = self.fwmark_hex();
        let subnet_str = subnet.to_string();

        // Remove MARK rule (loop to handle any duplicates)
        let mut removed = 0;
        while mark_rule_exists(&subnet_str, &mark).await && removed < 10 {
            let _ = crate::util::run_command(
                "iptables",
                [
                    "-t",
                    "mangle",
                    "-D",
                    SNX_CHAIN,
                    "-d",
                    &subnet_str,
                    "-j",
                    "MARK",
                    "--set-mark",
                    &mark,
                ],
            )
            .await;
            removed += 1;
        }

        // Remove RETURN rule (loop to handle any duplicates)
        let mut return_removed = 0;
        while return_rule_exists(&subnet_str, &mark).await && return_removed < 10 {
            let _ = crate::util::run_command(
                "iptables",
                [
                    "-t",
                    "mangle",
                    "-D",
                    SNX_CHAIN,
                    "-d",
                    &subnet_str,
                    "-m",
                    "mark",
                    "--mark",
                    &mark,
                    "-j",
                    "RETURN",
                ],
            )
            .await;
            return_removed += 1;
        }

        if removed > 0 || return_removed > 0 {
            debug!(
                "Removed iptables rules from {}: -d {} --set-mark {} ({} MARK, {} RETURN)",
                SNX_CHAIN, subnet_str, mark, removed, return_removed
            );
        }
    }

    /// Setup the ip rule for fwmark -> table lookup
    async fn setup_fwmark_rule(&self) -> anyhow::Result<()> {
        let mark = self.fwmark_hex();

        debug!("Adding ip rule: fwmark {} lookup {}", mark, self.table_id);
        crate::util::run_command("ip", ["rule", "add", "fwmark", &mark, "lookup", &self.table_id_str()]).await?;

        Ok(())
    }

    /// Remove the ip rule for fwmark -> table lookup
    async fn cleanup_fwmark_rule(&self) {
        let mark = self.fwmark_hex();

        debug!("Removing ip rule: fwmark {} lookup {}", mark, self.table_id);
        let _ = crate::util::run_command("ip", ["rule", "del", "fwmark", &mark, "lookup", &self.table_id_str()]).await;
    }

    /// Cleanup all iptables rules for this VPN's fwmark.
    /// Uses dynamic discovery by parsing iptables output to find rules with our fwmark,
    /// rather than relying on in-memory state (which is lost when configurator is dropped).
    async fn cleanup_all_subnet_marks(&self) {
        let mark = self.fwmark_hex();

        // Dynamically discover all subnets that have rules for our fwmark
        let subnets = find_subnets_for_mark(&mark).await;

        if subnets.is_empty() {
            debug!("No iptables rules found for mark {} in {}", mark, SNX_CHAIN);
        } else {
            debug!(
                "Cleaning up {} iptables rule(s) for mark {} in {}",
                subnets.len(),
                mark,
                SNX_CHAIN
            );
        }

        for subnet in subnets {
            self.remove_mark_for_subnet(subnet).await;
        }

        // Try to cleanup empty chain
        maybe_cleanup_empty_chain().await;
    }

    /// Add iptables mark rule for a subnet.
    /// If a more specific rule from another VPN exists, skips adding (traffic will use the more specific route).
    /// If our rule is more specific, removes the less specific rules from other VPNs.
    async fn add_mark_for_subnet(&self, subnet: Ipv4Net) -> anyhow::Result<()> {
        let mark = self.fwmark_hex();
        let subnet_str = subnet.to_string();
        let prefix_len = subnet.prefix_len();

        // Ensure shared chain exists
        ensure_snx_chain_exists().await;

        // Skip if rule already exists
        if mark_rule_exists(&subnet_str, &mark).await {
            debug!(
                "iptables rule already exists in {}: -d {} --set-mark {}",
                SNX_CHAIN, subnet_str, mark
            );
            return Ok(());
        }

        // Check for exact duplicate subnet from another VPN
        if check_exact_duplicate_rule(subnet, &mark).await {
            // Exact same subnet exists from another VPN - skip adding duplicate
            return Ok(());
        }

        // Find correct position based on prefix specificity
        let position = find_insert_position(prefix_len).await;

        debug!(
            "Adding iptables rule to {} at position {}: -d {} -j MARK --set-mark {}",
            SNX_CHAIN, position, subnet_str, mark
        );

        // Insert MARK rule at calculated position
        let mark_result = crate::util::run_command(
            "iptables",
            [
                "-t",
                "mangle",
                "-I",
                SNX_CHAIN,
                &position.to_string(),
                "-d",
                &subnet_str,
                "-j",
                "MARK",
                "--set-mark",
                &mark,
            ],
        )
        .await;

        if let Err(e) = &mark_result {
            warn!("Failed to add MARK rule for {} in {}: {}", subnet_str, SNX_CHAIN, e);
        }

        // Insert RETURN rule immediately after MARK (position + 1)
        let return_result = crate::util::run_command(
            "iptables",
            [
                "-t",
                "mangle",
                "-I",
                SNX_CHAIN,
                &(position + 1).to_string(),
                "-d",
                &subnet_str,
                "-m",
                "mark",
                "--mark",
                &mark,
                "-j",
                "RETURN",
            ],
        )
        .await;

        if let Err(e) = &return_result {
            warn!("Failed to add RETURN rule for {} in {}: {}", subnet_str, SNX_CHAIN, e);
        }

        Ok(())
    }
}

#[async_trait]
impl RoutingConfigurator for LinuxRoutingConfigurator {
    async fn add_routes(&self, routes: &[Ipv4Net], ignore_routes: &[Ipv4Net]) -> anyhow::Result<()> {
        let routes: HashSet<_> = routes.iter().collect();
        debug!("Routes to add: {:?}", routes);

        // First, setup the fwmark -> table rule
        if let Err(e) = self.setup_fwmark_rule().await {
            warn!("Failed to setup fwmark rule: {}", e);
        }

        // Add routes to VPN-specific table and iptables mark rules
        for route in &routes {
            if ignore_routes.iter().any(|ignore| ignore == *route) {
                debug!("Ignoring route: {}", route);
                continue;
            }

            // Add route to VPN-specific table (NOT to main!)
            let _ = self.add_route_to_table(**route).await;

            // Add iptables rule to mark packets destined to this subnet
            // If there's a conflict with a more specific rule from another VPN,
            // the rule is skipped. Use "Additional routes" with /32 to override.
            if self.add_mark_for_subnet(**route).await.is_err() {
                warn!("Failed to add mark for subnet {}", route);
            }
        }

        // Also add source-based rule as fallback for response packets
        let src_ip = self.address.to_string();
        debug!("Adding policy rule: from {} lookup {}", src_ip, self.table_id);
        let _ = crate::util::run_command("ip", ["rule", "add", "from", &src_ip, "lookup", &self.table_id_str()]).await;

        Ok(())
    }

    async fn remove_routes(&self) -> anyhow::Result<()> {
        // Cleanup all iptables rules for subnets
        self.cleanup_all_subnet_marks().await;

        // Cleanup fwmark rule
        self.cleanup_fwmark_rule().await;

        // Remove source-based policy rule
        let src_ip = self.address.to_string();
        debug!("Removing policy rule: from {} lookup {}", src_ip, self.table_id);
        let _ = crate::util::run_command("ip", ["rule", "del", "from", &src_ip, "lookup", &self.table_id_str()]).await;

        // Flush all routes from the VPN-specific table
        debug!("Flushing routing table {}", self.table_id);
        let _ = crate::util::run_command("ip", ["route", "flush", "table", &self.table_id_str()]).await;

        Ok(())
    }

    async fn setup_default_route(&self, destination: Ipv4Addr, disable_ipv6: bool) -> anyhow::Result<()> {
        debug!(
            "Setting up default route through {}, disable IPv6: {disable_ipv6}, table: {}",
            self.device, self.table_id
        );

        let dst = destination.to_string();

        crate::util::run_command(
            "ip",
            [
                "route",
                "add",
                "table",
                &self.table_id_str(),
                "default",
                "dev",
                &self.device,
            ],
        )
        .await?;
        crate::util::run_command("ip", ["rule", "add", "not", "to", &dst, "table", &self.table_id_str()]).await?;

        if disable_ipv6 {
            super::sysctl("net.ipv6.conf.all.disable_ipv6", "1")?;
            super::sysctl("net.ipv6.conf.default.disable_ipv6", "1")?;
        }

        Ok(())
    }

    async fn setup_keepalive_route(&self, destination: Ipv4Addr, with_table: bool) -> anyhow::Result<()> {
        debug!(
            "Setting up keepalive route through {}, table: {}",
            self.device, self.table_id
        );

        let port = crate::model::params::TunnelParams::IPSEC_KEEPALIVE_PORT.to_string();
        let dst = destination.to_string();

        if with_table {
            crate::util::run_command(
                "ip",
                ["route", "add", "table", &self.table_id_str(), &dst, "dev", &self.device],
            )
            .await?;
        }

        crate::util::run_command(
            "ip",
            [
                "rule",
                "add",
                "to",
                &dst,
                "ipproto",
                "udp",
                "dport",
                &port,
                "table",
                &self.table_id_str(),
            ],
        )
        .await?;

        Ok(())
    }

    async fn remove_default_route(&self, destination: Ipv4Addr, enable_ipv6: bool) -> anyhow::Result<()> {
        let dst = destination.to_string();

        crate::util::run_command("ip", ["rule", "del", "not", "to", &dst, "table", &self.table_id_str()]).await?;

        if enable_ipv6 {
            super::sysctl("net.ipv6.conf.all.disable_ipv6", "0")?;
            super::sysctl("net.ipv6.conf.default.disable_ipv6", "0")?;
        }

        Ok(())
    }

    async fn remove_keepalive_route(&self, destination: Ipv4Addr) -> anyhow::Result<()> {
        let port = crate::model::params::TunnelParams::IPSEC_KEEPALIVE_PORT.to_string();
        let dst = destination.to_string();

        crate::util::run_command(
            "ip",
            [
                "rule",
                "del",
                "to",
                &dst,
                "ipproto",
                "udp",
                "dport",
                &port,
                "table",
                &self.table_id_str(),
            ],
        )
        .await?;

        Ok(())
    }
}
