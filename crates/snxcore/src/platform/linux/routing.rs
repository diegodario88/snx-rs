use std::{collections::HashSet, net::Ipv4Addr};

use async_trait::async_trait;
use ipnet::Ipv4Net;
use tracing::{debug, warn};

use crate::platform::RoutingConfigurator;

/// Generate a unique routing table ID and fwmark from device name
/// Uses a simple hash to get a number in range 100-65000
fn generate_table_id(device: &str) -> u32 {
    let hash: u32 = device
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_add(b as u32).wrapping_mul(31));
    100 + (hash % 64900) // Range: 100-65000
}

pub struct LinuxRoutingConfigurator {
    device: String,
    address: Ipv4Addr,
    table_id: u32,
    fwmark: u32,
    /// Subnets that we added iptables rules for (for cleanup)
    added_subnets: std::sync::Mutex<Vec<Ipv4Net>>,
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
            added_subnets: std::sync::Mutex::new(Vec::new()),
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

        debug!(
            "Adding route to table {}: {} dev {}",
            self.table_id, route, self.device
        );
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

    /// Check if an iptables rule already exists
    async fn iptables_rule_exists(&self, chain: &str, subnet_str: &str, mark: &str) -> bool {
        crate::util::run_command(
            "iptables",
            [
                "-t",
                "mangle",
                "-C",
                chain,
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

    /// Add iptables mangle rules to mark packets by DESTINATION subnet
    /// This marks packets going TO specific subnets, not packets going OUT of a specific interface.
    /// We add rules to both OUTPUT (for locally generated packets) and PREROUTING
    /// (for packets from Docker containers, VMs, and other forwarded traffic).
    /// 
    /// Rules are only added if they don't already exist (prevents duplicates on reconnect).
    async fn add_mark_for_subnet(&self, subnet: Ipv4Net) -> anyhow::Result<()> {
        let mark = self.fwmark_hex();
        let subnet_str = subnet.to_string();

        // Add to OUTPUT chain (for locally generated packets from the host)
        // Only add if rule doesn't already exist
        if !self.iptables_rule_exists("OUTPUT", &subnet_str, &mark).await {
            debug!(
                "Adding iptables mangle OUTPUT: -d {} -j MARK --set-mark {}",
                subnet_str, mark
            );
            let _ = crate::util::run_command(
                "iptables",
                [
                    "-t",
                    "mangle",
                    "-I",
                    "OUTPUT",
                    "-d",
                    &subnet_str,
                    "-j",
                    "MARK",
                    "--set-mark",
                    &mark,
                ],
            )
            .await;
        } else {
            debug!(
                "iptables mangle OUTPUT rule already exists: -d {} -j MARK --set-mark {}",
                subnet_str, mark
            );
        }

        // Add to PREROUTING chain (for packets from Docker, VMs, and other networks)
        // Only add if rule doesn't already exist
        if !self.iptables_rule_exists("PREROUTING", &subnet_str, &mark).await {
            debug!(
                "Adding iptables mangle PREROUTING: -d {} -j MARK --set-mark {}",
                subnet_str, mark
            );
            let _ = crate::util::run_command(
                "iptables",
                [
                    "-t",
                    "mangle",
                    "-I",
                    "PREROUTING",
                    "-d",
                    &subnet_str,
                    "-j",
                    "MARK",
                    "--set-mark",
                    &mark,
                ],
            )
            .await;
        } else {
            debug!(
                "iptables mangle PREROUTING rule already exists: -d {} -j MARK --set-mark {}",
                subnet_str, mark
            );
        }

        // Track this subnet for cleanup
        if let Ok(mut subnets) = self.added_subnets.lock() {
            if !subnets.contains(&subnet) {
                subnets.push(subnet);
            }
        }

        Ok(())
    }

    /// Remove iptables mangle rules for a specific subnet (from both OUTPUT and PREROUTING)
    /// Removes ALL matching rules in a loop to handle duplicate rules from previous connections.
    async fn remove_mark_for_subnet(&self, subnet: Ipv4Net) {
        let mark = self.fwmark_hex();
        let subnet_str = subnet.to_string();

        // Remove ALL matching rules from OUTPUT chain (loop until none remain)
        let mut removed_count = 0;
        while self.iptables_rule_exists("OUTPUT", &subnet_str, &mark).await {
            let _ = crate::util::run_command(
                "iptables",
                [
                    "-t",
                    "mangle",
                    "-D",
                    "OUTPUT",
                    "-d",
                    &subnet_str,
                    "-j",
                    "MARK",
                    "--set-mark",
                    &mark,
                ],
            )
            .await;
            removed_count += 1;
            // Safety limit to prevent infinite loop
            if removed_count > 100 {
                warn!(
                    "Too many duplicate iptables OUTPUT rules for {} (removed {}), stopping",
                    subnet_str, removed_count
                );
                break;
            }
        }
        if removed_count > 0 {
            debug!(
                "Removed {} iptables mangle OUTPUT rule(s): -d {} -j MARK --set-mark {}",
                removed_count, subnet_str, mark
            );
        }

        // Remove ALL matching rules from PREROUTING chain (loop until none remain)
        removed_count = 0;
        while self.iptables_rule_exists("PREROUTING", &subnet_str, &mark).await {
            let _ = crate::util::run_command(
                "iptables",
                [
                    "-t",
                    "mangle",
                    "-D",
                    "PREROUTING",
                    "-d",
                    &subnet_str,
                    "-j",
                    "MARK",
                    "--set-mark",
                    &mark,
                ],
            )
            .await;
            removed_count += 1;
            // Safety limit to prevent infinite loop
            if removed_count > 100 {
                warn!(
                    "Too many duplicate iptables PREROUTING rules for {} (removed {}), stopping",
                    subnet_str, removed_count
                );
                break;
            }
        }
        if removed_count > 0 {
            debug!(
                "Removed {} iptables mangle PREROUTING rule(s): -d {} -j MARK --set-mark {}",
                removed_count, subnet_str, mark
            );
        }
    }

    /// Setup the ip rule for fwmark -> table lookup
    async fn setup_fwmark_rule(&self) -> anyhow::Result<()> {
        let mark = self.fwmark_hex();

        debug!("Adding ip rule: fwmark {} lookup {}", mark, self.table_id);
        crate::util::run_command(
            "ip",
            ["rule", "add", "fwmark", &mark, "lookup", &self.table_id_str()],
        )
        .await?;

        Ok(())
    }

    /// Remove the ip rule for fwmark -> table lookup
    async fn cleanup_fwmark_rule(&self) {
        let mark = self.fwmark_hex();

        debug!(
            "Removing ip rule: fwmark {} lookup {}",
            mark, self.table_id
        );
        let _ = crate::util::run_command(
            "ip",
            ["rule", "del", "fwmark", &mark, "lookup", &self.table_id_str()],
        )
        .await;
    }

    /// Cleanup all iptables rules we added
    async fn cleanup_all_subnet_marks(&self) {
        let subnets: Vec<Ipv4Net> = {
            if let Ok(mut guard) = self.added_subnets.lock() {
                std::mem::take(&mut *guard)
            } else {
                Vec::new()
            }
        };

        for subnet in subnets {
            self.remove_mark_for_subnet(subnet).await;
        }
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
            if let Err(e) = self.add_mark_for_subnet(**route).await {
                warn!("Failed to add mark for subnet {}: {}", route, e);
            }
        }

        // Also add source-based rule as fallback for response packets
        let src_ip = self.address.to_string();
        debug!(
            "Adding policy rule: from {} lookup {}",
            src_ip, self.table_id
        );
        let _ = crate::util::run_command(
            "ip",
            ["rule", "add", "from", &src_ip, "lookup", &self.table_id_str()],
        )
        .await;

        Ok(())
    }

    async fn remove_routes(&self) -> anyhow::Result<()> {
        // Cleanup all iptables rules for subnets
        self.cleanup_all_subnet_marks().await;

        // Cleanup fwmark rule
        self.cleanup_fwmark_rule().await;

        // Remove source-based policy rule
        let src_ip = self.address.to_string();
        debug!(
            "Removing policy rule: from {} lookup {}",
            src_ip, self.table_id
        );
        let _ = crate::util::run_command(
            "ip",
            ["rule", "del", "from", &src_ip, "lookup", &self.table_id_str()],
        )
        .await;

        // Flush all routes from the VPN-specific table
        debug!("Flushing routing table {}", self.table_id);
        let _ = crate::util::run_command(
            "ip",
            ["route", "flush", "table", &self.table_id_str()],
        )
        .await;

        Ok(())
    }

    async fn setup_default_route(
        &self,
        destination: Ipv4Addr,
        disable_ipv6: bool,
    ) -> anyhow::Result<()> {
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
        crate::util::run_command(
            "ip",
            ["rule", "add", "not", "to", &dst, "table", &self.table_id_str()],
        )
        .await?;

        if disable_ipv6 {
            super::sysctl("net.ipv6.conf.all.disable_ipv6", "1")?;
            super::sysctl("net.ipv6.conf.default.disable_ipv6", "1")?;
        }

        Ok(())
    }

    async fn setup_keepalive_route(
        &self,
        destination: Ipv4Addr,
        with_table: bool,
    ) -> anyhow::Result<()> {
        debug!(
            "Setting up keepalive route through {}, table: {}",
            self.device, self.table_id
        );

        let port = crate::model::params::TunnelParams::IPSEC_KEEPALIVE_PORT.to_string();
        let dst = destination.to_string();

        if with_table {
            crate::util::run_command(
                "ip",
                [
                    "route",
                    "add",
                    "table",
                    &self.table_id_str(),
                    &dst,
                    "dev",
                    &self.device,
                ],
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

    async fn remove_default_route(
        &self,
        destination: Ipv4Addr,
        enable_ipv6: bool,
    ) -> anyhow::Result<()> {
        let dst = destination.to_string();

        crate::util::run_command(
            "ip",
            ["rule", "del", "not", "to", &dst, "table", &self.table_id_str()],
        )
        .await?;

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
