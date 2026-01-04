use crate::config::params_from_connection;
use snxcore::model::params::TunnelParams;
use snxcore::model::{SessionState, VpnSession};
use snxcore::platform::{Keychain, Platform, PlatformAccess, set_no_device_config};
use snxcore::tunnel::{TunnelCommand, TunnelConnector, TunnelEvent, new_tunnel_connector};
use std::collections::HashMap;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::Value;
use zbus::{connection, fdo, interface, zvariant};

mod config;

// NetworkManager VPN Service States
const NM_VPN_SERVICE_STATE_INIT: u32 = 1;
const NM_VPN_SERVICE_STATE_STARTING: u32 = 3;
const NM_VPN_SERVICE_STATE_STARTED: u32 = 4;
const NM_VPN_SERVICE_STATE_STOPPED: u32 = 6;

struct VpnHandle {
    command_sender: mpsc::Sender<TunnelCommand>,
    /// Keep the connector alive to prevent its Drop from terminating the tunnel
    #[allow(dead_code)]
    connector: Box<dyn TunnelConnector + Send>,
}

/// Internal state that's NOT part of the D-Bus interface
struct InternalState {
    vpn_handle: Option<VpnHandle>,
    dbus_connection: Option<zbus::Connection>,
    /// Pending authentication when waiting for secrets
    pending_auth: Option<PendingAuth>,
}

struct PendingAuth {
    connector: Box<dyn TunnelConnector + Send>,
    session: Arc<VpnSession>,
    params: TunnelParams,
    /// What secret we're waiting for: "password" or "mfa_token"
    pending_hint: String,
}

/// The D-Bus interface - only contains Arc<Mutex<InternalState>>
struct VpnPlugin {
    inner: Arc<Mutex<InternalState>>,
}

impl VpnPlugin {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InternalState {
                vpn_handle: None,
                dbus_connection: None,
                pending_auth: None,
            })),
        }
    }
}

#[interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl VpnPlugin {
    #[zbus(property)]
    fn state(&self) -> u32 {
        NM_VPN_SERVICE_STATE_INIT
    }

    #[zbus(signal, name = "StateChanged")]
    async fn vpn_state_changed(ctx: &SignalEmitter<'_>, state: u32) -> zbus::Result<()>;

    #[zbus(signal, name = "SecretsRequired")]
    async fn secrets_required(ctx: &SignalEmitter<'_>, message: &str, secrets: Vec<&str>) -> zbus::Result<()>;

    /// Config signal - generic VPN configuration
    #[zbus(signal, name = "Config")]
    async fn config_signal(ctx: &SignalEmitter<'_>, config: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// Ip4Config signal - IPv4 configuration
    #[zbus(signal, name = "Ip4Config")]
    async fn ip4_config_signal(ctx: &SignalEmitter<'_>, config: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    async fn connect(&self, connection: HashMap<String, HashMap<String, zvariant::OwnedValue>>) -> fdo::Result<()> {
        info!("Connect request received");
        self.do_connect(connection, false).await
    }

    async fn connect_interactive(
        &self,
        connection: HashMap<String, HashMap<String, zvariant::OwnedValue>>,
        _details: HashMap<String, zvariant::OwnedValue>,
    ) -> fdo::Result<()> {
        info!("ConnectInteractive request received");
        self.do_connect(connection, true).await
    }

    async fn disconnect(&self) -> fdo::Result<()> {
        info!("Disconnect request received via D-Bus");

        // Log a backtrace-like info to see who's calling
        debug!("Disconnect called - dumping state");

        let mut inner = self.inner.lock().await;

        // Clear pending auth
        if inner.pending_auth.is_some() {
            info!("Clearing pending authentication");
            inner.pending_auth = None;
        }

        // Disconnect tunnel
        if let Some(handle) = inner.vpn_handle.take() {
            info!("Sending termination command to tunnel");
            let _ = handle.command_sender.send(TunnelCommand::Terminate(true)).await;
        } else {
            warn!("Disconnect called but no active VPN session");
        }

        Ok(())
    }

    async fn set_config(&self, _config: HashMap<String, zvariant::OwnedValue>) -> fdo::Result<()> {
        info!("SetConfig request received");
        Ok(())
    }

    async fn need_secrets(
        &self,
        settings: HashMap<String, HashMap<String, zvariant::OwnedValue>>,
    ) -> fdo::Result<String> {
        info!("NeedSecrets request received");

        // Parse params from connection settings
        let params = match params_from_connection(&settings) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to parse params in NeedSecrets: {}", e);
                return Ok("vpn".to_string());
            }
        };

        // Check if we have a username
        if params.user_name.is_empty() {
            info!("NeedSecrets: no username, need secrets");
            return Ok("vpn".to_string());
        }

        // Check if password is already in the settings
        if !params.password.is_empty() {
            info!("NeedSecrets: password found in settings");
            return Ok("".to_string());
        }

        // Try to get password from keychain (if no-keychain=false)
        if !params.no_keychain {
            debug!("NeedSecrets: checking keychain for user '{}'", params.user_name);
            if Platform::get()
                .new_keychain()
                .acquire_password(&params.user_name)
                .await
                .is_ok()
            {
                info!("NeedSecrets: password found in keychain");
                return Ok("".to_string());
            }
            debug!("NeedSecrets: password not found in keychain");
        }

        // Check if mfa_token is already provided (for subsequent auth steps)
        if let Some(vpn) = settings.get("vpn")
            && let Some(secrets) = vpn.get("secrets")
            && let Ok(dict) = secrets.downcast_ref::<zvariant::Dict<'_, '_>>()
        {
            for (k, v) in dict.iter() {
                if let Ok(key) = k.downcast_ref::<zvariant::Str>()
                    && (key.as_str() == "mfa_token" || key.as_str() == "mfa-token")
                    && let Ok(val) = v.downcast_ref::<zvariant::Str>()
                    && !val.as_str().is_empty()
                {
                    info!("NeedSecrets: mfa_token found");
                    return Ok("".to_string());
                }
            }
        }

        info!("NeedSecrets: no credentials found, need secrets");
        Ok("vpn".to_string())
    }

    async fn new_secrets(&self, connection: HashMap<String, HashMap<String, zvariant::OwnedValue>>) -> fdo::Result<()> {
        info!("NewSecrets request received");

        // Take pending auth
        let pending = {
            let mut inner = self.inner.lock().await;
            inner.pending_auth.take()
        };

        let Some(mut pending) = pending else {
            warn!("NewSecrets called but no pending auth");
            return Ok(());
        };

        // Parse new secrets
        let new_params =
            params_from_connection(&connection).map_err(|e| fdo::Error::Failed(format!("Invalid secrets: {}", e)))?;

        info!("Pending hint: {}", pending.pending_hint);

        // Get D-Bus connection for signals
        let conn = {
            let inner = self.inner.lock().await;
            inner.dbus_connection.clone()
        };
        let conn = conn.ok_or_else(|| fdo::Error::Failed("D-Bus connection lost".into()))?;

        // Check what we're waiting for
        if pending.pending_hint == "password" {
            // User provided a new password - restart authentication from scratch
            info!("Restarting authentication with new password");

            // Update params with new password
            let mut updated_params = pending.params.clone();
            updated_params.password = new_params.password.clone();

            // Drop old connector and session, create new connection
            drop(pending);

            // Re-run do_connect with updated connection data
            self.do_connect(connection, true).await
        } else {
            // MFA token - submit the code to the existing session
            let Some(mfa_code) = &new_params.mfa_code else {
                error!("NewSecrets called but no MFA code provided");
                return Err(fdo::Error::Failed("No MFA code in new secrets".into()));
            };

            info!("Submitting new MFA code");

            // Submit the new MFA code
            let new_session = pending
                .connector
                .challenge_code(pending.session.clone(), mfa_code)
                .await
                .map_err(|e| {
                    error!("MFA challenge failed: {}", e);
                    fdo::Error::Failed(format!("MFA failed: {}", e))
                })?;

            let iface_ref = conn
                .object_server()
                .interface::<_, VpnPlugin>("/org/freedesktop/NetworkManager/VPN/Plugin")
                .await
                .map_err(|e| fdo::Error::Failed(format!("Interface error: {}", e)))?;
            let ctx = iface_ref.signal_emitter();

            // Check result - extract prompt before moving session
            let challenge_prompt = match &new_session.state {
                SessionState::PendingChallenge(c) => Some(c.prompt.clone()),
                _ => None,
            };

            match new_session.state.clone() {
                SessionState::Authenticated(_) | SessionState::NoState => {
                    info!("Authenticated after NewSecrets!");
                    self.complete_connection(pending.connector, new_session, conn, pending.params)
                        .await
                }
                SessionState::PendingChallenge(_) => {
                    let prompt = challenge_prompt.unwrap();
                    info!("Still need secrets: {}", prompt);

                    // Store pending auth again (always MFA at this point)
                    {
                        let mut inner = self.inner.lock().await;
                        inner.pending_auth = Some(PendingAuth {
                            connector: pending.connector,
                            session: new_session,
                            params: pending.params,
                            pending_hint: "mfa_token".to_string(),
                        });
                    }

                    // Emit signal again
                    VpnPlugin::secrets_required(ctx, &prompt, vec!["mfa_token"])
                        .await
                        .map_err(|e| fdo::Error::Failed(format!("Signal error: {}", e)))?;

                    Ok(())
                }
            }
        }
    }
}

impl VpnPlugin {
    async fn do_connect(
        &self,
        connection: HashMap<String, HashMap<String, zvariant::OwnedValue>>,
        interactive: bool,
    ) -> fdo::Result<()> {
        // Get D-Bus connection
        let conn = {
            let inner = self.inner.lock().await;
            inner.dbus_connection.clone()
        };
        let conn = conn.ok_or_else(|| fdo::Error::Failed("D-Bus not initialized".into()))?;

        // Check if already connected
        {
            let inner = self.inner.lock().await;
            if inner.vpn_handle.is_some() {
                return Err(fdo::Error::Failed("Already connected".into()));
            }
        }

        // Parse config
        let mut params =
            params_from_connection(&connection).map_err(|e| fdo::Error::Failed(format!("Config error: {}", e)))?;

        // Fetch password from keychain if not provided and no-keychain=false
        if params.password.is_empty() && !params.no_keychain && !params.user_name.is_empty() {
            debug!(
                "Attempting to fetch password from keychain for user '{}'",
                params.user_name
            );
            match Platform::get().new_keychain().acquire_password(&params.user_name).await {
                Ok(password) => {
                    info!("Password retrieved from keychain");
                    params.password = password;
                }
                Err(e) => {
                    debug!("Could not get password from keychain: {}", e);
                }
            }
        }

        debug!(
            "Parsed params: server={}, user={}, password_len={}",
            params.server_name,
            params.user_name,
            params.password.len()
        );

        // Get signal emitter
        let iface_ref = conn
            .object_server()
            .interface::<_, VpnPlugin>("/org/freedesktop/NetworkManager/VPN/Plugin")
            .await
            .map_err(|e| fdo::Error::Failed(format!("Interface error: {}", e)))?;
        let ctx = iface_ref.signal_emitter();

        info!("Emitting StateChanged(STARTING)");
        let _ = VpnPlugin::vpn_state_changed(ctx, NM_VPN_SERVICE_STATE_STARTING).await;

        // Create connector
        let mut connector = new_tunnel_connector(Arc::new(params.clone()))
            .await
            .map_err(|e| fdo::Error::Failed(format!("Connector error: {}", e)))?;

        // Try to restore session if ike_persist is enabled
        let mut session = if params.ike_persist {
            debug!("Attempting to restore IKE session");
            match connector.restore_session().await {
                Ok(session) => {
                    info!("IKE session restored successfully");
                    session
                }
                Err(e) => {
                    debug!("Could not restore IKE session: {}, authenticating normally", e);
                    // Create new connector and authenticate
                    connector = new_tunnel_connector(Arc::new(params.clone()))
                        .await
                        .map_err(|e| fdo::Error::Failed(format!("Connector error: {}", e)))?;
                    connector
                        .authenticate()
                        .await
                        .map_err(|e| fdo::Error::Failed(format!("Auth error: {}", e)))?
                }
            }
        } else {
            // Authenticate normally
            connector
                .authenticate()
                .await
                .map_err(|e| fdo::Error::Failed(format!("Auth error: {}", e)))?
        };

        let mut mfa_code_used = false;
        // Never use MFA code from initial connection - TOTP codes are time-based
        // and any saved code will be stale. Only use codes from NewSecrets.
        let use_mfa_from_params = false;

        loop {
            // Extract challenge prompt before match to avoid borrow issues
            let challenge_prompt = match &session.state {
                SessionState::PendingChallenge(c) => Some(c.prompt.clone()),
                _ => None,
            };

            match session.state.clone() {
                SessionState::Authenticated(_) | SessionState::NoState => {
                    info!("Authenticated!");
                    return self.complete_connection(connector, session, conn, params).await;
                }
                SessionState::PendingChallenge(challenge) => {
                    info!("Challenge: '{}'", challenge.prompt);
                    let prompt_lower = challenge.prompt.to_lowercase();

                    if prompt_lower.contains("password") && !params.password.is_empty() {
                        info!("Auto-submitting password");
                        match connector.challenge_code(session.clone(), &params.password).await {
                            Ok(new_session) => {
                                session = new_session;
                            }
                            Err(e) => {
                                let err_msg = e.to_string();
                                if err_msg.contains("Authentication failed")
                                    || err_msg.contains("authentication failed")
                                {
                                    warn!("Password authentication failed for user '{}'", params.user_name);

                                    if interactive {
                                        // Request new password via UI
                                        info!("Requesting new password via reprompt");
                                        return self
                                            .request_secrets_with_hints(
                                                connector,
                                                session,
                                                params,
                                                ctx,
                                                "Password incorrect. Please enter your password:",
                                                vec!["password"],
                                            )
                                            .await;
                                    }
                                }
                                return Err(fdo::Error::Failed(format!("Password error: {}", e)));
                            }
                        }
                    } else if prompt_lower.contains("password") && params.password.is_empty() {
                        // No password provided - request it
                        if interactive {
                            info!("No password provided, requesting via UI");
                            return self
                                .request_secrets_with_hints(
                                    connector,
                                    session,
                                    params,
                                    ctx,
                                    "Please enter your password:",
                                    vec!["password"],
                                )
                                .await;
                        } else {
                            return Err(fdo::Error::Failed("Password required".into()));
                        }
                    } else if let Some(mfa) = &params.mfa_code {
                        // Only use MFA code if it's not empty AND we're allowed to use it
                        // (use_mfa_from_params is false for initial connection, true after NewSecrets)
                        debug!(
                            "MFA code in params: '{}' (len={}, use_from_params={})",
                            mfa,
                            mfa.len(),
                            use_mfa_from_params
                        );
                        if !mfa.is_empty() && !mfa_code_used && use_mfa_from_params {
                            info!("Submitting MFA code");
                            mfa_code_used = true;
                            session = connector
                                .challenge_code(session.clone(), mfa)
                                .await
                                .map_err(|e| fdo::Error::Failed(format!("MFA error: {}", e)))?;
                        } else if mfa_code_used {
                            // MFA was already used and rejected
                            if interactive {
                                info!("MFA rejected, requesting new secrets");
                                let prompt = challenge_prompt.unwrap();
                                return self.request_secrets(connector, session, params, ctx, &prompt).await;
                            } else {
                                return Err(fdo::Error::Failed("MFA rejected".into()));
                            }
                        } else {
                            // MFA code is empty, stale, or not allowed - need to request fresh one
                            if interactive {
                                info!("MFA required, requesting fresh secrets");
                                let prompt = challenge_prompt.unwrap();
                                return self.request_secrets(connector, session, params, ctx, &prompt).await;
                            } else {
                                return Err(fdo::Error::Failed("MFA required".into()));
                            }
                        }
                    } else {
                        // No MFA code
                        if interactive {
                            info!("MFA required, requesting secrets");
                            let prompt = challenge_prompt.unwrap();
                            return self.request_secrets(connector, session, params, ctx, &prompt).await;
                        } else {
                            return Err(fdo::Error::Failed("MFA required".into()));
                        }
                    }
                }
            }
        }
    }

    async fn request_secrets(
        &self,
        connector: Box<dyn TunnelConnector + Send>,
        session: Arc<VpnSession>,
        params: TunnelParams,
        ctx: &SignalEmitter<'_>,
        prompt: &str,
    ) -> fdo::Result<()> {
        self.request_secrets_with_hints(connector, session, params, ctx, prompt, vec!["mfa_token"])
            .await
    }

    async fn request_secrets_with_hints(
        &self,
        connector: Box<dyn TunnelConnector + Send>,
        session: Arc<VpnSession>,
        params: TunnelParams,
        ctx: &SignalEmitter<'_>,
        prompt: &str,
        hints: Vec<&str>,
    ) -> fdo::Result<()> {
        // Get the primary hint (first one)
        let pending_hint = hints.first().copied().unwrap_or("mfa_token").to_string();

        // Store pending auth
        {
            let mut inner = self.inner.lock().await;
            inner.pending_auth = Some(PendingAuth {
                connector,
                session,
                params,
                pending_hint,
            });
        }

        // Emit SecretsRequired signal
        info!("Emitting SecretsRequired: '{}' with hints: {:?}", prompt, hints);
        VpnPlugin::secrets_required(ctx, prompt, hints)
            .await
            .map_err(|e| fdo::Error::Failed(format!("Signal error: {}", e)))?;

        info!("Returning from ConnectInteractive, waiting for NewSecrets");
        Ok(())
    }

    async fn complete_connection(
        &self,
        mut connector: Box<dyn TunnelConnector + Send>,
        session: Arc<VpnSession>,
        conn: zbus::Connection,
        params: TunnelParams,
    ) -> fdo::Result<()> {
        // Resolve the VPN server address for the external gateway
        let server_name = &params.server_name;
        let gateway_addr: Ipv4Addr = {
            let addr_str = if server_name.contains(':') {
                server_name.clone()
            } else {
                format!("{}:443", server_name)
            };

            addr_str
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| {
                    addrs.find_map(|a| match a.ip() {
                        std::net::IpAddr::V4(v4) => Some(v4),
                        _ => None,
                    })
                })
                .unwrap_or_else(|| {
                    warn!("Could not resolve gateway address from {}, using 0.0.0.0", server_name);
                    Ipv4Addr::UNSPECIFIED
                })
        };

        info!("Resolved VPN gateway: {} -> {}", server_name, gateway_addr);

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (evt_tx, mut evt_rx) = mpsc::channel(32);

        let tunnel = connector
            .create_tunnel(session, cmd_tx.clone())
            .await
            .map_err(|e| fdo::Error::Failed(format!("Tunnel error: {}", e)))?;

        // Spawn tunnel
        tokio::spawn(async move {
            if let Err(e) = tunnel.run(cmd_rx, evt_tx).await {
                error!("Tunnel error: {}", e);
            }
        });

        // Spawn event handler
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            let iface_ref = match conn_clone
                .object_server()
                .interface::<_, VpnPlugin>("/org/freedesktop/NetworkManager/VPN/Plugin")
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    error!("Interface error: {}", e);
                    return;
                }
            };
            let ctx = iface_ref.signal_emitter();

            while let Some(event) = evt_rx.recv().await {
                match event {
                    TunnelEvent::Connected(info) => {
                        info!("Tunnel connected! IP: {}", info.ip_address);

                        // Get IP address - NM expects host byte order (little-endian on x86)
                        let addr_bytes = info.ip_address.addr().octets();
                        let addr_u32 = u32::from_ne_bytes(addr_bytes);
                        let prefix: u32 = info.ip_address.prefix_len() as u32;

                        // External gateway in host byte order
                        let gateway_u32 = u32::from_ne_bytes(gateway_addr.octets());

                        debug!(
                            "IP address: {} -> host order: 0x{:08x}, prefix: {}",
                            info.ip_address.addr(),
                            addr_u32,
                            prefix
                        );
                        debug!(
                            "External gateway: {} -> host order: 0x{:08x}",
                            gateway_addr, gateway_u32
                        );

                        // Build Config signal data
                        let mut config: HashMap<&str, Value<'_>> = HashMap::new();
                        config.insert("tundev", Value::new(info.interface_name.as_str()));
                        config.insert("gateway", Value::new(gateway_u32));
                        config.insert("has-ip4", Value::new(true));
                        config.insert("has-ip6", Value::new(false));

                        info!(
                            "Sending Config signal: tundev={}, gateway={} (0x{:08x})",
                            info.interface_name, gateway_addr, gateway_u32
                        );

                        // Emit Config signal
                        if let Err(e) = VpnPlugin::config_signal(ctx, config).await {
                            error!("Failed to emit Config signal: {}", e);
                        }

                        // Build Ip4Config signal data
                        let mut ip4_config: HashMap<&str, Value<'_>> = HashMap::new();

                        // Address in host byte order
                        ip4_config.insert("address", Value::new(addr_u32));
                        ip4_config.insert("prefix", Value::new(prefix));

                        // Tell NM not to add default route - snxcore handles routing
                        ip4_config.insert("never-default", Value::new(true));

                        // DNS priority - negative value means VPN DNS is preferred for matching domains (split DNS)
                        // This ensures VPN DNS servers are used for the specified search domains
                        ip4_config.insert("dns-priority", Value::new(-100i32));

                        // DNS servers as array of u32 in host byte order
                        let dns_servers: Vec<u32> = info
                            .dns_servers
                            .iter()
                            .map(|ip| u32::from_ne_bytes(ip.octets()))
                            .collect();
                        if !dns_servers.is_empty() {
                            debug!("DNS servers: {:?}", info.dns_servers);
                            ip4_config.insert("dns", Value::Array(dns_servers.into()));
                        }

                        // DNS domains - ensure all have ~ prefix for split DNS (routing domains)
                        // This tells NetworkManager/systemd-resolved to only use VPN DNS for these domains
                        // Note: domains must be declared outside the if block so references remain valid
                        // until ip4_config_signal is called
                        // We filter out "~." which is a wildcard that would route ALL DNS through VPN
                        let domains: Vec<String> = info
                            .search_domains
                            .iter()
                            .map(|s| {
                                let trimmed = s.trim();
                                if trimmed.starts_with('~') {
                                    trimmed.to_string()
                                } else {
                                    format!("~{}", trimmed)
                                }
                            })
                            .filter(|s| s != "~." && s != "~")
                            .collect();
                        if !domains.is_empty() {
                            debug!("DNS domains (with ~ prefix for split DNS): {:?}", domains);
                            let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
                            ip4_config.insert("domains", Value::Array(domain_refs.into()));
                        }

                        debug!(
                            "Sending Ip4Config signal: address=0x{:08x}, prefix={}",
                            addr_u32, prefix
                        );

                        // Emit Ip4Config signal
                        if let Err(e) = VpnPlugin::ip4_config_signal(ctx, ip4_config).await {
                            error!("Failed to emit Ip4Config signal: {}", e);
                        }

                        // Emit StateChanged(STARTED)
                        info!("Emitting StateChanged(STARTED)");
                        let _ = VpnPlugin::vpn_state_changed(ctx, NM_VPN_SERVICE_STATE_STARTED).await;
                    }
                    TunnelEvent::Disconnected => {
                        info!("Tunnel disconnected");
                        let _ = VpnPlugin::vpn_state_changed(ctx, NM_VPN_SERVICE_STATE_STOPPED).await;
                    }
                    _ => {}
                }
            }
            let _ = VpnPlugin::vpn_state_changed(ctx, NM_VPN_SERVICE_STATE_STOPPED).await;
        });

        // Store handle (including connector to keep it alive)
        {
            let mut inner = self.inner.lock().await;
            inner.vpn_handle = Some(VpnHandle {
                command_sender: cmd_tx,
                connector,
            });
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Try to write to file, but also write to stderr for journalctl
    let file_appender = tracing_appender::rolling::never("/var/tmp", "snx-service.log");
    let (_non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Use stderr as primary output so logs appear in journalctl
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .init();

    info!("Starting snx-nm-service");

    // Tell snxcore not to run "nmcli device set <dev> managed no"
    // because NetworkManager needs to manage the VPN interface
    set_no_device_config(true);
    info!("set_no_device_config(true) called");

    let plugin = VpnPlugin::new();
    let inner = plugin.inner.clone();

    let mut args = std::env::args();
    let mut bus_name = "org.freedesktop.NetworkManager.snx".to_string();

    while let Some(arg) = args.next() {
        if arg == "--bus-name"
            && let Some(name) = args.next()
        {
            bus_name = name;
        }
    }

    info!("Requesting bus name: {}", bus_name);

    let conn = connection::Builder::system()?
        .name(bus_name)?
        .serve_at("/org/freedesktop/NetworkManager/VPN/Plugin", plugin)?
        .build()
        .await?;

    info!("Connected to D-Bus");

    // Store D-Bus connection
    {
        let mut guard = inner.lock().await;
        guard.dbus_connection = Some(conn.clone());
    }

    let iface_ref = conn
        .object_server()
        .interface::<_, VpnPlugin>("/org/freedesktop/NetworkManager/VPN/Plugin")
        .await?;
    let ctx = iface_ref.signal_emitter();

    let _ = VpnPlugin::vpn_state_changed(ctx, NM_VPN_SERVICE_STATE_INIT).await;
    info!("Emitted StateChanged(INIT)");

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => info!("SIGTERM"),
        _ = sigint.recv() => info!("SIGINT"),
    }

    Ok(())
}
