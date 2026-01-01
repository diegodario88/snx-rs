use crate::config::params_from_connection;
use snxcore::model::params::TunnelParams;
use snxcore::model::{SessionState, VpnSession};
use snxcore::platform::set_no_device_config;
use snxcore::tunnel::{new_tunnel_connector, TunnelCommand, TunnelConnector, TunnelEvent};
use std::collections::HashMap;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, Mutex};
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
    async fn secrets_required(
        ctx: &SignalEmitter<'_>,
        message: &str,
        secrets: Vec<&str>,
    ) -> zbus::Result<()>;

    /// Config signal - generic VPN configuration
    #[zbus(signal, name = "Config")]
    async fn config_signal(
        ctx: &SignalEmitter<'_>,
        config: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    /// Ip4Config signal - IPv4 configuration
    #[zbus(signal, name = "Ip4Config")]
    async fn ip4_config_signal(
        ctx: &SignalEmitter<'_>,
        config: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    async fn connect(
        &self,
        connection: HashMap<String, HashMap<String, zvariant::OwnedValue>>,
    ) -> fdo::Result<()> {
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

        if let Some(vpn) = settings.get("vpn") {
            if let Some(secrets) = vpn.get("secrets") {
                if let Ok(dict) = secrets.downcast_ref::<zvariant::Dict<'_, '_>>() {
                    for (k, v) in dict.iter() {
                        if let Ok(key) = k.downcast_ref::<zvariant::Str>() {
                            if key.as_str() == "mfa_token" || key.as_str() == "mfa-token" {
                                if let Ok(val) = v.downcast_ref::<zvariant::Str>() {
                                    if !val.as_str().is_empty() {
                                        info!("NeedSecrets: mfa_token found");
                                        return Ok("".to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        info!("NeedSecrets: returning 'vpn'");
        Ok("vpn".to_string())
    }

    async fn new_secrets(
        &self,
        connection: HashMap<String, HashMap<String, zvariant::OwnedValue>>,
    ) -> fdo::Result<()> {
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
        let new_params = params_from_connection(&connection)
            .map_err(|e| fdo::Error::Failed(format!("Invalid secrets: {}", e)))?;

        let Some(mfa_code) = &new_params.mfa_code else {
            error!("NewSecrets called but no MFA code provided");
            return Err(fdo::Error::Failed("No MFA code in new secrets".into()));
        };

        info!("Submitting new MFA code");

        // Submit the new MFA code
        let new_session = pending.connector
            .challenge_code(pending.session.clone(), mfa_code)
            .await
            .map_err(|e| {
                error!("MFA challenge failed: {}", e);
                fdo::Error::Failed(format!("MFA failed: {}", e))
            })?;

        // Get D-Bus connection for signals
        let conn = {
            let inner = self.inner.lock().await;
            inner.dbus_connection.clone()
        };
        let conn = conn.ok_or_else(|| fdo::Error::Failed("D-Bus connection lost".into()))?;

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
                self.complete_connection(pending.connector, new_session, conn, pending.params).await
            }
            SessionState::PendingChallenge(_) => {
                let prompt = challenge_prompt.unwrap();
                info!("Still need secrets: {}", prompt);

                // Store pending auth again
                {
                    let mut inner = self.inner.lock().await;
                    inner.pending_auth = Some(PendingAuth {
                        connector: pending.connector,
                        session: new_session,
                        params: pending.params,
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
        let params = params_from_connection(&connection)
            .map_err(|e| fdo::Error::Failed(format!("Config error: {}", e)))?;

        debug!("Parsed params: {:?}", params);

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

        // Authenticate
        let mut session = connector
            .authenticate()
            .await
            .map_err(|e| fdo::Error::Failed(format!("Auth error: {}", e)))?;

        let mut mfa_code_used = false;

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
                        session = connector
                            .challenge_code(session.clone(), &params.password)
                            .await
                            .map_err(|e| fdo::Error::Failed(format!("Password error: {}", e)))?;
                    } else if let Some(mfa) = &params.mfa_code {
                        if !mfa_code_used {
                            info!("Submitting MFA code");
                            mfa_code_used = true;
                            session = connector
                                .challenge_code(session.clone(), mfa)
                                .await
                                .map_err(|e| fdo::Error::Failed(format!("MFA error: {}", e)))?;
                        } else {
                            // MFA rejected
                            if interactive {
                                info!("MFA rejected, requesting new secrets");
                                let prompt = challenge_prompt.unwrap();
                                return self.request_secrets(connector, session, params, ctx, &prompt).await;
                            } else {
                                return Err(fdo::Error::Failed("MFA rejected".into()));
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
        // Store pending auth
        {
            let mut inner = self.inner.lock().await;
            inner.pending_auth = Some(PendingAuth {
                connector,
                session,
                params,
            });
        }

        // Emit SecretsRequired signal
        info!("Emitting SecretsRequired: '{}'", prompt);
        VpnPlugin::secrets_required(ctx, prompt, vec!["mfa_token"])
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
                .and_then(|mut addrs| addrs.find_map(|a| match a.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                }))
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
                        
                        debug!("IP address: {} -> host order: 0x{:08x}, prefix: {}", 
                               info.ip_address.addr(), addr_u32, prefix);
                        debug!("External gateway: {} -> host order: 0x{:08x}", 
                               gateway_addr, gateway_u32);
                        
                        // Build Config signal data
                        let mut config: HashMap<&str, Value<'_>> = HashMap::new();
                        config.insert("tundev", Value::new(info.interface_name.as_str()));
                        config.insert("gateway", Value::new(gateway_u32));
                        config.insert("has-ip4", Value::new(true));
                        config.insert("has-ip6", Value::new(false));
                        
                        info!("Sending Config signal: tundev={}, gateway={} (0x{:08x})", 
                              info.interface_name, gateway_addr, gateway_u32);
                        
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
                        
                        // DNS servers as array of u32 in host byte order
                        let dns_servers: Vec<u32> = info.dns_servers
                            .iter()
                            .map(|ip| u32::from_ne_bytes(ip.octets()))
                            .collect();
                        if !dns_servers.is_empty() {
                            debug!("DNS servers: {:?}", info.dns_servers);
                            ip4_config.insert("dns", Value::Array(dns_servers.into()));
                        }
                        
                        // DNS domains (use "domains" not "dns-search")
                        if !info.search_domains.is_empty() {
                            debug!("DNS domains: {:?}", info.search_domains);
                            let domains: Vec<&str> = info.search_domains.iter().map(|s| s.as_str()).collect();
                            ip4_config.insert("domains", Value::Array(domains.into()));
                        }
                        
                        debug!("Sending Ip4Config signal: address=0x{:08x}, prefix={}", 
                               addr_u32, prefix);
                        
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
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

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
        if arg == "--bus-name" {
            if let Some(name) = args.next() {
                bus_name = name;
            }
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
