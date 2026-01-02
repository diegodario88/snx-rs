use anyhow::Result;
use libadwaita::Application;
use libadwaita::prelude::*;
use secret_service::{EncryptionType, SecretService};
use std::collections::HashMap;
use std::env;
use std::io::{self, BufRead, Write};
use std::process;
use std::time::Duration;

#[cfg(debug_assertions)]
use std::fs::OpenOptions;

mod ui;

use ui::AuthMode;

/// Debug logging macro - only writes to log file in debug builds
#[cfg(debug_assertions)]
macro_rules! log_debug {
    ($($arg:tt)*) => {{
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/nm-snx-auth-dialog.log")
        {
            let _ = writeln!(file, $($arg)*);
        }
    }};
}

// NetworkManager secret flags
const NM_SETTING_SECRET_FLAG_NOT_SAVED: u32 = 0x1;

/// VPN data read from stdin (connection settings)
#[derive(Default, Debug)]
struct VpnData {
    data: HashMap<String, String>,
    secrets: HashMap<String, String>,
}

/// Read VPN data and secrets from stdin in NetworkManager format.
/// The format from NetworkManager is:
///   DATA_KEY=keyname
///   DATA_VAL=value
///   (empty line)
///   SECRET_KEY=keyname  
///   SECRET_VAL=value
///   (empty line)
///   DONE
///
/// Both DATA and SECRET pairs come before a single DONE.
/// Uses a background thread with timeout to avoid blocking forever.
fn read_vpn_details_from_stdin() -> VpnData {
    use std::sync::mpsc;
    use std::thread;

    let (tx, rx) = mpsc::channel();

    // Spawn a thread to read stdin
    thread::spawn(move || {
        let mut result = VpnData::default();
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        let mut current_data_key: Option<String> = None;
        let mut current_secret_key: Option<String> = None;

        while let Some(Ok(line)) = lines.next() {
            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // DONE or QUIT signals end of input
            if line == "DONE" || line == "QUIT" {
                break;
            }

            if let Some((prefix, value)) = line.split_once('=') {
                match prefix {
                    "DATA_KEY" => {
                        current_data_key = Some(value.to_string());
                    }
                    "DATA_VAL" => {
                        if let Some(ref key) = current_data_key {
                            result.data.insert(key.clone(), value.to_string());
                        }
                        current_data_key = None;
                    }
                    "SECRET_KEY" => {
                        current_secret_key = Some(value.to_string());
                    }
                    "SECRET_VAL" => {
                        if let Some(ref key) = current_secret_key {
                            result.secrets.insert(key.clone(), value.to_string());
                        }
                        current_secret_key = None;
                    }
                    _ => {}
                }
            }
        }

        let _ = tx.send(result);
    });

    log_debug!("[auth-dialog] Reading VPN details from stdin (with 5s timeout)...");

    // Wait with timeout
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(data) => {
            log_debug!("[auth-dialog] VPN data: {:?}", data.data);
            log_debug!(
                "[auth-dialog] VPN secrets keys: {:?}",
                data.secrets.keys().collect::<Vec<_>>()
            );
            data
        }
        Err(_) => {
            log_debug!("[auth-dialog] Timeout reading stdin, proceeding with empty data");
            VpnData::default()
        }
    }
}

/// Wait for "QUIT" command from stdin (used in standard mode)
/// NetworkManager sends QUIT when it's done with the secrets.
/// We use a thread to avoid blocking, with a reasonable timeout.
fn wait_for_quit() {
    use std::sync::mpsc;
    use std::thread;

    log_debug!("[auth-dialog] Waiting for QUIT from stdin...");

    let (tx, rx) = mpsc::channel();

    // Spawn a thread to read from stdin
    thread::spawn(move || {
        let mut buffer = String::new();
        loop {
            let mut line = String::new();
            match io::stdin().read_line(&mut line) {
                Ok(0) => {
                    // EOF
                    let _ = tx.send("EOF");
                    break;
                }
                Ok(_) => {
                    buffer.push_str(&line);
                    if buffer.contains("QUIT") {
                        let _ = tx.send("QUIT");
                        break;
                    }
                    if buffer.len() > 100 {
                        buffer.clear();
                    }
                }
                Err(_) => {
                    let _ = tx.send("ERROR");
                    break;
                }
            }
        }
    });

    // Wait for the thread with a timeout
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(_msg) => log_debug!("[auth-dialog] Received: {}", _msg),
        Err(_) => log_debug!("[auth-dialog] Timeout waiting for QUIT"),
    }
}

/// Output secrets in GKeyFile format for external-ui-mode
fn output_external_ui_mode(
    _vpn_name: &str,
    prompt: &str,
    need_password: bool,
    password: &str,
    need_mfa: bool,
    _mfa_token: &str,
) {
    log_debug!(
        "[auth-dialog] Outputting external-ui-mode format (need_password={}, need_mfa={})",
        need_password,
        need_mfa
    );

    // GKeyFile format as used by OpenVPN
    println!("[VPN Plugin UI]");
    println!("Version=2");
    println!("Description={}", prompt);
    println!("Title=VPN Authentication");
    println!();

    // Only include password field if needed
    if need_password {
        println!("[password]");
        println!("Value={}", password);
        println!("Label=Password");
        println!("IsSecret=true");
        println!("ShouldAsk=true");
        println!();
    }

    // Only include MFA field if needed
    if need_mfa {
        println!("[mfa_token]");
        println!("Value=");
        println!("Label=OTP Code");
        println!("IsSecret=true");
        println!("ShouldAsk=true");
        println!();
    }

    // If nothing is needed, output a "no secrets required" marker
    if !need_password && !need_mfa {
        println!("[nosecret]");
        println!("Value=true");
        println!("Label=");
        println!("IsSecret=false");
        println!("ShouldAsk=false");
        println!();
    }

    // Flush stdout
    let _ = io::stdout().flush();
}

/// Output secrets in standard mode format
fn output_standard_mode(username: &str, password: &str, mfa_token: Option<&str>) {
    log_debug!("[auth-dialog] Outputting standard mode format");

    println!("username");
    println!("{}", username);
    println!("password");
    println!("{}", password);

    if let Some(token) = mfa_token
        && !token.is_empty()
    {
        println!("mfa_token");
        println!("{}", token);
        println!("mfa_token-flags");
        println!("{}", NM_SETTING_SECRET_FLAG_NOT_SAVED);
    }

    // Empty lines to signal end of secrets
    println!();
    println!();

    // Flush stdout
    let _ = io::stdout().flush();
}

/// Check if password exists in GNOME keychain for the given username
async fn get_password_from_keychain(username: &str) -> Result<String> {
    let props = HashMap::from([("snx-rs.username", username)]);

    let ss = SecretService::connect(EncryptionType::Dh).await?;
    let collection = ss.get_default_collection().await?;

    if let Ok(true) = collection.is_locked().await {
        let _ = collection.unlock().await;
    }

    let search_items = ss.search_items(props).await?;
    let item = search_items
        .unlocked
        .first()
        .ok_or_else(|| anyhow::anyhow!("No password in keychain"))?;
    let secret = item.get_secret().await?;

    Ok(String::from_utf8_lossy(&secret).into_owned())
}

/// Store password in GNOME keychain
async fn store_password_in_keychain(username: &str, password: &str) -> Result<()> {
    let props = HashMap::from([("snx-rs.username", username)]);

    let ss = SecretService::connect(EncryptionType::Dh).await?;
    let collection = ss.get_default_collection().await?;

    if let Ok(true) = collection.is_locked().await {
        let _ = collection.unlock().await;
    }

    collection
        .create_item(
            &format!("snx-rs - {username}"),
            props,
            password.as_bytes(),
            true,
            "text/plain",
        )
        .await?;

    Ok(())
}

/// Read username from snx-rs config file
fn read_username_from_config() -> Option<String> {
    let home = env::var("HOME").ok()?;
    let config_path = format!("{}/.config/snx-rs/snx-rs.conf", home);
    let content = std::fs::read_to_string(config_path).ok()?;

    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key == "username" || key == "user-name" {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Read password from config (base64 encoded)
fn read_password_from_config() -> Option<String> {
    let home = env::var("HOME").ok()?;
    let config_path = format!("{}/.config/snx-rs/snx-rs.conf", home);
    let content = std::fs::read_to_string(config_path).ok()?;

    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key == "password" && !value.is_empty() {
                // Try to decode base64
                use base64::Engine;
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value)
                    && let Ok(string) = String::from_utf8(decoded)
                {
                    return Some(string);
                }
                // If not base64, use raw value
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Check if no-keychain is set in config
fn is_keychain_disabled() -> bool {
    let home = match env::var("HOME") {
        Ok(h) => h,
        Err(_) => return true, // Default to disabled if can't read
    };
    let config_path = format!("{}/.config/snx-rs/snx-rs.conf", home);
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return true,
    };

    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().to_lowercase();
            if key == "no-keychain" {
                return value == "true" || value == "1" || value == "yes";
            }
        }
    }
    false // Default: keychain is enabled
}

#[allow(unused_variables, unused_assignments)]
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Log all arguments for debugging
    log_debug!("[auth-dialog] ========================================");
    log_debug!("[auth-dialog] Called with args: {:?}", args);

    let mut uuid = String::new();
    let mut name = String::new();
    let mut reprompt = false;
    let mut hints: Vec<String> = Vec::new();
    let mut external_ui_mode = false;
    let mut allow_interaction = false;
    let mut vpn_message: Option<String> = None;

    // Parse arguments manually since NM uses various formats
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--uuid" if i + 1 < args.len() => {
                uuid = args[i + 1].clone();
                i += 2;
            }
            "-n" | "--name" if i + 1 < args.len() => {
                name = args[i + 1].clone();
                i += 2;
            }
            "-s" | "--service" if i + 1 < args.len() => {
                // service_name is provided by NM but we don't use it
                i += 2;
            }
            "-r" | "--reprompt" => {
                reprompt = true;
                i += 1;
            }
            "-i" | "--allow-interaction" => {
                allow_interaction = true;
                i += 1;
            }
            "-t" | "--hint" if i + 1 < args.len() => {
                let hint = args[i + 1].clone();
                // Check for x-vpn-message prefix
                if hint.starts_with("x-vpn-message:") {
                    vpn_message = Some(hint.strip_prefix("x-vpn-message:").unwrap().to_string());
                } else {
                    hints.push(hint);
                }
                i += 2;
            }
            "-h" if i + 1 < args.len() => {
                // Also support -h for hints (legacy)
                hints.push(args[i + 1].clone());
                i += 2;
            }
            "--external-ui-mode" => {
                external_ui_mode = true;
                i += 1;
            }
            _ => {
                // Skip unknown arguments
                i += 1;
            }
        }
    }

    log_debug!(
        "[auth-dialog] Parsed: uuid={}, name={}, reprompt={}, hints={:?}, external_ui_mode={}, allow_interaction={}, vpn_message={:?}",
        uuid,
        name,
        reprompt,
        hints,
        external_ui_mode,
        allow_interaction,
        vpn_message
    );

    // Read VPN data from stdin (NetworkManager sends this)
    let vpn_details = read_vpn_details_from_stdin();

    // Get username/password from stdin data, or fall back to config
    let stdin_username = vpn_details
        .secrets
        .get("username")
        .cloned()
        .or_else(|| vpn_details.data.get("username").cloned());
    let stdin_password = vpn_details.secrets.get("password").cloned();

    log_debug!(
        "[auth-dialog] stdin_username={:?}, stdin_password={}",
        stdin_username,
        stdin_password.is_some()
    );

    // Check if we're being asked specifically for MFA token or password
    let mfa_only = hints.iter().any(|h| h == "mfa_token");
    let password_requested = hints.iter().any(|h| h == "password");

    // Read config values as fallback
    let config_username = read_username_from_config();
    let config_password = read_password_from_config();
    let keychain_disabled = is_keychain_disabled();

    log_debug!(
        "[auth-dialog] config_username={:?}, config_password={}, keychain_disabled={}",
        config_username,
        config_password.is_some(),
        keychain_disabled
    );

    // Determine which username to use (stdin > config)
    let username = stdin_username.or(config_username.clone()).unwrap_or_default();

    // For password, prefer keychain (most up-to-date) > stdin > config
    // BUT if password was explicitly requested (hint), don't use cached passwords
    let mut password: Option<String> = None;

    if password_requested {
        log_debug!("[auth-dialog] Password explicitly requested, ignoring cached passwords");
        // Don't use any cached password - force user to enter it
    } else {
        // Try keychain first (most reliable source)
        if !keychain_disabled && !username.is_empty() {
            let rt = tokio::runtime::Runtime::new()?;
            password = rt.block_on(get_password_from_keychain(&username)).ok();
            if password.is_some() {
                log_debug!("[auth-dialog] Got password from keychain (preferred)");
            }
        }

        // Fall back to stdin password if no keychain
        if password.is_none() {
            password = stdin_password;
            if password.is_some() {
                log_debug!("[auth-dialog] Using password from stdin");
            }
        }

        // Fall back to config password
        if password.is_none() {
            password = config_password.clone();
            if password.is_some() {
                log_debug!("[auth-dialog] Using password from config");
            }
        }
    }

    let prompt = vpn_message
        .clone()
        .unwrap_or_else(|| format!("Authentication required for VPN '{}'", name));

    // In external-ui-mode, we don't show a GUI - we output what fields are needed
    if external_ui_mode {
        log_debug!("[auth-dialog] External UI mode - outputting field requirements");

        let need_password = password.is_none() || reprompt;
        let need_mfa = mfa_only;

        output_external_ui_mode(
            &name,
            &prompt,
            need_password,
            password.as_deref().unwrap_or(""),
            need_mfa,
            "", // No MFA token yet
        );

        return Ok(());
    }

    // Standard mode - show GUI if needed

    // If password was explicitly requested, show password-only UI
    if password_requested {
        log_debug!("[auth-dialog] Password requested - showing password-only UI");
        return run_ui(name, Some(username), None, AuthMode::PasswordOnly, keychain_disabled);
    }

    // If MFA only mode, we need to show just the OTP field
    if mfa_only {
        log_debug!("[auth-dialog] MFA-only mode - showing OTP UI");

        if let Some(ref pwd) = password {
            // Show OTP-only UI
            return run_ui(
                name,
                Some(username),
                Some(pwd.clone()),
                AuthMode::MfaOnly,
                keychain_disabled,
            );
        } else {
            log_debug!("[auth-dialog] MFA mode but no password available - showing full UI");
        }
    }

    // Not reprompt and we have credentials: try to use them without UI
    if !reprompt
        && !username.is_empty()
        && let Some(ref pwd) = password
    {
        log_debug!("[auth-dialog] Have credentials, outputting without UI");
        output_standard_mode(&username, pwd, None);
        wait_for_quit();
        return Ok(());
    }

    log_debug!("[auth-dialog] Showing full UI");

    // Show full UI
    run_ui(name, Some(username), password, AuthMode::Full, keychain_disabled)
}

fn run_ui(
    name: String,
    prefilled_username: Option<String>,
    prefilled_password: Option<String>,
    mode: AuthMode,
    keychain_disabled: bool,
) -> Result<()> {
    let app = Application::builder()
        .application_id("org.freedesktop.NetworkManager.snx.AuthDialog")
        .build();

    app.connect_activate(move |app| {
        let dialog = ui::AuthDialog::new(app, &name, prefilled_username.clone(), prefilled_password.clone(), mode);

        // Handle Cancel
        let window_clone = dialog.window.clone();
        dialog.cancel_button.connect_clicked(move |_| {
            log_debug!("[auth-dialog] User cancelled");
            window_clone.close();
            process::exit(1);
        });

        // Handle Connect
        let username_entry = dialog.username_entry.clone();
        let password_entry = dialog.password_entry.clone();
        let mfa_entry = dialog.mfa_entry.clone();
        let window = dialog.window.clone();
        let keychain_disabled = keychain_disabled;
        let mode = mode;
        let prefilled_password_clone = prefilled_password.clone();

        dialog.connect_button.connect_clicked(move |_| {
            let username = username_entry.text().to_string();
            let password = if mode == AuthMode::MfaOnly {
                // In MFA-only mode, use prefilled password
                prefilled_password_clone.clone().unwrap_or_default()
            } else {
                password_entry.text().to_string()
            };
            let mfa_token = mfa_entry.text().to_string();
            // Remove separators (dash/space) before sending to server
            let mfa_token = mfa_token.replace(['-', ' '], "");

            log_debug!(
                "[auth-dialog] User submitted: username={}, password={}, mfa={}",
                username,
                !password.is_empty(),
                !mfa_token.is_empty()
            );

            // Save password to keychain if user entered it (not MFA-only mode)
            if mode != AuthMode::MfaOnly && !keychain_disabled && !username.is_empty() && !password.is_empty() {
                // Check if password was manually entered (different from prefilled)
                let should_save = prefilled_password_clone.as_ref() != Some(&password);
                if should_save {
                    let username_clone = username.clone();
                    let password_clone = password.clone();
                    // Fire and forget - don't block UI
                    std::thread::spawn(move || {
                        if let Ok(rt) = tokio::runtime::Runtime::new() {
                            let _ = rt.block_on(store_password_in_keychain(&username_clone, &password_clone));
                            log_debug!("[auth-dialog] Saved password to keychain");
                        }
                    });
                }
            }

            // Output secrets in standard mode format
            let mfa_opt = if mfa_token.is_empty() {
                None
            } else {
                Some(mfa_token.as_str())
            };
            output_standard_mode(&username, &password, mfa_opt);

            window.close();

            // Wait for QUIT from NetworkManager before exiting
            wait_for_quit();

            process::exit(0);
        });

        dialog.window.present();
    });

    app.run_with_args::<&str>(&[]);

    Ok(())
}
