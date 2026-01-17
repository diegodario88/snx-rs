use anyhow::Result;
use libadwaita::Application;
use libadwaita::prelude::*;
use std::env;
use std::io::{self, BufRead, Write};
use std::process;
use std::time::Duration;

#[cfg(debug_assertions)]
use std::fs::OpenOptions;

mod ui;

use std::collections::HashMap;

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

/// No-op in release builds
#[cfg(not(debug_assertions))]
macro_rules! log_debug {
    ($($arg:tt)*) => {{}};
}

/// VPN data read from stdin (connection settings from NetworkManager)
#[derive(Default, Debug)]
struct VpnData {
    data: HashMap<String, String>,
    secrets: HashMap<String, String>,
}

/// Read VPN data and secrets from stdin in NetworkManager format.
/// The format from NetworkManager is:
///   DATA_KEY=keyname
///   DATA_VAL=value
///   SECRET_KEY=keyname  
///   SECRET_VAL=value
///   DONE
///
/// Uses a background thread with timeout to avoid blocking forever.
fn read_vpn_details_from_stdin() -> VpnData {
    use std::sync::mpsc;
    use std::thread;

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut result = VpnData::default();
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        let mut current_data_key: Option<String> = None;
        let mut current_secret_key: Option<String> = None;

        while let Some(Ok(line)) = lines.next() {
            if line.is_empty() {
                continue;
            }

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

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(data) => {
            log_debug!(
                "[auth-dialog] VPN data keys: {:?}",
                data.data.keys().collect::<Vec<_>>()
            );
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
fn wait_for_quit() {
    use std::sync::mpsc;
    use std::thread;

    log_debug!("[auth-dialog] Waiting for QUIT from stdin...");

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut buffer = String::new();
        loop {
            let mut line = String::new();
            match io::stdin().read_line(&mut line) {
                Ok(0) => {
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

    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(_msg) => log_debug!("[auth-dialog] Received: {}", _msg),
        Err(_) => log_debug!("[auth-dialog] Timeout waiting for QUIT"),
    }
}

/// Output secrets in GKeyFile format for external-ui-mode
fn output_external_ui_mode(need_mfa: bool) {
    log_debug!(
        "[auth-dialog] Outputting external-ui-mode format (need_mfa={})",
        need_mfa
    );

    println!("[VPN Plugin UI]");
    println!("Version=2");
    println!("Description=VPN Authentication");
    println!("Title=VPN Authentication");
    println!();

    if need_mfa {
        println!("[mfa_token]");
        println!("Value=");
        println!("Label=OTP Code");
        println!("IsSecret=true");
        println!("ShouldAsk=true");
        println!();
    } else {
        println!("[nosecret]");
        println!("Value=true");
        println!("Label=");
        println!("IsSecret=false");
        println!("ShouldAsk=false");
        println!();
    }

    let _ = io::stdout().flush();
}

/// Output secrets in standard mode format
/// Re-sends password (from NM) plus any new MFA token
fn output_secrets(password: Option<&str>, mfa_token: Option<&str>) {
    log_debug!(
        "[auth-dialog] Outputting secrets: password={}, mfa={}",
        password.is_some(),
        mfa_token.is_some()
    );

    if let Some(pw) = password {
        println!("password");
        println!("{}", pw);
    }

    if let Some(mfa) = mfa_token {
        println!("mfa_token");
        println!("{}", mfa);
    }

    // Empty lines to signal end of secrets
    println!();
    println!();

    let _ = io::stdout().flush();
}

/// Output no secrets required marker
fn output_no_secrets_required() {
    log_debug!("[auth-dialog] No secrets required");
    println!("no-secret");
    println!("true");
    println!();
    println!();
    let _ = io::stdout().flush();
}

#[allow(unused_variables, unused_assignments)]
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    log_debug!("[auth-dialog] ========================================");
    log_debug!("[auth-dialog] Called with args: {:?}", args);

    let mut uuid = String::new();
    let mut name = String::new();
    let mut hints: Vec<String> = Vec::new();
    let mut external_ui_mode = false;
    let mut vpn_message: Option<String> = None;

    // Parse arguments
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
                i += 2;
            }
            "-r" | "--reprompt" => {
                i += 1;
            }
            "-i" | "--allow-interaction" => {
                i += 1;
            }
            "-t" | "--hint" if i + 1 < args.len() => {
                let hint = args[i + 1].clone();
                if hint.starts_with("x-vpn-message:") {
                    vpn_message = Some(hint.strip_prefix("x-vpn-message:").unwrap().to_string());
                } else {
                    hints.push(hint);
                }
                i += 2;
            }
            "-h" if i + 1 < args.len() => {
                hints.push(args[i + 1].clone());
                i += 2;
            }
            "--external-ui-mode" => {
                external_ui_mode = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    log_debug!(
        "[auth-dialog] Parsed: uuid={}, name={}, hints={:?}, external_ui_mode={}, vpn_message={:?}",
        uuid,
        name,
        hints,
        external_ui_mode,
        vpn_message
    );

    // Read VPN data from stdin (NetworkManager sends this)
    let vpn_details = read_vpn_details_from_stdin();

    // Get password from stdin secrets (from NetworkManager)
    let password = vpn_details.secrets.get("password").cloned();

    log_debug!("[auth-dialog] password from NM: {}", password.is_some());

    // Check if MFA is requested via hints
    let mfa_requested = hints.iter().any(|h| h == "mfa_token");

    // External UI mode - just output what fields are needed
    if external_ui_mode {
        output_external_ui_mode(mfa_requested);
        return Ok(());
    }

    // Standard mode
    if mfa_requested {
        log_debug!("[auth-dialog] MFA requested - showing OTP UI");

        // Get prompt from vpn_message or use default
        let prompt = vpn_message.unwrap_or_else(|| "Enter the code from your authenticator".to_string());

        // Show MFA UI and get token
        let mfa_token = run_mfa_ui(&name, &prompt)?;

        // Output password (from NM) + MFA token
        output_secrets(password.as_deref(), Some(&mfa_token));
        wait_for_quit();
        return Ok(());
    }

    // No MFA requested - just re-send password if we have it
    if password.is_some() {
        log_debug!("[auth-dialog] No MFA, re-sending password");
        output_secrets(password.as_deref(), None);
        wait_for_quit();
        return Ok(());
    }

    // No secrets available
    log_debug!("[auth-dialog] No secrets available");
    output_no_secrets_required();

    Ok(())
}

/// Show MFA dialog and return the entered token
fn run_mfa_ui(connection_name: &str, prompt: &str) -> Result<String> {
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();

    let name = connection_name.to_string();
    let prompt = prompt.to_string();

    let app = Application::builder()
        .application_id("org.freedesktop.NetworkManager.snx.AuthDialog")
        .build();

    app.connect_activate(move |app| {
        let dialog = ui::MfaDialog::new(app, &name, &prompt);
        let tx = tx.clone();

        // Handle window close (X button)
        dialog.window.connect_close_request(move |_| {
            log_debug!("[auth-dialog] Window closed by user (X button)");
            process::exit(1);
        });

        // Handle Cancel button
        let window_clone = dialog.window.clone();
        dialog.cancel_button.connect_clicked(move |_| {
            log_debug!("[auth-dialog] User cancelled");
            window_clone.close();
        });

        // Handle Connect
        let mfa_entry = dialog.mfa_entry.clone();
        let window = dialog.window.clone();

        dialog.connect_button.connect_clicked(move |_| {
            let mfa_token = mfa_entry.text().to_string();
            // Remove separators (dash/space) before sending
            let mfa_token = mfa_token.replace(['-', ' '], "");

            log_debug!("[auth-dialog] User submitted MFA token");

            let _ = tx.send(mfa_token);
            window.close();
        });

        dialog.window.present();
    });

    app.run_with_args::<&str>(&[]);

    // Get the MFA token from the channel
    let mfa_token = rx.recv().unwrap_or_default();

    if mfa_token.is_empty() {
        log_debug!("[auth-dialog] Empty MFA token, exiting");
        process::exit(1);
    }

    Ok(mfa_token)
}
