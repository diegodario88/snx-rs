use anyhow::Result;
use getopt::Opt;
use libadwaita::Application;
use libadwaita::prelude::*;
use secret_service::{EncryptionType, SecretService};
use std::collections::HashMap;
use std::env;
use std::process;

mod ui;

// NetworkManager secret flags
const NM_SETTING_SECRET_FLAG_NOT_SAVED: u32 = 0x1;

/// Check if password exists in GNOME keychain for the given username
async fn get_password_from_keychain(username: &str) -> Result<String> {
    let props = HashMap::from([("snx-rs.username", username)]);

    let ss = SecretService::connect(EncryptionType::Dh).await?;
    let collection = ss.get_default_collection().await?;
    
    if let Ok(true) = collection.is_locked().await {
        let _ = collection.unlock().await;
    }

    let search_items = ss.search_items(props).await?;
    let item = search_items.unlocked.first().ok_or_else(|| anyhow::anyhow!("No password in keychain"))?;
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
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) {
                    if let Ok(string) = String::from_utf8(decoded) {
                        return Some(string);
                    }
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

/// Output secrets to stdout in NetworkManager format and exit
fn output_secrets_and_exit(username: &str, password: &str, mfa_token: Option<&str>) -> ! {
    println!("username");
    println!("{}", username);
    println!("password");
    println!("{}", password);

    if let Some(token) = mfa_token {
        if !token.is_empty() {
            println!("mfa_token");
            println!("{}", token);
            println!("mfa_token-flags");
            println!("{}", NM_SETTING_SECRET_FLAG_NOT_SAVED);
        }
    }

    process::exit(0);
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut opts = getopt::Parser::new(&args, "u:n:s:rh:");

    let mut uuid = String::new();
    let mut name = String::new();
    let mut _service_name = String::new();
    let mut reprompt = false;
    let mut hints: Vec<String> = Vec::new();

    loop {
        match opts.next() {
            Some(Ok(Opt('u', Some(arg)))) => uuid = arg,
            Some(Ok(Opt('n', Some(arg)))) => name = arg,
            Some(Ok(Opt('s', Some(arg)))) => _service_name = arg,
            Some(Ok(Opt('r', _))) => reprompt = true,
            Some(Ok(Opt('h', Some(arg)))) => hints.push(arg),
            Some(Ok(Opt(_, _))) => {}
            Some(Err(_)) => {}
            None => break,
        }
    }

    // Fallback for long options
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--uuid" if i + 1 < args.len() => {
                uuid = args[i + 1].clone();
                i += 1;
            }
            "--name" if i + 1 < args.len() => {
                name = args[i + 1].clone();
                i += 1;
            }
            "--service" if i + 1 < args.len() => {
                _service_name = args[i + 1].clone();
                i += 1;
            }
            "--reprompt" => reprompt = true,
            "--hint" if i + 1 < args.len() => {
                hints.push(args[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    if uuid.is_empty() {
        eprintln!("UUID not provided. Usage: nm-snx-auth-dialog --uuid <UUID> --name <NAME> --service <SERVICE>");
    }

    eprintln!("[auth-dialog] Starting with name={}, reprompt={}, hints={:?}", name, reprompt, hints);

    // Check if we're being asked specifically for MFA token
    let mfa_only = hints.iter().any(|h| h == "mfa_token");

    // Read config values
    let config_username = read_username_from_config();
    let config_password = read_password_from_config();
    let keychain_disabled = is_keychain_disabled();

    eprintln!("[auth-dialog] config_username={:?}, config_password={}, keychain_disabled={}", 
              config_username, config_password.is_some(), keychain_disabled);

    // If MFA only mode, we need to show just the OTP field
    if mfa_only {
        eprintln!("[auth-dialog] MFA-only mode requested");
        // We still need username/password from somewhere to pass back
        let username = config_username.clone().unwrap_or_default();
        
        // Try to get password from keychain or config
        let password = if !keychain_disabled {
            if let Some(ref user) = config_username {
                // Try keychain first
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(get_password_from_keychain(user)).ok()
            } else {
                None
            }
        } else {
            None
        }.or(config_password.clone()).unwrap_or_default();

        // Show OTP-only UI
        return run_ui(name, Some(username), Some(password), true, keychain_disabled);
    }

    // Not reprompt and not MFA-only: try to get credentials without UI
    if !reprompt {
        if let Some(ref username) = config_username {
            // Try keychain first (if enabled)
            if !keychain_disabled {
                let rt = tokio::runtime::Runtime::new()?;
                if let Ok(password) = rt.block_on(get_password_from_keychain(username)) {
                    eprintln!("[auth-dialog] Found password in keychain, skipping UI");
                    output_secrets_and_exit(username, &password, None);
                }
            }

            // Try config password
            if let Some(ref password) = config_password {
                eprintln!("[auth-dialog] Found password in config, skipping UI");
                output_secrets_and_exit(username, password, None);
            }
        }
    }

    eprintln!("[auth-dialog] Showing full UI");

    // Show full UI
    run_ui(name, config_username, config_password, false, keychain_disabled)
}

fn run_ui(
    name: String,
    prefilled_username: Option<String>,
    prefilled_password: Option<String>,
    mfa_only: bool,
    keychain_disabled: bool,
) -> Result<()> {
    let app = Application::builder()
        .application_id("org.freedesktop.NetworkManager.snx.AuthDialog")
        .build();

    let name_clone = name.clone();

    app.connect_activate(move |app| {
        let dialog = ui::AuthDialog::new(
            app,
            &name_clone,
            prefilled_username.clone(),
            prefilled_password.clone(),
            mfa_only,
        );

        // Handle Cancel
        let window_clone = dialog.window.clone();
        dialog.cancel_button.connect_clicked(move |_| {
            window_clone.close();
            process::exit(1);
        });

        // Handle Connect
        let username_entry = dialog.username_entry.clone();
        let password_entry = dialog.password_entry.clone();
        let mfa_entry = dialog.mfa_entry.clone();
        let window = dialog.window.clone();
        let keychain_disabled = keychain_disabled;
        let mfa_only = mfa_only;
        let prefilled_password = prefilled_password.clone();

        dialog.connect_button.connect_clicked(move |_| {
            let username = username_entry.text().to_string();
            let password = if mfa_only {
                // In MFA-only mode, use prefilled password
                prefilled_password.clone().unwrap_or_default()
            } else {
                password_entry.text().to_string()
            };
            let mfa_token = mfa_entry.text().to_string();
            // Remove separators (dash/space) before sending to server
            let mfa_token = mfa_token.replace('-', "").replace(' ', "");

            // Save password to keychain if user entered it (not MFA-only mode)
            if !mfa_only && !keychain_disabled && !username.is_empty() && !password.is_empty() {
                // Check if password was manually entered (different from prefilled)
                let should_save = prefilled_password.as_ref().map_or(true, |p| p != &password);
                if should_save {
                    let username_clone = username.clone();
                    let password_clone = password.clone();
                    // Fire and forget - don't block UI
                    std::thread::spawn(move || {
                        if let Ok(rt) = tokio::runtime::Runtime::new() {
                            let _ = rt.block_on(store_password_in_keychain(&username_clone, &password_clone));
                            eprintln!("[auth-dialog] Saved password to keychain");
                        }
                    });
                }
            }

            // Output secrets to stdout
            println!("username");
            println!("{}", username);
            println!("password");
            println!("{}", password);

            if !mfa_token.is_empty() {
                println!("mfa_token");
                println!("{}", mfa_token);
                println!("mfa_token-flags");
                println!("{}", NM_SETTING_SECRET_FLAG_NOT_SAVED);
            }

            window.close();
            process::exit(0);
        });

        dialog.window.present();
    });

    app.run_with_args::<&str>(&[]);

    Ok(())
}
