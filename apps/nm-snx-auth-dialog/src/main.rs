use anyhow::Result;
use getopt::Opt;
use libadwaita::Application;
use libadwaita::prelude::*;
use std::env;
use std::process;

mod ui;

// Mocking constants
const NM_SETTING_SECRET_FLAG_NOT_SAVED: u32 = 0x1;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut opts = getopt::Parser::new(&args, "u:n:s:r");

    let mut uuid = String::new();
    let mut name = String::new();
    let mut _service_name = String::new();
    let mut _retry = false;

    loop {
        match opts.next() {
            Some(Ok(Opt('u', Some(arg)))) => uuid = arg,
            Some(Ok(Opt('n', Some(arg)))) => name = arg,
            Some(Ok(Opt('s', Some(arg)))) => _service_name = arg,
            Some(Ok(Opt('r', _))) => _retry = true,
            Some(Ok(Opt(_, _))) => {}
            Some(Err(_)) => {}
            None => break,
        }
    }

    // Fallback for long options if getopt doesn't handle them
    for i in 0..args.len() {
        if args[i] == "--uuid" && i + 1 < args.len() {
            uuid = args[i + 1].clone();
        }
        if args[i] == "--name" && i + 1 < args.len() {
            name = args[i + 1].clone();
        }
        if args[i] == "--service" && i + 1 < args.len() {
            _service_name = args[i + 1].clone();
        }
    }

    if uuid.is_empty() {
        eprintln!("UUID not provided. Usage: nm-snx-auth-dialog --uuid <UUID> --name <NAME> --service <SERVICE>");
    }

    // Try to read existing config from snx-rs.conf manually to be robust against encoding issues
    let mut prefilled_username = None;
    let mut prefilled_password = None;

    // Helper to expand ~ to home directory
    let expand_tilde = |path: &str| -> Option<String> {
        if path.starts_with("~/") {
            if let Ok(home) = env::var("HOME") {
                return Some(path.replacen("~", &home, 1));
            }
        }
        Some(path.to_string())
    };

    // Try default location
    let config_path = expand_tilde("~/.config/snx-rs/snx-rs.conf");

    if let Some(path) = config_path {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim().to_string();
                    match key {
                        "username" | "user-name" => prefilled_username = Some(value),
                        "password" => {
                            // Try to decode if it looks like base64, otherwise keep as is
                            // Since snxcore enforces base64, the file *should* be base64.
                            // But if user edited it manually, it might be plain text.
                            // We'll try to decode, if fail, use raw.
                            use base64::Engine;
                            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&value) {
                                if let Ok(string) = String::from_utf8(decoded) {
                                    prefilled_password = Some(string);
                                } else {
                                    prefilled_password = Some(value);
                                }
                            } else {
                                prefilled_password = Some(value);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Initialize libadwaita application
    let app = Application::builder()
        .application_id("org.freedesktop.NetworkManager.snx.AuthDialog")
        .build();

    let name_clone = name.clone();

    app.connect_activate(move |app| {
        let dialog = ui::AuthDialog::new(app, &name_clone, prefilled_username.clone(), prefilled_password.clone());

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

        dialog.connect_button.connect_clicked(move |_| {
            let username = username_entry.text();
            let password = password_entry.text();
            let mfa_token = mfa_entry.text();

            println!("username");
            println!("{}", username);
            println!("password");
            println!("{}", password);

            if !mfa_token.is_empty() {
                println!("mfa_token");
                println!("{}", mfa_token);
                // Informa ao NM para não salvar o token MFA
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
