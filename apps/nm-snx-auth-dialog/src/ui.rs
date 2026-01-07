use gtk4::prelude::*;
use gtk4::{Align, Entry, InputPurpose, Label, Orientation, PasswordEntry};
use libadwaita::prelude::*;
use libadwaita::{Application, ApplicationWindow, HeaderBar};
use std::rc::Rc;

/// UI display mode
#[derive(Clone, Copy, PartialEq)]
pub enum AuthMode {
    /// Show only username and password (no MFA field)
    PasswordOnly,
    /// Show only MFA field (username/password hidden, pre-filled)
    MfaOnly,
    /// Show all fields (username, password, and MFA)
    Full,
}

pub struct AuthDialog {
    pub window: ApplicationWindow,
    pub username_entry: Entry,
    pub password_entry: PasswordEntry,
    pub mfa_entry: Entry,
    pub cancel_button: gtk4::Button,
    pub connect_button: gtk4::Button,
}

impl AuthDialog {
    pub fn new(
        app: &Application,
        connection_name: &str,
        username: Option<String>,
        password: Option<String>,
        mode: AuthMode,
    ) -> Rc<Self> {
        let title_text = match mode {
            AuthMode::MfaOnly => {
                if connection_name.is_empty() {
                    "VPN - Enter OTP".to_string()
                } else {
                    format!("VPN - Enter OTP - {}", connection_name)
                }
            }
            _ => {
                if connection_name.is_empty() {
                    "VPN Authentication".to_string()
                } else {
                    format!("VPN Authentication - {}", connection_name)
                }
            }
        };

        // Main Window with Adwaita - no fixed height, let content determine size
        let window = ApplicationWindow::builder()
            .application(app)
            .title(&title_text)
            .default_width(400)
            .modal(true)
            .resizable(false)
            .build();

        // Main Layout Structure using Box + HeaderBar (compatible with libadwaita 1.1)
        let main_box = gtk4::Box::new(Orientation::Vertical, 0);

        // Header Bar (Title + Window Controls)
        let header = HeaderBar::new();
        main_box.append(&header);

        // Content Area with Clamp for better sizing
        let clamp = libadwaita::Clamp::builder()
            .maximum_size(400)
            .tightening_threshold(300)
            .build();

        // Main vertical box - align to start so it doesn't expand
        let vbox = gtk4::Box::new(Orientation::Vertical, 12);
        vbox.set_margin_top(24);
        vbox.set_margin_bottom(24);
        vbox.set_margin_start(24);
        vbox.set_margin_end(24);
        vbox.set_valign(Align::Start);

        // Title label
        let (title_text, description_text) = match mode {
            AuthMode::MfaOnly => ("Two-Factor Authentication", "Enter the code from your authenticator."),
            AuthMode::PasswordOnly => ("Credentials", "Enter your VPN password."),
            AuthMode::Full => ("Credentials", "Enter your VPN credentials and OTP code."),
        };

        let title_label = Label::new(Some(title_text));
        title_label.add_css_class("title-2");
        title_label.set_halign(Align::Start);
        vbox.append(&title_label);

        let desc_label = Label::new(Some(description_text));
        desc_label.add_css_class("dim-label");
        desc_label.set_halign(Align::Start);
        desc_label.set_margin_bottom(12);
        vbox.append(&desc_label);

        // Form fields container
        let form_box = gtk4::Box::new(Orientation::Vertical, 12);

        // Username Field - hidden in MFA-only mode
        let username_box = gtk4::Box::new(Orientation::Vertical, 4);
        let username_label = Label::new(Some("Username"));
        username_label.set_halign(Align::Start);
        username_label.add_css_class("dim-label");
        let username_entry = Entry::builder()
            .placeholder_text("Username")
            .activates_default(true)
            .build();

        if let Some(user) = &username {
            username_entry.set_text(user);
        }

        username_box.append(&username_label);
        username_box.append(&username_entry);

        if mode == AuthMode::MfaOnly {
            username_box.set_visible(false);
        }

        form_box.append(&username_box);

        // Password Field - hidden in MFA-only mode
        let password_box = gtk4::Box::new(Orientation::Vertical, 4);
        let password_label = Label::new(Some("Password"));
        password_label.set_halign(Align::Start);
        password_label.add_css_class("dim-label");
        let password_entry = PasswordEntry::builder()
            .placeholder_text("Password")
            .activates_default(true)
            .show_peek_icon(true)
            .build();

        let mut password_filled = false;
        if let Some(pass) = &password
            && !pass.is_empty()
        {
            password_entry.set_text(pass);
            password_filled = true;
        }

        password_box.append(&password_label);
        password_box.append(&password_entry);

        if mode == AuthMode::MfaOnly {
            password_box.set_visible(false);
        } else if password_filled {
            // In regular mode, hide password field if already filled
            password_box.set_visible(false);
        }

        form_box.append(&password_box);

        // MFA Token Field - hidden in PasswordOnly mode
        let mfa_box = gtk4::Box::new(Orientation::Vertical, 4);
        let mfa_label = Label::new(Some("MFA Token"));
        mfa_label.set_halign(Align::Start);
        mfa_label.add_css_class("dim-label");
        let mfa_entry = Entry::builder()
            .placeholder_text("123-456")
            .activates_default(true)
            .input_purpose(InputPurpose::Number)
            .max_length(7) // 6 digits + 1 separator
            .build();

        mfa_box.append(&mfa_label);
        mfa_box.append(&mfa_entry);

        // Hide MFA field in PasswordOnly mode
        if mode == AuthMode::PasswordOnly {
            mfa_box.set_visible(false);
        }

        // Auto-format OTP as user types (e.g., 123456 -> 123-456)
        mfa_entry.connect_changed(|entry| {
            let text = entry.text().to_string();

            // Extract only digits
            let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();

            // Limit to 6 digits
            let digits: String = digits.chars().take(6).collect();

            // Format with separator after 3 digits
            let formatted = if digits.len() > 3 {
                format!("{}-{}", &digits[..3], &digits[3..])
            } else {
                digits
            };

            // Avoid infinite loop - only update if different
            if text != formatted {
                entry.set_text(&formatted);
                entry.set_position(formatted.len() as i32);
            }
        });

        form_box.append(&mfa_box);
        vbox.append(&form_box);

        // Action Buttons
        let hbox_buttons = gtk4::Box::new(Orientation::Horizontal, 12);
        hbox_buttons.set_halign(Align::Center);
        hbox_buttons.set_margin_top(24);

        let cancel_button = gtk4::Button::with_label("Cancel");
        cancel_button.set_width_request(100);

        let connect_button = gtk4::Button::with_label("Connect");
        connect_button.add_css_class("suggested-action");
        connect_button.add_css_class("pill");
        connect_button.set_width_request(100);

        hbox_buttons.append(&cancel_button);
        hbox_buttons.append(&connect_button);
        vbox.append(&hbox_buttons);

        // Set default widget to Connect button so "Enter" triggers it
        window.set_default_widget(Some(&connect_button));

        // Logic for initial focus
        match mode {
            AuthMode::MfaOnly => {
                // In MFA-only mode, focus directly on OTP field
                mfa_entry.grab_focus();
            }
            AuthMode::PasswordOnly => {
                // In password-only mode, focus on password if username is filled
                if username.is_some() {
                    password_entry.grab_focus();
                } else {
                    username_entry.grab_focus();
                }
            }
            AuthMode::Full => {
                if username.is_some() && password_filled {
                    mfa_entry.grab_focus();
                } else if username.is_some() {
                    password_entry.grab_focus();
                } else {
                    username_entry.grab_focus();
                }
            }
        }

        clamp.set_child(Some(&vbox));
        main_box.append(&clamp);

        window.set_content(Some(&main_box));

        Rc::new(Self {
            window,
            username_entry,
            password_entry,
            mfa_entry,
            cancel_button,
            connect_button,
        })
    }
}
