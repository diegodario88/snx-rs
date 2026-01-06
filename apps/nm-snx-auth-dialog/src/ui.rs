use gtk4::prelude::*;
use gtk4::{Align, InputPurpose, Orientation};
use libadwaita::prelude::*;
use libadwaita::{
    Application, ApplicationWindow, EntryRow, HeaderBar, PasswordEntryRow, PreferencesGroup, PreferencesPage,
    ToolbarView,
};
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
    pub username_entry: EntryRow,
    pub password_entry: PasswordEntryRow,
    pub mfa_entry: EntryRow,
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

        // Main Layout Structure using ToolbarView
        let content = ToolbarView::new();

        // Header Bar (Title + Window Controls)
        let header = HeaderBar::new();
        content.add_top_bar(&header);

        // Content Area with Clamp for better sizing
        let clamp = libadwaita::Clamp::builder()
            .maximum_size(400)
            .tightening_threshold(300)
            .build();

        // Main vertical box - align to start so it doesn't expand
        let vbox = gtk4::Box::new(Orientation::Vertical, 0);
        vbox.set_margin_top(12);
        vbox.set_margin_bottom(12);
        vbox.set_margin_start(12);
        vbox.set_margin_end(12);
        vbox.set_valign(Align::Start);

        // Page & Group for Form Fields
        let page = PreferencesPage::new();

        let (group_title, group_description) = match mode {
            AuthMode::MfaOnly => ("Two-Factor Authentication", "Enter the code from your authenticator."),
            AuthMode::PasswordOnly => ("Credentials", "Enter your VPN password."),
            AuthMode::Full => ("Credentials", "Enter your VPN credentials and OTP code."),
        };

        let group = PreferencesGroup::builder()
            .title(group_title)
            .description(group_description)
            .build();

        // Username Field (EntryRow) - hidden in MFA-only mode
        let username_entry = EntryRow::builder().title("Username").activates_default(true).build();

        if let Some(user) = &username {
            username_entry.set_text(user);
        }

        if mode == AuthMode::MfaOnly {
            username_entry.set_visible(false);
        }

        // Password Field (PasswordEntryRow) - hidden in MFA-only mode
        let password_entry = PasswordEntryRow::builder()
            .title("Password")
            .activates_default(true)
            .build();

        let mut password_filled = false;
        if let Some(pass) = &password
            && !pass.is_empty()
        {
            password_entry.set_text(pass);
            password_filled = true;
        }

        if mode == AuthMode::MfaOnly {
            password_entry.set_visible(false);
        } else if password_filled {
            // In regular mode, hide password field if already filled
            password_entry.set_visible(false);
        }

        // MFA Token Field (EntryRow) - hidden in PasswordOnly mode
        // Note: max_length is not available in libadwaita < 1.6, but the connect_changed
        // handler below enforces the 6-digit limit programmatically
        let mfa_entry = EntryRow::builder()
            .title("MFA Token")
            .activates_default(true)
            .input_purpose(InputPurpose::Number)
            .build();

        // Hide MFA field in PasswordOnly mode
        if mode == AuthMode::PasswordOnly {
            mfa_entry.set_visible(false);
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

        group.add(&username_entry);
        group.add(&password_entry);
        group.add(&mfa_entry);
        page.add(&group);
        vbox.append(&page);

        // Action Buttons
        let hbox_buttons = gtk4::Box::new(Orientation::Horizontal, 12);
        hbox_buttons.set_halign(Align::Center);
        hbox_buttons.set_margin_top(24);
        hbox_buttons.set_margin_bottom(12);

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
        content.set_content(Some(&clamp));

        window.set_content(Some(&content));

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
