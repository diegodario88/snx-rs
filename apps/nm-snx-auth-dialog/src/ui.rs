use gtk4::prelude::*;
use libadwaita::prelude::*;
use gtk4::{Align, Orientation, InputPurpose};
use libadwaita::{Application, ApplicationWindow, HeaderBar, PreferencesGroup, PreferencesPage, EntryRow, PasswordEntryRow, ToolbarView};
use std::rc::Rc;

pub struct AuthDialog {
    pub window: ApplicationWindow,
    pub username_entry: EntryRow,
    pub password_entry: PasswordEntryRow,
    pub mfa_entry: EntryRow,
    pub cancel_button: gtk4::Button,
    pub connect_button: gtk4::Button,
}

impl AuthDialog {
    pub fn new(app: &Application, connection_name: &str, username: Option<String>, password: Option<String>) -> Rc<Self> {
        let title_text = if connection_name.is_empty() {
            "VPN Authentication".to_string()
        } else {
            format!("VPN Authentication - {}", connection_name)
        };

        // Main Window with Adwaita
        let window = ApplicationWindow::builder()
            .application(app)
            .title(&title_text)
            .default_width(400)
            .default_height(480)
            .modal(true)
            .resizable(false)
            .build();

        // Main Layout Structure using ToolbarView (requires v1_4+)
        let content = ToolbarView::new();

        // Header Bar (Title + Window Controls)
        let header = HeaderBar::new();
        content.add_top_bar(&header);

        // Content Area with Clamp for better sizing
        let clamp = libadwaita::Clamp::builder()
            .maximum_size(400)
            .tightening_threshold(300)
            .build();
            
        let scroll = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .build();
        
        let vbox = gtk4::Box::new(Orientation::Vertical, 0);
        vbox.set_margin_top(12);
        vbox.set_margin_bottom(12);
        vbox.set_margin_start(12);
        vbox.set_margin_end(12);

        // Page & Group for Form Fields
        let page = PreferencesPage::new();
        let group = PreferencesGroup::builder()
            .title("Credentials")
            .description("Enter your VPN login details.")
            .build();

        // Username Field (EntryRow)
        let username_entry = EntryRow::builder()
            .title("Username")
            .activates_default(true)
            .build();
        
        if let Some(user) = &username {
            username_entry.set_text(user);
        }

        // Password Field (PasswordEntryRow)
        let password_entry = PasswordEntryRow::builder()
            .title("Password")
            .activates_default(true)
            .build();

        let mut password_filled = false;
        if let Some(pass) = &password {
            if !pass.is_empty() {
                password_entry.set_text(pass);
                password_filled = true;
                // Hide it if we have a password
                password_entry.set_visible(false);
            }
        }

        // MFA Token Field (EntryRow)
        let mfa_entry = EntryRow::builder()
            .title("MFA Token")
            .activates_default(true)
            .input_purpose(InputPurpose::Number)
            .build();
        
        // Hide fields if they are already provided to reduce clutter?
        // Or keep them visible but disabled/filled? 
        // User asked: "only prompt for the MFA OTP code"
        // Let's keep them visible so user knows what account they are logging into, but maybe not editable if passed?
        // For now, just pre-filling is a good step.

        group.add(&username_entry);
        group.add(&password_entry);
        group.add(&mfa_entry);
        page.add(&group);
        vbox.append(&page);

        // Action Buttons
        let hbox_buttons = gtk4::Box::new(Orientation::Horizontal, 12);
        hbox_buttons.set_halign(Align::Center);
        hbox_buttons.set_margin_top(12);
        hbox_buttons.set_margin_bottom(24);

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
        if username.is_some() && password_filled {
            mfa_entry.grab_focus();
        } else if username.is_some() {
            password_entry.grab_focus();
        } else {
            username_entry.grab_focus();
        }

        scroll.set_child(Some(&vbox));
        clamp.set_child(Some(&scroll));
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
