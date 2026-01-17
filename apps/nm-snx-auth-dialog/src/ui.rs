use gtk4::prelude::*;
use gtk4::{Align, Entry, InputPurpose, Label, Orientation};
use libadwaita::prelude::*;
use libadwaita::{Application, ApplicationWindow, HeaderBar};
use std::rc::Rc;

/// MFA-only dialog - shows just the OTP field
pub struct MfaDialog {
    pub window: ApplicationWindow,
    pub mfa_entry: Entry,
    pub cancel_button: gtk4::Button,
    pub connect_button: gtk4::Button,
}

impl MfaDialog {
    pub fn new(app: &Application, connection_name: &str, prompt: &str) -> Rc<Self> {
        let title_text = if connection_name.is_empty() {
            "VPN - Enter OTP".to_string()
        } else {
            format!("VPN - Enter OTP - {}", connection_name)
        };

        // Main Window with Adwaita
        let window = ApplicationWindow::builder()
            .application(app)
            .title(&title_text)
            .default_width(350)
            .modal(true)
            .resizable(false)
            .build();

        // Main Layout
        let main_box = gtk4::Box::new(Orientation::Vertical, 0);

        // Header Bar
        let header = HeaderBar::new();
        main_box.append(&header);

        // Content Area with Clamp
        let clamp = libadwaita::Clamp::builder()
            .maximum_size(350)
            .tightening_threshold(300)
            .build();

        // Main vertical box
        let vbox = gtk4::Box::new(Orientation::Vertical, 12);
        vbox.set_margin_top(24);
        vbox.set_margin_bottom(24);
        vbox.set_margin_start(24);
        vbox.set_margin_end(24);
        vbox.set_valign(Align::Start);

        // Title
        let title_label = Label::new(Some("Two-Factor Authentication"));
        title_label.add_css_class("title-2");
        title_label.set_halign(Align::Start);
        vbox.append(&title_label);

        // Prompt/description from server
        let desc_label = Label::new(Some(prompt));
        desc_label.add_css_class("dim-label");
        desc_label.set_halign(Align::Start);
        desc_label.set_wrap(true);
        desc_label.set_margin_bottom(12);
        vbox.append(&desc_label);

        // MFA Token Field
        let mfa_box = gtk4::Box::new(Orientation::Vertical, 4);
        let mfa_label = Label::new(Some("OTP Code"));
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

        vbox.append(&mfa_box);

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

        // Set default widget to Connect button
        window.set_default_widget(Some(&connect_button));

        // Focus on OTP field
        mfa_entry.grab_focus();

        clamp.set_child(Some(&vbox));
        main_box.append(&clamp);

        window.set_content(Some(&main_box));

        Rc::new(Self {
            window,
            mfa_entry,
            cancel_button,
            connect_button,
        })
    }
}
