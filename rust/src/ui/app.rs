// AppWindow implementation for Slint
// This file contains the Rust code-behind for the Slint UI

use std::rc::Rc;
use std::cell::RefCell;

use crate::rsa::{generate_keypair, RsaKeyPair};
use crate::assembly::asm_available;

// Import the generated Slint types
slint::include_modules!();

// Global state for the application
struct AppState {
    keypair: Option<RsaKeyPair>,
    status_message: String,
    is_processing: bool,
    progress_value: f64,
    current_operation: String,
    asm_available: bool,
}

impl AppState {
    fn new() -> Self {
        Self {
            keypair: None,
            status_message: "Ready".to_string(),
            is_processing: false,
            progress_value: 0.0,
            current_operation: "".to_string(),
            asm_available: asm_available(),
        }
    }
}

pub fn create_app() -> Result<(), slint::PlatformError> {
    let app = AppWindow::new()?;

    // Initialize with app state
    let state = Rc::new(RefCell::new(AppState::new()));

    // Set up callbacks
    let weak_app = app.as_weak();

    // Generate keys callback
    {
        let weak_app = weak_app.clone();
        let state = Rc::clone(&state);

        app.on_generate_keys(move || {
            if let Some(app) = weak_app.upgrade() {
                let mut state = state.borrow_mut();

                if state.is_processing {
                    state.status_message = "Already processing...".to_string();
                    return;
                }

                state.is_processing = true;
                state.status_message = "Generating RSA key pair...".to_string();
                state.progress_value = 0.1;

                // Update UI
                app.set_status_message(state.status_message.clone().into());
                app.set_is_processing(true);

                // Generate keys
                let bit_length = app.get_key_bit_length().parse::<u32>().unwrap_or(2048);

                match generate_keypair(bit_length, 65537) {
                    Ok(keypair) => {
                        state.keypair = Some(keypair.clone());
                        state.progress_value = 1.0;
                        state.status_message = "Key pair generated successfully!".to_string();

                        // Update UI
                        app.set_public_key_n(format!("{}", keypair.public_key.n).into());
                        app.set_public_key_e(format!("{}", keypair.public_key.e).into());
                        app.set_private_key_d("[Stored in memory]".into());
                        app.set_keys_generated(true);
                        app.set_key_bit_length(bit_length.to_string().into());
                    }
                    Err(e) => {
                        state.status_message = format!("Error: {}", e);
                    }
                }

                state.is_processing = false;
                app.set_is_processing(false);
                app.set_progress_value(state.progress_value);
                app.set_status_message(state.status_message.clone().into());
            }
        });
    }

    // Save keys callback
    {
        let weak_app = weak_app.clone();
        let state = Rc::clone(&state);

        app.on_save_keys(move || {
            if let Some(app) = weak_app.upgrade() {
                let _state = state.borrow();

                if let Some(ref keypair) = _state.keypair {
                    app.set_status_message("Keys saved (implementation pending)".into());
                }
            }
        });
    }

    // Encrypt text callback
    {
        let weak_app = weak_app.clone();
        let state = Rc::clone(&state);

        app.on_encrypt_text(move || {
            if let Some(app) = weak_app.upgrade() {
                let input_text: String = app.get_input_text().into();
                let state = state.borrow();

                if let Some(ref keypair) = state.keypair {
                    match keypair.public_key.encrypt(input_text.as_bytes()) {
                        Ok(ciphertext) => {
                            let output = hex::encode(&ciphertext);
                            app.set_output_text(output.into());
                            app.set_status_message("Text encrypted successfully!".into());
                        }
                        Err(e) => {
                            app.set_status_message(format!("Encryption error: {}", e).into());
                        }
                    }
                } else {
                    app.set_status_message("No keys loaded!".into());
                }
            }
        });
    }

    // Decrypt text callback
    {
        let weak_app = weak_app.clone();
        let state = Rc::clone(&state);

        app.on_decrypt_text(move || {
            if let Some(app) = weak_app.upgrade() {
                let input_text: String = app.get_input_text().into();
                let state = state.borrow();

                if let Some(ref keypair) = state.keypair {
                    match hex::decode(&input_text) {
                        Ok(ciphertext) => {
                            match keypair.private_key.decrypt(&ciphertext) {
                                Ok(plaintext) => {
                                    let output = String::from_utf8_lossy(&plaintext);
                                    app.set_output_text(output.into());
                                    app.set_status_message("Text decrypted successfully!".into());
                                }
                                Err(e) => {
                                    app.set_status_message(format!("Decryption error: {}", e).into());
                                }
                            }
                        }
                        Err(e) => {
                            app.set_status_message(format!("Hex decode error: {}", e).into());
                        }
                    }
                } else {
                    app.set_status_message("No keys loaded!".into());
                }
            }
        });
    }

    // Clear text callback
    {
        let weak_app = weak_app.clone();

        app.on_clear_text(move || {
            if let Some(app) = weak_app.upgrade() {
                app.set_input_text("".into());
                app.set_output_text("".into());
                app.set_status_message("Text cleared".into());
            }
        });
    }

    // File operations
    {
        let weak_app = weak_app.clone();

        app.on_select_input_file(move || {
            if let Some(app) = weak_app.upgrade() {
                app.set_input_file_path("C:/path/to/input.txt".into());
            }
        });

        app.on_select_output_file(move || {
            if let Some(app) = weak_app.upgrade() {
                app.set_output_file_path("C:/path/to/output.enc".into());
            }
        });

        app.on_encrypt_file(move || {
            if let Some(app) = weak_app.upgrade() {
                app.set_status_message("File encryption (implementation pending)".into());
            }
        });

        app.on_decrypt_file(move || {
            if let Some(app) = weak_app.upgrade() {
                app.set_status_message("File decryption (implementation pending)".into());
            }
        });
    }

    // Key management callbacks
    {
        let weak_app = weak_app.clone();
        let state = Rc::clone(&state);

        app.on_load_keys(move || {
            if let Some(app) = weak_app.upgrade() {
                app.set_key_file_path("C:/path/to/keys.json".into());
                app.set_status_message("Key loading (implementation pending)".into());
            }
        });

        app.on_clear_keys(move || {
            if let Some(app) = weak_app.upgrade() {
                state.borrow_mut().keypair = None;
                app.set_keys_generated(false);
                app.set_public_key_n("".into());
                app.set_public_key_e("".into());
                app.set_private_key_d("".into());
                app.set_status_message("Keys cleared".into());
            }
        });
    }

    // Initialize status message
    let asm_status = if state.borrow().asm_available {
        "Enabled"
    } else {
        "Disabled"
    };
    app.set_status_message(format!("Ready - Assembly: {}", asm_status).into());

    app.run()
}