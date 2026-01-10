// Prevent console window in addition to Slint window in Windows release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::cell::RefCell;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use openssl::rsa::Rsa;
use rand::RngCore;

slint::include_modules!();

// Constants for file encryption
const RSAF_MAGIC: &[u8; 4] = b"RSAF";
const RSAF_VERSION: u16 = 1;
const MAX_ENCRYPT_PER_BLOCK: usize = 190;
const ENCRYPTED_BLOCK_SIZE: usize = 256;
const FILE_HEADER_SIZE: usize = 32;

struct RSAEngine {
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

impl RSAEngine {
    fn new() -> Self {
        Self {
            private_key: None,
            public_key: None,
        }
    }

    fn generate_keys(&mut self) -> Result<(), Box<dyn Error>> {
        let rsa = Rsa::generate(2048)?;
        self.private_key = Some(rsa.private_key_to_pem()?);
        self.public_key = Some(rsa.public_key_to_pem()?);
        Ok(())
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let pub_pem = self.public_key.as_ref()
            .ok_or("Keys not generated. Call generate_keys() first.")?;
        let rsa = Rsa::public_key_from_pem(pub_pem)?;
        let size = rsa.size() as usize;
        let mut ciphertext = vec![0u8; size];
        let encrypted_len = rsa.public_encrypt(plaintext, &mut ciphertext, openssl::rsa::Padding::PKCS1_OAEP)?;
        ciphertext.truncate(encrypted_len);
        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let priv_pem = self.private_key.as_ref()
            .ok_or("Keys not generated. Call generate_keys() first.")?;
        let rsa = Rsa::private_key_from_pem(priv_pem)?;
        let size = rsa.size() as usize;
        let mut decrypted = vec![0u8; size];
        let decrypted_len = rsa.private_decrypt(ciphertext, &mut decrypted, openssl::rsa::Padding::PKCS1_OAEP)?;
        decrypted.truncate(decrypted_len);
        Ok(decrypted)
    }

    fn save_private_key(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let priv_pem = self.private_key.as_ref()
            .ok_or("Keys not generated. Call generate_keys() first.")?;
        fs::write(path, priv_pem)?;
        Ok(())
    }

    fn save_public_key(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let pub_pem = self.public_key.as_ref()
            .ok_or("Keys not generated. Call generate_keys() first.")?;
        fs::write(path, pub_pem)?;
        Ok(())
    }

    fn load_private_key(&mut self, path: &Path) -> Result<(), Box<dyn Error>> {
        let bytes = fs::read(path)?;
        let _rsa = Rsa::private_key_from_pem(&bytes)?;
        self.private_key = Some(bytes);
        Ok(())
    }

    fn load_public_key(&mut self, path: &Path) -> Result<(), Box<dyn Error>> {
        let bytes = fs::read(path)?;
        let _rsa = Rsa::public_key_from_pem(&bytes)?;
        self.public_key = Some(bytes);
        Ok(())
    }

    fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    fn has_public_key(&self) -> bool {
        self.public_key.is_some()
    }

    fn encrypt_file<P: AsRef<Path>>(&self, src_path: P, dst_path: P, _progress_callback: impl Fn(u64, u64)) -> Result<(), Box<dyn Error>> {
        let src_path = src_path.as_ref();
        let dst_path = dst_path.as_ref();

        if !src_path.exists() {
            return Err("Source file not found".into());
        }

        if !self.has_public_key() {
            return Err("Keys not generated".into());
        }

        let filename = src_path.file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid filename")?
            .to_string();
        let file_size = fs::metadata(src_path)?.len();
        let block_count = (file_size as usize + MAX_ENCRYPT_PER_BLOCK - 1) / MAX_ENCRYPT_PER_BLOCK;

        let filename_bytes = filename.as_bytes();
        let mut src_file = fs::File::open(src_path)?;
        let mut dst_file = fs::File::create(dst_path)?;

        // Write header
        let mut header = Vec::with_capacity(FILE_HEADER_SIZE);
        header.extend_from_slice(RSAF_MAGIC);
        header.extend_from_slice(&RSAF_VERSION.to_le_bytes());
        header.extend_from_slice(&(filename_bytes.len() as u16).to_le_bytes());
        header.extend_from_slice(&file_size.to_le_bytes());
        header.extend_from_slice(&(block_count as u32).to_le_bytes());
        header.extend_from_slice(&[0u8; 12]); // Reserved
        dst_file.write_all(&header)?;
        dst_file.write_all(filename_bytes)?;

        // Generate random IV and encrypt it
        let mut iv = vec![0u8; MAX_ENCRYPT_PER_BLOCK];
        rand::thread_rng().fill_bytes(&mut iv);
        let iv_encrypted = self.encrypt(&iv)?;
        dst_file.write_all(&iv_encrypted)?;

        // Encrypt file in CBC mode
        let mut prev_ciphertext = iv_encrypted.clone();
        let mut bytes_processed: u64 = 0;

        let mut chunk = vec![0u8; MAX_ENCRYPT_PER_BLOCK];
        loop {
            let bytes_read = src_file.read(&mut chunk)?;
            if bytes_read == 0 {
                break;
            }

            let xored: Vec<u8> = if bytes_processed == 0 {
                chunk[..bytes_read].iter().zip(iv.iter()).map(|(a, b)| a ^ b).collect()
            } else {
                chunk[..bytes_read].iter().zip(prev_ciphertext.iter()).map(|(a, b)| a ^ b).collect()
            };

            let mut xored_padded = xored;
            if xored_padded.len() < MAX_ENCRYPT_PER_BLOCK {
                xored_padded.extend(std::iter::repeat(0u8).take(MAX_ENCRYPT_PER_BLOCK - xored_padded.len()));
            }

            let encrypted = self.encrypt(&xored_padded)?;
            dst_file.write_all(&encrypted)?;
            prev_ciphertext = encrypted;

            bytes_processed += bytes_read as u64;
            _progress_callback(bytes_processed, file_size);
        }

        Ok(())
    }

    fn decrypt_file<P: AsRef<Path>>(&self, src_path: P, dst_path: P, _progress_callback: impl Fn(u64, u64)) -> Result<(), Box<dyn Error>> {
        let src_path = src_path.as_ref();
        let dst_path = dst_path.as_ref();

        if !src_path.exists() {
            return Err("Encrypted file not found".into());
        }

        if !self.has_private_key() {
            return Err("Keys not generated".into());
        }

        let metadata = validate_rsaf_file(src_path)?;
        let file_size = metadata.file_size;
        let block_count = metadata.block_count;

        let mut src_file = fs::File::open(src_path)?;

        // Skip header and filename
        let filename_bytes_len = metadata.filename.as_bytes().len();
        src_file.seek(std::io::SeekFrom::Start((FILE_HEADER_SIZE + filename_bytes_len) as u64))?;

        // Read and decrypt IV block
        let mut iv_encrypted = vec![0u8; ENCRYPTED_BLOCK_SIZE];
        src_file.read_exact(&mut iv_encrypted)?;
        let iv = self.decrypt(&iv_encrypted)?;

        // Decrypt in CBC mode
        let mut dst_file = fs::File::create(dst_path)?;
        let mut prev_ciphertext = iv_encrypted;
        let mut bytes_processed: u64 = 0;

        for i in 0..block_count {
            let mut encrypted_block = vec![0u8; ENCRYPTED_BLOCK_SIZE];
            src_file.read_exact(&mut encrypted_block)?;

            let decrypted = self.decrypt(&encrypted_block)?;

            let xored: Vec<u8> = if i == 0 {
                decrypted.iter().zip(iv.iter()).map(|(a, b)| a ^ b).collect()
            } else {
                decrypted.iter().zip(prev_ciphertext.iter()).map(|(a, b)| a ^ b).collect()
            };

            prev_ciphertext = encrypted_block;

            let output_data = if i == block_count - 1 && file_size % MAX_ENCRYPT_PER_BLOCK as u64 != 0 {
                let actual_len = (file_size % MAX_ENCRYPT_PER_BLOCK as u64) as usize;
                &xored[..actual_len]
            } else {
                &xored
            };

            dst_file.write_all(output_data)?;
            bytes_processed += output_data.len() as u64;
            _progress_callback(bytes_processed, file_size);
        }

        Ok(())
    }
}

struct RsaFileMetadata {
    version: u16,
    filename: String,
    file_size: u64,
    block_count: usize,
}

fn validate_rsaf_file(filepath: &Path) -> Result<RsaFileMetadata, Box<dyn Error>> {
    let mut file = fs::File::open(filepath)?;
    let mut header = vec![0u8; FILE_HEADER_SIZE];
    file.read_exact(&mut header)?;

    let magic = &header[..4];
    if magic != RSAF_MAGIC {
        return Err("Invalid RSAF magic".into());
    }

    let version = u16::from_le_bytes(header[4..6].try_into()?);
    if version != RSAF_VERSION {
        return Err("Unsupported RSAF version".into());
    }

    let filename_len = u16::from_le_bytes(header[6..8].try_into()?) as usize;
    let file_size = u64::from_le_bytes(header[8..16].try_into()?);
    let block_count = u32::from_le_bytes(header[16..20].try_into()?) as usize;

    let mut filename_bytes = vec![0u8; filename_len];
    file.read_exact(&mut filename_bytes)?;
    let filename = String::from_utf8_lossy(&filename_bytes).into_owned();

    Ok(RsaFileMetadata {
        version,
        filename,
        file_size,
        block_count,
    })
}

fn get_work_subdir(work_dir: &str, subdir: &str) -> PathBuf {
    PathBuf::from(work_dir).join(subdir)
}

fn format_file_size(size: u64) -> String {
    if size < 1024 {
        format!("{} B", size)
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    }
}

use std::io::{Read, Seek, Write};

fn load_settings(app_dir: &Path) -> String {
    let settings_path = app_dir.join(".rsa_gui_settings");
    if let Ok(content) = std::fs::read_to_string(&settings_path) {
        if let Ok(settings) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(work_dir) = settings.get("work_dir").and_then(|v| v.as_str()) {
                if PathBuf::from(work_dir).exists() {
                    return work_dir.to_string();
                }
            }
        }
    }
    app_dir.to_string_lossy().into_owned()
}

fn save_settings(app_dir: &Path, work_dir: &str) {
    let settings_path = app_dir.join(".rsa_gui_settings");
    let settings = serde_json::json!({ "work_dir": work_dir });
    if let Ok(content) = serde_json::to_string(&settings) {
        let _ = std::fs::write(&settings_path, content);
    }
}

// Localized strings
const STRINGS: &[(&str, &str, &str)] = &[
    ("keys-generated", "Keys generated", "密钥已生成"),
    ("gen-failed", "Generation failed: ", "生成失败: "),
    ("enc-success", "Encryption successful", "加密成功"),
    ("enc-failed", "Encryption failed: ", "加密失败: "),
    ("dec-success", "Decryption successful", "解密成功"),
    ("dec-failed", "Decryption failed: ", "解密失败: "),
    ("no-ciphertext", "No ciphertext to save", "没有密文可保存"),
    ("cipher-saved", "Ciphertext saved: ", "密文已保存: "),
    ("save-failed", "Save failed: ", "保存失败: "),
    ("keys-saved", "Keys saved to file", "密钥已保存"),
    ("keys-loaded", "Keys loaded from file", "密钥已加载"),
    ("pub-loaded", "Public key loaded (encryption only)", "公钥已加载（仅可加密）"),
    ("no-keys", "Key files not found", "未找到密钥文件"),
    ("load-failed", "Load failed: ", "加载失败: "),
    ("loaded", "Loaded: ", "已加载: "),
    ("preview-no-keys", "Error: No keys. Generate or load keys first", "错误：无密钥，请先生成或加载密钥"),
    ("preview-ok", "OK Preview updated", "✓ 预览已更新"),
    ("preview-err", "Encrypt error: ", "加密错误: "),
    ("select-file", "Select file to encrypt", "选择要加密的文件"),
    ("file-info", " {} ({})", " {} ({})"),
    ("select-cipher", "Select encrypted file", "选择加密文件"),
    ("select-file-first", "Please select a file first", "请先选择文件"),
    ("encrypting", "Encrypting...", "加密中..."),
    ("ok-output", "OK Output: ", "✓ 输出: "),
    ("expansion", "Expansion: {:.2}x ({} -> {} bytes)", "膨胀率: {:.2}x ({} -> {} 字节)"),
    ("fail-enc", "FAIL Encrypt failed: ", "✗ 加密失败: "),
    ("select-cipher-first", "Please select an encrypted file first", "请先选择加密文件"),
    ("invalid-format", "FAIL Invalid RSAF file format", "✗ 无效的 RSAF 文件格式"),
    ("overwrite", "Overwrite ", "覆盖 "),
    ("cancelled", "Cancelled", "已取消"),
    ("decrypting", "Decrypting...", "解密中..."),
    ("ok-saved", "OK Saved: ", "✓ 已保存: "),
    ("file-size", "File size: {} bytes", "文件大小: {} 字节"),
    ("fail-dec", "FAIL Decrypt failed: ", "✗ 解密失败: "),
    ("select-workdir", "Select work directory", "选择工作目录"),
    ("workdir-changed", "Work directory updated", "工作目录已更新"),
    ("workdir-invalid", "Invalid directory", "无效的目录"),
];

fn get_string(key: &str, language: usize) -> String {
    STRINGS.iter()
        .find(|(k, _, _)| *k == key)
        .map(|(_, en, zh)| if language == 1 { *zh } else { *en })
        .unwrap_or(key)
        .to_string()
}

fn main() -> Result<(), Box<dyn Error>> {
    let app_dir = std::env::current_exe()
        .map(|p| p.parent().unwrap_or(&p).to_path_buf())
        .unwrap_or_else(|_| PathBuf::from("."));

    let work_dir = Rc::new(RefCell::new(load_settings(&app_dir)));
    let language = Rc::new(RefCell::new(0usize));

    let rsa_engine = Rc::new(RefCell::new(RSAEngine::new()));

    let ui = AppWindow::new()?;

    // Initialize UI state
    ui.set_work_dir(work_dir.borrow().as_str().into());
    ui.set_has_keys(false);
    ui.set_preview_enabled(true);
    ui.set_language_index(0);
    ui.set_status("Generate keys to start".into());

    // Generate keys
    {
        let ui_handle = ui.as_weak();
        let rsa_engine_clone = rsa_engine.clone();
        let language_clone = language.clone();
        ui.on_generate_keys(move || {
            let ui = ui_handle.unwrap();
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            if let Err(e) = rsa_engine_clone.borrow_mut().generate_keys() {
                ui.set_status((get_string("gen-failed") + &e.to_string()).as_str().into());
            } else {
                ui.set_has_keys(true);
                ui.set_status(get_string("keys-generated").as_str().into());
            }
        });
    }

    // Encrypt text
    {
        let ui_handle = ui.as_weak();
        let rsa_engine_clone = rsa_engine.clone();
        let language_clone = language.clone();
        ui.on_encrypt_text(move |plaintext| {
            let ui = ui_handle.unwrap();
            let plaintext = plaintext.as_str();
            if plaintext.is_empty() {
                return;
            }
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            match rsa_engine_clone.borrow().encrypt(plaintext.as_bytes()) {
                Ok(ciphertext) => {
                    ui.set_ciphertext(BASE64.encode(&ciphertext).as_str().into());
                    ui.set_status(get_string("enc-success").as_str().into());
                }
                Err(e) => {
                    ui.set_status((get_string("enc-failed") + &e.to_string()).as_str().into());
                }
            }
        });
    }

    // Decrypt text
    {
        let ui_handle = ui.as_weak();
        let rsa_engine_clone = rsa_engine.clone();
        let language_clone = language.clone();
        ui.on_decrypt_text(move |ciphertext_b64| {
            let ui = ui_handle.unwrap();
            let ciphertext_b64 = ciphertext_b64.as_str();
            if ciphertext_b64.is_empty() {
                return;
            }
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            match BASE64.decode(ciphertext_b64) {
                Ok(ciphertext) => {
                    match rsa_engine_clone.borrow().decrypt(&ciphertext) {
                        Ok(plaintext) => {
                            ui.set_plaintext(String::from_utf8_lossy(&plaintext).as_ref().into());
                            ui.set_status(get_string("dec-success").as_str().into());
                        }
                        Err(e) => {
                            ui.set_status((get_string("dec-failed") + &e.to_string()).as_str().into());
                        }
                    }
                }
                Err(e) => {
                    ui.set_status((get_string("dec-failed") + &e.to_string()).as_str().into());
                }
            }
        });
    }

    // Save keys
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        let rsa_engine_clone = rsa_engine.clone();
        let language_clone = language.clone();
        ui.on_save_keys(move || {
            let ui = ui_handle.unwrap();
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            let private_path = get_work_subdir(&work_dir_clone.borrow(), "private_key.pem");
            let public_path = get_work_subdir(&work_dir_clone.borrow(), "public_key.pem");
            if let Err(e) = rsa_engine_clone.borrow().save_private_key(&private_path) {
                ui.set_status((get_string("save-failed") + &e.to_string()).as_str().into());
            } else if let Err(e) = rsa_engine_clone.borrow().save_public_key(&public_path) {
                ui.set_status((get_string("save-failed") + &e.to_string()).as_str().into());
            } else {
                ui.set_status(get_string("keys-saved").as_str().into());
            }
        });
    }

    // Load keys
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        let rsa_engine_clone = rsa_engine.clone();
        let language_clone = language.clone();
        ui.on_load_keys(move || {
            let ui = ui_handle.unwrap();
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            let private_path = get_work_subdir(&work_dir_clone.borrow(), "private_key.pem");
            match rsa_engine_clone.borrow_mut().load_private_key(&private_path) {
                Ok(()) => {
                    ui.set_has_keys(true);
                    ui.set_status(get_string("keys-loaded").as_str().into());
                    return;
                }
                Err(_) => {}
            }

            let public_path = get_work_subdir(&work_dir_clone.borrow(), "public_key.pem");
            match rsa_engine_clone.borrow_mut().load_public_key(&public_path) {
                Ok(()) => {
                    ui.set_has_keys(true);
                    ui.set_status(get_string("pub-loaded").as_str().into());
                }
                Err(_) => {
                    ui.set_status(get_string("no-keys").as_str().into());
                }
            }
        });
    }

    // Save ciphertext bin
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        let language_clone = language.clone();
        ui.on_save_ciphertext_bin(move || {
            let ui = ui_handle.unwrap();
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            let ciphertext = ui.get_ciphertext();
            if ciphertext.as_str().is_empty() {
                ui.set_status(get_string("no-ciphertext").as_str().into());
                return;
            }

            if let Ok(ciphertext_bytes) = BASE64.decode(ciphertext.as_str()) {
                let work_dir_borrow = work_dir_clone.borrow();
                let ciphertext_dir = get_work_subdir(&work_dir_borrow, "ciphertexts");
                let _ = std::fs::create_dir_all(&ciphertext_dir);
                let filename = format!("{}.bin", hex::encode(&ciphertext_bytes[..10.min(ciphertext_bytes.len())]));
                let filepath = ciphertext_dir.join(&filename);
                let _ = std::fs::write(&filepath, &ciphertext_bytes);
                ui.set_status((get_string("cipher-saved") + &filename).as_str().into());
            } else {
                ui.set_status(get_string("save-failed").as_str().into());
            }
        });
    }

    // Get ciphertext list
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        let language_clone = language.clone();
        ui.on_get_ciphertext_list(move || {
            let ui = ui_handle.unwrap();
            let work_dir_borrow = work_dir_clone.borrow();
            let ciphertext_dir = get_work_subdir(&work_dir_borrow, "ciphertexts");
            let mut files: Vec<slint::StandardListViewItem> = if ciphertext_dir.exists() {
                std::fs::read_dir(&ciphertext_dir)
                    .ok()
                    .and_then(|entries| Some(entries
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name().into_string().unwrap_or_default())
                        .filter(|f| f.ends_with(".bin"))
                        .map(|f| {
                            let mut item = slint::StandardListViewItem::default();
                            item.text = f.into();
                            item
                        })
                        .collect()))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let model = Rc::new(slint::VecModel::from(files.clone()));
            ui.set_ciphertext_items(model.clone().into());
        });
    }

    // Load ciphertext file
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        let language_clone = language.clone();
        ui.on_load_ciphertext_file(move |filename| {
            let ui = ui_handle.unwrap();
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            let work_dir_borrow = work_dir_clone.borrow();
            let filepath = get_work_subdir(&work_dir_borrow, "ciphertexts").join(filename.as_str());
            match std::fs::read(&filepath) {
                Ok(ciphertext) => {
                    ui.set_ciphertext(BASE64.encode(&ciphertext).as_str().into());
                    ui.set_status((get_string("loaded") + filename.as_str()).as_str().into());
                }
                Err(e) => {
                    ui.set_status((get_string("load-failed") + &e.to_string()).as_str().into());
                }
            }
        });
    }

    // Select source file
    {
        let ui_handle = ui.as_weak();
        ui.on_select_source_file(move || {
            let ui = ui_handle.unwrap();
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select file to encrypt")
                .pick_file()
            {
                ui.set_selected_file(path.to_string_lossy().as_ref().into());
                if let Ok(size) = path.metadata() {
                    ui.set_file_info(format!("{} ({})",
                        path.file_name().unwrap_or_default().to_string_lossy(),
                        format_file_size(size.len())
                    ).as_str().into());
                }
                ui.set_file_status("".into());
                ui.set_progress_value(0.0);
            }
        });
    }

    // Select cipher file
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        ui.on_select_cipher_file(move || {
            let ui = ui_handle.unwrap();
            let work_dir_borrow = work_dir_clone.borrow();
            let rsa_dir = get_work_subdir(&work_dir_borrow, "ciphertexts");
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select encrypted file")
                .set_directory(&rsa_dir)
                .add_filter("RSA encrypted files", &["rsa"])
                .add_filter("All files", &["*"])
                .pick_file()
            {
                ui.set_selected_cipher(path.to_string_lossy().as_ref().into());
                ui.set_file_status("".into());
            }
        });
    }

    // Get RSA file list
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        ui.on_get_rsa_file_list(move || {
            let ui = ui_handle.unwrap();
            let work_dir_borrow = work_dir_clone.borrow();
            let rsa_dir = get_work_subdir(&work_dir_borrow, "ciphertexts");
            let _ = std::fs::create_dir_all(&rsa_dir);
            let mut files: Vec<slint::StandardListViewItem> = std::fs::read_dir(&rsa_dir)
                .ok()
                .and_then(|entries| Some(entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().into_string().unwrap_or_default())
                    .filter(|f| f.ends_with(".rsa"))
                    .map(|f| {
                        let mut item = slint::StandardListViewItem::default();
                        item.text = f.into();
                        item
                    })
                    .collect()))
                .unwrap_or_default();
            let model = Rc::new(slint::VecModel::from(files.clone()));
            ui.set_rsa_file_items(model.clone().into());
        });
    }

    // Encrypt file
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        let rsa_engine_clone = rsa_engine.clone();
        let language_clone = language.clone();
        ui.on_encrypt_file(move || {
            let ui = ui_handle.unwrap();
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            let selected_file = ui.get_selected_file();
            if selected_file.as_str().is_empty() {
                ui.set_file_status(get_string("select-file-first").as_str().into());
                return;
            }

            let src_path = PathBuf::from(selected_file.as_str());
            if !src_path.exists() {
                ui.set_file_status(get_string("select-file-first").as_str().into());
                return;
            }

            let work_dir_borrow = work_dir_clone.borrow();
            let ciphertext_dir = get_work_subdir(&work_dir_borrow, "ciphertexts");
            let _ = std::fs::create_dir_all(&ciphertext_dir);

            let src_size = src_path.metadata().unwrap().len();
            let dst_filename = {
                let mut file = std::fs::File::open(&src_path).unwrap();
                let mut sample = vec![0u8; 10];
                let _ = file.read_exact(&mut sample);
                format!("{}.rsa", hex::encode(&sample))
            };
            let dst_path = ciphertext_dir.join(&dst_filename);

            ui.set_progress_value(0.0);
            ui.set_file_status(get_string("encrypting").as_str().into());

            if let Err(e) = rsa_engine_clone.borrow().encrypt_file(&src_path, &dst_path, |processed, total| {
                if total > 0 {
                    let progress = processed as f32 / total as f32;
                    ui.set_progress_value(progress as f32);
                    if processed < total {
                        let percent = (processed * 100) / total;
                        ui.set_file_progress(format!("Processing: {}% ({}/{} bytes)", percent, processed, total).as_str().into());
                    } else {
                        ui.set_file_progress("Complete!".into());
                    }
                }
            }) {
                ui.set_file_status((get_string("fail-enc") + &e.to_string()).as_str().into());
                ui.set_progress_value(0.0);
                return;
            }

            let dst_size = dst_path.metadata().unwrap().len();
            let ratio = if src_size > 0 { dst_size as f64 / src_size as f64 } else { 0.0 };

            ui.set_file_status((get_string("ok-output") + &dst_filename).as_str().into());
            ui.set_progress_value(1.0);
            ui.set_file_progress(format!("Expansion: {:.2}x ({} -> {} bytes)", ratio, src_size, dst_size).as_str().into());

            // Refresh file list
            let rsa_dir = get_work_subdir(&work_dir_borrow, "ciphertexts");
            let mut files: Vec<slint::StandardListViewItem> = std::fs::read_dir(&rsa_dir)
                .ok()
                .and_then(|entries| Some(entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().into_string().unwrap_or_default())
                    .filter(|f| f.ends_with(".rsa"))
                    .map(|f| {
                        let mut item = slint::StandardListViewItem::default();
                        item.text = f.into();
                        item
                    })
                    .collect()))
                .unwrap_or_default();
            let model = Rc::new(slint::VecModel::from(files.clone()));
            ui.set_rsa_file_items(model.clone().into());
        });
    }

    // Decrypt file
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        let rsa_engine_clone = rsa_engine.clone();
        let language_clone = language.clone();
        ui.on_decrypt_file(move || {
            let ui = ui_handle.unwrap();
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            let selected_cipher = ui.get_selected_cipher();
            if selected_cipher.as_str().is_empty() {
                ui.set_file_status(get_string("select-cipher-first").as_str().into());
                return;
            }

            let src_path = PathBuf::from(selected_cipher.as_str());
            if !src_path.exists() {
                ui.set_file_status(get_string("select-cipher-first").as_str().into());
                return;
            }

            let metadata = validate_rsaf_file(&src_path);
            if let Err(_) = metadata {
                ui.set_file_status(get_string("invalid-format").as_str().into());
                return;
            }
            let metadata = metadata.unwrap();

            let work_dir_borrow = work_dir_clone.borrow();
            let output_dir = get_work_subdir(&work_dir_borrow, "decrypted");
            let _ = std::fs::create_dir_all(&output_dir);
            let dst_path = output_dir.join(&metadata.filename);

            ui.set_progress_value(0.0);
            ui.set_file_status(get_string("decrypting").as_str().into());

            if let Err(e) = rsa_engine_clone.borrow().decrypt_file(&src_path, &dst_path, |processed, total| {
                if total > 0 {
                    let progress = processed as f32 / total as f32;
                    ui.set_progress_value(progress as f32);
                }
            }) {
                ui.set_file_status((get_string("fail-dec") + &e.to_string()).as_str().into());
                ui.set_progress_value(0.0);
                return;
            }

            ui.set_file_status((get_string("ok-saved") + &metadata.filename).as_str().into());
            ui.set_progress_value(1.0);
            ui.set_file_progress(format!("File size: {} bytes", metadata.file_size).as_str().into());
        });
    }

    // Set language
    {
        let language_clone = language.clone();
        ui.on_set_language(move |index| {
            *language_clone.borrow_mut() = index as usize;
        });
    }

    // Select work dir
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        let language_clone = language.clone();
        ui.on_select_work_dir(move || {
            let ui = ui_handle.unwrap();
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            if let Some(path) = rfd::FileDialog::new()
                .set_title(&get_string("select-workdir"))
                .pick_folder()
            {
                *work_dir_clone.borrow_mut() = path.to_string_lossy().into_owned();
                ui.set_work_dir(work_dir_clone.borrow().as_str().into());
            }
        });
    }

    // Apply work dir
    {
        let ui_handle = ui.as_weak();
        let work_dir_clone = work_dir.clone();
        let language_clone = language.clone();
        ui.on_apply_work_dir(move || {
            let ui = ui_handle.unwrap();
            let lang = *language_clone.borrow();
            let get_string = |key: &str| -> String {
                get_string(key, lang)
            };
            let wd = work_dir_clone.borrow();
            if PathBuf::from(wd.as_str()).exists() {
                save_settings(&app_dir, &wd);
                ui.set_status(get_string("workdir-changed").as_str().into());
            } else {
                ui.set_status(get_string("workdir-invalid").as_str().into());
            }
        });
    }

    ui.run()?;
    Ok(())
}