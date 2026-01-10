use std::process;

fn main() {
    if let Err(e) = rsa_gui::ui::app::create_app() {
        eprintln!("Error running application: {}", e);
        process::exit(1);
    }
}