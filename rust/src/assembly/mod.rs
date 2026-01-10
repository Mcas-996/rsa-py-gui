// Assembly Acceleration Module
// Provides Assembly-optimized multiplication for RSA operations

pub mod mul_asm;

pub use mul_asm::asm_available;
pub use mul_asm::init_asm;