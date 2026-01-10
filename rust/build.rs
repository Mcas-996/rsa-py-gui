// Build script for NASM assembly integration
// This script compiles x64 assembly code to object files

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Determine target architecture and OS
    let target = env::var("TARGET").unwrap_or_default();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("Target: {}", target);
    println!("OUT_DIR: {:?}", out_dir);

    // Define assembly source file
    let asm_file = "src/assembly/mul_asm_x64.asm";
    let src_path = PathBuf::from(asm_file);
    let obj_file = out_dir.join("mul_asm_x64.o");

    // Check if assembly file exists
    if !src_path.exists() {
        println!("Assembly file not found: {:?}", src_path);
        println!("Assembly acceleration will be disabled");
        return;
    }

    // Determine output format based on target OS
    let format = if target.contains("windows") {
        "win64"
    } else if target.contains("apple") {
        "macho64"
    } else {
        "elf64"
    };

    println!("Compiling {} -> {:?} (format: {})", asm_file, obj_file, format);

    // Try to compile with nasm
    let output = Command::new("nasm")
        .args(&[
            "-f", format,
            "-o", obj_file.to_str().unwrap(),
            src_path.to_str().unwrap(),
        ])
        .output();

    match output {
        Ok(result) => {
            if result.status.success() {
                println!("Successfully compiled {}", asm_file);
                println!("{}", String::from_utf8_lossy(&result.stdout));
            } else {
                println!("Warning: NASM compilation failed");
                println!("stderr: {}", String::from_utf8_lossy(&result.stderr));
                println!("Assembly acceleration will be disabled");
            }
        }
        Err(e) => {
            println!("Warning: Could not run nasm: {}", e);
            println!("Assembly acceleration will be disabled");
        }
    }

    // Notify cargo to rerun if assembly file changes
    println!("cargo:rerun-if-changed=src/assembly/mul_asm_x64.asm");
}