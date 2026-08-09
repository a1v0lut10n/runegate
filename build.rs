use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let phenotypes_dir = Path::new("src/phenotypes");

    if phenotypes_dir.exists() {
        // Read all .pht and .md files in the phenotypes directory
        if let Ok(entries) = fs::read_dir(phenotypes_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext == "pht" || ext == "md" {
                        // Use phenotyper to compile the template
                        if let Err(diags) = phenotyper::compile(&path, &out_dir) {
                            for diag in diags {
                                eprintln!("{:?}", diag);
                            }
                            panic!("Failed to compile phenotyper template: {}", path.display());
                        }
                        println!("cargo:rerun-if-changed={}", path.display());
                    }
                }
            }
        }
    } else {
        println!(
            "cargo:warning=Phenotypes directory 'src/phenotypes' not found. Skipping UI generation."
        );
    }

    println!("cargo:rerun-if-changed=build.rs");
}
