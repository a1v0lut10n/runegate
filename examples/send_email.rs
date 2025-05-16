use runegate::email::EmailConfig;
use runegate::send_magic_link::send_magic_link;

use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load email config from config/email.toml
    let config_text = fs::read_to_string("config/email.toml")?;
    let email_config: EmailConfig = toml::from_str(&config_text)?;

    // Get recipient from command line argument
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <recipient_email>", args[0]);
        std::process::exit(1);
    }
    let recipient_email = &args[1];

    // Generate a dummy login URL
    let login_url = "https://example.com/magic-link";

    // Send the email
    send_magic_link(&email_config, recipient_email, login_url)?;

    Ok(())
}
