use lettre::message::{header, Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use crate::email::EmailConfig;
use std::error::Error;

pub fn send_magic_link(
    config: &EmailConfig,
    recipient_email: &str,
    login_url: &str,
) -> Result<(), Box<dyn Error>> {
    let body = config
        .body_template
        .replace("{login_url}", login_url);

    let email = Message::builder()
        .from(config.from_address.parse::<Mailbox>()?)
        .to(recipient_email.parse::<Mailbox>()?)
        .subject(&config.subject)
        .header(header::ContentType::TEXT_PLAIN)
        .body(body)?;

    let creds = Credentials::new(
        config.smtp_user.clone(),
        config.smtp_pass.clone(),
    );

    // For Gmail on port 587, we need to use STARTTLS
    let mailer = SmtpTransport::starttls_relay(&config.smtp_host)?
        .port(config.smtp_port)
        .credentials(creds)
        .build();

    mailer.send(&email)?;
    println!("📧 Magic link sent to {}", recipient_email);

    Ok(())
}
