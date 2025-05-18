// SPDX-License-Identifier: Apache-2.0
use std::env;
use tracing::subscriber::set_global_default;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{
    fmt::MakeWriter, layer::SubscriberExt, EnvFilter, Registry,
};

/// Initialize the tracing subscriber for the application
pub fn init_tracing<Sink>(name: &str, sink: Sink)
where
    Sink: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    // Skip setting LogTracer if it's already been set
    let _ = LogTracer::init();

    // Get log level from environment or default to INFO
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            // Check if we have LOG environment variable
            let filter_level = env::var("RUST_LOG")
                .unwrap_or_else(|_| format!("{}=info,actix_web=info", name));
            EnvFilter::new(filter_level)
        });

    // Create and register the Bunyan (JSON) formatting layer
    let formatting_layer = BunyanFormattingLayer::new(
        name.into(),
        sink,
    );

    // Compose all layers into a tracing subscriber
    let subscriber = Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer);

    // Set the subscriber as global default
    set_global_default(subscriber).expect("Failed to set tracing subscriber");
    tracing::info!("Tracing initialized with Bunyan formatter");
}

/// Initialize a more readable console logger for development
pub fn init_console_tracing() {
    // Skip setting LogTracer if it's already been set
    let _ = LogTracer::init();

    // Get log level from environment or default to INFO
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            let filter_level = env::var("RUST_LOG")
                .unwrap_or_else(|_| "runegate=debug,actix_web=info".into());
            EnvFilter::new(filter_level)
        });

    // Create console subscriber with pretty formatting
    let subscriber = tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(env_filter)
        .finish();

    // Set the subscriber as global default
    set_global_default(subscriber).expect("Failed to set tracing subscriber");
    tracing::info!("Console tracing initialized");
}
