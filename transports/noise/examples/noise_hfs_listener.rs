//! Standalone TCP listener for cross-language interop testing.
//!
//! Accepts one connection, completes a Noise_XXhfs_25519+ML-KEM-768 handshake
//! as the responder, prints the remote peer ID, and exits 0.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example noise_hfs_listener --features mlkem-hfs -- 9999
//! # or with named flag:
//! cargo run --example noise_hfs_listener --features mlkem-hfs -- --port 9999
//! ```
//!
//! Then dial it from Python (py-libp2p PR #1310):
//! ```bash
//! python scripts/interop_dial.py --port 9999 --protocol /noise-mlkem768-hfs/0.1.0
//! ```
//!
//! Or from JavaScript (js-libp2p-noise PR #665):
//! ```bash
//! node scripts/interop-dial.mjs --port 9999
//! ```
//!
//! ## Output protocol
//!
//! The binary writes to stdout in this order:
//! 1. `READY <port>` — emitted before blocking on `accept()`, so callers know when to connect.
//! 2. `PEER <peer_id>` — the libp2p `PeerId` of the remote party, printed after a successful handshake.
//!
//! On any error the binary prints a message to stderr and exits with code 1.

use futures::executor::block_on;
use futures::io::AllowStdIo;
use libp2p_core::upgrade::InboundConnectionUpgrade;
use libp2p_identity as identity;
use libp2p_noise as noise;
use std::net::TcpListener;

/// Must match `NOISE_MLKEM_HFS_PROTOCOL` in the crate (kept private there).
const HFS_PROTOCOL: &str = "/noise-mlkem768-hfs/0.1.0";

fn main() {
    let port = parse_port();

    let id_keys = identity::Keypair::generate_ed25519();
    let noise_config = match noise::Config::new(&id_keys) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("ERROR config init: {e}");
            std::process::exit(1);
        }
    };

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ERROR bind 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };

    // Signal readiness *before* blocking on accept, so callers know when to connect.
    println!("READY {port}");

    let (stream, peer_addr) = match listener.accept() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR accept: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("connection from {peer_addr}");

    let result = block_on(noise_config.upgrade_inbound(AllowStdIo::new(stream), HFS_PROTOCOL));

    match result {
        Ok((peer_id, _io)) => {
            println!("PEER {peer_id}");
        }
        Err(e) => {
            eprintln!("ERROR handshake failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Parse the port from command-line arguments.
///
/// Accepted forms:
/// - positional: `noise_hfs_listener 9999`
/// - named flag: `noise_hfs_listener --port 9999`
///
/// Defaults to 9999 when no argument is provided.
fn parse_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--port" {
            if let Some(val) = args.get(i + 1) {
                return val.parse().unwrap_or_else(|_| {
                    eprintln!("ERROR invalid port value: {val}");
                    std::process::exit(1);
                });
            }
            eprintln!("ERROR --port requires a value");
            std::process::exit(1);
        }
        if !args[i].starts_with("--")
            && let Ok(port) = args[i].parse::<u16>()
        {
            return port;
        }
        i += 1;
    }
    9999
}
