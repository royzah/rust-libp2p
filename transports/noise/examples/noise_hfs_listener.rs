//! Interop listener (responder) for `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`.
//!
//! Accepts one connection, completes the handshake, sends one greeting, checks
//! the reply, prints `INTEROP_OK` and exits 0. Stdout contract: `LOCAL`,
//! `READY`, `PEER`, `SENT`, `RECV`, `INTEROP_OK`; errors go to stderr, exit 1.
//!
//! The whole run is bounded by `interop::RUN_DEADLINE`, so a peer that
//! connects and then sends nothing cannot pin the process or its port when
//! this binary is used standalone rather than under `run-matrix.sh`.
//!
//! ```bash
//! cargo run -p libp2p-noise --example noise_hfs_listener --features mlkem-hfs -- 9999
//! ```

#[path = "common/interop.rs"]
mod interop;

use std::net::TcpListener;

use futures::{executor::block_on, io::AllowStdIo};
use libp2p_core::upgrade::InboundConnectionUpgrade;

fn main() {
    let (port, config) = interop::init(9999);

    let listener = TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| interop::fail(format!("bind 127.0.0.1:{port}: {e}")));
    println!("READY {port}");
    let (stream, peer_addr) = listener
        .accept()
        .unwrap_or_else(|e| interop::fail(format!("accept: {e}")));
    eprintln!("connection from {peer_addr}");

    block_on(async {
        let (peer_id, mut io) = config
            .upgrade_inbound(AllowStdIo::new(stream), interop::HFS_PROTOCOL)
            .await
            .unwrap_or_else(|e| interop::fail(format!("handshake failed: {e}")));
        println!("PEER {peer_id}");
        interop::send_greeting(&mut io)
            .await
            .unwrap_or_else(|e| interop::fail(e));
        interop::read_greeting(&mut io)
            .await
            .unwrap_or_else(|e| interop::fail(e));
        println!("INTEROP_OK");
    });
}
