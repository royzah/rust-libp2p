//! Shared pieces of the cross-implementation interop harness: port parsing,
//! peer bootstrap and the one-line greeting exchange every implementation
//! speaks (listener first).

use std::{fmt::Write as _, time::Duration};

use futures::prelude::*;
use libp2p_identity as identity;
use libp2p_noise as noise;

/// Must match `NOISE_MLKEM_HFS_PROTOCOL` in the crate (kept private there).
pub(crate) const HFS_PROTOCOL: &str = "/noise-mlkem768-hfs/0.2.0";
pub(crate) const IMPL: &str = "Rust";
const GREETING_PREFIX: &str = "hello from ";

/// A greeting is "hello from <Impl>\n", under 32 bytes. Bound the reader well
/// above that so a peer which completed the handshake and then streams
/// newline-free data cannot grow the buffer without limit.
pub(crate) const MAX_GREETING_BYTES: usize = 1024;

/// Wall-clock bound on one harness run, covering accept, handshake and the
/// greeting exchange. `run-matrix.sh` bounds its runs externally, but the file
/// headers invite standalone use, where a peer that connects and then sends
/// nothing would otherwise pin the process and its port forever. Generous
/// enough not to fire against the slow pure-Python ML-KEM path, which is why
/// the socket read timeout is still set only after the handshake.
pub(crate) const RUN_DEADLINE: Duration = Duration::from_secs(120);

pub(crate) fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("ERROR {msg}");
    std::process::exit(1)
}

/// Positional `<port>` or `--port <port>`; `default` when absent.
pub(crate) fn parse_port(default: u16) -> u16 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let raw = match args.iter().position(|a| a == "--port") {
        Some(i) => args
            .get(i + 1)
            .cloned()
            .unwrap_or_else(|| fail("--port requires a value")),
        None => match args.first() {
            Some(a) => a.clone(),
            None => return default,
        },
    };
    raw.parse()
        .unwrap_or_else(|_| fail(format!("invalid port value: {raw}")))
}

/// Fails the process if the run has not finished within `RUN_DEADLINE`. The
/// thread is detached: a run that completes normally exits first and takes the
/// watchdog with it.
fn start_run_deadline(limit: Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        eprintln!("ERROR run deadline of {}s exceeded", limit.as_secs());
        std::process::exit(1);
    });
}

/// Parses the port, arms the overall run deadline, generates an ephemeral
/// identity, prints `LOCAL`, and builds the Noise config every interop binary
/// starts from.
pub(crate) fn init(default_port: u16) -> (u16, noise::Config) {
    let port = parse_port(default_port);
    start_run_deadline(RUN_DEADLINE);
    let id_keys = identity::Keypair::generate_ed25519();
    println!("LOCAL {}", id_keys.public().to_peer_id());
    let config = noise::Config::new(&id_keys).unwrap_or_else(|e| fail(format!("config init: {e}")));
    (port, config)
}

pub(crate) async fn send_greeting<T: AsyncWrite + Unpin>(io: &mut T) -> std::io::Result<()> {
    io.write_all(format!("{GREETING_PREFIX}{IMPL}\n").as_bytes())
        .await?;
    io.flush().await?;
    println!("SENT {GREETING_PREFIX}{IMPL}");
    Ok(())
}

/// Escapes control characters so a peer cannot smuggle ANSI CSI or OSC
/// sequences into a committed run log that a human later reads with `cat`.
/// A legitimate greeting contains none, so the runner's exact match on
/// `RECV hello from <Impl>` is unaffected.
pub(crate) fn printable_greeting(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for c in line.chars() {
        if c.is_control() {
            let _ = write!(out, "\\x{:02x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) async fn read_greeting<T: AsyncRead + Unpin>(io: &mut T) -> std::io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if io.read(&mut byte).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_GREETING_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("greeting exceeded {MAX_GREETING_BYTES} bytes without a newline"),
            ));
        }
    }
    let line = String::from_utf8(line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    println!("RECV {}", printable_greeting(&line));
    match line.strip_prefix(GREETING_PREFIX) {
        Some(name) if !name.is_empty() => Ok(line),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected greeting {line:?}"),
        )),
    }
}
