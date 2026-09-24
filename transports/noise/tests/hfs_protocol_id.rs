// Pins which handshake each multistream id selects, observed on the wire.
//
// `Config` selects classical XX for any protocol id it does not recognise, so
// a stale hybrid id yields a classical handshake instead of an error. These
// tests look only at the first frame the initiator writes: message A is
// 32 bytes (e) for XX and 32 + 1184 bytes (e, e1) for XXhfs. They also pin the
// id copies in the interop harness and the benchmark, so neither can drift
// into a classical handshake unnoticed.
#![cfg(feature = "mlkem-hfs")]

use std::{future::Future, time::Duration};

use futures::{channel::oneshot, future, prelude::*};
use libp2p_core::upgrade::OutboundConnectionUpgrade;
use libp2p_identity as identity;
use libp2p_noise as noise;

// Only `HFS_PROTOCOL` is used here; the rest serves the interop examples.
#[allow(dead_code)]
#[path = "../examples/common/interop.rs"]
mod interop;

// `HFS` is the id this branch ships, not a spec-endorsed one. The Working
// Draft for the suite, libp2p/specs#727, writes "/noise-mlkem768-hfs/0.1.0"
// and lists the identifier string as the first of its open issues, so
// `STALE_HFS` is stale only with respect to this branch's rename. These
// constants follow whatever #727 settles on.
const HFS: &str = "/noise-mlkem768-hfs/0.2.0";
const STALE_HFS: &str = "/noise-mlkem768-hfs/0.1.0";

/// e (32) + e1, the ML-KEM-768 encapsulation key (1184).
const HFS_MSG_A_LEN: u16 = 1216;
/// e (32).
const XX_MSG_A_LEN: u16 = 32;

/// Upper bound for the first frame to appear; a handshake start takes
/// milliseconds.
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// The benchmark's hybrid id, read from its source (the bench is a separate
/// binary, so its constant cannot be imported).
fn bench_hfs_id() -> &'static str {
    const BENCH_SRC: &str = include_str!("../benches/noise_hfs.rs");
    BENCH_SRC
        .lines()
        .find_map(|line| {
            line.strip_prefix("const HFS: &str = \"")?
                .strip_suffix("\";")
        })
        .expect("benches/noise_hfs.rs declares `const HFS: &str = \"...\";`")
}

/// Starts an outbound upgrade with `protocol` and returns the length prefix of
/// the first frame it writes. The handshake itself is abandoned.
fn first_frame_len(protocol: &'static str) -> u16 {
    let id = identity::Keypair::generate_ed25519();
    let (client, server) = futures_ringbuf::Endpoint::pair(4096, 4096);
    let upgrade = noise::Config::new(&id)
        .unwrap()
        .upgrade_outbound(client, protocol);
    read_frame_len(server, upgrade, FRAME_TIMEOUT).unwrap_or_else(|e| panic!("{protocol}: {e}"))
}

/// Reads the 2-byte length prefix of the first frame written to `server`
/// while `upgrade` drives the other end. Fails after `timeout` so a stalled
/// upgrade surfaces as a test failure rather than a hang.
fn read_frame_len<U, O, E>(
    mut server: futures_ringbuf::Endpoint,
    upgrade: U,
    timeout: Duration,
) -> Result<u16, String>
where
    U: Future<Output = Result<O, E>> + Unpin,
    E: std::fmt::Debug,
{
    futures::executor::block_on(async move {
        let read_len = async move {
            let mut len = [0u8; 2];
            server
                .read_exact(&mut len)
                .await
                .expect("read length prefix");
            u16::from_be_bytes(len)
        };
        let first_frame = future::select(Box::pin(read_len), upgrade);

        match future::select(first_frame, timer(timeout)).await {
            future::Either::Left((future::Either::Left((len, _abandoned_upgrade)), _)) => Ok(len),
            future::Either::Left((future::Either::Right((result, _)), _)) => Err(format!(
                "upgrade finished before message A was read: {:?}",
                result.err()
            )),
            future::Either::Right(_) => Err(format!("no frame written within {timeout:?}")),
        }
    })
}

/// Resolves once `after` has elapsed, measured on a helper thread.
fn timer(after: Duration) -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel();
    std::thread::spawn(move || {
        std::thread::sleep(after);
        let _ = tx.send(());
    });
    rx
}

#[test]
fn hybrid_id_sends_hybrid_message_a() {
    assert_eq!(first_frame_len(HFS), HFS_MSG_A_LEN);
}

#[test]
fn interop_harness_id_sends_hybrid_message_a() {
    assert_eq!(first_frame_len(interop::HFS_PROTOCOL), HFS_MSG_A_LEN);
}

#[test]
fn bench_id_sends_hybrid_message_a() {
    assert_eq!(first_frame_len(bench_hfs_id()), HFS_MSG_A_LEN);
}

#[test]
fn classical_id_sends_classical_message_a() {
    assert_eq!(first_frame_len("/noise"), XX_MSG_A_LEN);
}

#[test]
fn stale_hybrid_id_falls_back_to_classical() {
    assert_ne!(first_frame_len(STALE_HFS), HFS_MSG_A_LEN);
    assert_eq!(first_frame_len(STALE_HFS), XX_MSG_A_LEN);
}

#[test]
fn stalled_peer_fails_instead_of_hanging() {
    let (_client, server) = futures_ringbuf::Endpoint::pair(4096, 4096);
    let never_writes = future::pending::<Result<(), ()>>();
    let result = read_frame_len(server, never_writes, Duration::from_millis(200));
    let err = result.expect_err("a stalled upgrade must time out");
    assert!(err.contains("no frame written"), "unexpected error: {err}");
}
