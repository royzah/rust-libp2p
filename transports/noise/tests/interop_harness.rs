//! Bounds and output-hygiene checks for the shared interop harness helpers in
//! `examples/common/interop.rs`.
//!
//! The harness reads one `hello from <Impl>\n` greeting from a peer that has
//! completed the XXhfs handshake. Completing the handshake proves the peer
//! holds some libp2p identity, not that it is friendly, so the reader must
//! refuse to buffer unbounded newline-free data and must not echo raw control
//! characters into a run log that a human later reads with `cat`.
//!
//! Security audit 2026-09-18, harnesses-tooling F-001 and F-006.
#![cfg(feature = "mlkem-hfs")]

use futures::{executor::block_on, io::Cursor};

// The harness lives under examples/, which cargo builds but does not test.
// Pull the same file into a test crate so its helpers are covered.
#[path = "../examples/common/interop.rs"]
#[allow(dead_code)]
mod interop;

#[test]
fn reads_a_well_formed_greeting() {
    let mut io = Cursor::new(b"hello from JS\nignored trailing bytes".to_vec());
    let line = block_on(interop::read_greeting(&mut io)).expect("greeting should parse");
    assert_eq!(line, "hello from JS");
}

#[test]
fn rejects_a_newline_free_stream_past_the_cap() {
    let flood = vec![b'A'; interop::MAX_GREETING_BYTES * 4];
    let mut io = Cursor::new(flood);

    let err = block_on(interop::read_greeting(&mut io))
        .expect_err("a newline-free flood must not be buffered without bound");

    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "expected a data error, got: {err}"
    );
    assert!(
        err.to_string().contains("exceeded"),
        "error should name the cap, got: {err}"
    );
}

// The cap must clear the longest real greeting by a wide margin and still be
// small enough to matter. Checked at compile time: both sides are constants,
// so a runtime assertion would be a constant one.
const _: () = assert!(interop::MAX_GREETING_BYTES > "hello from Python\n".len());
const _: () = assert!(interop::MAX_GREETING_BYTES <= 4096);

#[test]
fn escapes_control_characters_before_echoing() {
    // A hostile peer can hide ANSI CSI or OSC sequences in the greeting.
    let hostile = "hello from Rust\u{1b}[2K\u{1b}[1APASS";
    let escaped = interop::printable_greeting(hostile);
    assert!(
        !escaped.contains('\u{1b}'),
        "escape byte survived: {escaped}"
    );
    assert!(escaped.contains("\\x1b"), "escape not rendered: {escaped}");
}

#[test]
fn leaves_a_legitimate_greeting_byte_identical() {
    // run-matrix.sh grades on an exact match of `RECV hello from <Impl>`.
    for impl_name in ["JS", "Rust", "Python", "Nim"] {
        let greeting = format!("hello from {impl_name}");
        assert_eq!(interop::printable_greeting(&greeting), greeting);
    }
}
