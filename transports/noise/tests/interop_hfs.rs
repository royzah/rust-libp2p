//! Cross-language interop tests and deterministic test vectors for
//! Noise_XXhfs_25519+ML-KEM-768_ChaChaPoly_SHA256 (PR #6481).
//!
//! # Cross-language interop (run manually)
//!
//! Terminal 1 — Rust listener:
//! ```
//! cargo run --example noise_hfs_listener --features mlkem-hfs -- 9999
//! ```
//! Terminal 2 — Python dialer (py-libp2p PR #1310):
//! ```
//! python scripts/interop_dial.py --port 9999 --protocol /noise-mlkem768-hfs/0.1.0
//! ```
//! Terminal 3 — JS dialer (js-libp2p-noise PR #665):
//! ```
//! node scripts/interop-dial.mjs --port 9999
//! ```

#![cfg(feature = "mlkem-hfs")]

use rand::{RngCore, SeedableRng};
use snow::{
    params::NoiseParams,
    resolvers::CryptoResolver,
    types::{Cipher, Dh, Hash, Kem, Random},
};
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Deterministic resolver — identical to production Resolver except the RNG
// is seeded, making every handshake reproducible.
// ---------------------------------------------------------------------------

struct SeededRng(rand::rngs::StdRng);

impl Random for SeededRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

struct SeededResolver {
    seed: u64,
}

impl CryptoResolver for SeededResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(SeededRng(rand::rngs::StdRng::seed_from_u64(
            self.seed,
        ))))
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn Dh>> {
        snow::resolvers::DefaultResolver.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &snow::params::HashChoice) -> Option<Box<dyn Hash>> {
        snow::resolvers::DefaultResolver.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &snow::params::CipherChoice) -> Option<Box<dyn Cipher>> {
        snow::resolvers::DefaultResolver.resolve_cipher(choice)
    }

    fn resolve_kem(&self, choice: &snow::params::KemChoice) -> Option<Box<dyn Kem>> {
        snow::resolvers::DefaultResolver.resolve_kem(choice)
    }
}

// ---------------------------------------------------------------------------
// Fixed static private keys — any 32 bytes are valid X25519 private keys
// (x25519 clamps bits internally).
// ---------------------------------------------------------------------------

const INIT_STATIC_PRIV: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const RESP_STATIC_PRIV: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

static PARAMS_HFS: LazyLock<NoiseParams> = LazyLock::new(|| {
    "Noise_XXhfs_25519+ML-KEM-768_ChaChaPoly_SHA256"
        .parse()
        .expect("valid params")
});

// ---------------------------------------------------------------------------
// Core helper — runs one full XXhfs handshake with seeded resolvers.
// Returns (msgs, initiator_hash, responder_hash).
// NOTE: ML-KEM generate() calls system entropy regardless of the seeded RNG,
// so the handshake hash is NOT reproducible across runs or machines.
// Both hashes are returned so callers can assert they agree (intra-run check).
// initiator_seed and responder_seed MUST differ.
// ---------------------------------------------------------------------------

fn run_seeded_handshake(
    initiator_seed: u64,
    responder_seed: u64,
) -> ([Vec<u8>; 3], [u8; 32], [u8; 32]) {
    let mut initiator = snow::Builder::with_resolver(
        PARAMS_HFS.clone(),
        Box::new(SeededResolver {
            seed: initiator_seed,
        }),
    )
    .local_private_key(&INIT_STATIC_PRIV)
    .unwrap()
    .build_initiator()
    .unwrap();

    let mut responder = snow::Builder::with_resolver(
        PARAMS_HFS.clone(),
        Box::new(SeededResolver {
            seed: responder_seed,
        }),
    )
    .local_private_key(&RESP_STATIC_PRIV)
    .unwrap()
    .build_responder()
    .unwrap();

    let mut buf = vec![0u8; 65535];

    // msg1: initiator → responder  (tokens: e, e1 — ephemeral KEM pubkey)
    let n = initiator.write_message(&[], &mut buf).unwrap();
    let msg1 = buf[..n].to_vec();
    buf.resize(65535, 0);
    responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: responder → initiator  (tokens: e, ee, s, es, ekem1)
    let n = responder.write_message(&[], &mut buf).unwrap();
    let msg2 = buf[..n].to_vec();
    buf.resize(65535, 0);
    initiator.read_message(&msg2, &mut buf).unwrap();

    // msg3: initiator → responder  (tokens: s, se)
    let n = initiator.write_message(&[], &mut buf).unwrap();
    let msg3 = buf[..n].to_vec();
    buf.resize(65535, 0);
    responder.read_message(&msg3, &mut buf).unwrap();

    let init_hash: [u8; 32] = initiator.get_handshake_hash().try_into().unwrap();
    let resp_hash: [u8; 32] = responder.get_handshake_hash().try_into().unwrap();

    ([msg1, msg2, msg3], init_hash, resp_hash)
}

// ---------------------------------------------------------------------------
// Structural compliance tests
// ---------------------------------------------------------------------------

/// Verifies the XXhfs message geometry and intra-run hash agreement.
///
/// ML-KEM key generation calls system entropy regardless of the seeded RNG,
/// so exact byte values change each run. What we CAN assert deterministically:
/// - Message lengths (fixed by the protocol specification)
/// - Both sides compute the same handshake hash within a single run
/// - The handshake hash is non-trivial (not all-zeros)
#[test]
fn handshake_structural_properties() {
    let ([msg1, msg2, msg3], init_hash, resp_hash) = run_seeded_handshake(1, 2);

    // msg1 = 32 (e) + 1184 (e1 / ML-KEM-768 public key) = 1216 bytes
    assert_eq!(
        msg1.len(),
        1216,
        "msg1 must be 1216 bytes (e + e1 KEM pubkey)"
    );

    // msg2 contains an ML-KEM-768 ciphertext (1088 bytes) plus overhead
    assert_eq!(
        msg2.len(),
        1200,
        "msg2 must be 1200 bytes (e + ee + s + es + ekem1 ciphertext + AEAD tags)"
    );

    // msg3 = 32 (s encrypted) + 16 (se AEAD tag) + 16 (payload AEAD tag) = 64 bytes
    assert_eq!(msg3.len(), 64, "msg3 must be 64 bytes (s + se tokens)");

    // Both sides must agree on the handshake hash within a single run.
    assert_eq!(
        init_hash, resp_hash,
        "initiator and responder handshake hashes must agree"
    );

    // Hash must be non-trivial.
    assert_ne!(init_hash, [0u8; 32], "handshake hash must be non-trivial");
}

/// Confirms that a second independent handshake also produces coherent results.
///
/// Because ML-KEM generate() uses system entropy, hashes are not reproducible
/// across runs. This test therefore only checks intra-run consistency: that
/// each side of the second handshake agrees with the other, and that message
/// lengths conform to the protocol specification.
#[test]
fn second_run_produces_coherent_results() {
    let ([msg1, msg2, msg3], init_hash, resp_hash) = run_seeded_handshake(3, 4);

    assert_eq!(msg1.len(), 1216, "msg1 must be 1216 bytes");
    assert_eq!(
        msg2.len(),
        1200,
        "msg2 must be 1200 bytes (e + ee + s + es + ekem1 ciphertext + AEAD tags)"
    );
    assert_eq!(msg3.len(), 64, "msg3 must be 64 bytes");

    assert_eq!(
        init_hash, resp_hash,
        "initiator and responder must agree on handshake hash"
    );
    assert_ne!(init_hash, [0u8; 32], "handshake hash must be non-trivial");
}

// ---------------------------------------------------------------------------
// Vector generator — prints message sizes and verifies intra-run hash
// agreement. Run with `-- --ignored --nocapture`.
// Note: HANDSHAKE_HASH bytes vary across runs because ML-KEM generate()
// uses system entropy; only intra-run consistency can be asserted here.
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn print_vectors() {
    let ([msg1, msg2, msg3], init_hash, resp_hash) = run_seeded_handshake(1, 2);

    println!("msg1 ({} bytes): {}", msg1.len(), hex_string(&msg1));
    println!("msg2 ({} bytes): {}", msg2.len(), hex_string(&msg2));
    println!("msg3 ({} bytes): {}", msg3.len(), hex_string(&msg3));
    println!("HANDSHAKE_HASH (initiator): {:?}", init_hash);
    println!("HANDSHAKE_HASH (responder): {:?}", resp_hash);

    // Both sides must compute the same handshake hash within a single run.
    assert_eq!(
        init_hash, resp_hash,
        "initiator and responder handshake hashes must agree"
    );

    // Hash must be non-trivial (not all zeroes).
    assert_ne!(init_hash, [0u8; 32], "handshake hash must be non-trivial");

    // Message sizes must match the XXhfs pattern geometry.
    // msg1 = 32 (e) + 1184 (e1/ML-KEM-768 pubkey) = 1216 bytes
    assert_eq!(msg1.len(), 1216, "msg1 must be 1216 bytes");
    // msg2 = 32 (e) + 16 (ee AEAD tag) + 32 (s encrypted) + 16 (es AEAD tag)
    //      + 1088 (ekem1 ciphertext) + 16 (ekem1 AEAD tag) = 1200 bytes
    assert_eq!(msg2.len(), 1200, "msg2 must be 1200 bytes");
    // msg3 = 32 (s encrypted) + 16 (se AEAD tag) + 16 (payload AEAD tag) = 64 bytes
    assert_eq!(msg3.len(), 64, "msg3 must be 64 bytes");
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
