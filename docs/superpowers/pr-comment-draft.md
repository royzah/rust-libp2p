# Cross-language interop + structural tests + benchmarks added

We've been working on cross-language PQC interop across the libp2p ecosystem (JS: js-libp2p-noise PR #665, Python: py-libp2p PR #1310) and wanted to contribute the Rust side of that work here.

## 1. Live Rust ↔ Python interop — it works ✓

We wrote a standalone Python dialer (`py-libp2p/scripts/interop_dial_mlkem768.py`) that speaks `Noise_XXhfs_25519+ML-KEM-768_ChaChaPoly_SHA256` directly (using `kyber-py`'s ML_KEM_768 for the KEM), then dialed the `noise_hfs_listener` binary live:

```
# Terminal 1
cargo run --example noise_hfs_listener --features mlkem-hfs -- 9999

# Terminal 2
cd py-libp2p && python scripts/interop_dial_mlkem768.py --port 9999

# Output
msg1 sent: 1216 bytes (e_pk=32, e1_pk=1184)
msg2 received: 1304 bytes
msg2: responder identity verified, peer=12D3KooWHvA2VB6DBguv9i27jy41SbYexFub8bXRmucFUevAGaWJ
msg3 sent: 168 bytes
PEER 12D3KooWHvA2VB6DBguv9i27jy41SbYexFub8bXRmucFUevAGaWJ
HANDSHAKE COMPLETE
```

Both sides completed mutual authentication (identity signatures verified) and the three-message handshake succeeded end-to-end. **Message geometry confirmed: msg1=1216B, msg2=1304B, msg3=168B** (the 1304B reflects the identity payload size from Rust's libp2p-noise protobuf encoding).

Note on the X-Wing variant: our existing JS and Python implementations use X-Wing (ML-KEM-768 + X25519 bundled as one KEM, protocol `/noise-pq/1.0.0`) — a valid but distinct approach from this PR's raw ML-KEM-768 pattern. The two protocols are not wire-compatible; that's expected and worth calling out for specs#723.

## 2. Structural compliance tests (`tests/interop_hfs.rs`)

`SeededResolver` pins the X25519 static keys, but ML-KEM ephemeral keys still use system entropy — the snow fork's `generate()` bypasses the seeded RNG. Tests assert what can be determined deterministically:

- **Intra-run hash agreement**: both initiator and responder compute the same handshake hash.
- **Message length geometry**: msg1=1216B, msg2=1200B (snow-level, no identity payload), msg3=64B.

## 3. Interop listener binary (`examples/noise_hfs_listener.rs`)

```
cargo run --example noise_hfs_listener --features mlkem-hfs -- 9999
```

Prints `READY <port>` then `PEER <peer_id>` on success. Tested with the Python dialer above.

## 4. Criterion benchmarks (`benches/noise_hfs.rs`)

Classical Noise XX vs XXhfs handshake latency + 1KB transport throughput.

```
cargo bench --features mlkem-hfs
```

---

## Finding: snow's ML-KEM entropy bypasses the seeded resolver

The snow fork's `generate()` in `DefaultResolver` calls system entropy directly, ignoring the injected `CryptoResolver`. This prevents fully deterministic cross-language test vectors (needed for specs#723 question 2). Worth considering a seeded generation path in the fork for interop testing.

## Suggestion: RustCrypto `ml-kem` swap

`Resolver::resolve_kem()` delegates to snow's `DefaultResolver`, whose ML-KEM backend is marked unaudited. The RustCrypto `ml-kem` crate (FIPS 203 compliant, audited by NCC Group) could replace it by implementing `snow::types::Kem` directly — same pattern as the existing `x25519-dalek` DH wrapper. Happy to write that as a follow-up if you're open to it.

---

Thanks for shepherding the XXhfs spec forward!
