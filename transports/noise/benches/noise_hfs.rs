//! Benchmarks comparing classical Noise XX vs hybrid Noise XXhfs
//! (X25519 + ML-KEM-768).
//!
//! Run with:
//! ```bash
//! cargo bench --features mlkem-hfs
//! ```

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use futures::{
    executor::block_on,
    future::try_join,
    io::{AsyncReadExt, AsyncWriteExt},
};
use libp2p_core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade};
use libp2p_identity as identity;
use libp2p_noise as noise;

const CLASSICAL: &str = "/noise";
const HFS: &str = "/noise-mlkem768-hfs/0.1.0";

// ---------------------------------------------------------------------------
// Handshake benchmarks
// ---------------------------------------------------------------------------

fn bench_xx_handshake(c: &mut Criterion) {
    c.bench_function("noise_xx_classical_handshake", |b| {
        b.iter_batched(
            || {
                let server_id = identity::Keypair::generate_ed25519();
                let client_id = identity::Keypair::generate_ed25519();
                let (client_sock, server_sock) = futures_ringbuf::Endpoint::pair(65535, 65535);
                (server_id, client_id, client_sock, server_sock)
            },
            |(server_id, client_id, client_sock, server_sock)| {
                block_on(try_join(
                    noise::Config::new(&server_id)
                        .unwrap()
                        .upgrade_inbound(server_sock, CLASSICAL),
                    noise::Config::new(&client_id)
                        .unwrap()
                        .upgrade_outbound(client_sock, CLASSICAL),
                ))
                .unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_xxhfs_handshake(c: &mut Criterion) {
    c.bench_function("noise_xxhfs_mlkem768_handshake", |b| {
        b.iter_batched(
            || {
                let server_id = identity::Keypair::generate_ed25519();
                let client_id = identity::Keypair::generate_ed25519();
                let (client_sock, server_sock) = futures_ringbuf::Endpoint::pair(65535, 65535);
                (server_id, client_id, client_sock, server_sock)
            },
            |(server_id, client_id, client_sock, server_sock)| {
                block_on(try_join(
                    noise::Config::new(&server_id)
                        .unwrap()
                        .upgrade_inbound(server_sock, HFS),
                    noise::Config::new(&client_id)
                        .unwrap()
                        .upgrade_outbound(client_sock, HFS),
                ))
                .unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

// ---------------------------------------------------------------------------
// Transport throughput benchmark (post-handshake)
// ---------------------------------------------------------------------------

fn bench_xxhfs_transport_1kb(c: &mut Criterion) {
    c.bench_function("noise_xxhfs_transport_send_1kb", |b| {
        b.iter_batched(
            || {
                let server_id = identity::Keypair::generate_ed25519();
                let client_id = identity::Keypair::generate_ed25519();
                let (client_sock, server_sock) = futures_ringbuf::Endpoint::pair(65535, 65535);

                let ((_, server_io), (_, client_io)) = block_on(try_join(
                    noise::Config::new(&server_id)
                        .unwrap()
                        .upgrade_inbound(server_sock, HFS),
                    noise::Config::new(&client_id)
                        .unwrap()
                        .upgrade_outbound(client_sock, HFS),
                ))
                .unwrap();
                let payload = vec![0u8; 1024];
                (server_io, client_io, payload)
            },
            |(mut server_io, mut client_io, payload)| {
                block_on(async move {
                    client_io.write_all(&payload).await.unwrap();
                    client_io.flush().await.unwrap();
                    let mut buf = vec![0u8; 1024];
                    server_io.read_exact(&mut buf).await.unwrap();
                    buf
                })
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_xx_handshake,
    bench_xxhfs_handshake,
    bench_xxhfs_transport_1kb
);
criterion_main!(benches);
