# Quic.jl

A pure Julia implementation of the QUIC transport protocol (RFC 9000) with support for TLS 1.3 handshake, JAMNP-S networking, and optional Quiche FFI bindings for production use.

## Features

- **QUIC v1** - Full packet structure, frames, and connection management
- **TLS 1.3** - ClientHello, ServerHello, Certificate, CertificateVerify messages
- **Cryptography** - ChaCha20-Poly1305, AES-128-GCM, HKDF via libsodium/MbedTLS
- **Ed25519** - Keypair generation, signing, verification
- **X25519** - ECDHE key exchange (RFC 7748)
- **X.509** - Certificate generation with Subject Alternative Name extension
- **JAMNP-S** - JAM Simple Networking Protocol implementation
- **Quiche FFI** - Optional bindings to Cloudflare's quiche library

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/parity/quic.jl")
```

Or for development:

```julia
Pkg.develop(path="/path/to/quic.jl")
```

## Quick Start

### Basic QUIC Connection

```julia
using Quic

# Create endpoint
endpoint = Endpoint("0.0.0.0", 4433)

# Connect to server
conn = connect(endpoint, "server.example.com", 443)

# Send data on stream
stream_id = open_stream!(conn, :bidirectional)
send_stream(conn, stream_id, b"Hello, QUIC!")

# Receive response
data = recv_stream(conn, stream_id)
```

### JAMNP-S (JAM Networking)

```julia
using Quic.JAMNPS

# Generate identity (Ed25519 keypair + X.509 certificate)
identity = generate_identity()

# Derive alt name from public key
alt_name = derive_alt_name(identity.keypair.public_key)

# Create ALPN protocol identifier
genesis_hash = hex2bytes("0123456789abcdef...")
alpn = make_alpn(genesis_hash)  # "jamnp-s/0/01234567"

# Determine connection initiator
initiator = preferred_initiator(my_key, peer_key)
```

### Cryptographic Operations

```julia
using Quic.Crypto
using Quic.Ed25519
using Quic.X25519

# Ed25519 signatures
keypair = Ed25519.generate_keypair()
signature = Ed25519.sign(message, keypair)
valid = Ed25519.verify(signature, message, keypair.public_key)

# X25519 key exchange
alice_priv, alice_pub = X25519.generate_keypair()
bob_priv, bob_pub = X25519.generate_keypair()
shared_secret = X25519.compute_shared_secret(alice_priv, bob_pub)

# ChaCha20-Poly1305 encryption
ctx = CryptoContext()
ciphertext = encrypt_payload(ctx, plaintext, key, iv, packet_number, aad)
plaintext = decrypt_payload(ctx, ciphertext, key, iv, packet_number, aad)

# HKDF key derivation
secret = hkdf_extract(ikm, salt)
derived = hkdf_expand_label(secret, "quic key", context, 16)
```

### X.509 Certificates

```julia
using Quic.X509
using Quic.Ed25519

keypair = Ed25519.generate_keypair()

# Generate self-signed certificate
cert = generate_x509_certificate(
    keypair;
    subject_cn="MyService",
    alt_name="ecustom.alt.name"
)

# Extract public key from certificate
pubkey = extract_public_key(cert)
```

## Architecture

```
Quic.jl/
├── src/
│   ├── Quic.jl              # Main module
│   ├── protocol.jl          # QUIC constants and types
│   ├── packet.jl            # Packet structures
│   ├── frame.jl             # QUIC frames
│   ├── crypto.jl            # ChaCha20-Poly1305, AES-GCM, HKDF
│   ├── ed25519.jl           # Ed25519 via libsodium
│   ├── x25519.jl            # X25519 ECDHE
│   ├── x509.jl              # X.509 certificate generation
│   ├── handshake.jl         # TLS 1.3 handshake messages
│   ├── stream.jl            # Stream management
│   ├── connection.jl        # Connection state machine
│   ├── endpoint.jl          # UDP endpoint management
│   ├── congestion.jl        # Congestion control (NewReno, CUBIC)
│   ├── loss_detection.jl    # Loss detection and recovery
│   ├── packet_pacing.jl     # Packet pacing
│   ├── jamnps.jl            # JAMNP-S protocol
│   ├── jamnps_connection.jl # JAMNP-S connection management
│   ├── quiche_ffi.jl        # Quiche FFI bindings
│   └── http3.jl             # HTTP/3 support
├── test/
│   └── runtests.jl
├── benchmark/
│   └── jamnps_benchmark.jl
└── examples/
```

## Performance

Benchmark results on typical hardware (see `benchmark/jamnps_benchmark.jl`):

| Operation | Time |
|-----------|------|
| ChaCha20-Poly1305 (1200 bytes) | ~1.2 μs |
| Ed25519 Sign | ~24 μs |
| Ed25519 Verify | ~48 μs |
| X.509 Certificate Generation | ~36 μs |
| HKDF Initial Secrets | ~89 μs |
| X25519 Shared Secret | ~1.1 ms |

## Quiche FFI (Production)

For production deployments, use the Quiche FFI bindings:

```julia
using Quic.QuicheFFI

# Get quiche version
version = quiche_version()

# Create JAMNP-S configuration
genesis = rand(UInt8, 32)
config = jamnps_config(genesis)

# Create connection
conn = quiche_connect(host, scid, local_addr, remote_addr, config)
```

Build quiche with:

```bash
cd ~/quiche-ffi
cargo build --release
```

## Testing

```julia
using Pkg
Pkg.test("Quic")
```

Run benchmarks:

```bash
julia benchmark/jamnps_benchmark.jl
```

## Dependencies

- **Sodium.jl** - libsodium bindings for Ed25519, X25519
- **MbedTLS.jl** - AES-GCM encryption
- **SHA.jl** - SHA-256 for HKDF
- **Sockets.jl** - UDP networking

## Supported RFCs

- RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001 - Using TLS to Secure QUIC
- RFC 8446 - TLS 1.3
- RFC 7748 - X25519 Elliptic Curve Diffie-Hellman
- RFC 8032 - Ed25519 Digital Signatures

## JAMNP-S Protocol

This library implements the JAM Simple Networking Protocol for JAM validator communication:

- Alternative name derivation from Ed25519 public keys
- ALPN protocol identifiers (`jamnp-s/V/H`)
- Preferred initiator selection
- UP (Unique Persistent) and CE (Common Ephemeral) streams
- Block announcements, work package distribution, etc.

## Contributing

Contributions welcome! Please ensure:

1. All tests pass: `julia test/runtests.jl`
2. Code follows Julia style conventions
3. New features include tests and documentation

## License

MIT License

## See Also

- [quinn](https://github.com/quinn-rs/quinn) - Rust QUIC implementation
- [quiche](https://github.com/cloudflare/quiche) - Cloudflare's QUIC library
- [JAM Graypaper](https://graypaper.com) - JAM specification
