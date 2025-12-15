# Quic.jl

A production-ready pure Julia implementation of the QUIC transport protocol (RFC 9000) with TLS 1.3 handshake, JAMNP-S networking, GFW mitigation, and MLS support. Native performance matches or exceeds Cloudflare's quiche.

## Features

- **QUIC v1** - Full packet structure, frames, and connection management
- **TLS 1.3** - ClientHello, ServerHello, Certificate, CertificateVerify messages
- **Cryptography** - ChaCha20-Poly1305, AES-128-GCM, HKDF via libsodium/MbedTLS
- **Ed25519** - Keypair generation, signing, verification
- **X25519** - ECDHE key exchange (RFC 7748)
- **X.509** - Certificate generation with Subject Alternative Name extension
- **JAMNP-S** - JAM Simple Networking Protocol implementation
- **Quiche FFI** - Optional bindings to Cloudflare's quiche for interop testing
- **GFW Mitigation** - Censorship circumvention for restrictive networks
- **MLS (QUIC-MLS)** - Messaging Layer Security for group key management

## Status

**Production Ready** - Full RFC 9000/9001/9002 compliance with:

- Complete TLS 1.3 handshake (ClientHello, ServerHello, Certificate, CertificateVerify, Finished)
- AEAD encryption with header protection (AES-128-GCM, ChaCha20-Poly1305)
- Loss detection and recovery (RFC 9002)
- Congestion control (NewReno, CUBIC)
- Stream multiplexing and flow control
- Connection migration
- 0-RTT support
- IPv6 ready for JAM network deployment

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
│   ├── http3.jl             # HTTP/3 support
│   ├── gfw_mitigation.jl    # GFW censorship circumvention
│   └── mls/                 # MLS (QUIC-MLS) support
│       ├── MLS.jl           # Main MLS module
│       ├── mls_types.jl     # Core data structures
│       ├── mls_crypto.jl    # Cryptographic primitives
│       ├── mls_tree.jl      # Ratchet tree implementation
│       ├── mls_key_schedule.jl # Key derivation
│       ├── mls_handshake.jl # Group state machine
│       └── quic_mls.jl      # QUIC integration
├── test/
│   └── runtests.jl
├── benchmark/
│   └── jamnps_benchmark.jl
└── examples/
```

## Performance

Native Julia implementation performance vs Cloudflare quiche (lower is better):

| Operation | Quic.jl | quiche | Ratio |
|-----------|---------|--------|-------|
| Parse Long Header | 39 ns | 49 ns | 0.8x |
| Parse Short Header | 24 ns | 31 ns | 0.8x |
| Build Packet | 17 ns | 84 ns | 0.2x (5x faster) |
| AEAD Encrypt/Decrypt | 980 ns | 840 ns | 1.2x |
| **Overall** | - | - | **0.7x-0.8x** |

Cryptographic operations (see `benchmark/jamnps_benchmark.jl`):

| Operation | Time |
|-----------|------|
| ChaCha20-Poly1305 (1200 bytes) | ~1.2 μs |
| AES-128-GCM (1200 bytes) | ~0.98 μs |
| Ed25519 Sign | ~24 μs |
| Ed25519 Verify | ~48 μs |
| X.509 Certificate Generation | ~36 μs |
| HKDF Initial Secrets | ~89 μs |
| X25519 Shared Secret | ~1.1 ms |

## Quiche FFI (Optional)

Alternative Quiche FFI bindings are available for interoperability testing:

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
- RFC 9420 - The Messaging Layer Security (MLS) Protocol
- RFC 8446 - TLS 1.3
- RFC 7748 - X25519 Elliptic Curve Diffie-Hellman
- RFC 8032 - Ed25519 Digital Signatures
- draft-tian-quic-quicmls - QUIC-MLS Integration

## JAMNP-S Protocol

This library implements the JAM Simple Networking Protocol for JAM validator communication:

- Alternative name derivation from Ed25519 public keys
- ALPN protocol identifiers (`jamnp-s/V/H`)
- Preferred initiator selection
- UP (Unique Persistent) and CE (Common Ephemeral) streams
- Block announcements, work package distribution, etc.

## GFW Censorship Mitigation

This library includes built-in strategies to circumvent QUIC censorship, based on research from "Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China" (USENIX Security 2025).

### Mitigation Strategies

| Strategy | Description | Effectiveness |
|----------|-------------|---------------|
| **Dummy Packet Prefix** | Send random UDP before QUIC Initial | High - GFW only inspects first packet in flow |
| **SNI Fragmentation** | Split ClientHello across CRYPTO frames | High - GFW doesn't reassemble fragments |
| **Port Selection** | Ensure source_port ≤ dest_port | High - GFW ignores these packets |
| **Version Negotiation** | Send invalid version first | Medium - Triggers version negotiation |

### Quick Start (Censored Networks)

```julia
using Quic

# Use pre-configured China settings
config = ChinaEndpointConfig(server_name="example.com")
endpoint = Endpoint(addr, config, false)

# Connect with mitigations automatically applied
conn = connect(endpoint, server_addr)
```

### Custom Configuration

```julia
using Quic.GFWMitigation

# Create custom mitigation config
config = GFWMitigationConfig(
    enabled = true,
    strategies = MITIGATION_DUMMY_PREFIX | MITIGATION_SNI_FRAGMENTATION,
    dummy_packet_size_range = (10, 64),
    fragment_count = 3,
    chaos_mode = true  # Chrome-style frame shuffling
)

# Apply to endpoint
endpoint_config = EndpointConfig(
    server_name = "example.com",
    gfw_mitigation = config
)
```

### Available Presets

```julia
# Disabled (default)
config = GFWMitigation.default_config()

# Optimized for China
config = GFWMitigation.china_config()

# Maximum evasion (may impact performance)
config = GFWMitigation.aggressive_config()
```

### Server-Side Requirements

For best results with port selection:

```bash
# Server should listen on high port (e.g., 65535)
# Use iptables to redirect from standard QUIC port:
iptables -t nat -A PREROUTING -p udp --dport 65535 -j REDIRECT --to-port 443
```

### How It Works

1. **Flow Tracking Evasion**: The GFW tracks UDP flows for 60 seconds. By sending a non-QUIC packet first, subsequent QUIC packets are not inspected.

2. **SNI Hiding**: The GFW extracts SNI from QUIC Initial packets. By fragmenting the ClientHello across multiple CRYPTO frames, the SNI cannot be extracted from any single frame.

3. **Inspection Bypass**: The GFW only inspects packets where `source_port > dest_port`. By using source ports ≤ destination port, packets bypass inspection entirely.

## MLS (QUIC-MLS)

This library implements MLS (Messaging Layer Security, RFC 9420) for QUIC, following draft-tian-quic-quicmls. MLS replaces TLS 1.3 for key establishment, providing:

- **Forward secrecy** through epoch-based key derivation
- **Post-compromise security** via ratchet tree updates
- **Group key management** for future multi-party QUIC

### Quick Start (QUIC-MLS)

```julia
using Quic

# Server side
server_conn = Connection(socket, false;
    use_mls = true,
    mls_identity = Vector{UInt8}("server.example.com"))

# Client side
client_conn = Connection(socket, true;
    use_mls = true,
    mls_identity = Vector{UInt8}("client@example.com"))

# Initiate MLS handshake (instead of TLS)
initiate_mls_handshake(client_conn)

# Process incoming CRYPTO frames with MLS data
process_handshake_data(conn, crypto_data)

# Check if handshake is complete
if is_mls_handshake_complete(conn)
    # Keys are now derived from MLS epoch secret
    epoch = get_mls_epoch(conn)
    println("MLS established at epoch $epoch")
end
```

### Direct MLS API

```julia
using Quic.MLS

# Create MLS configuration
config = QuicMLSConfig(Vector{UInt8}("my-identity"))

# Initialize client (generates KeyPackage automatically)
client = init_quic_mls_client(config)

# Get KeyPackage to send in CRYPTO frame
kp_data = get_crypto_data_to_send(client)

# Initialize server
server = init_quic_mls_server(config)

# Server processes KeyPackage, generates Welcome
process_crypto_data(server, kp_data)
welcome_data = get_crypto_data_to_send(server)

# Client processes Welcome
process_crypto_data(client, welcome_data)

# Both sides now have keys
if is_handshake_complete(client)
    keys = get_quic_keys(client)
    # keys.client_key, keys.client_iv, keys.client_hp
    # keys.server_key, keys.server_iv, keys.server_hp
end
```

### Exporting Secrets

```julia
# Export application-specific secret from MLS
secret = mls_export_secret(conn, "my-app-label", context_data, 32)
```

### MLS vs TLS

| Feature | TLS 1.3 | MLS |
|---------|---------|-----|
| Key Exchange | ECDHE | Ratchet Tree |
| Forward Secrecy | Per-session | Per-epoch |
| Post-Compromise | No | Yes |
| Multi-party | No | Yes |
| Message Overhead | Lower | Higher |

### Supported Cipher Suites

- `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (default)
- `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`

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
