# Quic.jl

A production-ready pure Julia implementation of the QUIC transport protocol (RFC 9000) with TLS 1.3 handshake, GFW mitigation, and MLS support. Native performance matches or exceeds Cloudflare's quiche.

## Features

- **QUIC v1** - Full packet structure, frames, and connection management
- **TLS 1.3** - Complete handshake (ClientHello, ServerHello, Certificate, CertificateVerify, Finished)
- **Cryptography** - ChaCha20-Poly1305, AES-128-GCM, HKDF via libsodium/MbedTLS
- **Ed25519** - Keypair generation, signing, verification for certificate authentication
- **X25519** - ECDHE key exchange (RFC 7748)
- **X.509** - Certificate generation with Subject Alternative Name extension
- **Quiche FFI** - Optional bindings to Cloudflare's quiche for interop testing
- **GFW Mitigation** - Censorship circumvention for restrictive networks
- **MLS (QUIC-MLS)** - Messaging Layer Security for group key management

## Status

**Production Ready** - Full RFC 9000/9001/9002 compliance with:

- Complete TLS 1.3 handshake with mutual authentication
- AEAD encryption with header protection (AES-128-GCM, ChaCha20-Poly1305)
- Loss detection and recovery (RFC 9002)
- Congestion control (NewReno, CUBIC)
- Stream multiplexing and flow control
- Connection migration
- 0-RTT support
- Coalesced packet handling
- Full IPv6 support

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/rotkonetworks/Quic.jl")
```

Or for development:

```julia
Pkg.develop(path="/path/to/quic.jl")
```

## Quick Start

### QuicClient API (Primary Interface)

The `QuicClient` module provides the primary high-level API for QUIC connections:

```julia
using Quic
using Sockets

# Create configuration
config = QuicConfig(
    "jamnp-s";                              # ALPN protocol identifier
    server_name = "validator.example.com",  # SNI for TLS
    idle_timeout_ms = UInt64(30000),        # 30 second timeout
    max_streams = UInt64(100)               # Max concurrent streams
)

# Optional: Add Ed25519 identity for mutual TLS authentication
# config = QuicConfig(
#     "jamnp-s";
#     ed25519_keypair = Ed25519.generate_keypair(),
#     certificate = my_cert_der
# )

# Create UDP socket and connection
socket = UDPSocket()
conn = QuicConnection(config, socket, true)  # true = client mode

# Initiate connection
connect!(conn, "validator.example.com", UInt16(4433))

# Receive and process server response
data, addr = recvfrom(socket)
process_packet!(conn, data)

# Check connection state
if conn.state == CONNECTED
    # Open a stream
    stream_id = open_stream!(conn)

    # Send data
    send_stream_data!(conn, stream_id, b"Hello, QUIC!", true)
end

# Close connection
close!(conn)
```

### Connection States

```julia
@enum ConnectionState begin
    DISCONNECTED  # Initial state
    CONNECTING    # DNS resolution / socket setup
    HANDSHAKING   # TLS 1.3 handshake in progress
    CONNECTED     # Ready for application data
    CLOSING       # Connection close initiated
    CLOSED        # Connection terminated
end
```

### Endpoint API (Server/Client Setup)

For simpler server/client setup with GFW mitigation support:

```julia
using Quic

# Standard endpoint
config = EndpointConfig(
    server_name = "example.com",
    alpn_protocols = ["h3", "jamnp-s"],
    max_idle_timeout_ms = UInt64(30000)
)
endpoint = Endpoint(Sockets.InetAddr(ip"0.0.0.0", 4433), config, true)

# China-optimized endpoint with GFW mitigation
china_config = ChinaEndpointConfig(
    server_name = "example.com",
    alpn_protocols = ["h3"]
)
china_endpoint = Endpoint(addr, china_config, false)

# Connect to server
conn = connect(endpoint, server_addr)

# Accept incoming connection (server)
conn = accept(endpoint)
```

### Cryptographic Operations

```julia
using Quic

# Access internal modules for direct crypto operations
import Quic: Ed25519, X25519, Crypto

# Ed25519 signatures
keypair = Ed25519.generate_keypair()
signature = Ed25519.sign(message, keypair)
valid = Ed25519.verify(signature, message, keypair.public_key)

# X25519 key exchange
alice_priv, alice_pub = X25519.generate_keypair()
bob_priv, bob_pub = X25519.generate_keypair()
shared_secret = X25519.compute_shared_secret(alice_priv, bob_pub)

# AEAD encryption (AES-128-GCM)
ciphertext = Crypto.encrypt_aes_gcm(plaintext, key, iv, packet_number, aad, Crypto.AES128GCM())
plaintext = Crypto.decrypt_aes_gcm(ciphertext, key, iv, packet_number, aad, Crypto.AES128GCM())

# HKDF key derivation
secret = Crypto.hkdf_extract(ikm, salt)
derived = Crypto.hkdf_expand_label(secret, "quic key", context, 16)
```

### X.509 Certificates

```julia
using Quic
import Quic: X509, Ed25519

keypair = Ed25519.generate_keypair()

# Generate self-signed certificate
cert = X509.generate_x509_certificate(
    keypair;
    subject_cn = "MyService",
    alt_name = "custom.alt.name"
)

# Extract public key from certificate
pubkey = X509.extract_public_key(cert)
```

## API Reference

### Core Exports

```julia
# Connection API (QuicClient module)
export QuicConnection, QuicConfig, ConnectionState
export DISCONNECTED, CONNECTING, HANDSHAKING, CONNECTED, CLOSED
export connect!, process_packet!, send_stream_data!, open_stream!, close!

# Endpoint API
export Endpoint, EndpointConfig, ChinaEndpointConfig
export connect, accept

# GFW Mitigation
export GFWMitigationConfig, china_config, aggressive_config
export MITIGATION_NONE, MITIGATION_DUMMY_PREFIX, MITIGATION_SNI_FRAGMENTATION
export MITIGATION_PORT_SELECTION, MITIGATION_ALL

# MLS (Messaging Layer Security)
export QuicMLSConnection, QuicMLSConfig, QuicMLSKeys
export QUIC_MLS_CLIENT, QUIC_MLS_SERVER
export init_quic_mls_client, init_quic_mls_server
export process_crypto_data, get_crypto_data_to_send
export is_handshake_complete, get_quic_keys

# Benchmarks
export run_benchmarks, compare_with_quiche
```

### QuicConfig Fields

| Field | Type | Description |
|-------|------|-------------|
| `alpn` | `String` | ALPN protocol identifier (e.g., "h3", "jamnp-s") |
| `server_name` | `String?` | Server Name Indication for TLS |
| `idle_timeout_ms` | `UInt64` | Connection idle timeout (default: 30000) |
| `max_streams` | `UInt64` | Maximum concurrent streams (default: 100) |
| `ed25519_keypair` | `Ed25519.KeyPair?` | Optional keypair for client certificate |
| `certificate` | `Vector{UInt8}?` | Optional DER-encoded certificate |

### QuicConnection Fields

| Field | Type | Description |
|-------|------|-------------|
| `state` | `ConnectionState` | Current connection state |
| `peer_pubkey` | `Vector{UInt8}?` | Peer's Ed25519 public key from certificate |
| `on_connected` | `Function?` | Callback when connection established |
| `on_stream_data` | `Function?` | Callback for incoming stream data |

## Architecture

```
Quic.jl/
├── src/
│   ├── Quic.jl              # Main module and exports
│   ├── protocol.jl          # QUIC constants, VarInt encoding
│   ├── packet.jl            # Packet structures (Initial, Handshake, Short)
│   ├── frame.jl             # QUIC frames (CRYPTO, STREAM, ACK, etc.)
│   ├── crypto.jl            # ChaCha20-Poly1305, AES-GCM, HKDF
│   ├── ed25519.jl           # Ed25519 via libsodium
│   ├── x25519.jl            # X25519 ECDHE
│   ├── x509.jl              # X.509 certificate generation
│   ├── handshake.jl         # TLS 1.3 handshake messages
│   ├── stream.jl            # Stream management
│   ├── quic_client.jl       # High-level QuicClient API
│   ├── connection.jl        # Connection state machine
│   ├── endpoint.jl          # UDP endpoint management
│   ├── packet_coalescing.jl # Coalesced packet handling
│   ├── congestion.jl        # Congestion control (NewReno, CUBIC)
│   ├── loss_detection.jl    # Loss detection and recovery
│   ├── packet_pacing.jl     # Packet pacing
│   ├── zero_rtt.jl          # 0-RTT support
│   ├── version_negotiation.jl # Version negotiation
│   ├── retry.jl             # Retry packet handling
│   ├── quiche_ffi.jl        # Quiche FFI bindings
│   ├── http3.jl             # HTTP/3 support
│   ├── gfw_mitigation.jl    # GFW censorship circumvention
│   ├── cert_generator.jl    # Certificate utilities
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
└── examples/
    ├── jamnps.jl            # JAM networking protocol example
    └── jamnps_connection.jl # JAMNP-S connection example
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

Cryptographic operations:

| Operation | Time |
|-----------|------|
| ChaCha20-Poly1305 (1200 bytes) | ~1.2 μs |
| AES-128-GCM (1200 bytes) | ~0.98 μs |
| Ed25519 Sign | ~24 μs |
| Ed25519 Verify | ~48 μs |
| X.509 Certificate Generation | ~36 μs |
| HKDF Initial Secrets | ~89 μs |
| X25519 Shared Secret | ~1.1 ms |

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
config = ChinaEndpointConfig(server_name = "example.com")
endpoint = Endpoint(addr, config, false)

# Connect with mitigations automatically applied
conn = connect(endpoint, server_addr)
```

### Custom Configuration

```julia
using Quic

# Create custom mitigation config
config = GFWMitigationConfig(
    enabled = true,
    strategies = UInt8(MITIGATION_DUMMY_PREFIX) | UInt8(MITIGATION_SNI_FRAGMENTATION),
    dummy_packet_size_range = (10, 64),
    dummy_packet_delay_ms = 1,
    fragment_count = 3,
    fragment_size_variance = 0.2,
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
config = default_config()

# Optimized for China
config = china_config()

# Maximum evasion (may impact performance)
config = aggressive_config()
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

## Quiche FFI (Optional)

Alternative Quiche FFI bindings are available for interoperability testing:

```julia
using Quic.QuicheFFI

# Get quiche version
version = quiche_version()

# Create configuration and connection
config = quiche_config_new(QUIC_VERSION_1)
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

```julia
using Quic
run_benchmarks()
compare_with_quiche()
```

## Dependencies

- **Sodium.jl** - libsodium bindings for Ed25519, X25519, ChaCha20-Poly1305
- **MbedTLS.jl** - AES-GCM encryption
- **SHA.jl** - SHA-256 for HKDF
- **Sockets.jl** - UDP networking
- **Base64.jl** - Certificate encoding

## Supported RFCs

- RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 9001 - Using TLS to Secure QUIC
- RFC 9002 - QUIC Loss Detection and Congestion Control
- RFC 9420 - The Messaging Layer Security (MLS) Protocol
- RFC 8446 - TLS 1.3
- RFC 7748 - X25519 Elliptic Curve Diffie-Hellman
- RFC 8032 - Ed25519 Digital Signatures
- draft-tian-quic-quicmls - QUIC-MLS Integration

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
- [ngtcp2](https://github.com/ngtcp2/ngtcp2) - C QUIC implementation
- [litep2p](https://github.com/paritytech/litep2p) - Rust p2p networking library
