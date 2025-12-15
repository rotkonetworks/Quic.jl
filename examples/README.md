# Quic.jl Examples

Examples demonstrating QUIC features including TLS 1.3, MLS key exchange, and protocol extensions.

## Example Files

### MLS (Messaging Layer Security)
- `mls_handshake.jl` - **QUIC-MLS key exchange demo** (RFC 9420)
  - KeyPackage/Welcome exchange
  - Traffic key derivation
  - AEAD encryption with MLS-derived keys

### Core QUIC Examples
- `quic_server.jl` - Full QUIC server implementation
- `quic_bidirectional_client.jl` - Complete bidirectional client
- `simple_client.jl` / `simple_server.jl` - Basic QUIC connection
- `zero_rtt_client.jl` - 0-RTT early data demonstration

### HTTP/3
- `http3_client.jl` - HTTP/3 client implementation
- `http3_server.jl` - HTTP/3 server implementation

### Quinn (Rust) Interoperability
- `quinn_client.jl` - Basic Quinn interop client
- `quinn_client_with_loss_detection.jl` - Loss detection demo
- `quinn_client_with_cid_rotation.jl` - Connection ID rotation
- `quinn_client_with_pacing.jl` - Packet pacing demonstration
- `quinn_interop.jl` - Full interop test suite

### Protocol Extensions
- `jamnps.jl` - JAM Simple Networking Protocol (JAMNP-S) implementation
- `jamnps_connection.jl` - JAMNP-S connection management
- `jamnps_benchmark.jl` - JAMNP-S performance benchmarks

## Running the Examples

### MLS Key Exchange Demo
```bash
julia --project=. examples/mls_handshake.jl
```

### QUIC Server/Client
```bash
# Terminal 1: Start server
julia --project=. examples/quic_server.jl

# Terminal 2: Run client
julia --project=. examples/quic_bidirectional_client.jl
```

### HTTP/3
```bash
# Terminal 1: Start HTTP/3 server
julia --project=. examples/http3_server.jl

# Terminal 2: Run HTTP/3 client
julia --project=. examples/http3_client.jl
```

### Quinn Interop
```bash
# Start Rust Quinn server
cargo run --example server

# Run Julia client
julia --project=. examples/quinn_client_with_pacing.jl
```

## Features Demonstrated

- TLS 1.3 handshake with X25519 ECDHE
- MLS (RFC 9420) key exchange as TLS alternative
- ChaCha20-Poly1305 and AES-GCM encryption
- Loss detection and retransmission
- Packet pacing and congestion control
- Connection ID rotation and path migration
- Bidirectional stream multiplexing
- 0-RTT early data
- HTTP/3 over QUIC