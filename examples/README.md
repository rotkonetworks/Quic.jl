# Quic.jl Examples

## Core QUIC
- `simple_client.jl` / `simple_server.jl` - Basic QUIC connection
- `quic_server.jl` - Full-featured QUIC server
- `zero_rtt_client.jl` - 0-RTT early data

## HTTP/3
- `http3_client.jl` - HTTP/3 client
- `http3_server.jl` - HTTP/3 server

## MLS (RFC 9420)
- `mls_handshake.jl` - QUIC-MLS key exchange demo

## Interoperability
- `quinn_interop.jl` - Quinn (Rust) interop test

## JAMNP-S Reference
- `jamnps.jl` - JAM networking protocol implementation
- `jamnps_connection.jl` - JAMNP-S connection management
- `jamnps_benchmark.jl` - Performance benchmarks

## Running Examples

```bash
# Basic QUIC
julia --project=. examples/simple_server.jl  # Terminal 1
julia --project=. examples/simple_client.jl  # Terminal 2

# MLS handshake demo
julia --project=. examples/mls_handshake.jl

# HTTP/3
julia --project=. examples/http3_server.jl   # Terminal 1
julia --project=. examples/http3_client.jl   # Terminal 2
```
