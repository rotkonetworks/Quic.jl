module Quic

#=
    Pure Julia QUIC v1 Implementation

    Architecture:
    - Public API: QuicClient module (primary), Endpoint module
    - Internal: Protocol implementation (tightly coupled modules)
    - Extensions: HTTP/3, MLS, GFW mitigation, benchmarks

    Note: Unlike litep2p (thin wrapper over quinn), this is a full QUIC
    implementation from scratch, similar to quinn itself. The module
    coupling reflects the inherent complexity of QUIC v1.
=#

# ============================================================================
# Public API Exports
# ============================================================================

# Core connection API (primary interface)
export QuicConnection, QuicConfig, ConnectionState
export DISCONNECTED, CONNECTING, HANDSHAKING, CONNECTED, CLOSED
export connect!, process_packet!, send_stream_data!, open_stream!, close!

# Endpoint API (server/client setup)
export Endpoint, EndpointConfig, ChinaEndpointConfig
export connect, accept

# ============================================================================
# Internal Implementation
# ============================================================================

# Logging (loaded first for use by other modules)
include("logging.jl")

# Core protocol types and constants
include("protocol.jl")

# GFW censorship mitigation (after protocol for VarInt)
include("gfw_mitigation.jl")

# Packet and frame handling
include("packet.jl")
include("frame.jl")

# Cryptography
include("crypto.jl")
include("ed25519.jl")
include("x509.jl")
include("x25519.jl")

# Stream and packet management
include("stream.jl")
include("packet_codec.jl")
include("version_negotiation.jl")
include("retry.jl")
include("packet_coalescing.jl")
include("zero_rtt.jl")

# TLS 1.3 handshake
include("handshake.jl")

# Reliability
include("loss_detection.jl")
include("packet_pacing.jl")
include("connection_id_manager.jl")

# HTTP/3 and protocol extensions
include("http3.jl")
include("quicnet_protocol.jl")

# MLS (Messaging Layer Security)
include("mls/MLS.jl")

# Connection modules
include("connection.jl")
include("quic_client.jl")
include("packet_receiver.jl")
include("endpoint.jl")
include("congestion.jl")
include("transport.jl")

# Performance and benchmarking
include("perf.jl")
include("packet_fast.jl")
include("benchmark.jl")

# FFI bindings to quiche (optional)
include("quiche_ffi.jl")

# Certificate generation utilities
include("cert_generator.jl")

# ============================================================================
# Re-exports from modules
# ============================================================================

# QuicClient - primary API
using .QuicClient: QuicConnection, QuicConfig, ConnectionState
using .QuicClient: DISCONNECTED, CONNECTING, HANDSHAKING, CONNECTED, CLOSED
using .QuicClient: connect!, process_packet!, send_stream_data!, open_stream!

# Endpoint
using .EndpointModule: Endpoint, EndpointConfig, ChinaEndpointConfig, connect, accept

# Legacy connection module
using .ConnectionModule: Connection, send_stream

# ============================================================================
# Extension Re-exports
# ============================================================================

# GFW Mitigation
export GFWMitigationConfig, china_config, aggressive_config
export MITIGATION_NONE, MITIGATION_DUMMY_PREFIX, MITIGATION_SNI_FRAGMENTATION
export MITIGATION_PORT_SELECTION, MITIGATION_ALL
using .GFWMitigation: GFWMitigationConfig, china_config, aggressive_config, default_config
using .GFWMitigation: MITIGATION_NONE, MITIGATION_DUMMY_PREFIX, MITIGATION_SNI_FRAGMENTATION
using .GFWMitigation: MITIGATION_PORT_SELECTION, MITIGATION_ALL

# MLS exports
export QuicMLSConnection, QuicMLSConfig, QuicMLSKeys
export QUIC_MLS_CLIENT, QUIC_MLS_SERVER
export init_quic_mls_client, init_quic_mls_server
export process_crypto_data, get_crypto_data_to_send
export is_handshake_complete, get_quic_keys
using .MLS: QuicMLSConnection, QuicMLSConfig, QuicMLSKeys
using .MLS: QUIC_MLS_CLIENT, QUIC_MLS_SERVER
using .MLS: init_quic_mls_client, init_quic_mls_server
using .MLS: process_crypto_data, get_crypto_data_to_send
using .MLS: is_handshake_complete, get_quic_keys

# Benchmarks
export run_benchmarks, compare_with_quiche
using .Benchmark: run_benchmarks, compare_with_quiche

end # module Quic
