module Quic

# re-exports and public api
export Endpoint, EndpointConfig, ChinaEndpointConfig, Connection, Config
export connect, accept, send_stream, recv_stream

# GFW mitigation exports
export GFWMitigationConfig, china_config, aggressive_config
export MITIGATION_NONE, MITIGATION_DUMMY_PREFIX, MITIGATION_SNI_FRAGMENTATION
export MITIGATION_PORT_SELECTION, MITIGATION_ALL

# MLS (QUIC-MLS) exports
export QuicMLSConnection, QuicMLSConfig, QuicMLSKeys
export QUIC_MLS_CLIENT, QUIC_MLS_SERVER
export init_quic_mls_client, init_quic_mls_server
export process_crypto_data, get_crypto_data_to_send
export is_handshake_complete, get_quic_keys

# Logging (load first for use by other modules)
include("logging.jl")

# submodules - core QUIC
include("protocol.jl")

# GFW censorship mitigation (after protocol for VarInt)
include("gfw_mitigation.jl")
include("packet.jl")
include("frame.jl")
include("crypto.jl")
include("ed25519.jl")
include("x509.jl")
include("x25519.jl")
include("stream.jl")
include("packet_codec.jl")
include("version_negotiation.jl")
include("retry.jl")
include("packet_coalescing.jl")
include("zero_rtt.jl")
include("handshake.jl")
include("loss_detection.jl")
include("packet_pacing.jl")
include("connection_id_manager.jl")
include("http3.jl")
include("quicnet_protocol.jl")

# MLS (Messaging Layer Security) for QUIC-MLS - must be before connection.jl
include("mls/MLS.jl")

include("connection.jl")
include("packet_receiver.jl")
include("endpoint.jl")
include("congestion.jl")
include("transport.jl")

# JAM networking protocol (JAMNP-S)
include("jamnps.jl")

# JAMNP-S connection management
include("jamnps_connection.jl")

# FFI bindings to quiche (optional, for comparison/production use)
include("quiche_ffi.jl")

# Re-export from submodules
using .GFWMitigation: GFWMitigationConfig, china_config, aggressive_config, default_config
using .GFWMitigation: MITIGATION_NONE, MITIGATION_DUMMY_PREFIX, MITIGATION_SNI_FRAGMENTATION
using .GFWMitigation: MITIGATION_PORT_SELECTION, MITIGATION_ALL
using .EndpointModule: Endpoint, EndpointConfig, ChinaEndpointConfig, connect, accept
using .ConnectionModule: Connection, send_stream

# MLS re-exports
using .MLS: QuicMLSConnection, QuicMLSConfig, QuicMLSKeys
using .MLS: QUIC_MLS_CLIENT, QUIC_MLS_SERVER
using .MLS: init_quic_mls_client, init_quic_mls_server
using .MLS: process_crypto_data, get_crypto_data_to_send
using .MLS: is_handshake_complete, get_quic_keys

end # module
