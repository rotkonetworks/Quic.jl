module Quic

# re-exports and public api
export Endpoint, Connection, Config
export connect, accept, send_stream, recv_stream

# Logging (load first for use by other modules)
include("logging.jl")

# submodules - core QUIC
include("protocol.jl")
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

end # module
