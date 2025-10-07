#!/usr/bin/env julia

# Simple QuicNet functionality test
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

println("🦀 QuicNet Library Test")
println("="^50)

# Load the QUIC library
using Quic
println("✅ QUIC library loaded successfully")

# Test basic components
println("\n📦 Testing basic components:")

# ConnectionId
cid = Quic.Packet.ConnectionId()
println("   ✅ ConnectionId: $(bytes2hex(cid.data))")

# PacketNumber
pn = Quic.Packet.PacketNumber(42)
println("   ✅ PacketNumber: $(pn.value)")

# Frames
ping = Quic.Frame.PingFrame()
println("   ✅ PingFrame created")

# Crypto
ctx = Quic.Crypto.CryptoContext()
println("   ✅ CryptoContext created")

# Handshake
hs = Quic.Handshake.HandshakeState(:client)
println("   ✅ HandshakeState: $(hs.role)")

println("\n🎉 QuicNet library is functional and ready for testing!")
println("\n📋 Next steps:")
println("   1. Start a Rust QuicNet server on port 4433")
println("   2. Run the quicnet_client.jl example to test connectivity")
println("   3. Monitor the handshake and data exchange")