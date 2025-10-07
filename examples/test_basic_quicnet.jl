#!/usr/bin/env julia

# Basic QuicNet functionality test
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

using Quic
using Sockets

println("🦀 Basic QuicNet Test")
println("="^50)

function test_basic_quicnet()
    println("\n📋 Testing basic QUIC components...")

    # Test ConnectionId
    println("\n🆔 Testing ConnectionId...")
    cid = Quic.Packet.ConnectionId()
    println("   Created CID: $(bytes2hex(cid.data))")
    println("   ✅ ConnectionId working")

    # Test PacketNumber
    println("\n📦 Testing PacketNumber...")
    pn = Quic.Packet.PacketNumber(42)
    println("   PacketNumber: $(pn.value)")
    println("   ✅ PacketNumber working")

    # Test Frame creation
    println("\n🏗️ Testing Frame types...")

    ping = Quic.Frame.PingFrame()
    println("   ✅ PING frame created")

    ack = Quic.Frame.AckFrame(
        UInt64(10),  # largest
        UInt64(100), # delay
        UInt64(5),   # first_range
        Vector{@NamedTuple{gap::UInt64, length::UInt64}}(),  # ranges
        nothing      # ecn_counts
    )
    println("   ✅ ACK frame created")

    stream = Quic.Frame.StreamFrame(
        UInt64(4),  # stream_id
        UInt64(0),  # offset
        UInt8[0x48, 0x69],  # "Hi"
        false  # fin
    )
    println("   ✅ STREAM frame created")

    # Test packet header types
    println("\n📨 Testing Packet headers...")

    long_header = Quic.Packet.LongHeader(
        0xc0,  # packet_type
        UInt32(1),  # version
        Quic.Packet.ConnectionId(),  # dest_cid
        Quic.Packet.ConnectionId()   # src_cid
    )
    println("   ✅ Long header created")

    short_header = Quic.Packet.ShortHeader(
        0x40,  # flags
        Quic.Packet.ConnectionId()  # dest_cid
    )
    println("   ✅ Short header created")

    # Test crypto components
    println("\n🔐 Testing Crypto components...")

    ctx = Quic.Crypto.CryptoContext()
    println("   ✅ CryptoContext created")

    # Test handshake components
    println("\n🤝 Testing Handshake components...")

    hs = Quic.Handshake.HandshakeState(:client)
    println("   Role: $(hs.role)")
    println("   State: $(hs.state)")
    println("   ✅ HandshakeState created")

    # Test stream state
    println("\n🌊 Testing Stream components...")

    stream_state = Quic.Stream.StreamState(
        UInt64(0),  # stream_id
        :bidirectional,
        :open
    )
    println("   Stream ID: $(stream_state.stream_id)")
    println("   Type: $(stream_state.stream_type)")
    println("   State: $(stream_state.state)")
    println("   ✅ StreamState created")

    println("\n✨ All basic tests passed!")
    return true
end

# Run the test
try
    if test_basic_quicnet()
        println("\n🎉 Basic QuicNet test completed successfully!")
    end
catch e
    println("\n❌ Test failed: $e")
    for (i, frame) in enumerate(stacktrace())
        println("   $i. $frame")
    end
end