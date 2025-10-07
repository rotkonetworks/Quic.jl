#!/usr/bin/env julia

# Test QuicNet connection functionality
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

using Quic
using Sockets

println("🦀 QuicNet Connection Test")
println("="^50)

function test_quicnet_connection()
    println("\n📋 Testing QuicNet connection creation...")

    # Create a client connection
    sock = UDPSocket()
    conn = Quic.ConnectionModule.Connection(sock, true)

    println("   ✅ Connection created")

    # Test initial packet creation
    println("\n📦 Creating Initial packet...")

    # Create Initial packet with CRYPTO frame containing ClientHello
    initial_packet = Quic.Packet.InitialPacket(
        Quic.Protocol.ConnectionId(),  # Destination CID
        Quic.Protocol.ConnectionId(),  # Source CID
        Quic.Protocol.PacketNumber(0),
        UInt8[]  # Payload (would contain CRYPTO frames)
    )

    println("   ✅ Initial packet created")

    # Test handshake state
    println("\n🤝 Testing handshake state...")

    hs = conn.handshake_state
    println("   State: $(hs.state)")
    println("   Role: $(hs.role)")

    # Test frame creation
    println("\n🏗️ Testing frame creation...")

    # Create PING frame
    ping_frame = Quic.Frame.PingFrame()
    println("   ✅ PING frame created")

    # Create ACK frame
    ack_frame = Quic.Frame.AckFrame(
        UInt64(5),                      # largest_acknowledged
        UInt64(100),                    # ack_delay
        UInt64(0),                       # first_ack_range
        Vector{@NamedTuple{gap::UInt64, length::UInt64}}(),  # ranges
        nothing                         # ecn_counts
    )
    println("   ✅ ACK frame created")

    # Create STREAM frame
    stream_frame = Quic.Frame.StreamFrame(
        UInt64(0),      # stream_id
        UInt64(0),      # offset
        UInt8[0x48, 0x65, 0x6c, 0x6c, 0x6f],  # "Hello"
        true            # fin
    )
    println("   ✅ STREAM frame created")

    # Test packet coalescing
    println("\n📦 Testing packet coalescing...")

    coalescer = conn.packet_coalescer
    println("   Max size: $(coalescer.max_size)")
    println("   Current packets: $(length(coalescer.pending_packets))")

    # Test loss detection
    println("\n🔍 Testing loss detection...")

    ld_ctx = conn.loss_detection_context
    println("   Latest RTT: $(ld_ctx.latest_rtt) ns")
    println("   Smoothed RTT: $(ld_ctx.smoothed_rtt) ns")

    # Test connection ID management
    println("\n🆔 Testing connection ID management...")

    cid_mgr = conn.cid_manager
    current_remote = Quic.ConnectionIdManager.get_current_remote_cid(cid_mgr)
    println("   Current remote CID: $(bytes2hex(current_remote.cid.data))")

    # Test pacing state
    println("\n⏱️ Testing packet pacing...")

    pacing = conn.pacing_state
    println("   Pacing rate: $(pacing.pacing_rate) bytes/sec")
    println("   Bucket tokens: $(pacing.bucket_tokens)")

    # Clean up
    close(sock)

    println("\n✨ All tests completed successfully!")
    return true
end

# Run the test
try
    if test_quicnet_connection()
        println("\n🎉 QuicNet connection test passed!")
    end
catch e
    println("\n❌ Test failed: $e")
    println(stacktrace())
end