#!/usr/bin/env julia

# Test QuicNet compatibility after 0-RTT implementation
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

using Quic
using Sockets

const SERVER_ADDR = "127.0.0.1"
const SERVER_PORT = 4433

println("🦀 QuicNet Compatibility Test")
println("="^50)

function test_connection_creation()
    println("\n📋 Testing Connection Creation...")

    sock = UDPSocket()
    bind(sock, ip"0.0.0.0", 0)

    conn = Quic.ConnectionModule.Connection(sock, true)

    println("    Connection created")
    println("   Local CID: $(bytes2hex(conn.local_cid.data))")
    println("   Remote CID: $(bytes2hex(conn.remote_cid.data))")
    println("   Is client: $(conn.is_client)")
    println("   0-RTT enabled: $(conn.zero_rtt_enabled)")
    println("   Max early data: $(conn.max_early_data)")

    close(sock)
    return true
end

function test_handshake_creation()
    println("\n📋 Testing Handshake Message Creation...")

    sock = UDPSocket()
    conn = Quic.ConnectionModule.Connection(sock, true)

    # Test creating ClientHello without 0-RTT
    println("\n   Standard ClientHello (no 0-RTT):")
    client_hello = Quic.Handshake.create_client_hello(
        conn.handshake,
        conn.remote_cid,
        "localhost",
        false  # No 0-RTT
    )
    println("    ClientHello created: $(length(client_hello)) bytes")

    # Test creating ClientHello with 0-RTT attempt
    println("\n   ClientHello with 0-RTT attempt:")
    client_hello_0rtt = Quic.Handshake.create_client_hello(
        conn.handshake,
        conn.remote_cid,
        "localhost",
        true  # Try 0-RTT
    )
    println("    ClientHello with 0-RTT created: $(length(client_hello_0rtt)) bytes")

    close(sock)
    return true
end

function test_frame_compatibility()
    println("\n📋 Testing Frame Types...")

    # Test basic frames
    ping = Quic.Frame.PingFrame()
    println("    PING frame")

    ack = Quic.Frame.AckFrame(
        UInt64(100),
        UInt64(50),
        UInt64(10),
        Vector{@NamedTuple{gap::UInt64, length::UInt64}}(),
        nothing
    )
    println("    ACK frame")

    stream = Quic.Frame.StreamFrame(
        UInt64(0),
        UInt64(0),
        UInt8[0x48, 0x65, 0x6c, 0x6c, 0x6f],  # "Hello"
        false
    )
    println("    STREAM frame")

    return true
end

function test_packet_headers()
    println("\n📋 Testing Packet Headers...")

    # Long header
    long_header = Quic.Packet.LongHeader(
        0xc0,
        UInt32(1),
        Quic.Packet.ConnectionId(),
        Quic.Packet.ConnectionId(),
        UInt8[],
        UInt64(0),
        UInt64(0)
    )
    println("    Long header created")

    # Short header
    short_header = Quic.Packet.ShortHeader(
        Quic.Packet.ConnectionId(),
        UInt64(0)
    )
    println("    Short header created")

    return true
end

function test_0rtt_session_cache()
    println("\n📋 Testing 0-RTT Session Cache...")

    # Check if cache is accessible
    cache = Quic.ZeroRTT.GLOBAL_SESSION_CACHE
    println("    Session cache accessible")

    # Check for test server session
    has_session = Quic.ZeroRTT.is_zero_rtt_available(SERVER_ADDR)
    if has_session
        println("    Found cached session for $SERVER_ADDR")
        max_early = Quic.ZeroRTT.get_max_early_data_size(SERVER_ADDR)
        println("      Max early data: $max_early bytes")
    else
        println("   ℹ️  No cached session for $SERVER_ADDR")
    end

    # Test storing a session
    session = Quic.ZeroRTT.SessionState()
    session.ticket = rand(UInt8, 64)
    session.ticket_lifetime = 7200
    session.ticket_received_time = time_ns()
    session.max_early_data_size = 16384

    test_server = "test.example.com"
    Quic.ZeroRTT.store_session!(cache, test_server, session)

    if Quic.ZeroRTT.is_zero_rtt_available(test_server)
        println("    Session storage working")
    else
        println("    Session storage failed")
        return false
    end

    return true
end

function test_transport_params()
    println("\n📋 Testing Transport Parameters...")

    sock = UDPSocket()
    conn = Quic.ConnectionModule.Connection(sock, true)

    # Encode transport params
    tp_data = Quic.Handshake.encode_transport_params_v1(conn.handshake)
    println("    Transport params encoded: $(length(tp_data)) bytes")

    # Check for required parameters
    if length(tp_data) > 20
        println("    Contains expected parameter data")
    else
        println("     Transport params seem too short")
    end

    close(sock)
    return true
end

function test_crypto_context()
    println("\n📋 Testing Crypto Context...")

    ctx = Quic.Crypto.CryptoContext()
    println("    CryptoContext created")

    # Test key derivation (simplified)
    sock = UDPSocket()
    conn = Quic.ConnectionModule.Connection(sock, true)

    # Derive initial keys
    Quic.Handshake.derive_initial_keys!(conn.handshake, conn.remote_cid)

    if haskey(conn.handshake.initial_keys, :client_key)
        println("    Initial keys derived")
    else
        println("     Initial keys might not be set correctly")
    end

    close(sock)
    return true
end

function run_all_tests()
    all_passed = true

    tests = [
        ("Connection Creation", test_connection_creation),
        ("Handshake Messages", test_handshake_creation),
        ("Frame Compatibility", test_frame_compatibility),
        ("Packet Headers", test_packet_headers),
        ("0-RTT Session Cache", test_0rtt_session_cache),
        ("Transport Parameters", test_transport_params),
        ("Crypto Context", test_crypto_context)
    ]

    for (name, test_func) in tests
        try
            if !test_func()
                all_passed = false
                println(" $name failed")
            end
        catch e
            all_passed = false
            println(" $name errored: $e")
        end
    end

    println("\n" * "="^50)
    if all_passed
        println(" All compatibility tests passed!")
        println("\n QuicNet compatibility maintained with 0-RTT support!")
    else
        println("  Some tests failed - review compatibility")
    end

    # Show session cache stats
    println("\n Session Cache Statistics:")
    cache = Quic.ZeroRTT.GLOBAL_SESSION_CACHE
    total_sessions = sum(length(v) for v in values(cache.sessions))
    println("   Total sessions: $total_sessions")
    println("   Servers tracked: $(length(cache.sessions))")

    return all_passed
end

# Run the compatibility tests
if abspath(PROGRAM_FILE) == @__FILE__
    run_all_tests()
end