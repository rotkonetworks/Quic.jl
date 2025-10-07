#!/usr/bin/env julia

# 0-RTT QUIC client example
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

using Quic
using Sockets

# Configuration
const SERVER_ADDR = "127.0.0.1"
const SERVER_PORT = 4433
const SERVER_NAME = "localhost"

mutable struct ZeroRTTClient
    connection::Quic.ConnectionModule.Connection
    socket::UDPSocket
    server_addr::IPAddr
    server_port::Int
    zero_rtt_available::Bool
    early_data_sent::Bool
end

function create_zero_rtt_client(server_addr::String, server_port::Int)
    # Create UDP socket
    sock = UDPSocket()
    bind(sock, ip"0.0.0.0", 0)

    # Create connection
    conn = Quic.ConnectionModule.Connection(sock, true)

    # Parse server address
    server_ip = parse(IPAddr, server_addr)

    # Check if 0-RTT is available for this server
    zero_rtt_available = Quic.ZeroRTT.is_zero_rtt_available(server_addr)

    if zero_rtt_available
        println("✅ 0-RTT available for $server_addr - session found in cache")
        max_early_data = Quic.ZeroRTT.get_max_early_data_size(server_addr)
        println("   Max early data size: $max_early_data bytes")

        # Enable 0-RTT on connection
        conn.zero_rtt_enabled = true
        conn.max_early_data = max_early_data
    else
        println("ℹ️  No 0-RTT session available for $server_addr - will establish new connection")
    end

    return ZeroRTTClient(conn, sock, server_ip, server_port, zero_rtt_available, false)
end

function send_early_data!(client::ZeroRTTClient, data::Vector{UInt8})
    if !client.zero_rtt_available
        println("⚠️  Cannot send early data - 0-RTT not available")
        return false
    end

    if client.early_data_sent
        println("⚠️  Early data already sent")
        return false
    end

    println("\n🚀 Sending 0-RTT early data...")
    println("   Data: $(String(data))")
    println("   Size: $(length(data)) bytes")

    # Get session from cache
    session = Quic.ZeroRTT.get_resumption_session(
        Quic.ZeroRTT.GLOBAL_SESSION_CACHE,
        string(client.server_addr)
    )

    if session === nothing
        println("❌ Session expired or invalid")
        return false
    end

    # Create STREAM frame with early data
    stream_frame = Quic.Frame.StreamFrame(
        UInt64(0),  # Stream 0 for initial data
        UInt64(0),  # Offset 0
        data,
        false       # Not fin
    )

    # Create 0-RTT packet
    zero_rtt_packet = Quic.ZeroRTT.create_zero_rtt_packet(
        session,
        client.connection.remote_cid,
        client.connection.local_cid,
        Quic.Packet.PacketNumber(0),
        [stream_frame]
    )

    # Serialize packet (simplified)
    packet_data = serialize_zero_rtt_packet(zero_rtt_packet)

    # Send packet
    send(client.socket, client.server_addr, client.server_port, packet_data)

    client.early_data_sent = true
    println("✅ Early data sent in 0-RTT packet")

    return true
end

function serialize_zero_rtt_packet(packet::Quic.ZeroRTT.ZeroRTTPacket)::Vector{UInt8}
    buf = UInt8[]

    # Long header with 0-RTT packet type (0x1c for v1)
    push!(buf, 0xdc)  # Long header, 0-RTT packet

    # Version (QUIC v1)
    append!(buf, [0x00, 0x00, 0x00, 0x01])

    # Destination connection ID
    push!(buf, length(packet.dest_cid.data))
    append!(buf, packet.dest_cid.data)

    # Source connection ID
    push!(buf, length(packet.src_cid.data))
    append!(buf, packet.src_cid.data)

    # No token in 0-RTT packets
    push!(buf, 0x00)

    # Length (variable length encoding)
    payload_length = length(packet.payload) + 4  # Including packet number
    if payload_length < 64
        push!(buf, UInt8(payload_length))
    else
        push!(buf, UInt8(0x40 | ((payload_length >> 8) & 0x3f)))
        push!(buf, UInt8(payload_length & 0xff))
    end

    # Packet number (4 bytes for initial packets)
    pn = packet.packet_number.value
    append!(buf, [
        UInt8((pn >> 24) & 0xff),
        UInt8((pn >> 16) & 0xff),
        UInt8((pn >> 8) & 0xff),
        UInt8(pn & 0xff)
    ])

    # Encrypted payload
    append!(buf, packet.payload)

    return buf
end

function complete_handshake!(client::ZeroRTTClient, enable_zero_rtt::Bool=false)
    println("\n🤝 Starting handshake...")

    # Create ClientHello with 0-RTT if available
    client_hello = Quic.Handshake.create_client_hello(
        client.connection.handshake,
        client.connection.remote_cid,
        SERVER_NAME,
        enable_zero_rtt
    )

    # Create Initial packet with ClientHello
    initial_packet = create_initial_packet(client.connection, client_hello)

    # Send Initial packet
    packet_data = serialize_initial_packet(initial_packet)
    send(client.socket, client.server_addr, client.server_port, packet_data)

    if enable_zero_rtt && client.zero_rtt_available
        println("✅ ClientHello sent with 0-RTT indication")
    else
        println("✅ ClientHello sent (standard handshake)")
    end

    # In a real implementation, we would:
    # 1. Wait for server response (ServerHello, etc.)
    # 2. Process handshake messages
    # 3. Derive keys
    # 4. Confirm handshake
    # 5. Store session for future 0-RTT

    # For demo, simulate successful handshake
    println("✅ Handshake completed (simulated)")

    # Store session for next connection (demo)
    if !client.zero_rtt_available
        store_demo_session(string(client.server_addr))
        println("💾 Session stored for future 0-RTT connections")
    end
end

function create_initial_packet(conn::Quic.ConnectionModule.Connection, payload::Vector{UInt8})
    # Simplified Initial packet creation
    return Dict(
        :type => :initial,
        :dest_cid => conn.remote_cid,
        :src_cid => conn.local_cid,
        :packet_number => Quic.Packet.PacketNumber(0),
        :payload => payload
    )
end

function serialize_initial_packet(packet::Dict)::Vector{UInt8}
    buf = UInt8[]

    # Long header, Initial packet
    push!(buf, 0xc0)

    # Version
    append!(buf, [0x00, 0x00, 0x00, 0x01])

    # Connection IDs
    push!(buf, length(packet[:dest_cid].data))
    append!(buf, packet[:dest_cid].data)
    push!(buf, length(packet[:src_cid].data))
    append!(buf, packet[:src_cid].data)

    # Token (empty for client)
    push!(buf, 0x00)

    # Length and packet number (simplified)
    payload_length = length(packet[:payload]) + 4
    append!(buf, [UInt8((payload_length >> 8) & 0xff), UInt8(payload_length & 0xff)])
    append!(buf, [0x00, 0x00, 0x00, 0x00])  # Packet number

    # Payload
    append!(buf, packet[:payload])

    # Padding to reach minimum Initial packet size (1200 bytes)
    while length(buf) < 1200
        push!(buf, 0x00)
    end

    return buf
end

function store_demo_session(server_addr::String)
    # Create a demo session for testing
    session = Quic.ZeroRTT.SessionState()

    # Set demo values
    session.ticket = rand(UInt8, 128)  # Random ticket
    session.ticket_age_add = rand(UInt32)
    session.ticket_lifetime = 7200  # 2 hours
    session.ticket_nonce = rand(UInt8, 8)
    session.resumption_master_secret = rand(UInt8, 32)
    session.ticket_received_time = time_ns()
    session.cipher_suite = 0x1301  # TLS_AES_128_GCM_SHA256
    session.max_early_data_size = 0x4000  # 16KB
    session.alpn = "h3"
    session.server_name = server_addr

    # Store in cache
    Quic.ZeroRTT.store_session!(Quic.ZeroRTT.GLOBAL_SESSION_CACHE, server_addr, session)
end

function run_zero_rtt_demo()
    println("🦀 QUIC 0-RTT Client Demo")
    println("="^50)

    # First connection - establish session
    println("\n📡 First connection to $SERVER_ADDR:$SERVER_PORT")
    client1 = create_zero_rtt_client(SERVER_ADDR, SERVER_PORT)
    complete_handshake!(client1, false)
    close(client1.socket)

    println("\n" * "="^50)

    # Second connection - use 0-RTT
    println("\n📡 Second connection to $SERVER_ADDR:$SERVER_PORT (with 0-RTT)")
    client2 = create_zero_rtt_client(SERVER_ADDR, SERVER_PORT)

    if client2.zero_rtt_available
        # Send early data before handshake completes
        early_data = Vector{UInt8}("GET / HTTP/3\r\n\r\n")
        send_early_data!(client2, early_data)

        # Complete handshake with 0-RTT
        complete_handshake!(client2, true)
    else
        println("⚠️  0-RTT not available, falling back to standard handshake")
        complete_handshake!(client2, false)
    end

    close(client2.socket)

    println("\n✨ Demo completed!")
    println("\n📊 Session Cache Statistics:")
    cache = Quic.ZeroRTT.GLOBAL_SESSION_CACHE
    total_sessions = sum(length(v) for v in values(cache.sessions))
    println("   Total sessions cached: $total_sessions")
    println("   Servers with sessions: $(length(cache.sessions))")
end

# Run the demo
if abspath(PROGRAM_FILE) == @__FILE__
    run_zero_rtt_demo()
end