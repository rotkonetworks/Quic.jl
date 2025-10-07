#!/usr/bin/env julia

# Full QUIC Server Implementation
# Demonstrates complete server-side QUIC protocol with bidirectional streams

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Sockets

mutable struct QuicServer
    endpoint::Quic.EndpointModule.Endpoint
    active_connections::Dict{Quic.Packet.ConnectionId, Quic.ConnectionModule.Connection}
    running::Bool
    stats::@NamedTuple{
        connections_accepted::Int,
        bytes_received::Int,
        bytes_sent::Int,
        streams_opened::Int
    }

    function QuicServer(port::Int = 4433)
        server_addr = Sockets.InetAddr(ip"0.0.0.0", port)
        config = Quic.EndpointModule.EndpointConfig()
        endpoint = Quic.EndpointModule.Endpoint(server_addr, config, true)

        new(endpoint, Dict(), false, (connections_accepted=0, bytes_received=0, bytes_sent=0, streams_opened=0))
    end
end

function start_server!(server::QuicServer)
    server.running = true
    println("🚀 QUIC Server starting on port $(getsockname(server.endpoint.socket)[2])...")
    println("📊 Server capabilities:")
    println("   ✅ TLS 1.3 handshake with X25519 ECDHE")
    println("   ✅ ChaCha20-Poly1305 & AES-GCM encryption")
    println("   ✅ Loss detection and recovery")
    println("   ✅ Packet pacing and congestion control")
    println("   ✅ Connection ID rotation")
    println("   ✅ Bidirectional streams")
    println()

    # Main server loop
    data = Vector{UInt8}(undef, 65536)

    while server.running
        try
            # Receive packets from clients
            nbytes, client_addr = recvfrom(server.endpoint.socket, data, timeout=1.0)

            if nbytes > 0
                handle_client_packet!(server, data[1:nbytes], client_addr)
            end

            # Process existing connections
            process_active_connections!(server)

        catch e
            if isa(e, Base.UVError) && e.code == Base.UV_ETIMEDOUT
                # Timeout is normal, continue processing
                continue
            else
                println("❌ Server error: $e")
                break
            end
        end

        # Small yield to prevent 100% CPU usage
        sleep(0.001)
    end

    println("🛑 QUIC Server stopped")
end

function handle_client_packet!(server::QuicServer, packet_data::Vector{UInt8}, client_addr)
    try
        # Try to find existing connection by parsing destination CID
        dest_cid = extract_destination_cid(packet_data)

        if dest_cid !== nothing && haskey(server.active_connections, dest_cid)
            # Handle packet for existing connection
            conn = server.active_connections[dest_cid]
            conn.remote_addr = client_addr

            result = Quic.PacketReceiver.process_incoming_packet(conn, packet_data, client_addr)

            if result !== nothing
                handle_connection_events!(server, conn, result)
            end
        else
            # New connection attempt
            handle_new_connection!(server, packet_data, client_addr)
        end

    catch e
        println("⚠️ Error handling packet from $client_addr: $e")
    end
end

function extract_destination_cid(packet_data::Vector{UInt8})
    # Simple CID extraction - assumes 8-byte CID at offset 6 for long headers
    if length(packet_data) >= 14 && (packet_data[1] & 0x80) != 0
        return Quic.Packet.ConnectionId(packet_data[7:14])
    elseif length(packet_data) >= 9 && (packet_data[1] & 0x80) == 0
        return Quic.Packet.ConnectionId(packet_data[2:9])
    end
    return nothing
end

function handle_new_connection!(server::QuicServer, packet_data::Vector{UInt8}, client_addr)
    println("🤝 New connection attempt from $client_addr")

    # Create new connection
    conn = Quic.ConnectionModule.Connection(server.endpoint.socket, false)  # server = false for is_client
    conn.remote_addr = client_addr

    # Setup crypto
    conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()

    # Store connection
    server.active_connections[conn.local_cid] = conn
    server.stats = (
        connections_accepted = server.stats.connections_accepted + 1,
        bytes_received = server.stats.bytes_received,
        bytes_sent = server.stats.bytes_sent,
        streams_opened = server.stats.streams_opened
    )

    # Process the initial packet
    result = Quic.PacketReceiver.process_incoming_packet(conn, packet_data, client_addr)

    if result !== nothing
        println("✅ Initial packet processed: $result")
        handle_connection_events!(server, conn, result)
    end
end

function handle_connection_events!(server::QuicServer, conn::Quic.ConnectionModule.Connection, event)
    # Update statistics
    server.stats = (
        connections_accepted = server.stats.connections_accepted,
        bytes_received = server.stats.bytes_received + length(get(conn.sent_packets, 1, (data=UInt8[],)).data),
        bytes_sent = server.stats.bytes_sent,
        streams_opened = server.stats.streams_opened + length(conn.streams)
    )

    # Handle completed handshake
    if conn.connected && !get(conn, :handshake_handled, false)
        println("🎉 Handshake completed with $(conn.remote_addr)")

        # Send a welcome message on a new stream
        welcome_stream = Quic.ConnectionModule.open_stream(conn, true)
        welcome_msg = Vector{UInt8}("Hello from Julia QUIC Server! 🚀")
        Quic.ConnectionModule.send_stream(conn, welcome_stream, welcome_msg, false)

        # Mark handshake as handled
        setfield!(conn, :handshake_handled, true)

        server.stats = (
            connections_accepted = server.stats.connections_accepted,
            bytes_received = server.stats.bytes_received,
            bytes_sent = server.stats.bytes_sent + length(welcome_msg),
            streams_opened = server.stats.streams_opened + 1
        )

        println("📤 Sent welcome message on stream $(welcome_stream.value)")
    end

    # Handle incoming stream data
    for (stream_id, stream_state) in conn.streams
        if !isempty(stream_state.recv_buf)
            handle_stream_data!(server, conn, stream_id, stream_state)
        end
    end
end

function handle_stream_data!(server::QuicServer, conn::Quic.ConnectionModule.Connection,
                            stream_id::UInt64, stream_state::Quic.Stream.StreamState)

    # Read all available data
    data, fin_received = Quic.Stream.read_stream!(stream_state, length(stream_state.recv_buf))

    if !isempty(data)
        message = String(data)
        println("📥 Received on stream $stream_id: \"$message\"")

        server.stats = (
            connections_accepted = server.stats.connections_accepted,
            bytes_received = server.stats.bytes_received + length(data),
            bytes_sent = server.stats.bytes_sent,
            streams_opened = server.stats.streams_opened
        )

        # Echo back with server processing
        response_data = Vector{UInt8}("Server processed: \"$message\" ✅")

        # Send response on the same stream
        sid = Quic.Stream.StreamId(stream_id, :server, :bidi)
        Quic.ConnectionModule.send_stream(conn, sid, response_data, fin_received)

        server.stats = (
            connections_accepted = server.stats.connections_accepted,
            bytes_received = server.stats.bytes_received,
            bytes_sent = server.stats.bytes_sent + length(response_data),
            streams_opened = server.stats.streams_opened
        )

        println("📤 Sent response: \"$(String(response_data))\"")
    end
end

function process_active_connections!(server::QuicServer)
    # Process timers and maintenance for all active connections
    for (cid, conn) in server.active_connections
        try
            # Process timers (loss detection, pacing updates)
            Quic.ConnectionModule.process_timers(conn)

            # Maintain connection IDs
            Quic.ConnectionModule.maintain_connection_ids!(conn)

            # Update pacing parameters
            Quic.ConnectionModule.update_pacing_parameters!(conn)

            # Check for connection timeout or closure
            if conn.closing
                println("👋 Connection $(bytes2hex(cid.data)) closing")
                delete!(server.active_connections, cid)
            end

        catch e
            println("⚠️ Error processing connection $(bytes2hex(cid.data)): $e")
            delete!(server.active_connections, cid)
        end
    end
end

function stop_server!(server::QuicServer)
    server.running = false
    close(server.endpoint.socket)
end

function print_server_stats(server::QuicServer)
    println("\n📊 Server Statistics:")
    println("   Active connections: $(length(server.active_connections))")
    println("   Total connections: $(server.stats.connections_accepted)")
    println("   Bytes received: $(server.stats.bytes_received)")
    println("   Bytes sent: $(server.stats.bytes_sent)")
    println("   Streams opened: $(server.stats.streams_opened)")

    # Print connection details
    for (cid, conn) in server.active_connections
        loss_stats = Quic.ConnectionModule.get_cid_statistics(conn)
        pacing_stats = Quic.ConnectionModule.get_pacing_statistics(conn)

        println("   Connection $(bytes2hex(cid.data)[1:8])..."):")
        println("     RTT: $(conn.loss_detection.smoothed_rtt ÷ 1_000_000) ms")
        println("     CWND: $(conn.cwnd) bytes")
        println("     Pacing rate: $(Int(pacing_stats.pacing_rate)) B/s")
        println("     Active streams: $(length(conn.streams))")
    end
end

function main()
    server = QuicServer(4433)

    # Handle Ctrl+C gracefully
    signal_caught = false

    # Start server in background task would be:
    # @async start_server!(server)

    println("Starting QUIC server... Press Ctrl+C to stop")

    try
        start_server!(server)
    catch InterruptException
        println("\n🛑 Received interrupt signal")
        signal_caught = true
    finally
        stop_server!(server)
        print_server_stats(server)
    end

    return true
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end