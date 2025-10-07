#!/usr/bin/env julia

# QuicNet-Compatible Server
# Designed to interoperate with Rust QuicNet clients and libraries

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Sockets
using Dates

mutable struct QuicNetServer
    endpoint::Quic.EndpointModule.Endpoint
    active_connections::Dict{Quic.Packet.ConnectionId, Quic.ConnectionModule.Connection}
    running::Bool
    compatibility_mode::Symbol  # :quicnet, :universal, :strict_rfc
    stats::@NamedTuple{
        connections_accepted::Int,
        quicnet_clients::Int,
        bytes_received::Int,
        bytes_sent::Int,
        http3_requests::Int,
        connection_migrations::Int
    }

    function QuicNetServer(port::Int = 4433, compatibility_mode::Symbol = :quicnet)
        server_addr = Sockets.InetAddr(ip"0.0.0.0", port)
        config = Quic.EndpointModule.EndpointConfig()
        endpoint = Quic.EndpointModule.Endpoint(server_addr, config, true)

        new(
            endpoint,
            Dict{Quic.Packet.ConnectionId, Quic.ConnectionModule.Connection}(),
            false,
            compatibility_mode,
            (connections_accepted=0, quicnet_clients=0, bytes_received=0,
             bytes_sent=0, http3_requests=0, connection_migrations=0)
        )
    end
end

function start_quicnet_server!(server::QuicNetServer)
    server.running = true
    port = getsockname(server.endpoint.socket)[2]

    println("🦀 QuicNet-Compatible Server starting on port $port...")
    println("📊 Server capabilities ($(server.compatibility_mode) mode):")
    println("   ✅ QuicNet client compatibility")
    println("   ✅ TLS 1.3 with ChaCha20-Poly1305")
    println("   ✅ Connection migration support")
    println("   ✅ HTTP/3 over QUIC")
    println("   ✅ Multiple stream types")
    println("   ✅ Adaptive congestion control")
    println("   ✅ Advanced loss detection")
    println()

    data = Vector{UInt8}(undef, 65536)

    while server.running
        try
            # Receive packets from clients
            nbytes, client_addr = recvfrom(server.endpoint.socket, data, timeout=1.0)

            if nbytes > 0
                handle_quicnet_packet!(server, data[1:nbytes], client_addr)
            end

            # Process existing connections with QuicNet features
            process_quicnet_connections!(server)

        catch e
            if isa(e, Base.UVError) && e.code == Base.UV_ETIMEDOUT
                continue
            else
                println("❌ QuicNet server error: $e")
                break
            end
        end

        sleep(0.001)
    end

    println("🛑 QuicNet server stopped")
end

function handle_quicnet_packet!(server::QuicNetServer, packet_data::Vector{UInt8}, client_addr)
    try
        # Extract destination CID
        dest_cid = extract_destination_cid(packet_data)

        if dest_cid !== nothing && haskey(server.active_connections, dest_cid)
            # Handle packet for existing connection
            conn = server.active_connections[dest_cid]
            conn.remote_addr = client_addr

            result = Quic.PacketReceiver.process_incoming_packet(conn, packet_data, client_addr)

            if result !== nothing
                handle_quicnet_connection_events!(server, conn, result, packet_data)
            end
        else
            # New QuicNet connection attempt
            handle_new_quicnet_connection!(server, packet_data, client_addr)
        end

    catch e
        println("⚠️ Error handling QuicNet packet from $client_addr: $e")
    end
end

function extract_destination_cid(packet_data::Vector{UInt8})
    if length(packet_data) >= 14 && (packet_data[1] & 0x80) != 0
        return Quic.Packet.ConnectionId(packet_data[7:14])
    elseif length(packet_data) >= 9 && (packet_data[1] & 0x80) == 0
        return Quic.Packet.ConnectionId(packet_data[2:9])
    end
    return nothing
end

function handle_new_quicnet_connection!(server::QuicNetServer, packet_data::Vector{UInt8}, client_addr)
    println("🦀 New QuicNet connection from $client_addr")

    # Create connection with QuicNet compatibility
    conn = Quic.ConnectionModule.Connection(server.endpoint.socket, false)
    conn.remote_addr = client_addr

    # Configure for QuicNet compatibility
    configure_quicnet_server_connection!(conn, server.compatibility_mode)

    # Store connection
    server.active_connections[conn.local_cid] = conn

    # Update stats
    server.stats = (
        connections_accepted = server.stats.connections_accepted + 1,
        quicnet_clients = server.stats.quicnet_clients + 1,
        bytes_received = server.stats.bytes_received,
        bytes_sent = server.stats.bytes_sent,
        http3_requests = server.stats.http3_requests,
        connection_migrations = server.stats.connection_migrations
    )

    # Process initial packet
    result = Quic.PacketReceiver.process_incoming_packet(conn, packet_data, client_addr)

    if result !== nothing
        println("✅ Initial QuicNet packet processed: $result")
        handle_quicnet_connection_events!(server, conn, result, packet_data)
    end
end

function configure_quicnet_server_connection!(conn::Quic.ConnectionModule.Connection, mode::Symbol)
    # QuicNet-specific server configuration
    conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()

    if mode == :quicnet
        # Optimize for QuicNet clients
        conn.cwnd = 14720  # QuicNet-compatible initial window
        conn.rtt_ns = 50_000_000  # 50ms initial estimate

        println("🔧 Configured for QuicNet client compatibility")

    elseif mode == :universal
        # Universal compatibility
        conn.cwnd = 14720
        conn.rtt_ns = 100_000_000  # 100ms conservative estimate

        println("🔧 Configured for universal QUIC compatibility")

    elseif mode == :strict_rfc
        # Strict RFC compliance
        conn.cwnd = 14720
        conn.rtt_ns = 333_000_000  # RFC default

        println("🔧 Configured for strict RFC compliance")
    end

    # Enable optimal features for QuicNet
    Quic.ConnectionModule.set_pacing_enabled!(conn, true)
end

function handle_quicnet_connection_events!(server::QuicNetServer, conn, event, packet_data::Vector{UInt8})
    # Handle completed handshake
    if conn.connected && !get(conn, :quicnet_setup_complete, false)
        setup_quicnet_connection!(server, conn)
        setfield!(conn, :quicnet_setup_complete, true)
    end

    # Handle stream data with QuicNet awareness
    for (stream_id, stream_state) in conn.streams
        if !isempty(stream_state.recv_buf)
            handle_quicnet_stream_data!(server, conn, stream_id, stream_state)
        end
    end

    # Update connection statistics
    server.stats = (
        connections_accepted = server.stats.connections_accepted,
        quicnet_clients = server.stats.quicnet_clients,
        bytes_received = server.stats.bytes_received + length(packet_data),
        bytes_sent = server.stats.bytes_sent,
        http3_requests = server.stats.http3_requests,
        connection_migrations = server.stats.connection_migrations
    )
end

function setup_quicnet_connection!(server::QuicNetServer, conn)
    println("🔧 Setting up QuicNet connection features...")

    # Enable HTTP/3 for QuicNet compatibility
    Quic.ConnectionModule.enable_http3!(conn)

    # Send welcome message on a new stream
    welcome_stream = Quic.ConnectionModule.open_stream(conn, true)
    welcome_msg = Vector{UInt8}("🦀 Welcome to Julia QUIC server with QuicNet compatibility!")

    Quic.ConnectionModule.send_stream(conn, welcome_stream, welcome_msg, false)

    println("📤 Sent QuicNet welcome message on stream $(welcome_stream.value)")

    # Maintain connection IDs for migration support
    Quic.ConnectionModule.maintain_connection_ids!(conn)
end

function handle_quicnet_stream_data!(server::QuicNetServer, conn, stream_id::UInt64, stream_state)
    # Read data from stream
    data, fin_received = Quic.Stream.read_stream!(stream_state, length(stream_state.recv_buf))

    if !isempty(data)
        message = String(data)
        println("📥 QuicNet stream $stream_id: \"$message\"")

        # Detect if this is HTTP/3 data
        if conn.http3 !== nothing
            # Process as HTTP/3
            http3_frames = Quic.ConnectionModule.process_http3_data!(conn, stream_id, data)

            if http3_frames !== nothing && !isempty(http3_frames)
                server.stats = (
                    connections_accepted = server.stats.connections_accepted,
                    quicnet_clients = server.stats.quicnet_clients,
                    bytes_received = server.stats.bytes_received,
                    bytes_sent = server.stats.bytes_sent,
                    http3_requests = server.stats.http3_requests + 1,
                    connection_migrations = server.stats.connection_migrations
                )

                # Send HTTP/3 response
                handle_quicnet_http3_request!(server, conn, stream_id, http3_frames)
                return
            end
        end

        # Handle as regular QUIC stream data
        handle_quicnet_data_message!(server, conn, stream_id, message, fin_received)
    end
end

function handle_quicnet_http3_request!(server::QuicNetServer, conn, stream_id::UInt64, frames)
    # Process HTTP/3 frames from QuicNet client
    for frame in frames
        if frame isa Quic.HTTP3.HTTP3HeadersFrame
            headers = Quic.HTTP3.decode_headers_qpack(frame.encoded_headers)
            method = get(headers, ":method", "")
            path = get(headers, ":path", "/")

            println("🌐 QuicNet HTTP/3 request: $method $path")

            # Generate response based on path
            response_body = if path == "/"
                """
                {
                    "message": "Hello from Julia QUIC server!",
                    "client_type": "QuicNet",
                    "timestamp": "$(now())",
                    "features": ["HTTP/3", "QUIC", "Connection Migration", "Stream Multiplexing"]
                }
                """
            elseif path == "/quicnet"
                """
                {
                    "server": "Julia QUIC",
                    "compatibility": "QuicNet",
                    "transport": "QUIC over UDP",
                    "encryption": "TLS 1.3 + ChaCha20-Poly1305",
                    "features": {
                        "connection_migration": true,
                        "0rtt": false,
                        "http3": true,
                        "multiplexing": true
                    }
                }
                """
            else
                """
                {
                    "error": "Not Found",
                    "path": "$path",
                    "available_endpoints": ["/", "/quicnet", "/test"],
                    "server": "Julia QUIC QuicNet-compatible"
                }
                """
            end

            # Send HTTP/3 response
            response_headers = Dict(
                "content-type" => "application/json",
                "server" => "Julia-QUIC-QuicNet/1.0",
                "x-quicnet-compatible" => "true"
            )

            stream_sid = Quic.Stream.StreamId(stream_id, :server, :bidi)
            status = path == "/" || path == "/quicnet" ? 200 : 404

            success = Quic.ConnectionModule.send_http_response!(
                conn, stream_sid, status, response_headers, response_body
            )

            if success
                println("📤 QuicNet HTTP/3 response sent: $status")

                server.stats = (
                    connections_accepted = server.stats.connections_accepted,
                    quicnet_clients = server.stats.quicnet_clients,
                    bytes_received = server.stats.bytes_received,
                    bytes_sent = server.stats.bytes_sent + length(response_body),
                    http3_requests = server.stats.http3_requests,
                    connection_migrations = server.stats.connection_migrations
                )
            end
        end
    end
end

function handle_quicnet_data_message!(server::QuicNetServer, conn, stream_id::UInt64, message::String, fin::Bool)
    # Process regular QUIC data from QuicNet client
    println("📊 Processing QuicNet data message: \"$message\"")

    # Generate echo response with QuicNet-specific info
    response_data = if contains(message, "migration")
        "QuicNet migration test acknowledged - Julia QUIC supports connection migration ✅"
    elseif contains(message, "Hello")
        "Hello back from Julia QUIC! QuicNet compatibility confirmed 🦀"
    elseif contains(message, "test")
        "QuicNet test response: Connection working perfectly with Julia QUIC implementation"
    else
        "Julia QUIC server received: \"$message\" - QuicNet interoperability active 🚀"
    end

    # Send response on same stream
    stream_sid = Quic.Stream.StreamId(stream_id, :server, :bidi)
    response_bytes = Vector{UInt8}(response_data)

    bytes_sent = Quic.ConnectionModule.send_stream(conn, stream_sid, response_bytes, fin)

    if bytes_sent > 0
        println("📤 QuicNet response sent: \"$response_data\"")

        server.stats = (
            connections_accepted = server.stats.connections_accepted,
            quicnet_clients = server.stats.quicnet_clients,
            bytes_received = server.stats.bytes_received,
            bytes_sent = server.stats.bytes_sent + bytes_sent,
            http3_requests = server.stats.http3_requests,
            connection_migrations = server.stats.connection_migrations
        )
    end
end

function process_quicnet_connections!(server::QuicNetServer)
    # Process all active QuicNet connections
    for (cid, conn) in server.active_connections
        try
            # Process QUIC timers
            Quic.ConnectionModule.process_timers(conn)

            # Maintain connection IDs for migration
            new_cids = Quic.ConnectionModule.maintain_connection_ids!(conn)
            if new_cids > 0
                server.stats = (
                    connections_accepted = server.stats.connections_accepted,
                    quicnet_clients = server.stats.quicnet_clients,
                    bytes_received = server.stats.bytes_received,
                    bytes_sent = server.stats.bytes_sent,
                    http3_requests = server.stats.http3_requests,
                    connection_migrations = server.stats.connection_migrations + 1
                )
            end

            # Update pacing parameters
            Quic.ConnectionModule.update_pacing_parameters!(conn)

            # Check for connection closure
            if conn.closing
                println("👋 QuicNet connection $(bytes2hex(cid.data)[1:8])... closing")
                delete!(server.active_connections, cid)
            end

        catch e
            println("⚠️ Error processing QuicNet connection $(bytes2hex(cid.data)[1:8])...: $e")
            delete!(server.active_connections, cid)
        end
    end
end

function print_quicnet_server_stats(server::QuicNetServer)
    println("\n📊 QuicNet Server Statistics:")
    println("   Compatibility mode: $(server.compatibility_mode)")
    println("   Active connections: $(length(server.active_connections))")
    println("   Total connections: $(server.stats.connections_accepted)")
    println("   QuicNet clients: $(server.stats.quicnet_clients)")
    println("   Bytes received: $(server.stats.bytes_received)")
    println("   Bytes sent: $(server.stats.bytes_sent)")
    println("   HTTP/3 requests: $(server.stats.http3_requests)")
    println("   Connection migrations: $(server.stats.connection_migrations)")

    # Print active connection details
    for (cid, conn) in server.active_connections
        println("   QuicNet connection $(bytes2hex(cid.data)[1:8])...:")
        println("     RTT: $(conn.loss_detection.smoothed_rtt ÷ 1_000_000) ms")
        println("     CWND: $(conn.cwnd) bytes")

        if conn.http3 !== nothing
            println("     HTTP/3: enabled")
            println("     Control streams: $(conn.http3.control_stream_id)/$(conn.http3.peer_control_stream_id)")
        end

        pacing_stats = Quic.ConnectionModule.get_pacing_statistics(conn)
        println("     Pacing rate: $(Int(pacing_stats.pacing_rate)) B/s")
        println("     Active streams: $(length(conn.streams))")

        cid_stats = Quic.ConnectionModule.get_cid_statistics(conn)
        println("     Connection IDs: $(cid_stats.active_local_cids)/$(cid_stats.active_remote_cids)")
    end
end

function stop_quicnet_server!(server::QuicNetServer)
    server.running = false

    # Send close to all QuicNet connections
    for (cid, conn) in server.active_connections
        try
            close_frame = Quic.Frame.ConnectionCloseFrame(0, 0, "QuicNet server shutdown")
            Quic.ConnectionModule.queue_frame!(conn, close_frame, Quic.PacketCoalescing.Application)
            Quic.ConnectionModule.flush_packets!(conn)
        catch e
            println("⚠️ Error closing QuicNet connection: $e")
        end
    end

    close(server.endpoint.socket)
    println("🔌 QuicNet server socket closed")
end

function main()
    # Test different compatibility modes
    modes = [:quicnet, :universal, :strict_rfc]

    for mode in modes
        println("\n" * "="^70)
        println("🦀 Starting QuicNet server in $mode mode")
        println("Use Ctrl+C to stop and test next mode")
        println("="^70)

        server = QuicNetServer(4433, mode)

        try
            start_quicnet_server!(server)
        catch InterruptException
            println("\n🛑 Received interrupt signal")
        finally
            stop_quicnet_server!(server)
            print_quicnet_server_stats(server)
        end

        if mode != modes[end]
            println("\nPress Enter to continue to next mode...")
            readline()
        end
    end

    return true
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end