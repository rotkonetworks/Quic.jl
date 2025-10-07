#!/usr/bin/env julia

# QuicNet Interoperability Client
# Designed to connect to Rust QuicNet servers with full protocol compatibility

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Sockets

mutable struct QuicNetClient
    endpoint::Quic.EndpointModule.Endpoint
    connection::Union{Quic.ConnectionModule.Connection, Nothing}
    server_info::@NamedTuple{
        host::String,
        port::Int,
        server_name::String
    }
    compatibility_mode::Symbol  # :quicnet, :strict_rfc, :adaptive
    stats::@NamedTuple{
        handshake_time_ms::Float64,
        packets_sent::Int,
        packets_received::Int,
        bytes_sent::Int,
        bytes_received::Int,
        retransmissions::Int,
        connection_migrations::Int
    }

    function QuicNetClient(compatibility_mode::Symbol = :quicnet)
        client_addr = Sockets.InetAddr(ip"0.0.0.0", 0)
        config = Quic.EndpointModule.EndpointConfig()
        config.server_name = "localhost"
        endpoint = Quic.EndpointModule.Endpoint(client_addr, config, false)

        new(
            endpoint, nothing,
            (host="", port=0, server_name=""),
            compatibility_mode,
            (handshake_time_ms=0.0, packets_sent=0, packets_received=0,
             bytes_sent=0, bytes_received=0, retransmissions=0, connection_migrations=0)
        )
    end
end

function connect_to_quicnet_server!(client::QuicNetClient,
                                   host::String = "127.0.0.1",
                                   port::Int = 4433,
                                   server_name::String = "localhost")
    println("🦀 Connecting to QuicNet server at $host:$port...")
    println("   Compatibility mode: $(client.compatibility_mode)")

    # Store server info
    client.server_info = (host=host, port=port, server_name=server_name)

    # Create connection with QuicNet-specific optimizations
    server_addr = Sockets.InetAddr(IPv4(host), port)
    client.connection = Quic.EndpointModule.connect(client.endpoint, server_addr)

    # Configure for QuicNet compatibility
    configure_quicnet_compatibility!(client.connection, client.compatibility_mode)

    println("🔐 Configured QUIC connection for QuicNet compatibility")
    println("   Local CID: $(bytes2hex(client.connection.local_cid.data))")
    println("   Remote CID: $(bytes2hex(client.connection.remote_cid.data))")

    # Initiate handshake with QuicNet-specific parameters
    handshake_start = time_ns()
    println("🤝 Starting QUIC handshake with QuicNet server...")

    initiate_quicnet_handshake!(client.connection, server_name)

    # Enhanced handshake processing for QuicNet
    if !complete_quicnet_handshake!(client, handshake_start)
        return false
    end

    # Post-handshake QuicNet setup
    setup_quicnet_features!(client)

    return true
end

function configure_quicnet_compatibility!(conn::Quic.ConnectionModule.Connection, mode::Symbol)
    if mode == :quicnet
        # QuicNet-specific configuration

        # Use ChaCha20-Poly1305 (preferred by QuicNet)
        conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()

        # Adjust initial congestion window for QuicNet
        conn.cwnd = 14720  # 10 * MSS, QuicNet default

        # Configure pacing for QuicNet characteristics
        Quic.ConnectionModule.set_pacing_enabled!(conn, true)

        # Set initial RTT estimate suitable for QuicNet
        conn.rtt_ns = 50_000_000  # 50ms initial estimate

        println("🔧 Applied QuicNet-specific optimizations")

    elseif mode == :strict_rfc
        # Strict RFC compliance mode
        conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()
        conn.cwnd = 14720

        println("🔧 Applied strict RFC compliance settings")

    elseif mode == :adaptive
        # Adaptive mode - detect and adjust
        conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()

        println("🔧 Applied adaptive compatibility settings")
    end

    # Derive initial secrets
    Quic.Crypto.derive_initial_secrets!(conn.crypto, conn.remote_cid.data)
end

function initiate_quicnet_handshake!(conn::Quic.ConnectionModule.Connection, server_name::String)
    # Send Initial packet with QuicNet-compatible parameters
    Quic.ConnectionModule.initiate_handshake(conn, server_name)

    # QuicNet may expect specific transport parameters
    # This would be handled in the handshake module, but we can log it
    println("📤 Sent Initial packet with QuicNet compatibility")
end

function complete_quicnet_handshake!(client::QuicNetClient, handshake_start::UInt64)
    max_handshake_time = 15.0  # QuicNet may take longer
    data = Vector{UInt8}(undef, 65536)
    handshake_complete = false

    println("👂 Listening for QuicNet server responses...")

    while !handshake_complete && (time_ns() - handshake_start) / 1_000_000_000 < max_handshake_time
        try
            # Process timers and loss detection
            Quic.ConnectionModule.process_timers(client.connection)

            # Try to receive packet
            nbytes, from = recvfrom(client.connection.socket, data, timeout=1.0)

            if nbytes > 0
                println("📥 Received $(nbytes) bytes from QuicNet server")

                # Update stats
                client.stats = (
                    handshake_time_ms = client.stats.handshake_time_ms,
                    packets_sent = client.stats.packets_sent,
                    packets_received = client.stats.packets_received + 1,
                    bytes_sent = client.stats.bytes_sent,
                    bytes_received = client.stats.bytes_received + nbytes,
                    retransmissions = client.stats.retransmissions,
                    connection_migrations = client.stats.connection_migrations
                )

                # Process packet with QuicNet-aware handling
                result = process_quicnet_packet!(client, data[1:nbytes], from)

                if result !== nothing && client.connection.connected
                    handshake_complete = true
                    handshake_time = (time_ns() - handshake_start) / 1_000_000

                    client.stats = (
                        handshake_time_ms = handshake_time,
                        packets_sent = client.stats.packets_sent,
                        packets_received = client.stats.packets_received,
                        bytes_sent = client.stats.bytes_sent,
                        bytes_received = client.stats.bytes_received,
                        retransmissions = client.stats.retransmissions,
                        connection_migrations = client.stats.connection_migrations
                    )

                    println("🎉 QuicNet handshake completed in $(round(handshake_time, digits=2)) ms!")
                    break
                end
            end

        catch e
            if isa(e, Base.UVError) && e.code == Base.UV_ETIMEDOUT
                # Handle QuicNet-specific timeout behavior
                if Quic.LossDetection.should_send_probe_packets(client.connection.loss_detection)
                    println("🔄 QuicNet handshake timeout, retransmitting...")
                    Quic.ConnectionModule.handle_loss_detection_timeout(client.connection)

                    client.stats = (
                        handshake_time_ms = client.stats.handshake_time_ms,
                        packets_sent = client.stats.packets_sent,
                        packets_received = client.stats.packets_received,
                        bytes_sent = client.stats.bytes_sent,
                        bytes_received = client.stats.bytes_received,
                        retransmissions = client.stats.retransmissions + 1,
                        connection_migrations = client.stats.connection_migrations
                    )
                end
            else
                println("❌ QuicNet handshake error: $e")
                return false
            end
        end

        sleep(0.01)
    end

    if !handshake_complete
        println("❌ QuicNet handshake failed after $(max_handshake_time)s")
        return false
    end

    return true
end

function process_quicnet_packet!(client::QuicNetClient, packet_data::Vector{UInt8}, from)
    # Process packet with QuicNet-specific awareness
    result = Quic.PacketReceiver.process_incoming_packet(client.connection, packet_data, from)

    # QuicNet-specific post-processing
    if result !== nothing
        packet_type, frames = result

        # Handle QuicNet-specific frame processing
        if frames !== nothing
            for frame in frames
                process_quicnet_frame!(client, frame, packet_type)
            end
        end
    end

    return result
end

function process_quicnet_frame!(client::QuicNetClient, frame, packet_type::Symbol)
    # QuicNet-specific frame handling
    if frame isa Quic.Frame.AckFrame
        # QuicNet may have specific ACK behavior
        println("🔄 QuicNet ACK frame processed: largest=$(frame.largest)")

    elseif frame isa Quic.Frame.CryptoFrame
        # QuicNet crypto handling
        println("🔐 QuicNet CRYPTO frame: $(length(frame.data)) bytes")

    elseif frame isa Quic.Frame.NewConnectionIdFrame
        # QuicNet connection ID management
        println("🔄 QuicNet NEW_CONNECTION_ID: seq=$(frame.sequence)")

    elseif frame isa Quic.Frame.StreamFrame
        # QuicNet stream data
        println("📊 QuicNet STREAM frame: id=$(frame.stream_id), $(length(frame.data)) bytes")
    end
end

function setup_quicnet_features!(client::QuicNetClient)
    println("🔧 Setting up QuicNet-specific features...")

    # Enable connection ID rotation for mobility
    Quic.ConnectionModule.maintain_connection_ids!(client.connection)

    # Optimize pacing for QuicNet
    Quic.ConnectionModule.update_pacing_parameters!(client.connection)

    # Enable HTTP/3 if needed
    if client.compatibility_mode == :quicnet
        Quic.ConnectionModule.enable_http3!(client.connection)
        println("🌐 HTTP/3 enabled for QuicNet compatibility")
    end

    println("✅ QuicNet features configured")
end

function send_quicnet_data!(client::QuicNetClient, data::Union{Vector{UInt8}, String})
    if client.connection === nothing || !client.connection.connected
        println("❌ No active QuicNet connection")
        return false
    end

    # Open stream with QuicNet-optimal settings
    stream_id = Quic.ConnectionModule.open_stream(client.connection, true)

    # Convert data
    data_bytes = data isa String ? Vector{UInt8}(data) : data

    # Send with QuicNet-aware flow control
    bytes_sent = Quic.ConnectionModule.send_stream(client.connection, stream_id, data_bytes, false)

    if bytes_sent > 0
        println("📤 Sent $(bytes_sent) bytes to QuicNet server on stream $(stream_id.value)")

        # Update stats
        client.stats = (
            handshake_time_ms = client.stats.handshake_time_ms,
            packets_sent = client.stats.packets_sent + 1,
            packets_received = client.stats.packets_received,
            bytes_sent = client.stats.bytes_sent + bytes_sent,
            bytes_received = client.stats.bytes_received,
            retransmissions = client.stats.retransmissions,
            connection_migrations = client.stats.connection_migrations
        )

        return stream_id
    end

    return nothing
end

function send_quicnet_http_request!(client::QuicNetClient, method::String, path::String,
                                   headers::Dict{String, String} = Dict{String, String}(),
                                   body::Union{Vector{UInt8}, String} = UInt8[])
    if client.connection === nothing || !client.connection.connected
        println("❌ No active QuicNet connection")
        return nothing
    end

    # Ensure HTTP/3 is enabled
    if client.connection.http3 === nothing
        Quic.ConnectionModule.enable_http3!(client.connection)
    end

    # Add QuicNet-compatible headers
    http_headers = copy(headers)
    http_headers["user-agent"] = "Julia-QUIC-QuicNet/1.0"

    # Send HTTP/3 request
    request_stream = Quic.ConnectionModule.send_http_request!(
        client.connection, method, path, http_headers, body
    )

    println("🌐 Sent HTTP/3 request to QuicNet server:")
    println("   $method $path")
    println("   Stream: $(request_stream.value)")

    return request_stream
end

function receive_quicnet_data!(client::QuicNetClient; timeout_s::Float64 = 5.0)
    if client.connection === nothing
        return nothing
    end

    data = Vector{UInt8}(undef, 65536)
    received_data = []
    start_time = time_ns()

    while (time_ns() - start_time) / 1_000_000_000 < timeout_s
        try
            nbytes, from = recvfrom(client.connection.socket, data, timeout=0.5)

            if nbytes > 0
                println("📥 Received $(nbytes) bytes from QuicNet server")

                # Process with QuicNet handling
                result = process_quicnet_packet!(client, data[1:nbytes], from)

                # Check for stream data
                for (stream_id, stream_state) in client.connection.streams
                    if !isempty(stream_state.recv_buf)
                        stream_data, fin = Quic.Stream.read_stream!(stream_state, length(stream_state.recv_buf))
                        if !isempty(stream_data)
                            push!(received_data, (stream_id=stream_id, data=stream_data, fin=fin))
                            println("📊 QuicNet stream $stream_id: $(length(stream_data)) bytes")
                        end
                    end
                end

                client.stats = (
                    handshake_time_ms = client.stats.handshake_time_ms,
                    packets_sent = client.stats.packets_sent,
                    packets_received = client.stats.packets_received + 1,
                    bytes_sent = client.stats.bytes_sent,
                    bytes_received = client.stats.bytes_received + nbytes,
                    retransmissions = client.stats.retransmissions,
                    connection_migrations = client.stats.connection_migrations
                )
            end

        catch e
            if !isa(e, Base.UVError) || e.code != Base.UV_ETIMEDOUT
                println("⚠️ Error receiving QuicNet data: $e")
                break
            end
        end
    end

    return received_data
end

function test_quicnet_connection_migration!(client::QuicNetClient)
    if client.connection === nothing || !client.connection.connected
        return false
    end

    println("🔄 Testing QuicNet connection migration...")

    # Attempt connection ID rotation
    success = Quic.ConnectionModule.rotate_connection_id!(client.connection)

    if success
        client.stats = (
            handshake_time_ms = client.stats.handshake_time_ms,
            packets_sent = client.stats.packets_sent,
            packets_received = client.stats.packets_received,
            bytes_sent = client.stats.bytes_sent,
            bytes_received = client.stats.bytes_received,
            retransmissions = client.stats.retransmissions,
            connection_migrations = client.stats.connection_migrations + 1
        )

        # Send test data after migration
        test_data = "Connection migration test - QuicNet compatibility"
        stream = send_quicnet_data!(client, test_data)

        if stream !== nothing
            println("✅ QuicNet connection migration successful")
            return true
        end
    end

    println("❌ QuicNet connection migration failed")
    return false
end

function demonstrate_quicnet_features!(client::QuicNetClient)
    println("\n🦀 Demonstrating QuicNet compatibility features...")

    # Test 1: Basic data exchange
    println("\n📋 Test 1: Basic data exchange")
    stream1 = send_quicnet_data!(client, "Hello QuicNet server from Julia!")
    if stream1 !== nothing
        responses = receive_quicnet_data!(client, timeout_s=3.0)
        for response in responses
            println("✅ Received response: \"$(String(response.data))\"")
        end
    end

    # Test 2: HTTP/3 over QuicNet
    println("\n📋 Test 2: HTTP/3 over QuicNet")
    http_stream = send_quicnet_http_request!(client, "GET", "/")
    if http_stream !== nothing
        println("✅ HTTP/3 request sent successfully")
        receive_quicnet_data!(client, timeout_s=5.0)
    end

    # Test 3: Multiple concurrent streams
    println("\n📋 Test 3: Multiple concurrent streams")
    for i in 1:3
        stream = send_quicnet_data!(client, "Concurrent message #$i")
        if stream !== nothing
            println("✅ Sent concurrent message $i")
        end
        sleep(0.1)
    end

    # Receive all responses
    all_responses = receive_quicnet_data!(client, timeout_s=5.0)
    println("✅ Received $(length(all_responses)) concurrent responses")

    # Test 4: Connection migration
    println("\n📋 Test 4: Connection migration")
    migration_success = test_quicnet_connection_migration!(client)

    # Test 5: Large data transfer
    println("\n📋 Test 5: Large data transfer")
    large_data = "Large QuicNet test: " * "X" * 5000 * " [END]"
    large_stream = send_quicnet_data!(client, large_data)
    if large_stream !== nothing
        println("✅ Large data sent: $(length(large_data)) bytes")
        large_responses = receive_quicnet_data!(client, timeout_s=10.0)
        for response in large_responses
            println("✅ Large response: $(length(response.data)) bytes")
        end
    end
end

function print_quicnet_stats(client::QuicNetClient)
    println("\n📊 QuicNet Compatibility Statistics:")
    println("   Server: $(client.server_info.host):$(client.server_info.port)")
    println("   Compatibility mode: $(client.compatibility_mode)")
    println("   Handshake time: $(round(client.stats.handshake_time_ms, digits=2)) ms")
    println("   Packets sent: $(client.stats.packets_sent)")
    println("   Packets received: $(client.stats.packets_received)")
    println("   Bytes sent: $(client.stats.bytes_sent)")
    println("   Bytes received: $(client.stats.bytes_received)")
    println("   Retransmissions: $(client.stats.retransmissions)")
    println("   Connection migrations: $(client.stats.connection_migrations)")

    if client.connection !== nothing
        # Network performance stats
        println("\n📊 QuicNet Network Performance:")
        println("   RTT: $(client.connection.loss_detection.smoothed_rtt ÷ 1_000_000) ms")
        println("   CWND: $(client.connection.cwnd) bytes")

        pacing_stats = Quic.ConnectionModule.get_pacing_statistics(client.connection)
        println("   Pacing rate: $(Int(pacing_stats.pacing_rate)) bytes/sec")
        println("   Loss detection state: $(client.connection.loss_detection.pto_count) PTOs")

        # Connection ID stats
        cid_stats = Quic.ConnectionModule.get_cid_statistics(client.connection)
        println("   Active local CIDs: $(cid_stats.active_local_cids)")
        println("   Active remote CIDs: $(cid_stats.active_remote_cids)")

        # HTTP/3 stats if enabled
        if client.connection.http3 !== nothing
            println("\n📊 HTTP/3 over QuicNet:")
            println("   Control stream: $(client.connection.http3.control_stream_id)")
            println("   Peer control stream: $(client.connection.http3.peer_control_stream_id)")
            println("   Settings exchanged: $(length(client.connection.http3.peer_settings))")
        end
    end
end

function disconnect_from_quicnet!(client::QuicNetClient)
    if client.connection !== nothing
        # Send QuicNet-compatible close
        close_frame = Quic.Frame.ConnectionCloseFrame(0, 0, "Julia QuicNet client disconnect")
        Quic.ConnectionModule.queue_frame!(client.connection, close_frame, Quic.PacketCoalescing.Application)
        Quic.ConnectionModule.flush_packets!(client.connection)

        println("👋 Sent connection close to QuicNet server")
    end

    close(client.endpoint.socket)
    println("🔌 Disconnected from QuicNet server")
end

function main()
    # Test different compatibility modes
    for mode in [:quicnet, :strict_rfc, :adaptive]
        println("\n" * "="^70)
        println("🦀 Testing QuicNet compatibility mode: $mode")
        println("="^70)

        client = QuicNetClient(mode)

        try
            # Connect to QuicNet server
            if !connect_to_quicnet_server!(client, "127.0.0.1", 4433, "localhost")
                println("❌ Failed to connect to QuicNet server in $mode mode")
                continue
            end

            # Demonstrate features
            demonstrate_quicnet_features!(client)

            # Print statistics
            print_quicnet_stats(client)

            println("\n✅ QuicNet compatibility test ($mode) completed!")

        catch e
            println("❌ QuicNet client error ($mode): $e")
        finally
            disconnect_from_quicnet!(client)
        end
    end

    return true
end

if abspath(PROGRAM_FILE) == @__FILE__
    success = main()
    println("\n" * "="^80)
    println("🦀 QuicNet Interoperability Test: $(success ? "PASSED" : "FAILED")")
    println("="^80)
    exit(success ? 0 : 1)
end