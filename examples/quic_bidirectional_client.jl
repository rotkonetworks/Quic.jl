#!/usr/bin/env julia

# Full QUIC Bidirectional Client
# Demonstrates complete client-side QUIC with bidirectional stream communication

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Sockets

mutable struct QuicClient
    endpoint::Quic.EndpointModule.Endpoint
    connection::Union{Quic.ConnectionModule.Connection, Nothing}
    streams::Dict{UInt64, @NamedTuple{sent_messages::Int, received_messages::Int}}
    stats::@NamedTuple{
        handshake_time_ms::Float64,
        total_bytes_sent::Int,
        total_bytes_received::Int,
        messages_sent::Int,
        messages_received::Int
    }

    function QuicClient()
        client_addr = Sockets.InetAddr(ip"0.0.0.0", 0)
        config = Quic.EndpointModule.EndpointConfig()
        config.server_name = "localhost"
        endpoint = Quic.EndpointModule.Endpoint(client_addr, config, false)

        new(endpoint, nothing, Dict(), (handshake_time_ms=0.0, total_bytes_sent=0, total_bytes_received=0, messages_sent=0, messages_received=0))
    end
end

function connect_to_server!(client::QuicClient, server_host::String = "127.0.0.1", server_port::Int = 4433)
    println("🔗 Connecting to QUIC server at $server_host:$server_port...")

    # Create connection
    server_addr = Sockets.InetAddr(ip"127.0.0.1", server_port)
    client.connection = Quic.EndpointModule.connect(client.endpoint, server_addr)

    # Setup crypto
    client.connection.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()
    Quic.Crypto.derive_initial_secrets!(client.connection.crypto, client.connection.remote_cid.data)

    println("🔐 Crypto initialized: ChaCha20-Poly1305")
    println("   Local CID: $(bytes2hex(client.connection.local_cid.data))")
    println("   Remote CID: $(bytes2hex(client.connection.remote_cid.data))")

    # Start handshake
    handshake_start = time_ns()
    println("🤝 Initiating TLS 1.3 handshake...")
    Quic.ConnectionModule.initiate_handshake(client.connection, "localhost")

    # Wait for handshake completion
    max_handshake_time = 10.0  # 10 seconds
    data = Vector{UInt8}(undef, 65536)
    handshake_complete = false

    while !handshake_complete && (time_ns() - handshake_start) / 1_000_000_000 < max_handshake_time
        try
            # Process timers
            Quic.ConnectionModule.process_timers(client.connection)

            # Try to receive packet
            nbytes, from = recvfrom(client.connection.socket, data, timeout=1.0)

            if nbytes > 0
                println("📥 Received $(nbytes) bytes during handshake")

                # Process packet
                result = Quic.PacketReceiver.process_incoming_packet(
                    client.connection, data[1:nbytes], from
                )

                if result !== nothing && client.connection.connected
                    handshake_complete = true
                    handshake_time = (time_ns() - handshake_start) / 1_000_000  # ms
                    client.stats = (
                        handshake_time_ms = handshake_time,
                        total_bytes_sent = client.stats.total_bytes_sent,
                        total_bytes_received = client.stats.total_bytes_received,
                        messages_sent = client.stats.messages_sent,
                        messages_received = client.stats.messages_received
                    )

                    println("🎉 Handshake completed in $(round(handshake_time, digits=2)) ms!")
                    break
                end
            end

        catch e
            if isa(e, Base.UVError) && e.code == Base.UV_ETIMEDOUT
                # Check for timeout retransmissions
                if Quic.LossDetection.should_send_probe_packets(client.connection.loss_detection)
                    println("🔄 Handshake timeout, retransmitting...")
                    Quic.ConnectionModule.handle_loss_detection_timeout(client.connection)
                end
            else
                println("❌ Handshake error: $e")
                return false
            end
        end

        sleep(0.01)
    end

    if !handshake_complete
        println("❌ Handshake failed - timeout after $(max_handshake_time)s")
        return false
    end

    # Start receiving welcome message and server data
    process_incoming_data!(client)

    return true
end

function process_incoming_data!(client::QuicClient)
    # Process any incoming data (like welcome message)
    data = Vector{UInt8}(undef, 65536)

    for i in 1:5  # Try a few times to get server messages
        try
            nbytes, from = recvfrom(client.connection.socket, data, timeout=0.5)

            if nbytes > 0
                result = Quic.PacketReceiver.process_incoming_packet(
                    client.connection, data[1:nbytes], from
                )

                # Check for received stream data
                for (stream_id, stream_state) in client.connection.streams
                    if !isempty(stream_state.recv_buf)
                        handle_received_data!(client, stream_id, stream_state)
                    end
                end
            end

        catch e
            if !isa(e, Base.UVError) || e.code != Base.UV_ETIMEDOUT
                println("⚠️ Error receiving data: $e")
            end
            break
        end
    end
end

function handle_received_data!(client::QuicClient, stream_id::UInt64, stream_state::Quic.Stream.StreamState)
    data, fin_received = Quic.Stream.read_stream!(stream_state, length(stream_state.recv_buf))

    if !isempty(data)
        message = String(data)
        println("📥 Received on stream $stream_id: \"$message\"")

        # Update statistics
        client.stats = (
            handshake_time_ms = client.stats.handshake_time_ms,
            total_bytes_sent = client.stats.total_bytes_sent,
            total_bytes_received = client.stats.total_bytes_received + length(data),
            messages_sent = client.stats.messages_sent,
            messages_received = client.stats.messages_received + 1
        )

        # Update stream statistics
        if haskey(client.streams, stream_id)
            current = client.streams[stream_id]
            client.streams[stream_id] = (
                sent_messages = current.sent_messages,
                received_messages = current.received_messages + 1
            )
        else
            client.streams[stream_id] = (sent_messages = 0, received_messages = 1)
        end
    end
end

function send_message!(client::QuicClient, message::String, stream_id::Union{Quic.Stream.StreamId, Nothing} = nothing)
    if client.connection === nothing || !client.connection.connected
        println("❌ No active connection to send message")
        return false
    end

    # Create new stream if not provided
    if stream_id === nothing
        stream_id = Quic.ConnectionModule.open_stream(client.connection, true)
        println("📂 Opened new bidirectional stream $(stream_id.value)")

        client.streams[stream_id.value] = (sent_messages = 0, received_messages = 0)
    end

    # Send message
    message_data = Vector{UInt8}(message)
    bytes_sent = Quic.ConnectionModule.send_stream(client.connection, stream_id, message_data, false)

    if bytes_sent > 0
        println("📤 Sent $(bytes_sent) bytes on stream $(stream_id.value): \"$message\"")

        # Update statistics
        client.stats = (
            handshake_time_ms = client.stats.handshake_time_ms,
            total_bytes_sent = client.stats.total_bytes_sent + bytes_sent,
            total_bytes_received = client.stats.total_bytes_received,
            messages_sent = client.stats.messages_sent + 1,
            messages_received = client.stats.messages_received
        )

        # Update stream statistics
        current = client.streams[stream_id.value]
        client.streams[stream_id.value] = (
            sent_messages = current.sent_messages + 1,
            received_messages = current.received_messages
        )

        return true
    end

    println("❌ Failed to send message")
    return false
end

function send_and_wait_response!(client::QuicClient, message::String; timeout_s::Float64 = 5.0)
    # Open new stream for request-response
    stream_id = Quic.ConnectionModule.open_stream(client.connection, true)
    client.streams[stream_id.value] = (sent_messages = 0, received_messages = 0)

    println("🔄 Request-Response on stream $(stream_id.value)")

    # Send message
    if !send_message!(client, message, stream_id)
        return nothing
    end

    # Wait for response
    start_time = time_ns()
    data = Vector{UInt8}(undef, 65536)

    while (time_ns() - start_time) / 1_000_000_000 < timeout_s
        try
            # Process timers
            Quic.ConnectionModule.process_timers(client.connection)

            # Check for incoming data
            nbytes, from = recvfrom(client.connection.socket, data, timeout=0.1)

            if nbytes > 0
                Quic.PacketReceiver.process_incoming_packet(
                    client.connection, data[1:nbytes], from
                )

                # Check if we got a response on our stream
                if haskey(client.connection.streams, stream_id.value)
                    stream_state = client.connection.streams[stream_id.value]
                    if !isempty(stream_state.recv_buf)
                        response_data, _ = Quic.Stream.read_stream!(stream_state, length(stream_state.recv_buf))
                        if !isempty(response_data)
                            response = String(response_data)
                            println("📥 Response: \"$response\"")

                            # Update stats
                            client.stats = (
                                handshake_time_ms = client.stats.handshake_time_ms,
                                total_bytes_sent = client.stats.total_bytes_sent,
                                total_bytes_received = client.stats.total_bytes_received + length(response_data),
                                messages_sent = client.stats.messages_sent,
                                messages_received = client.stats.messages_received + 1
                            )

                            return response
                        end
                    end
                end
            end

        catch e
            if !isa(e, Base.UVError) || e.code != Base.UV_ETIMEDOUT
                println("⚠️ Error waiting for response: $e")
                break
            end
        end

        sleep(0.01)
    end

    println("⏰ Response timeout after $(timeout_s)s")
    return nothing
end

function demonstrate_bidirectional_communication!(client::QuicClient)
    println("\n🔄 Demonstrating bidirectional communication...")

    # Test 1: Simple message exchange
    println("\n📋 Test 1: Simple message exchange")
    response1 = send_and_wait_response!(client, "Hello from Julia QUIC client! 👋")

    # Test 2: Multiple streams
    println("\n📋 Test 2: Multiple concurrent streams")
    stream1 = Quic.ConnectionModule.open_stream(client.connection, true)
    stream2 = Quic.ConnectionModule.open_stream(client.connection, true)
    stream3 = Quic.ConnectionModule.open_stream(client.connection, true)

    client.streams[stream1.value] = (sent_messages = 0, received_messages = 0)
    client.streams[stream2.value] = (sent_messages = 0, received_messages = 0)
    client.streams[stream3.value] = (sent_messages = 0, received_messages = 0)

    # Send on multiple streams
    send_message!(client, "Stream 1: Technical data 🔧", stream1)
    send_message!(client, "Stream 2: User message 👤", stream2)
    send_message!(client, "Stream 3: Binary data ⚡", stream3)

    # Wait for responses
    println("⏳ Waiting for responses on multiple streams...")
    process_incoming_data!(client)

    # Test 3: Large data transfer
    println("\n📋 Test 3: Large data transfer")
    large_message = "Large data: " * "X" * 1000 * " 📊"
    response3 = send_and_wait_response!(client, large_message, timeout_s=10.0)

    # Test 4: Rapid fire messages
    println("\n📋 Test 4: Rapid message burst")
    burst_stream = Quic.ConnectionModule.open_stream(client.connection, true)
    client.streams[burst_stream.value] = (sent_messages = 0, received_messages = 0)

    for i in 1:5
        send_message!(client, "Burst message #$i ⚡", burst_stream)
        sleep(0.1)  # Small delay between messages
    end

    # Process any remaining responses
    println("⏳ Processing remaining responses...")
    for i in 1:10
        process_incoming_data!(client)
        sleep(0.2)
    end
end

function print_client_stats(client::QuicClient)
    println("\n📊 Client Statistics:")
    println("   Handshake time: $(round(client.stats.handshake_time_ms, digits=2)) ms")
    println("   Total bytes sent: $(client.stats.total_bytes_sent)")
    println("   Total bytes received: $(client.stats.total_bytes_received)")
    println("   Messages sent: $(client.stats.messages_sent)")
    println("   Messages received: $(client.stats.messages_received)")
    println("   Active streams: $(length(client.streams))")

    if client.connection !== nothing
        # Network statistics
        loss_stats = Quic.ConnectionModule.get_cid_statistics(client.connection)
        pacing_stats = Quic.ConnectionModule.get_pacing_statistics(client.connection)

        println("\n📊 Network Statistics:")
        println("   RTT: $(client.connection.loss_detection.smoothed_rtt ÷ 1_000_000) ms")
        println("   CWND: $(client.connection.cwnd) bytes")
        println("   Pacing rate: $(Int(pacing_stats.pacing_rate)) bytes/sec")
        println("   Bytes in flight: $(client.connection.loss_detection.bytes_in_flight)")
        println("   PTO count: $(client.connection.loss_detection.pto_count)")

        println("\n📊 Stream Statistics:")
        for (stream_id, stats) in client.streams
            println("   Stream $stream_id: sent=$(stats.sent_messages), received=$(stats.received_messages)")
        end
    end
end

function disconnect!(client::QuicClient)
    if client.connection !== nothing
        # Send connection close
        close_frame = Quic.Frame.ConnectionCloseFrame(0, 0, "Client disconnect")
        Quic.ConnectionModule.queue_frame!(client.connection, close_frame, Quic.PacketCoalescing.Application)
        Quic.ConnectionModule.flush_packets!(client.connection)

        println("👋 Sent connection close frame")
    end

    close(client.endpoint.socket)
    println("🔌 Disconnected from server")
end

function main()
    client = QuicClient()

    try
        # Connect to server
        if !connect_to_server!(client)
            println("❌ Failed to connect to server")
            return false
        end

        # Demonstrate bidirectional communication
        demonstrate_bidirectional_communication!(client)

        # Print final statistics
        print_client_stats(client)

        println("\n✅ Bidirectional QUIC communication demonstration completed!")

    catch e
        println("❌ Client error: $e")
        return false
    finally
        disconnect!(client)
    end

    return true
end

if abspath(PROGRAM_FILE) == @__FILE__
    success = main()
    println("\n" * "="^70)
    println("QUIC Bidirectional Client Test: $(success ? "PASSED" : "FAILED")")
    println("="^70)
    exit(success ? 0 : 1)
end