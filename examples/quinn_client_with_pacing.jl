#!/usr/bin/env julia

# Quinn interoperability client with packet pacing demonstration
# Shows how QUIC manages transmission rates to prevent network congestion

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Sockets

function main()
    println("🚀 Starting Quinn client with packet pacing...")

    # create client socket
    client_addr = Sockets.InetAddr(ip"0.0.0.0", 0)
    config = Quic.EndpointModule.EndpointConfig()
    config.server_name = "localhost"

    # create endpoint and connection
    endpoint = Quic.EndpointModule.Endpoint(client_addr, config, false)
    server_addr = Sockets.InetAddr(ip"127.0.0.1", 4433)
    conn = Quic.EndpointModule.connect(endpoint, server_addr)

    println("📡 Created connection to Quinn server at 127.0.0.1:4433")
    println("   Local CID: $(bytes2hex(conn.local_cid.data))")
    println("   Remote CID: $(bytes2hex(conn.remote_cid.data))")

    # Display initial pacing state
    initial_pacing = Quic.ConnectionModule.get_pacing_statistics(conn)
    println("📊 Initial pacing statistics:")
    println("   Pacing enabled: $(initial_pacing.pacing_enabled)")
    println("   Pacing rate: $(Int(initial_pacing.pacing_rate)) bytes/sec")
    println("   Burst size: $(initial_pacing.burst_size) bytes")

    # setup crypto
    conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()
    Quic.Crypto.derive_initial_secrets!(conn.crypto, conn.remote_cid.data)

    println("🔐 Initialized ChaCha20-Poly1305 encryption")

    # initiate handshake
    println("🤝 Starting TLS 1.3 handshake...")
    Quic.ConnectionModule.initiate_handshake(conn, "localhost")

    # track handshake progress
    handshake_complete = false
    max_retries = 10
    retry_count = 0

    # receive and process responses
    println("👂 Listening for server responses...")
    data = Vector{UInt8}(undef, 65536)

    while !handshake_complete && retry_count < max_retries
        try
            # Process timers and update pacing
            Quic.ConnectionModule.process_timers(conn)
            Quic.ConnectionModule.update_pacing_parameters!(conn)

            # try to receive a packet
            nbytes, from = recvfrom(conn.socket, data, timeout=1.0)

            if nbytes > 0
                println("📥 Received $(nbytes) bytes from $(from)")

                # process the packet
                result = Quic.PacketReceiver.process_incoming_packet(
                    conn, data[1:nbytes], from
                )

                if result !== nothing
                    println("✅ Processed packet type: $(result)")

                    # check if handshake completed
                    if conn.connected
                        handshake_complete = true
                        println("🎉 Handshake completed successfully!")

                        # Show pacing stats after handshake
                        post_handshake_pacing = Quic.ConnectionModule.get_pacing_statistics(conn)
                        println("📊 Post-handshake pacing:")
                        println("   Rate: $(Int(post_handshake_pacing.pacing_rate)) B/s")
                        println("   Current rate: $(Int(post_handshake_pacing.current_rate)) B/s")
                        break
                    end
                end
            end

        catch e
            if isa(e, Base.UVError) && e.code == Base.UV_ETIMEDOUT
                # timeout - handle timers
                if Quic.LossDetection.should_send_probe_packets(conn.loss_detection)
                    println("🔄 Sending probe packets (with pacing)")
                    Quic.ConnectionModule.handle_loss_detection_timeout(conn)
                end

                retry_count += 1
                println("🔄 Retry $(retry_count)/$(max_retries)")
            else
                println("❌ Error: $e")
                break
            end
        end

        sleep(0.1)
    end

    # Demonstrate packet pacing with burst data transfer
    if handshake_complete
        println("\n📊 Testing packet pacing with burst data transfer...")

        # Open a stream for data transfer
        stream_id = Quic.ConnectionModule.open_stream(conn, true)
        println("📂 Opened stream $(stream_id.value)")

        # Test 1: Small data transfer (should not be paced significantly)
        println("\n🔬 Test 1: Small data transfer")
        small_data = Vector{UInt8}("Hello Quinn! This is a small message.")
        delay_expected = Quic.ConnectionModule.would_pacing_delay(conn, UInt64(length(small_data)))
        println("   Data size: $(length(small_data)) bytes")
        println("   Pacing delay expected: $delay_expected")

        start_time = time_ns()
        Quic.ConnectionModule.send_stream(conn, stream_id, small_data, false)
        elapsed = (time_ns() - start_time) / 1_000_000  # convert to ms
        println("   Actual send time: $(round(elapsed, digits=2)) ms")

        # Test 2: Large data transfer (should be paced)
        println("\n🔬 Test 2: Large data transfer with pacing")
        large_data = Vector{UInt8}("X" ^ 5000)  # 5KB of data
        delay_expected = Quic.ConnectionModule.would_pacing_delay(conn, UInt64(length(large_data)))
        println("   Data size: $(length(large_data)) bytes")
        println("   Pacing delay expected: $delay_expected")

        start_time = time_ns()
        bytes_sent = 0
        chunk_size = 1000

        for i in 1:chunk_size:length(large_data)
            chunk_end = min(i + chunk_size - 1, length(large_data))
            chunk = large_data[i:chunk_end]

            # Check pacing before sending each chunk
            pacing_stats = Quic.ConnectionModule.get_pacing_statistics(conn)
            if pacing_stats.bucket_tokens < length(chunk)
                println("   ⏳ Pacing active, tokens: $(Int(pacing_stats.bucket_tokens))")
            end

            Quic.ConnectionModule.send_stream(conn, stream_id, chunk, chunk_end == length(large_data))
            bytes_sent += length(chunk)

            # Small delay to see pacing in action
            sleep(0.01)
        end

        elapsed = (time_ns() - start_time) / 1_000_000  # convert to ms
        rate_mbps = (bytes_sent * 8.0) / (elapsed * 1000.0)  # Mbps
        println("   Total bytes sent: $bytes_sent")
        println("   Transfer time: $(round(elapsed, digits=2)) ms")
        println("   Effective rate: $(round(rate_mbps, digits=2)) Mbps")

        # Test 3: Disable pacing and compare
        println("\n🔬 Test 3: Transfer with pacing disabled")
        Quic.ConnectionModule.set_pacing_enabled!(conn, false)

        medium_data = Vector{UInt8}("Y" ^ 2000)  # 2KB of data
        start_time = time_ns()
        Quic.ConnectionModule.send_stream(conn, stream_id, medium_data, false)
        elapsed_no_pacing = (time_ns() - start_time) / 1_000_000

        println("   Data size: $(length(medium_data)) bytes")
        println("   Transfer time (no pacing): $(round(elapsed_no_pacing, digits=2)) ms")

        # Re-enable pacing
        Quic.ConnectionModule.set_pacing_enabled!(conn, true)

        # Test 4: Compare with pacing enabled
        println("\n🔬 Test 4: Same transfer with pacing enabled")
        Quic.ConnectionModule.update_pacing_parameters!(conn)

        start_time = time_ns()
        Quic.ConnectionModule.send_stream(conn, stream_id, medium_data, false)
        elapsed_with_pacing = (time_ns() - start_time) / 1_000_000

        println("   Transfer time (with pacing): $(round(elapsed_with_pacing, digits=2)) ms")
        println("   Pacing overhead: $(round(elapsed_with_pacing - elapsed_no_pacing, digits=2)) ms")

        # Display final pacing statistics
        final_pacing = Quic.ConnectionModule.get_pacing_statistics(conn)
        println("\n📊 Final pacing statistics:")
        println("   Target rate: $(Int(final_pacing.pacing_rate)) bytes/sec")
        println("   Current rate: $(Int(final_pacing.current_rate)) bytes/sec")
        println("   Burst size: $(final_pacing.burst_size) bytes")
        println("   Bucket tokens: $(Int(final_pacing.bucket_tokens))")
        println("   Bytes sent this interval: $(final_pacing.bytes_sent_interval)")

        # Display loss detection and congestion control stats
        println("\n📊 Network condition statistics:")
        println("   RTT: $(conn.loss_detection.smoothed_rtt ÷ 1_000_000) ms")
        println("   CWND: $(conn.cwnd) bytes")
        println("   Bytes in flight: $(conn.loss_detection.bytes_in_flight)")

        # Send final data
        final_data = Vector{UInt8}(" [Pacing test complete]")
        Quic.ConnectionModule.send_stream(conn, stream_id, final_data, true)

        println("\n✅ Packet pacing demonstration completed!")
        println("🚦 QUIC pacing prevents network congestion and ensures fair bandwidth usage")

    else
        println("\n❌ Handshake failed after $(max_retries) retries")
    end

    # Wait for any final packets
    try
        nbytes, from = recvfrom(conn.socket, data, timeout=1.0)
        if nbytes > 0
            Quic.PacketReceiver.process_incoming_packet(conn, data[1:nbytes], from)
        end
    catch
        # timeout expected
    end

    # close connection
    close(endpoint.socket)
    println("🔌 Connection closed")

    return handshake_complete
end

if abspath(PROGRAM_FILE) == @__FILE__
    success = main()
    println("\n" * "="^70)
    println("Quinn Packet Pacing Test: $(success ? "PASSED" : "FAILED")")
    println("="^70)
    exit(success ? 0 : 1)
end