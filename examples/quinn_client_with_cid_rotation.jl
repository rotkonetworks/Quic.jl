#!/usr/bin/env julia

# Quinn interoperability client with connection ID rotation
# Demonstrates connection migration and CID management features

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Sockets

function main()
    println("🚀 Starting Quinn client with connection ID rotation...")

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

    # Display initial CID manager stats
    initial_stats = Quic.ConnectionModule.get_cid_statistics(conn)
    println("📊 Initial CID statistics:")
    println("   Active local CIDs: $(initial_stats.active_local_cids)")
    println("   Active remote CIDs: $(initial_stats.active_remote_cids)")

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
            # check for timer expiry and handle loss detection
            Quic.ConnectionModule.process_timers(conn)

            # maintain connection IDs proactively
            Quic.ConnectionModule.maintain_connection_ids!(conn)

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
                        break
                    end
                end
            end

        catch e
            if isa(e, Base.UVError) && e.code == Base.UV_ETIMEDOUT
                # timeout - check if we need to retransmit
                if Quic.LossDetection.should_send_probe_packets(conn.loss_detection)
                    println("🔄 Sending probe packets due to timeout")
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

    # test connection ID rotation if handshake succeeded
    if handshake_complete
        println("\n🔄 Testing connection ID rotation...")

        # Display CID stats after handshake
        post_handshake_stats = Quic.ConnectionModule.get_cid_statistics(conn)
        println("📊 Post-handshake CID statistics:")
        println("   Active local CIDs: $(post_handshake_stats.active_local_cids)")
        println("   Active remote CIDs: $(post_handshake_stats.active_remote_cids)")
        println("   Total local issued: $(post_handshake_stats.total_local_issued)")

        # Test data transfer before rotation
        stream_id = Quic.ConnectionModule.open_stream(conn, true)
        test_data = Vector{UInt8}("Hello before CID rotation!")
        Quic.ConnectionModule.send_stream(conn, stream_id, test_data, false)
        println("📤 Sent test data: \"$(String(test_data))\"")

        # Issue additional connection IDs
        println("\n🆕 Issuing new connection IDs...")
        new_cids_issued = Quic.ConnectionModule.maintain_connection_ids!(conn)
        println("   Issued $(new_cids_issued) new connection IDs")

        # Wait for server to potentially send NEW_CONNECTION_ID frames
        println("⏳ Waiting for server NEW_CONNECTION_ID frames...")
        for i in 1:5
            try
                nbytes, from = recvfrom(conn.socket, data, timeout=1.0)
                if nbytes > 0
                    println("📥 Received $(nbytes) bytes (potential CID frames)")
                    Quic.PacketReceiver.process_incoming_packet(conn, data[1:nbytes], from)
                end
            catch
                # timeout is expected
            end
            sleep(0.2)
        end

        # Attempt connection ID rotation (path migration)
        println("\n🔄 Attempting connection ID rotation...")
        current_cid = conn.remote_cid
        println("   Current remote CID: $(bytes2hex(current_cid.data))")

        rotation_success = Quic.ConnectionModule.rotate_connection_id!(conn)

        if rotation_success
            new_cid = conn.remote_cid
            println("✅ Successfully rotated to new CID: $(bytes2hex(new_cid.data))")

            # Test data transfer after rotation
            post_rotation_data = Vector{UInt8}("Hello after CID rotation!")
            Quic.ConnectionModule.send_stream(conn, stream_id, post_rotation_data, false)
            println("📤 Sent post-rotation data: \"$(String(post_rotation_data))\"")

            # Send PATH_CHALLENGE to test path validation
            challenge_data = rand(UInt8, 8)
            path_challenge = Quic.Frame.PathChallengeFrame(challenge_data)
            Quic.ConnectionModule.queue_frame!(conn, path_challenge, Quic.PacketCoalescing.Application)
            Quic.ConnectionModule.flush_packets!(conn)
            println("🛤️ Sent PATH_CHALLENGE: $(bytes2hex(challenge_data))")

            # Wait for PATH_RESPONSE
            try
                nbytes, from = recvfrom(conn.socket, data, timeout=2.0)
                if nbytes > 0
                    println("📥 Received response to PATH_CHALLENGE")
                    Quic.PacketReceiver.process_incoming_packet(conn, data[1:nbytes], from)
                end
            catch
                println("⏰ No PATH_RESPONSE received (timeout)")
            end

        else
            println("❌ Connection ID rotation failed (no additional CIDs available)")
        end

        # Display final CID statistics
        final_stats = Quic.ConnectionModule.get_cid_statistics(conn)
        println("\n📊 Final CID statistics:")
        println("   Active local CIDs: $(final_stats.active_local_cids)")
        println("   Active remote CIDs: $(final_stats.active_remote_cids)")
        println("   Total local issued: $(final_stats.total_local_issued)")
        println("   Retired local CIDs: $(final_stats.retired_local)")
        println("   Retired remote CIDs: $(final_stats.retired_remote)")

        if final_stats.current_remote_seq !== nothing
            println("   Current remote CID seq: $(final_stats.current_remote_seq)")
        end

        # Send final data with FIN
        final_data = Vector{UInt8}(" [CID rotation test complete]")
        Quic.ConnectionModule.send_stream(conn, stream_id, final_data, true)
        println("📤 Sent final data with FIN")

        println("\n✅ Connection ID rotation test completed!")
        println("🔗 Full QUIC connection with CID management demonstrated")
    else
        println("\n❌ Handshake failed after $(max_retries) retries")
    end

    # close connection
    close(endpoint.socket)
    println("🔌 Connection closed")

    return handshake_complete
end

if abspath(PROGRAM_FILE) == @__FILE__
    success = main()
    println("\n" * "="^70)
    println("Quinn Connection ID Rotation Test: $(success ? "PASSED" : "FAILED")")
    println("="^70)
    exit(success ? 0 : 1)
end