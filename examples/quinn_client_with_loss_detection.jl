#!/usr/bin/env julia

# Quinn interoperability client with loss detection and ACK processing
# Tests full QUIC connection with reliability features

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Sockets

function main()
    println("🚀 Starting Quinn client with loss detection...")

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
    println("   Loss detection enabled: $(conn.loss_detection !== nothing)")

    # setup crypto
    conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()
    Quic.Crypto.derive_initial_secrets!(conn.crypto, conn.remote_cid.data)

    println("🔐 Initialized ChaCha20-Poly1305 encryption")
    println("   Initial keys derived from DCID: $(bytes2hex(conn.remote_cid.data))")

    # initiate handshake
    println("🤝 Starting TLS 1.3 handshake...")
    Quic.ConnectionModule.initiate_handshake(conn, "localhost")

    # track handshake progress
    handshake_packets_sent = 1
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

                    # send ACK for received data
                    ack_frame = Quic.Frame.AckFrame(
                        conn.next_recv_pn.value - 1,  # largest_acked
                        0,                             # ack_delay
                        0,                             # first_range
                        UInt64[],                      # gaps
                        nothing                        # ecn_counts
                    )

                    # queue ACK frame
                    Quic.ConnectionModule.queue_frame!(conn, ack_frame, Quic.PacketCoalescing.Application)
                    Quic.ConnectionModule.flush_packets!(conn)

                    println("📤 Sent ACK for packet $(conn.next_recv_pn.value - 1)")
                end
            end

        catch e
            if isa(e, Base.UVError) && e.code == Base.UV_ETIMEDOUT
                # timeout - check if we need to retransmit
                println("⏰ Timeout, checking loss detection...")

                if Quic.LossDetection.should_send_probe_packets(conn.loss_detection)
                    println("🔄 Sending probe packets due to timeout")
                    Quic.ConnectionModule.handle_loss_detection_timeout(conn)
                    handshake_packets_sent += 1
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

    # test data transfer if handshake succeeded
    if handshake_complete
        println("\n🔄 Testing reliable data transfer...")

        # open a bidirectional stream
        stream_id = Quic.ConnectionModule.open_stream(conn, true)
        println("📂 Opened stream $(stream_id.value)")

        # send test data with loss detection
        test_data = Vector{UInt8}("Hello Quinn from Julia QUIC with loss detection!")
        bytes_sent = Quic.ConnectionModule.send_stream(conn, stream_id, test_data, false)
        println("📤 Sent $(bytes_sent) bytes: \"$(String(test_data))\"")

        # wait for potential ACK of stream data
        try
            nbytes, from = recvfrom(conn.socket, data, timeout=2.0)
            if nbytes > 0
                println("📥 Received response: $(nbytes) bytes")
                Quic.PacketReceiver.process_incoming_packet(conn, data[1:nbytes], from)
            end
        catch
            # timeout is expected for this test
        end

        # send final data with FIN
        final_data = Vector{UInt8}(" [FIN]")
        Quic.ConnectionModule.send_stream(conn, stream_id, final_data, true)
        println("📤 Sent final data with FIN flag")

        # display loss detection statistics
        println("\n📊 Loss Detection Statistics:")
        println("   Smoothed RTT: $(conn.loss_detection.smoothed_rtt ÷ 1_000_000) ms")
        println("   Latest RTT: $(conn.loss_detection.latest_rtt ÷ 1_000_000) ms")
        println("   Min RTT: $(conn.loss_detection.min_rtt ÷ 1_000_000) ms")
        println("   RTT Variation: $(conn.loss_detection.rttvar ÷ 1_000_000) ms")
        println("   PTO Count: $(conn.loss_detection.pto_count)")
        println("   Bytes in flight: $(conn.loss_detection.bytes_in_flight)")

        # check for any lost packets
        for (i, space) in enumerate(conn.loss_detection.spaces)
            space_name = ["Initial", "Handshake", "Application"][i]
            println("   $(space_name) space: $(length(space.sent_packets)) unacked packets")
        end

        println("\n✅ Quinn compatibility test completed successfully!")
        println("🔗 Full QUIC connection established with loss detection")
    else
        println("\n❌ Handshake failed after $(max_retries) retries")
        println("📊 Loss detection statistics:")
        println("   PTO count: $(conn.loss_detection.pto_count)")
        println("   Timer state: $(conn.loss_detection.loss_detection_timer !== nothing ? "active" : "inactive")")
    end

    # close connection
    close(endpoint.socket)
    println("🔌 Connection closed")

    return handshake_complete
end

if abspath(PROGRAM_FILE) == @__FILE__
    success = main()
    println("\n" * "="^60)
    println("Quinn Interoperability Test: $(success ? "PASSED" : "FAILED")")
    println("="^60)
    exit(success ? 0 : 1)
end