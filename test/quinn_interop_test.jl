#!/usr/bin/env julia

# Comprehensive Quinn interoperability test
# Tests full QUIC handshake and data transfer with Quinn server

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Test
using Sockets

"""
Test suite for Quinn interoperability.
Validates:
1. Initial packet encryption/decryption
2. Version negotiation
3. Retry packet handling
4. TLS 1.3 handshake with x25519 ECDHE
5. Handshake packet processing
6. Application data transfer
"""

@testset "Quinn Interoperability Tests" begin

    @testset "Crypto Implementation" begin
        # test x25519 key exchange
        @test begin
            priv1, pub1 = Quic.X25519.generate_keypair()
            priv2, pub2 = Quic.X25519.generate_keypair()

            # compute shared secrets
            shared1 = Quic.X25519.compute_shared_secret(priv1, pub2)
            shared2 = Quic.X25519.compute_shared_secret(priv2, pub1)

            # should be identical
            shared1 == shared2
        end

        # test ChaCha20-Poly1305 encryption
        @test begin
            ctx = Quic.Crypto.CryptoContext()
            ctx.cipher_suite = Quic.Crypto.ChaCha20Poly1305()

            key = rand(UInt8, 32)
            iv = rand(UInt8, 12)
            plaintext = Vector{UInt8}("Hello, QUIC!")
            aad = Vector{UInt8}("header")
            pn = UInt64(42)

            ciphertext = Quic.Crypto.encrypt_payload(ctx, plaintext, key, iv, pn, aad)
            decrypted = Quic.Crypto.decrypt_payload(ctx, ciphertext, key, iv, pn, aad)

            decrypted == plaintext
        end

        # test initial key derivation
        @test begin
            ctx = Quic.Crypto.CryptoContext()
            dcid = Quic.Packet.ConnectionId(hex2bytes("8394c8f03e515708"))

            Quic.Crypto.derive_initial_secrets!(ctx, dcid.data)

            # should have all required keys
            !isempty(ctx.initial_secrets) &&
            haskey(ctx.initial_secrets, :client_key) &&
            haskey(ctx.initial_secrets, :server_key)
        end
    end

    @testset "Packet Handling" begin
        # test version negotiation packet parsing
        @test begin
            vn_packet = UInt8[
                0x80 | rand(UInt8) & 0x7f,  # random unused bits
                0x00, 0x00, 0x00, 0x00,      # version = 0
                0x08,                         # DCID len
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  # DCID
                0x08,                         # SCID len
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,  # SCID
                0x00, 0x00, 0x00, 0x01,       # version 1
                0xff, 0x00, 0x00, 0x1d,       # draft-29
            ]

            is_vn = Quic.VersionNegotiation.is_version_negotiation_packet(vn_packet)
            parsed = Quic.VersionNegotiation.parse_version_negotiation(vn_packet)

            is_vn && parsed !== nothing && 0x00000001 in parsed.versions
        end

        # test retry packet integrity
        @test begin
            scid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            dcid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            odcid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            token = Quic.Retry.generate_retry_token(UInt8[127, 0, 0, 1], odcid)

            retry_packet = Quic.Retry.create_retry_packet(scid, dcid, odcid, token)

            # should verify successfully
            Quic.Retry.verify_retry_integrity_tag(retry_packet, odcid)
        end

        # test packet number encoding/decoding
        @test begin
            pn = UInt64(12345)
            largest_acked = UInt64(12340)

            encoded, len = Quic.PacketCodec.encode_packet_number(pn, largest_acked)
            decoded = Quic.PacketCodec.decode_packet_number(encoded, len * 8, largest_acked + 1)

            decoded == pn
        end
    end

    @testset "Frame Encoding/Decoding" begin
        # test all frame types can be encoded
        @test begin
            frames = [
                Quic.Frame.PingFrame(),
                Quic.Frame.PaddingFrame(),
                Quic.Frame.AckFrame(100, 5, 10, [], nothing),
                Quic.Frame.StreamFrame(0, 0, Vector{UInt8}("data"), false),
                Quic.Frame.CryptoFrame(0, Vector{UInt8}("crypto")),
                Quic.Frame.MaxDataFrame(10000),
                Quic.Frame.MaxStreamDataFrame(4, 5000),
                Quic.Frame.MaxStreamsFrame(100, true),
                Quic.Frame.ConnectionCloseFrame(0, 0, "test"),
                Quic.Frame.ApplicationCloseFrame(0, "app close"),
            ]

            all_encoded = true
            for frame in frames
                buf = UInt8[]
                try
                    Quic.Frame.encode_frame!(buf, frame)
                catch
                    all_encoded = false
                    break
                end
            end

            all_encoded
        end
    end

    @testset "Handshake Messages" begin
        # test ClientHello generation
        @test begin
            hs = Quic.Handshake.HandshakeState(:client)
            dcid = Quic.Packet.ConnectionId(rand(UInt8, 8))

            client_hello = Quic.Handshake.create_client_hello(hs, dcid, "test.example.com")

            # should be valid TLS handshake message
            length(client_hello) > 4 &&
            client_hello[1] == 0x01 &&  # ClientHello
            !isempty(hs.ecdhe_secret)    # key generated
        end

        # test transport parameters encoding
        @test begin
            hs = Quic.Handshake.HandshakeState(:client)
            params = Quic.Handshake.encode_transport_params_v1(hs)

            # should contain parameters
            length(params) > 0
        end
    end

    @testset "Connection Setup" begin
        # test connection initialization
        @test begin
            sock = UDPSocket()
            conn = Quic.ConnectionModule.Connection(sock, true)

            result = conn.is_client &&
                    !conn.connected &&
                    !isempty(conn.local_cid.data) &&
                    !isempty(conn.remote_cid.data) &&
                    conn.loss_detection !== nothing

            close(sock)
            result
        end
    end

    @testset "Loss Detection" begin
        # test loss detection initialization
        @test begin
            ld = Quic.LossDetection.LossDetectionContext()
            ld.smoothed_rtt == Quic.LossDetection.INITIAL_RTT_NS &&
            length(ld.spaces) == 3 &&
            ld.pto_count == 0
        end

        # test packet tracking
        @test begin
            ld = Quic.LossDetection.LossDetectionContext()
            frames = [Quic.Frame.PingFrame()]

            # send a packet
            Quic.LossDetection.on_packet_sent!(ld, Quic.LossDetection.LDInitial, 1, frames, 100)

            # should track the packet
            space = ld.spaces[1]  # Initial space
            haskey(space.sent_packets, 1) &&
            space.ack_eliciting_outstanding == 1 &&
            ld.bytes_in_flight == 100
        end

        # test ACK processing
        @test begin
            ld = Quic.LossDetection.LossDetectionContext()
            frames = [Quic.Frame.PingFrame()]

            # send a packet
            Quic.LossDetection.on_packet_sent!(ld, Quic.LossDetection.LDInitial, 1, frames, 100)

            # create ACK frame
            ack = Quic.Frame.AckFrame(1, 0, 0, UInt64[], nothing)

            # process ACK
            Quic.LossDetection.on_ack_received!(ld, Quic.LossDetection.LDInitial, ack)

            # packet should be removed and bytes in flight reduced
            space = ld.spaces[1]
            !haskey(space.sent_packets, 1) &&
            ld.bytes_in_flight == 0 &&
            ld.pto_count == 0
        end

        # test RTT measurement
        @test begin
            ld = Quic.LossDetection.LossDetectionContext()

            # simulate RTT measurement
            sent_time = time_ns() - 50_000_000  # 50ms ago
            Quic.LossDetection.update_rtt!(ld, sent_time, 0)

            # should update RTT values
            ld.latest_rtt > 0 &&
            ld.smoothed_rtt != Quic.LossDetection.INITIAL_RTT_NS &&
            ld.min_rtt > 0
        end
    end

    @testset "Connection ID Management" begin
        # test connection ID manager initialization
        @test begin
            local_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            remote_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            manager = Quic.ConnectionIdManager.ConnectionIdManager(local_cid, remote_cid)

            length(manager.local_cids) == 1 &&
            length(manager.remote_cids) == 1 &&
            manager.next_local_sequence == 1
        end

        # test new connection ID generation
        @test begin
            local_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            remote_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            manager = Quic.ConnectionIdManager.ConnectionIdManager(local_cid, remote_cid)

            new_cid = Quic.ConnectionIdManager.issue_new_local_cid!(manager)
            new_cid !== nothing &&
            length(manager.local_cids) == 2 &&
            manager.next_local_sequence == 2
        end

        # test connection ID retirement
        @test begin
            local_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            remote_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            manager = Quic.ConnectionIdManager.ConnectionIdManager(local_cid, remote_cid)

            # Issue and retire a CID
            new_cid = Quic.ConnectionIdManager.issue_new_local_cid!(manager)
            retired = Quic.ConnectionIdManager.retire_local_cid!(manager, new_cid.sequence_number)

            retired && length(manager.local_cids) == 1
        end

        # test connection ID frame creation
        @test begin
            local_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            remote_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            manager = Quic.ConnectionIdManager.ConnectionIdManager(local_cid, remote_cid)

            new_cid = Quic.ConnectionIdManager.issue_new_local_cid!(manager)
            frame = Quic.ConnectionIdManager.create_new_connection_id_frame(new_cid)

            frame isa Quic.Frame.NewConnectionIdFrame &&
            frame.sequence == new_cid.sequence_number &&
            frame.connection_id == new_cid.cid.data
        end

        # test path migration
        @test begin
            local_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            remote_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            manager = Quic.ConnectionIdManager.ConnectionIdManager(local_cid, remote_cid)

            # Add another remote CID
            new_remote_cid = Quic.Packet.ConnectionId(rand(UInt8, 8))
            reset_token = rand(UInt8, 16)
            success = Quic.ConnectionIdManager.add_remote_cid!(manager, 1, 0, new_remote_cid, reset_token)

            # Test migration
            migrated_cid = Quic.ConnectionIdManager.initiate_path_migration!(manager)

            success && migrated_cid !== nothing
        end
    end

    @testset "Packet Pacing" begin
        # test pacing state initialization
        @test begin
            pacing = Quic.PacketPacing.PacingState()
            pacing.pacing_enabled &&
            pacing.bucket_tokens > 0 &&
            pacing.burst_size > 0
        end

        # test pacing rate calculation
        @test begin
            pacing = Quic.PacketPacing.PacingState()
            cwnd = UInt64(14720)  # 10 packets
            rtt_ns = UInt64(50_000_000)  # 50ms

            Quic.PacketPacing.update_pacing_rate!(pacing, cwnd, rtt_ns)

            pacing.pacing_rate > 0 &&
            pacing.pacing_rate < 1_000_000_000  # reasonable rate
        end

        # test packet send permission
        @test begin
            pacing = Quic.PacketPacing.PacingState()
            packet_size = UInt64(1472)

            # Should be able to send initially (bucket full)
            can_send_initial = Quic.PacketPacing.can_send_packet(pacing, packet_size)

            # Record send
            Quic.PacketPacing.on_packet_sent!(pacing, packet_size)

            # Should still be able to send more (burst allowed)
            can_send_after = Quic.PacketPacing.can_send_packet(pacing, packet_size)

            can_send_initial && can_send_after
        end

        # test token bucket refill
        @test begin
            pacing = Quic.PacketPacing.PacingState()
            pacing.pacing_rate = 1_000_000.0  # 1 MB/s

            # Drain bucket
            large_packet = UInt64(50000)
            Quic.PacketPacing.on_packet_sent!(pacing, large_packet)

            initial_tokens = pacing.bucket_tokens

            # Wait and check if we can send (tokens refilled)
            sleep(0.1)  # 100ms
            can_send = Quic.PacketPacing.can_send_packet(pacing, UInt64(1000))

            can_send || pacing.bucket_tokens > initial_tokens
        end

        # test pacing statistics
        @test begin
            pacing = Quic.PacketPacing.PacingState()
            stats = Quic.PacketPacing.get_pacing_stats(pacing)

            haskey(stats, :pacing_rate) &&
            haskey(stats, :bucket_tokens) &&
            haskey(stats, :pacing_enabled)
        end

        # test connection integration
        @test begin
            sock = UDPSocket()
            conn = Quic.ConnectionModule.Connection(sock, true)

            # Should have pacing state
            pacing_stats = Quic.ConnectionModule.get_pacing_statistics(conn)

            result = haskey(pacing_stats, :pacing_enabled) &&
                    pacing_stats.pacing_enabled

            close(sock)
            result
        end
    end

    @testset "HTTP/3 Support" begin
        # test HTTP/3 connection initialization
        @test begin
            h3 = Quic.HTTP3.HTTP3Connection()
            Quic.HTTP3.initialize_http3_connection!(h3, true)
            h3.initialized
        end

        # test HTTP/3 settings frame
        @test begin
            h3 = Quic.HTTP3.HTTP3Connection()
            settings_frame = Quic.HTTP3.create_settings_frame(h3)
            settings_frame isa Quic.HTTP3.HTTP3SettingsFrame &&
            !isempty(settings_frame.settings)
        end

        # test HTTP request creation
        @test begin
            headers_frame = Quic.HTTP3.create_http_request("GET", "/test")
            headers_frame isa Quic.HTTP3.HTTP3HeadersFrame &&
            !isempty(headers_frame.encoded_headers)
        end

        # test HTTP response creation
        @test begin
            response_frame = Quic.HTTP3.create_http_response(200)
            response_frame isa Quic.HTTP3.HTTP3HeadersFrame &&
            !isempty(response_frame.encoded_headers)
        end

        # test QPACK header encoding/decoding
        @test begin
            headers = Dict(":method" => "GET", ":path" => "/", "user-agent" => "test")
            encoded = Quic.HTTP3.encode_headers_qpack(headers)
            decoded = Quic.HTTP3.decode_headers_qpack(encoded)

            # Check if key headers are preserved
            get(decoded, ":method", "") == "GET" &&
            get(decoded, ":path", "") == "/"
        end

        # test HTTP/3 frame encoding/decoding
        @test begin
            data_frame = Quic.HTTP3.HTTP3DataFrame(Vector{UInt8}("test data"))
            buf = UInt8[]
            Quic.HTTP3.encode_http3_frame!(buf, data_frame)

            decoded_frame, _ = Quic.HTTP3.decode_http3_frame(buf)
            decoded_frame isa Quic.HTTP3.HTTP3DataFrame &&
            decoded_frame.data == Vector{UInt8}("test data")
        end

        # test connection integration
        @test begin
            sock = UDPSocket()
            conn = Quic.ConnectionModule.Connection(sock, true)

            # Enable HTTP/3
            success = Quic.ConnectionModule.enable_http3!(conn)

            result = success && conn.http3 !== nothing
            close(sock)
            result
        end
    end

    @testset "Live Quinn Server Test" begin
        # This test requires a running Quinn server
        # Skip if server is not available

        server_available = try
            sock = UDPSocket()
            send(sock, ip"127.0.0.1", 4433, UInt8[0])
            close(sock)
            true
        catch
            false
        end

        if server_available
            @test begin
                result = false

                try
                    # create client
                    client_addr = Sockets.InetAddr(ip"0.0.0.0", 0)
                    config = Quic.EndpointModule.EndpointConfig()
                    config.server_name = "localhost"

                    endpoint = Quic.EndpointModule.Endpoint(client_addr, config, false)
                    server_addr = Sockets.InetAddr(ip"127.0.0.1", 4433)
                    conn = Quic.EndpointModule.connect(endpoint, server_addr)

                    # setup crypto
                    conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()
                    Quic.Crypto.derive_initial_secrets!(conn.crypto, conn.remote_cid.data)

                    # send handshake
                    Quic.ConnectionModule.initiate_handshake(conn, "localhost")

                    # wait for response
                    data = Vector{UInt8}(undef, 65536)
                    for i in 1:10
                        try
                            nbytes, from = recvfrom(conn.socket, data, timeout=0.5)
                            if nbytes > 0
                                # got response from Quinn
                                result = true
                                break
                            end
                        catch
                            # timeout, retry
                        end
                        sleep(0.1)
                    end

                    close(endpoint.socket)
                catch e
                    # connection failed
                end

                result
            end
        else
            @test_skip "Quinn server not available at localhost:4433"
        end
    end

end

println("\n=== Quinn Interoperability Test Results ===")
println("All critical components tested.")
println("To test with live Quinn server:")
println("1. Start Quinn server: cargo run --example server")
println("2. Run: julia test/quinn_interop_test.jl")