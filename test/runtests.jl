using Quic
using Test
using Sockets

# TODO: Tests still needed for full Quinn parity:
# - Full handshake integration tests (client-server loopback)
# - Key update tests (key_update_simple, key_update_reordered)
# - Migration tests (path migration, CID rotation during migration)
# - MTU discovery tests (connect_detects_mtu, blackhole_after_mtu_change)
# - Datagram tests (datagram_send_recv, datagram_recv_buffer_overflow)
# - Multi-stream tests with ordering and flow control
# - Stateless reset tests
# - ALPN negotiation tests
# - Zero-RTT rejection/acceptance tests
# - ACK frequency tests
# - Idle timeout tests

@testset "Quic.jl" begin

    @testset "Protocol" begin
        @testset "VarInt encoding/decoding" begin
            # test various varint values
            test_values = [0, 63, 64, 16383, 16384, 1073741823, 1073741824]

            for val in test_values
                v = Quic.Protocol.VarInt(val)
                buf = UInt8[]
                Quic.Protocol.encode_varint!(buf, v)

                decoded, pos = Quic.Protocol.decode_varint(buf, 1)
                @test decoded.value == val
                @test pos == length(buf) + 1
            end

            # test overflow
            @test_throws ErrorException Quic.Protocol.VarInt(2^62)
        end

        @testset "VarInt edge cases" begin
            # test boundary values (where encoding length changes)
            boundary_values = [
                (0x3f, 1),      # max 1-byte
                (0x40, 2),      # min 2-byte
                (0x3fff, 2),    # max 2-byte
                (0x4000, 4),    # min 4-byte
                (0x3fffffff, 4),  # max 4-byte
                (0x40000000, 8),  # min 8-byte
            ]

            for (val, expected_len) in boundary_values
                v = Quic.Protocol.VarInt(val)
                buf = UInt8[]
                Quic.Protocol.encode_varint!(buf, v)
                @test length(buf) == expected_len
                decoded, _ = Quic.Protocol.decode_varint(buf, 1)
                @test decoded.value == val
            end
        end

        @testset "VarInt max value" begin
            max_val = UInt64(2)^62 - 1
            v = Quic.Protocol.VarInt(max_val)
            buf = UInt8[]
            Quic.Protocol.encode_varint!(buf, v)
            @test length(buf) == 8
            decoded, _ = Quic.Protocol.decode_varint(buf, 1)
            @test decoded.value == max_val
        end
    end

    @testset "Crypto" begin
        @testset "HKDF-Extract" begin
            # Test vector from RFC 5869
            ikm = hex2bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
            salt = hex2bytes("000102030405060708090a0b0c")
            prk = Quic.Crypto.hkdf_extract(ikm, salt)
            @test length(prk) == 32  # SHA-256 output
        end

        @testset "HKDF-Expand" begin
            # Test with known inputs
            prk = fill(0x01, 32)
            info = Vector{UInt8}("test info")
            okm = Quic.Crypto.hkdf_expand(prk, info, 42)
            @test length(okm) == 42
        end

        @testset "HKDF-Expand-Label" begin
            secret = fill(0x01, 32)
            label = "quic key"
            context = UInt8[]
            output = Quic.Crypto.hkdf_expand_label(secret, label, context, 16)
            @test length(output) == 16

            # Different labels should produce different outputs
            output2 = Quic.Crypto.hkdf_expand_label(secret, "quic iv", context, 12)
            @test length(output2) == 12
            @test output[1:12] != output2  # Should be different
        end

        @testset "HMAC-SHA256" begin
            # Test basic HMAC
            key = Vector{UInt8}("key")
            data = Vector{UInt8}("The quick brown fox jumps over the lazy dog")
            hmac = Quic.Crypto.hmac_sha256(key, data)
            @test length(hmac) == 32

            # Same inputs should produce same output
            hmac2 = Quic.Crypto.hmac_sha256(key, data)
            @test hmac == hmac2

            # Different key should produce different output
            hmac3 = Quic.Crypto.hmac_sha256(Vector{UInt8}("other"), data)
            @test hmac != hmac3
        end

        @testset "Initial secret derivation" begin
            # Test that initial secrets are derived correctly
            ctx = Quic.Crypto.CryptoContext()
            dcid = UInt8[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]  # Example DCID

            Quic.Crypto.derive_initial_secrets!(ctx, dcid)

            # Check all required keys are present
            @test haskey(ctx.initial_secrets, :client_key)
            @test haskey(ctx.initial_secrets, :client_iv)
            @test haskey(ctx.initial_secrets, :client_hp)
            @test haskey(ctx.initial_secrets, :server_key)
            @test haskey(ctx.initial_secrets, :server_iv)
            @test haskey(ctx.initial_secrets, :server_hp)

            # Check key lengths (AES-128-GCM for initial)
            @test length(ctx.initial_secrets[:client_key]) == 16
            @test length(ctx.initial_secrets[:client_iv]) == 12
            @test length(ctx.initial_secrets[:client_hp]) == 16
            @test length(ctx.initial_secrets[:server_key]) == 16
            @test length(ctx.initial_secrets[:server_iv]) == 12
            @test length(ctx.initial_secrets[:server_hp]) == 16
        end

        @testset "AES-GCM encrypt/decrypt roundtrip" begin
            ctx = Quic.Crypto.CryptoContext()
            ctx.cipher_suite = Quic.Crypto.AES128GCM()

            key = rand(UInt8, 16)
            iv = rand(UInt8, 12)
            packet_number = UInt64(42)
            aad = Vector{UInt8}("associated data")
            plaintext = Vector{UInt8}("Hello, QUIC!")

            ciphertext = Quic.Crypto.encrypt_payload(ctx, plaintext, key, iv, packet_number, aad)
            @test length(ciphertext) == length(plaintext) + 16  # plaintext + tag

            decrypted = Quic.Crypto.decrypt_payload(ctx, ciphertext, key, iv, packet_number, aad)
            @test decrypted == plaintext
        end

        @testset "ChaCha20-Poly1305 encrypt/decrypt roundtrip" begin
            ctx = Quic.Crypto.CryptoContext()
            ctx.cipher_suite = Quic.Crypto.ChaCha20Poly1305()

            key = rand(UInt8, 32)
            iv = rand(UInt8, 12)
            packet_number = UInt64(42)
            aad = Vector{UInt8}("associated data")
            plaintext = Vector{UInt8}("Hello, QUIC!")

            ciphertext = Quic.Crypto.encrypt_payload(ctx, plaintext, key, iv, packet_number, aad)
            @test length(ciphertext) == length(plaintext) + 16  # plaintext + tag

            decrypted = Quic.Crypto.decrypt_payload(ctx, ciphertext, key, iv, packet_number, aad)
            @test decrypted == plaintext
        end

        @testset "AEAD authentication failure" begin
            ctx = Quic.Crypto.CryptoContext()
            ctx.cipher_suite = Quic.Crypto.AES128GCM()

            key = rand(UInt8, 16)
            iv = rand(UInt8, 12)
            packet_number = UInt64(42)
            aad = Vector{UInt8}("associated data")
            plaintext = Vector{UInt8}("Hello, QUIC!")

            ciphertext = Quic.Crypto.encrypt_payload(ctx, plaintext, key, iv, packet_number, aad)

            # Tamper with ciphertext
            ciphertext[1] ⊻= 0xff

            @test_throws ErrorException Quic.Crypto.decrypt_payload(ctx, ciphertext, key, iv, packet_number, aad)
        end

        @testset "Nonce construction" begin
            # Test that different packet numbers produce different nonces
            ctx = Quic.Crypto.CryptoContext()
            ctx.cipher_suite = Quic.Crypto.AES128GCM()

            key = rand(UInt8, 16)
            iv = rand(UInt8, 12)
            aad = Vector{UInt8}("aad")
            plaintext = Vector{UInt8}("test")

            # Same plaintext with different packet numbers should produce different ciphertext
            ct1 = Quic.Crypto.encrypt_payload(ctx, plaintext, key, iv, UInt64(1), aad)
            ct2 = Quic.Crypto.encrypt_payload(ctx, plaintext, key, iv, UInt64(2), aad)
            @test ct1 != ct2
        end
    end

    @testset "Version Negotiation" begin
        @testset "Supported versions" begin
            @test Quic.VersionNegotiation.is_supported_version(Quic.VersionNegotiation.QUIC_VERSION_1)
            @test !Quic.VersionNegotiation.is_supported_version(0x12345678)
        end

        @testset "Version preference" begin
            @test Quic.VersionNegotiation.get_preferred_version() == Quic.VersionNegotiation.QUIC_VERSION_1
        end

        @testset "Create and parse version negotiation packet" begin
            dcid = Quic.Packet.ConnectionId(UInt8[1, 2, 3, 4])
            scid = Quic.Packet.ConnectionId(UInt8[5, 6, 7, 8])

            packet = Quic.VersionNegotiation.create_version_negotiation_packet(dcid, scid)

            # Should have long header bit set
            @test (packet[1] & 0x80) != 0

            # Version field should be 0
            @test packet[2:5] == zeros(UInt8, 4)

            parsed = Quic.VersionNegotiation.parse_version_negotiation(packet)
            @test parsed !== nothing
            @test parsed.dcid == dcid.data
            @test parsed.scid == scid.data
            # Check that at least one supported version is present
            @test !isempty(parsed.versions)
        end

        @testset "Is version negotiation packet" begin
            # Valid version negotiation packet
            vn_packet = UInt8[0xc0, 0x00, 0x00, 0x00, 0x00, 0x08]
            @test Quic.VersionNegotiation.is_version_negotiation_packet(vn_packet)

            # Regular initial packet (version 1)
            initial_packet = UInt8[0xc0, 0x00, 0x00, 0x00, 0x01, 0x08]
            @test !Quic.VersionNegotiation.is_version_negotiation_packet(initial_packet)

            # Short header packet
            short_packet = UInt8[0x40, 0x00, 0x00, 0x00, 0x00, 0x08]
            @test !Quic.VersionNegotiation.is_version_negotiation_packet(short_packet)
        end

        @testset "Choose version" begin
            offered = [Quic.VersionNegotiation.QUIC_VERSION_1, 0x12345678]
            @test Quic.VersionNegotiation.choose_version(offered) == Quic.VersionNegotiation.QUIC_VERSION_1

            # No compatible version
            @test Quic.VersionNegotiation.choose_version([0x12345678]) === nothing
        end

        @testset "Handle version mismatch" begin
            dcid = Quic.Packet.ConnectionId(UInt8[1, 2, 3, 4])
            scid = Quic.Packet.ConnectionId(UInt8[5, 6, 7, 8])

            # Unsupported version should trigger VN packet
            result = Quic.VersionNegotiation.handle_version_mismatch(0x12345678, dcid, scid)
            @test result !== nothing
            @test Quic.VersionNegotiation.is_version_negotiation_packet(result)

            # Supported version should return nothing
            result2 = Quic.VersionNegotiation.handle_version_mismatch(Quic.VersionNegotiation.QUIC_VERSION_1, dcid, scid)
            @test result2 === nothing

            # Version 0 (VN packet) should return nothing
            result3 = Quic.VersionNegotiation.handle_version_mismatch(0x00000000, dcid, scid)
            @test result3 === nothing
        end
    end

    @testset "Packet" begin
        @testset "ConnectionId" begin
            # test creation with specific length
            cid = Quic.Packet.ConnectionId(8)
            @test length(cid) == 8

            # test creation with data
            data = UInt8[1, 2, 3, 4]
            cid2 = Quic.Packet.ConnectionId(data)
            @test cid2.data == data
            @test length(cid2) == 4

            # test equality
            cid3 = Quic.Packet.ConnectionId(data)
            @test cid2 == cid3
        end

        @testset "PacketNumber" begin
            pn = Quic.Packet.PacketNumber()
            @test Quic.Packet.current(pn) == 0

            val = Quic.Packet.next!(pn)
            @test val == 0
            @test Quic.Packet.current(pn) == 1

            val = Quic.Packet.next!(pn)
            @test val == 1
            @test Quic.Packet.current(pn) == 2
        end
    end

    @testset "Stream" begin
        @testset "StreamId" begin
            # client-initiated bidirectional stream
            sid = Quic.Stream.StreamId(0, :client, :bidi)
            @test Quic.Stream.is_client_initiated(sid)
            @test Quic.Stream.is_bidirectional(sid)
            @test Quic.Stream.stream_index(sid) == 0

            # server-initiated unidirectional stream
            sid2 = Quic.Stream.StreamId(1, :server, :uni)
            @test !Quic.Stream.is_client_initiated(sid2)
            @test !Quic.Stream.is_bidirectional(sid2)
            @test Quic.Stream.stream_index(sid2) == 1
        end

        @testset "StreamState" begin
            sid = Quic.Stream.StreamId(0, :client, :bidi)
            stream = Quic.Stream.StreamState(sid)

            # test writing
            data = Vector{UInt8}("Hello, QUIC!")
            written = Quic.Stream.write_stream!(stream, data, false)
            @test written == length(data)
            @test stream.send_offset == length(data)
            @test !stream.fin_sent

            # test writing with fin
            data2 = Vector{UInt8}(" More data")
            written2 = Quic.Stream.write_stream!(stream, data2, true)
            @test written2 == length(data2)
            @test stream.fin_sent

            # test reading
            stream.recv_buf = Vector{UInt8}("Received data")
            read_data, is_fin = Quic.Stream.read_stream!(stream, 8)
            @test length(read_data) == 8
            @test !is_fin

            # read remaining
            read_data2, is_fin2 = Quic.Stream.read_stream!(stream, 100)
            @test length(read_data2) == 5  # remaining bytes
            @test !is_fin2  # fin_recv not set
        end
    end

    @testset "Frame" begin
        @testset "Frame encoding" begin
            buf = UInt8[]

            # test PING frame
            ping = Quic.Frame.PingFrame()
            Quic.Frame.encode_frame!(buf, ping)
            @test buf[1] == Quic.Protocol.FRAME_PING

            # test STREAM frame
            empty!(buf)
            stream_frame = Quic.Frame.StreamFrame(
                42,  # stream_id
                100,  # offset
                Vector{UInt8}("test data"),
                true  # fin
            )
            Quic.Frame.encode_frame!(buf, stream_frame)
            @test buf[1] & 0xf8 == Quic.Protocol.FRAME_STREAM
            @test buf[1] & 0x01 == 0x01  # fin bit set
            @test buf[1] & 0x04 == 0x04  # offset bit set
        end
    end

    @testset "Congestion Control" begin
        @testset "NewReno" begin
            cc = Quic.Congestion.NewReno()
            @test cc.cwnd == Quic.Congestion.INITIAL_CWND
            @test cc.bytes_in_flight == 0

            # test sending
            @test Quic.Congestion.can_send(cc, 1000)
            Quic.Congestion.on_packet_sent!(cc, 1000)
            @test cc.bytes_in_flight == 1000

            # test acking (slow start)
            old_cwnd = cc.cwnd
            Quic.Congestion.on_packet_acked!(cc, 1000)
            @test cc.bytes_in_flight == 0
            @test cc.cwnd > old_cwnd  # increased in slow start

            # test loss
            Quic.Congestion.on_packet_sent!(cc, 1000)
            old_cwnd = cc.cwnd
            Quic.Congestion.on_packet_lost!(cc, 1000, time_ns())
            @test cc.cwnd == max(old_cwnd ÷ 2, Quic.Congestion.MIN_CWND)
        end

        @testset "RTT Estimator" begin
            rtt = Quic.Congestion.RttEstimator()

            # first sample
            sample = UInt64(50_000_000)  # 50ms
            Quic.Congestion.update_rtt!(rtt, sample)
            @test rtt.smoothed_rtt == sample
            @test rtt.min_rtt == sample

            # subsequent samples
            Quic.Congestion.update_rtt!(rtt, UInt64(60_000_000))
            @test rtt.min_rtt == sample  # min unchanged
            @test rtt.smoothed_rtt > sample  # smoothed increased

            # RTO calculation
            rto_val = Quic.Congestion.rto(rtt)
            @test rto_val > rtt.smoothed_rtt
        end
    end

    @testset "Transport" begin
        @testset "FlowController" begin
            config = Quic.Transport.TransportConfig()
            fc = Quic.Transport.FlowController(config)

            # test connection-level flow control
            @test Quic.Transport.can_send_data(fc, 1000)
            Quic.Transport.on_data_sent!(fc, 0, 1000)
            @test fc.data_sent == 1000

            # test stream limits
            @test Quic.Transport.can_open_stream(fc, true)
            @test Quic.Transport.can_open_stream(fc, false)

            # test MAX_DATA processing
            Quic.Transport.process_max_data!(fc, config.initial_max_data * 2)
            @test fc.max_data_peer == config.initial_max_data * 2

            # test per-stream flow control
            Quic.Transport.process_max_stream_data!(fc, 1, 5000)
            @test haskey(fc.stream_windows, 1)
            @test fc.stream_windows[1].max_data == 5000
        end
    end

    @testset "Connection" begin
        @testset "Connection creation" begin
            sock = UDPSocket()
            conn = Quic.ConnectionModule.Connection(sock, true)

            @test conn.is_client == true
            @test !conn.connected
            @test !conn.closing
            @test conn.next_stream_id == 0  # client starts with 0

            # server connection
            conn2 = Quic.ConnectionModule.Connection(sock, false)
            @test conn2.next_stream_id == 1  # server starts with 1

            close(sock)
        end

        @testset "Stream management" begin
            sock = UDPSocket()
            conn = Quic.ConnectionModule.Connection(sock, true)

            # open bidirectional stream
            sid = Quic.ConnectionModule.open_stream(conn, true)
            @test haskey(conn.streams, sid.value)
            @test Quic.Stream.is_bidirectional(sid)

            # open unidirectional stream
            sid2 = Quic.ConnectionModule.open_stream(conn, false)
            @test haskey(conn.streams, sid2.value)
            @test !Quic.Stream.is_bidirectional(sid2)

            close(sock)
        end
    end

    @testset "Loss Detection" begin
        @testset "LossDetectionContext creation" begin
            ld = Quic.LossDetection.LossDetectionContext()
            @test ld.smoothed_rtt == Quic.LossDetection.INITIAL_RTT_NS
            @test ld.pto_count == 0
            @test length(ld.spaces) == 3  # Initial, Handshake, Application
        end

        @testset "SpaceState initialization" begin
            space = Quic.LossDetection.SpaceState()
            @test space.largest_acked_packet === nothing
            @test space.loss_time === nothing
            @test isempty(space.sent_packets)
            @test space.ack_eliciting_outstanding == 0
        end

        @testset "SentPacket tracking" begin
            pkt = Quic.LossDetection.SentPacket(
                UInt64(1),      # packet_number
                time_ns(),      # time_sent
                true,           # ack_eliciting
                true,           # in_flight
                UInt64(1200),   # size
                Quic.Frame.QuicFrame[]  # frames
            )
            @test pkt.packet_number == 1
            @test pkt.ack_eliciting
            @test pkt.in_flight
            @test pkt.size == 1200
        end

        @testset "AckRange" begin
            range = Quic.LossDetection.AckRange(UInt64(5), UInt64(10))
            @test range.smallest == 5
            @test range.largest == 10
        end
    end

    @testset "Retry" begin
        @testset "Retry token generation and validation" begin
            client_addr = UInt8[192, 168, 1, 1]
            dcid = Quic.Packet.ConnectionId(UInt8[1, 2, 3, 4, 5, 6, 7, 8])

            token = Quic.Retry.generate_retry_token(client_addr, dcid)
            @test length(token) > 16  # Should have HMAC

            # Validate immediately (should succeed)
            valid, original_dcid = Quic.Retry.validate_retry_token(token, client_addr)
            @test valid
            @test original_dcid.data == dcid.data
        end

        @testset "Retry token wrong address" begin
            client_addr = UInt8[192, 168, 1, 1]
            wrong_addr = UInt8[192, 168, 1, 2]
            dcid = Quic.Packet.ConnectionId(UInt8[1, 2, 3, 4])

            token = Quic.Retry.generate_retry_token(client_addr, dcid)

            # Validation with wrong address should fail
            valid, _ = Quic.Retry.validate_retry_token(token, wrong_addr)
            @test !valid
        end

        @testset "Retry token tampered HMAC" begin
            client_addr = UInt8[192, 168, 1, 1]
            dcid = Quic.Packet.ConnectionId(UInt8[1, 2, 3, 4])

            token = Quic.Retry.generate_retry_token(client_addr, dcid)

            # Tamper with HMAC
            token[end] ⊻= 0xff

            valid, _ = Quic.Retry.validate_retry_token(token, client_addr)
            @test !valid
        end

        # Note: create_retry_packet and verify_retry_integrity_tag tests
        # are skipped because MbedTLS.jl update_ad! API is not available
        # TODO: Fix retry.jl to use correct MbedTLS API
    end

    @testset "Pacer" begin
        @testset "Basic pacing" begin
            pacer = Quic.Congestion.Pacer()
            @test pacer.rate == 0
            @test pacer.tokens == 0

            # Update pacing rate
            Quic.Congestion.update_pacing_rate!(pacer, UInt64(14720), UInt64(100_000_000))  # ~100ms RTT
            @test pacer.rate > 0

            # First send should always succeed
            @test Quic.Congestion.can_send_paced(pacer, UInt64(1200), time_ns())
        end
    end

    @testset "Header Protection" begin
        @testset "AES header protection mask" begin
            ctx = Quic.Crypto.CryptoContext()
            ctx.cipher_suite = Quic.Crypto.AES128GCM()

            hp_key = rand(UInt8, 16)
            sample = rand(UInt8, 16)

            mask = Quic.Crypto.aes_header_protection_mask(hp_key, sample, ctx.cipher_suite)
            @test length(mask) == 16

            # Same inputs should produce same mask
            mask2 = Quic.Crypto.aes_header_protection_mask(hp_key, sample, ctx.cipher_suite)
            @test mask == mask2

            # Different sample should produce different mask
            mask3 = Quic.Crypto.aes_header_protection_mask(hp_key, rand(UInt8, 16), ctx.cipher_suite)
            @test mask != mask3
        end

        @testset "ChaCha20 header protection mask" begin
            hp_key = rand(UInt8, 32)
            sample = rand(UInt8, 16)

            mask = Quic.Crypto.chacha20_header_protection_mask(hp_key, sample)
            @test length(mask) == 5  # Only need 5 bytes for header protection

            # Same inputs should produce same mask
            mask2 = Quic.Crypto.chacha20_header_protection_mask(hp_key, sample)
            @test mask == mask2
        end
    end

    @testset "Packet Coalescing" begin
        @testset "Coalescer initialization" begin
            coalescer = Quic.PacketCoalescing.PacketCoalescer()
            @test coalescer.max_size == Quic.PacketCoalescing.MAX_UDP_PAYLOAD
            @test isempty(coalescer.pending_packets)
        end

        @testset "PacketSpace enum" begin
            @test Int(Quic.PacketCoalescing.Initial) == 0
            @test Int(Quic.PacketCoalescing.Handshake) == 1
            @test Int(Quic.PacketCoalescing.Application) == 2
        end

        @testset "PendingPacket creation" begin
            packet = Quic.PacketCoalescing.PendingPacket(Quic.PacketCoalescing.Initial, UInt64(0))
            @test packet.space == Quic.PacketCoalescing.Initial
            @test isempty(packet.frames)
            @test packet.pn == 0
        end
    end

    @testset "Zero RTT" begin
        @testset "SessionState creation" begin
            session = Quic.ZeroRTT.SessionState()
            @test isempty(session.ticket)
            @test session.ticket_age_add == 0
            @test session.cipher_suite == 0x1301  # TLS_AES_128_GCM_SHA256
        end

        @testset "SessionCache creation" begin
            cache = Quic.ZeroRTT.SessionCache()
            @test isempty(cache.sessions)
            @test cache.max_sessions_per_server == 10
            @test cache.max_total_sessions == 100
        end

        @testset "Session validity check" begin
            session = Quic.ZeroRTT.SessionState()
            # Empty ticket should not be valid
            @test !Quic.ZeroRTT.is_session_valid(session, time_ns())

            # Non-empty ticket should be valid initially
            session.ticket = UInt8[1, 2, 3, 4]
            session.ticket_lifetime = 3600  # 1 hour
            session.ticket_received_time = time_ns()
            @test Quic.ZeroRTT.is_session_valid(session, time_ns())
        end

        @testset "0-RTT availability check" begin
            # With empty cache, 0-RTT should not be available
            @test !Quic.ZeroRTT.is_zero_rtt_available("nonexistent.example.com")
        end
    end

    @testset "Connection ID Manager" begin
        @testset "Manager initialization" begin
            local_cid = Quic.Packet.ConnectionId(UInt8[1, 2, 3, 4])
            remote_cid = Quic.Packet.ConnectionId(UInt8[5, 6, 7, 8])
            mgr = Quic.ConnectionIdManager.ConnectionIdManagerState(local_cid, remote_cid)

            @test length(mgr.local_cids) == 1
            @test mgr.next_local_sequence == 1
            @test length(mgr.remote_cids) == 1
        end

        @testset "Issue new local CID" begin
            local_cid = Quic.Packet.ConnectionId(UInt8[1, 2, 3, 4])
            remote_cid = Quic.Packet.ConnectionId(UInt8[5, 6, 7, 8])
            mgr = Quic.ConnectionIdManager.ConnectionIdManagerState(local_cid, remote_cid)

            # Issue a new CID
            cid_data = Quic.ConnectionIdManager.issue_new_local_cid!(mgr)
            @test cid_data !== nothing
            @test length(mgr.local_cids) == 2
            @test mgr.next_local_sequence == 2
            @test cid_data.sequence_number == 1
        end

        @testset "Retire local CID" begin
            local_cid = Quic.Packet.ConnectionId(UInt8[1, 2, 3, 4])
            remote_cid = Quic.Packet.ConnectionId(UInt8[5, 6, 7, 8])
            mgr = Quic.ConnectionIdManager.ConnectionIdManagerState(local_cid, remote_cid)

            # Issue a new CID first
            Quic.ConnectionIdManager.issue_new_local_cid!(mgr)
            @test length(mgr.local_cids) == 2

            # Retire first CID
            result = Quic.ConnectionIdManager.retire_local_cid!(mgr, UInt64(0))
            @test result
            @test length(mgr.local_cids) == 1
            @test 0 in mgr.retired_local_cids
        end

        @testset "Get current remote CID" begin
            local_cid = Quic.Packet.ConnectionId(UInt8[1, 2, 3, 4])
            remote_cid = Quic.Packet.ConnectionId(UInt8[5, 6, 7, 8])
            mgr = Quic.ConnectionIdManager.ConnectionIdManagerState(local_cid, remote_cid)

            current = Quic.ConnectionIdManager.get_current_remote_cid(mgr)
            @test current !== nothing
            @test current.data == remote_cid.data
        end

        @testset "Generate connection ID" begin
            cid = Quic.ConnectionIdManager.generate_connection_id()
            @test length(cid.data) == 8  # default length

            cid_short = Quic.ConnectionIdManager.generate_connection_id(UInt8(4))
            @test length(cid_short.data) == 4
        end
    end

end