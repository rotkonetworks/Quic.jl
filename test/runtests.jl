using Quic
using Test
using Sockets

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

end