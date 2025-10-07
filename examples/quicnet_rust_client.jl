#!/usr/bin/env julia

# Julia QUIC client for connecting to Rust QuicNet servers
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

using Quic
using Sockets

const DEFAULT_PORT = 4433
const DEFAULT_HOST = "127.0.0.1"

mutable struct RustQuicNetClient
    socket::UDPSocket
    connection::Quic.ConnectionModule.Connection
    server_addr::IPAddr
    server_port::Int
    connected::Bool
end

function create_rust_client(host::String=DEFAULT_HOST, port::Int=DEFAULT_PORT)
    println("🦀 Julia QUIC Client for Rust QuicNet Server")
    println("="^50)

    # Create UDP socket
    sock = UDPSocket()
    bind(sock, ip"0.0.0.0", 0)
    println("📡 Local UDP socket created")

    # Create QUIC connection
    conn = Quic.ConnectionModule.Connection(sock, true)

    # Parse server address
    server_ip = parse(IPAddr, host)

    client = RustQuicNetClient(sock, conn, server_ip, port, false)

    println("🎯 Target server: $host:$port")
    println()

    return client
end

function send_initial_packet!(client::RustQuicNetClient)
    println("📤 Sending Initial packet to Rust QuicNet server...")

    # Create ClientHello
    client_hello = Quic.Handshake.create_client_hello(
        client.connection.handshake,
        client.connection.remote_cid,
        string(client.server_addr),
        false  # No 0-RTT for initial connection
    )

    println("   ClientHello size: $(length(client_hello)) bytes")

    # Create Initial packet header
    packet_data = UInt8[]

    # Long header with Initial packet type (0xc0 for v1)
    push!(packet_data, 0xc0 | 0x03)  # Long header, Initial packet, PN length 4

    # Version (QUIC v1)
    append!(packet_data, [0x00, 0x00, 0x00, 0x01])

    # Destination connection ID
    dcid = client.connection.remote_cid.data
    push!(packet_data, length(dcid))
    append!(packet_data, dcid)

    # Source connection ID
    scid = client.connection.local_cid.data
    push!(packet_data, length(scid))
    append!(packet_data, scid)

    # Token (empty for initial client packet)
    push!(packet_data, 0x00)

    # Create CRYPTO frame with ClientHello
    crypto_frame = create_crypto_frame(0, client_hello)

    # Calculate payload (CRYPTO frame + padding)
    payload = crypto_frame

    # Add padding to reach minimum Initial packet size (1200 bytes)
    padding_needed = 1200 - length(packet_data) - 2 - 4 - length(payload) - 16  # 16 for auth tag
    if padding_needed > 0
        append!(payload, zeros(UInt8, padding_needed))
    end

    # Length field (variable-length encoding)
    payload_length = length(payload) + 4 + 16  # packet number + auth tag
    append!(packet_data, encode_varint(payload_length))

    # Packet number (4 bytes for Initial)
    pn = Quic.Packet.current(client.connection.next_send_pn)
    append!(packet_data, [
        UInt8((pn >> 24) & 0xff),
        UInt8((pn >> 16) & 0xff),
        UInt8((pn >> 8) & 0xff),
        UInt8(pn & 0xff)
    ])
    Quic.Packet.next!(client.connection.next_send_pn)

    # Add payload (would be encrypted in real implementation)
    append!(packet_data, payload)

    # Add fake auth tag (16 bytes)
    append!(packet_data, rand(UInt8, 16))

    println("   Initial packet size: $(length(packet_data)) bytes")

    # Send packet
    send(client.socket, client.server_addr, client.server_port, packet_data)
    println("   ✅ Initial packet sent")

    return packet_data
end

function create_crypto_frame(offset::Int, data::Vector{UInt8})
    frame = UInt8[]

    # CRYPTO frame type (0x06)
    push!(frame, 0x06)

    # Offset (variable-length)
    append!(frame, encode_varint(offset))

    # Length (variable-length)
    append!(frame, encode_varint(length(data)))

    # Data
    append!(frame, data)

    return frame
end

function encode_varint(value::Int)
    if value < 64
        return [UInt8(value)]
    elseif value < 16384
        return [
            UInt8(0x40 | ((value >> 8) & 0x3f)),
            UInt8(value & 0xff)
        ]
    elseif value < 1073741824
        return [
            UInt8(0x80 | ((value >> 24) & 0x3f)),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff)
        ]
    else
        return [
            UInt8(0xc0 | ((value >> 56) & 0x3f)),
            UInt8((value >> 48) & 0xff),
            UInt8((value >> 40) & 0xff),
            UInt8((value >> 32) & 0xff),
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff)
        ]
    end
end

function receive_packets!(client::RustQuicNetClient, timeout_ms::Int=5000)
    println("\n📥 Waiting for response from Rust server...")

    start_time = time() * 1000
    packets_received = 0

    while (time() * 1000 - start_time) < timeout_ms
        # Try to receive with short timeout
        try
            # Set socket to non-blocking mode
            data = Vector{UInt8}(undef, 65535)
            from = Ref{Sockets.InetAddr}()

            # This is a simplified receive - in real implementation would use proper async
            if bytesavailable(client.socket) > 0
                n = recvfrom!(client.socket, data, from)
                if n > 0
                    packets_received += 1
                    data = data[1:n]
                    println("   📦 Received packet: $(n) bytes from $(from[])")

                    # Parse packet header
                    if length(data) > 0
                        header_byte = data[1]
                        if (header_byte & 0x80) != 0
                            println("      Long header packet")
                            if (header_byte & 0x30) == 0x20
                                println("      Type: Retry")
                            elseif (header_byte & 0x30) == 0x10
                                println("      Type: Initial")
                            elseif (header_byte & 0x30) == 0x00
                                println("      Type: Handshake")
                            end
                        else
                            println("      Short header packet")
                        end
                    end

                    # Check if handshake-related
                    if packets_received == 1
                        client.connected = true
                        println("   🤝 Handshake response received!")
                    end
                end
            end

            sleep(0.1)  # Small delay to avoid busy waiting

        catch e
            if !isa(e, Base.IOError)
                println("   ⚠️  Error receiving: $e")
            end
            break
        end
    end

    if packets_received == 0
        println("   ⏰ Timeout - no response received")
        println("   ℹ️  Make sure the Rust QuicNet server is running:")
        println("      quicnet -l -v")
    else
        println("   📊 Total packets received: $packets_received")
    end

    return packets_received > 0
end

function test_echo_mode!(client::RustQuicNetClient)
    if !client.connected
        println("\n⚠️  Not connected - skipping echo test")
        return
    end

    println("\n🔊 Testing echo mode...")
    println("   (Requires server started with: quicnet -l --echo)")

    # Send test data on stream 0
    test_data = "Hello from Julia QUIC!"
    stream_frame = create_stream_frame(0, test_data)

    # Create short header packet for application data
    packet = create_short_header_packet(client, stream_frame)

    send(client.socket, client.server_addr, client.server_port, packet)
    println("   📤 Sent: \"$test_data\"")

    # Wait for echo response
    if receive_packets!(client, 2000)
        println("   ✅ Echo test completed")
    else
        println("   ❌ No echo response")
    end
end

function create_stream_frame(stream_id::Int, data::String)
    frame = UInt8[]

    # STREAM frame with FIN bit (0x09)
    push!(frame, 0x09)

    # Stream ID (variable-length)
    append!(frame, encode_varint(stream_id))

    # Data
    data_bytes = Vector{UInt8}(data)
    append!(frame, data_bytes)

    return frame
end

function create_short_header_packet(client::RustQuicNetClient, payload::Vector{UInt8})
    packet = UInt8[]

    # Short header (0x40) with key phase 0
    push!(packet, 0x43)  # Short header, key phase 0, PN length 4

    # Destination connection ID
    append!(packet, client.connection.remote_cid.data)

    # Packet number (4 bytes)
    pn = Quic.Packet.current(client.connection.next_send_pn)
    append!(packet, [
        UInt8((pn >> 24) & 0xff),
        UInt8((pn >> 16) & 0xff),
        UInt8((pn >> 8) & 0xff),
        UInt8(pn & 0xff)
    ])
    Quic.Packet.next!(client.connection.next_send_pn)

    # Payload
    append!(packet, payload)

    # Auth tag (fake)
    append!(packet, rand(UInt8, 16))

    return packet
end

function run_rust_compatibility_test(host::String=DEFAULT_HOST, port::Int=DEFAULT_PORT)
    println("🧪 Testing Julia QUIC ↔ Rust QuicNet Compatibility")
    println("="^50)

    # Create client
    client = create_rust_client(host, port)

    try
        # Send Initial packet
        send_initial_packet!(client)

        # Wait for response
        if receive_packets!(client)
            println("\n✅ Successfully communicated with Rust QuicNet server!")

            # Try echo test if connected
            test_echo_mode!(client)
        else
            println("\n❌ Failed to establish connection with Rust server")
            println("\nTroubleshooting:")
            println("1. Ensure Rust QuicNet server is running:")
            println("   quicnet -l -v")
            println("2. Check firewall settings for UDP port $port")
            println("3. Try with verbose mode on server:")
            println("   quicnet -l -v --bind 0.0.0.0")
        end

    finally
        close(client.socket)
        println("\n📊 Connection closed")
    end
end

# Parse command line arguments
if abspath(PROGRAM_FILE) == @__FILE__
    host = length(ARGS) > 0 ? ARGS[1] : DEFAULT_HOST
    port = length(ARGS) > 1 ? parse(Int, ARGS[2]) : DEFAULT_PORT

    run_rust_compatibility_test(host, port)
end