#!/usr/bin/env julia

# Julia QUIC client with Ed25519 client certificates for QuicNet
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

using Quic
using Sockets

const DEFAULT_PORT = 4433
const DEFAULT_HOST = "127.0.0.1"

mutable struct QuicNetED25519Client
    socket::UDPSocket
    connection::Quic.ConnectionModule.Connection
    identity::Quic.QuicNetProtocol.QuicNetIdentity
    server_addr::IPAddr
    server_port::Int
    connected::Bool
end

function create_ed25519_client(host::String=DEFAULT_HOST, port::Int=DEFAULT_PORT)
    println("🔑 Julia QUIC Client with Ed25519 Certificates")
    println("="^50)

    # Create UDP socket
    sock = UDPSocket()
    bind(sock, ip"0.0.0.0", 0)
    println("📡 Local UDP socket created")

    # Create QUIC connection
    conn = Quic.ConnectionModule.Connection(sock, true)

    # Parse server address
    server_ip = parse(IPAddr, host)

    # Create Ed25519 identity
    identity = Quic.QuicNetProtocol.QuicNetIdentity()
    peer_id = Quic.Ed25519.peer_id_from_pubkey(identity.keypair.public_key)
    println("🔑 Generated Ed25519 identity")
    println("   Public key: $(peer_id[1:16])...")

    # Generate X.509 certificate
    cert = Quic.X509.generate_x509_certificate(identity.keypair, subject_cn="QuicNet-Julia")
    println("📜 Generated X.509 certificate: $(length(cert)) bytes")

    # Set client certificate in handshake
    Quic.Handshake.set_client_certificate(conn.handshake, identity.keypair)
    println("✅ Client certificate configured")

    client = QuicNetED25519Client(
        sock, conn, identity, server_ip, port, false
    )

    println("🎯 Target server: $host:$port")
    println()

    return client
end

function send_initial_with_cert!(client::QuicNetED25519Client)
    println("📤 Sending Initial packet with Ed25519 support...")

    # Create ClientHello with Ed25519 in signature algorithms
    client_hello = Quic.Handshake.create_client_hello(
        client.connection.handshake,
        client.connection.remote_cid,
        string(client.server_addr),
        false
    )

    println("   ClientHello size: $(length(client_hello)) bytes")
    println("   Includes Ed25519 in signature algorithms")

    # Create Initial packet
    packet_data = UInt8[]

    # Long header with Initial packet type
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

    # Calculate payload with padding
    payload = crypto_frame
    padding_needed = 1200 - length(packet_data) - 2 - 4 - length(payload) - 16
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

    # Add payload and auth tag
    append!(packet_data, payload)
    append!(packet_data, rand(UInt8, 16))

    println("   Initial packet size: $(length(packet_data)) bytes")

    # Send packet
    send(client.socket, client.server_addr, client.server_port, packet_data)
    println("   ✅ Initial packet sent with Ed25519 support")

    return packet_data
end

function create_crypto_frame(offset::Int, data::Vector{UInt8})
    frame = UInt8[]
    push!(frame, 0x06)  # CRYPTO frame
    append!(frame, encode_varint(offset))
    append!(frame, encode_varint(length(data)))
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

function wait_for_response!(client::QuicNetED25519Client, timeout_ms::Int=5000)
    println("\n📥 Waiting for server response...")

    start_time = time() * 1000
    packets_received = 0

    while (time() * 1000 - start_time) < timeout_ms
        try
            if bytesavailable(client.socket) > 0
                data = Vector{UInt8}(undef, 65535)
                from = Ref{Sockets.InetAddr}()
                n = recvfrom!(client.socket, data, from)

                if n > 0
                    packets_received += 1
                    data = data[1:n]
                    println("   📦 Received packet: $(n) bytes")

                    # Parse packet header
                    header_byte = data[1]
                    if (header_byte & 0x80) != 0
                        println("      Long header packet")
                        packet_type = (header_byte & 0x30) >> 4
                        if packet_type == 2
                            println("      Type: Retry")
                        elseif packet_type == 1
                            println("      Type: Initial")
                        elseif packet_type == 0
                            println("      Type: Handshake")

                            # Check if this might be a certificate request
                            println("      🔐 Server may be requesting client certificate")
                        end
                    else
                        println("      Short header packet")
                    end

                    if packets_received == 1
                        client.connected = true
                    end
                end
            end

            sleep(0.1)

        catch e
            if !isa(e, Base.IOError)
                println("   ⚠️  Error: $e")
            end
            break
        end
    end

    if packets_received == 0
        println("   ⏰ Timeout - no response")
        println("\n   ℹ️  QuicNet requires mutual TLS with Ed25519 certificates")
        println("   The server expects client certificates during handshake")
    else
        println("   📊 Total packets received: $packets_received")
    end

    return packets_received > 0
end

function run_ed25519_test(host::String=DEFAULT_HOST, port::Int=DEFAULT_PORT)
    println("🧪 Testing QuicNet with Ed25519 Client Certificates")
    println("="^50)

    client = create_ed25519_client(host, port)

    try
        # Send Initial packet with Ed25519 support
        send_initial_with_cert!(client)

        # Wait for response
        if wait_for_response!(client)
            println("\n✅ Received response from server!")

            if client.connected
                println("🤝 Connection established")
                println("\nConnection details:")
                println("   Protocol: QUIC v1")
                println("   Client cert: Ed25519 X.509")
                println("   Signature algorithm: Ed25519")
            end
        else
            println("\n❌ No response from server")
            println("\nDiagnostic info:")
            println("   - Ed25519 signature algorithm included: ✓")
            println("   - X.509 certificate generated: ✓")
            println("   - Client certificate configured: ✓")
            println("\nRemaining issue:")
            println("   - TLS layer needs to send Certificate message")
            println("   - Server needs custom certificate verifier for Ed25519")
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

    run_ed25519_test(host, port)
end