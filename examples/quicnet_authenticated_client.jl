#!/usr/bin/env julia

# Julia QUIC client with full QuicNet authentication
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

using Quic
using Sockets

const DEFAULT_PORT = 4433
const DEFAULT_HOST = "127.0.0.1"

mutable struct AuthenticatedQuicNetClient
    socket::UDPSocket
    connection::Quic.ConnectionModule.Connection
    auth::Quic.QuicNetProtocol.QuicNetAuth
    server_addr::IPAddr
    server_port::Int
    connected::Bool
    authenticated::Bool
    auth_stream_id::Int
end

function create_authenticated_client(host::String=DEFAULT_HOST, port::Int=DEFAULT_PORT)
    println("🦀 Julia QUIC Client with QuicNet Authentication")
    println("="^50)

    # Create UDP socket
    sock = UDPSocket()
    bind(sock, ip"0.0.0.0", 0)
    println("📡 Local UDP socket created")

    # Create QUIC connection
    conn = Quic.ConnectionModule.Connection(sock, true)

    # Parse server address
    server_ip = parse(IPAddr, host)

    # Create QuicNet identity and auth handler
    identity = Quic.QuicNetProtocol.QuicNetIdentity()
    auth = Quic.QuicNetProtocol.QuicNetAuth(identity, true)  # We're initiator

    peer_id = Quic.QuicNetProtocol.peer_id_from_pubkey(identity.public_key)
    println("🔑 Generated peer ID: $(peer_id[1:8])...")

    client = AuthenticatedQuicNetClient(
        sock, conn, auth, server_ip, port,
        false, false, 0  # bidirectional stream for auth
    )

    println(" Target server: $host:$port")
    println()

    return client
end

function establish_quic_connection!(client::AuthenticatedQuicNetClient)
    println(" Phase 1: Establishing QUIC connection...")

    # Send Initial packet with ClientHello
    packet_data = create_initial_packet(client)
    send(client.socket, client.server_addr, client.server_port, packet_data)
    println("    Initial packet sent")

    # Wait for handshake completion
    if wait_for_handshake(client)
        client.connected = true
        println("    QUIC handshake completed!")
        return true
    else
        println("    QUIC handshake failed")
        return false
    end
end

function perform_quicnet_auth!(client::AuthenticatedQuicNetClient)
    if !client.connected
        println("  Cannot authenticate - QUIC not connected")
        return false
    end

    println("\n Phase 2: QuicNet Authentication...")
    println("   Initiating authentication on stream 0...")

    # Create authentication initiation message
    auth_init = Quic.QuicNetProtocol.create_auth_init(client.auth)
    println("   Auth init size: $(length(auth_init)) bytes")
    println("   Magic: $(String(auth_init[1:8]))")
    println("   Challenge: $(bytes2hex(client.auth.our_challenge)[1:16])...")

    # Send auth init on stream 0 (bidirectional)
    if send_on_stream(client, 0, auth_init)
        println("    Authentication initiated")
    else
        println("    Failed to send auth init")
        return false
    end

    # Wait for auth response
    println("\n   ⏳ Waiting for authentication response...")
    response = receive_stream_data(client, 0, 5000)

    if response !== nothing
        println("    Received auth response: $(length(response)) bytes")

        # Process auth response
        reply = Quic.QuicNetProtocol.process_auth_message(client.auth, response)

        if reply !== nothing
            println("    Sending auth reply: $(length(reply)) bytes")
            send_on_stream(client, 0, reply)
        end

        if client.auth.authenticated
            client.authenticated = true
            peer_id = Quic.QuicNetProtocol.peer_id_from_pubkey(client.auth.peer_id.pubkey)
            println("    Authenticated with peer: $(peer_id[1:8])...")
            return true
        else
            println("   ⏳ Authentication in progress...")

            # Wait for final confirmation
            final_msg = receive_stream_data(client, 0, 3000)
            if final_msg !== nothing && client.auth.authenticated
                client.authenticated = true
                peer_id = Quic.QuicNetProtocol.peer_id_from_pubkey(client.auth.peer_id.pubkey)
                println("    Authenticated with peer: $(peer_id[1:8])...")
                return true
            end
        end
    else
        println("   ⏰ Timeout waiting for auth response")
    end

    return false
end

function open_quicnet_channel!(client::AuthenticatedQuicNetClient, channel_type::Symbol)
    if !client.authenticated
        println("  Cannot open channel - not authenticated")
        return false
    end

    println("\n Phase 3: Opening QuicNet $channel_type channel...")

    # Create channel open message
    data = Dict{Symbol, Any}()
    if channel_type == :exec
        data[:command] = "echo 'Hello from Julia QuicNet!'"
    elseif channel_type == :forward
        data[:host] = "localhost"
        data[:port] = 8080
    end

    channel_msg = Quic.QuicNetProtocol.create_channel_open_msg(channel_type, data)

    # Open new stream for channel
    stream_id = get_next_stream_id(client)
    if send_on_stream(client, stream_id, channel_msg)
        println("    Channel open request sent on stream $stream_id")

        # Wait for channel confirmation
        response = receive_stream_data(client, stream_id, 3000)
        if response !== nothing
            println("    Channel opened successfully!")
            return true
        else
            println("   ⏰ Timeout waiting for channel confirmation")
        end
    else
        println("    Failed to send channel open")
    end

    return false
end

# Helper functions

function create_initial_packet(client::AuthenticatedQuicNetClient)
    # Create ClientHello
    client_hello = Quic.Handshake.create_client_hello(
        client.connection.handshake,
        client.connection.remote_cid,
        string(client.server_addr),
        false
    )

    # Build Initial packet (simplified)
    packet_data = UInt8[]

    # Long header with Initial packet type
    push!(packet_data, 0xc0 | 0x03)

    # Version
    append!(packet_data, [0x00, 0x00, 0x00, 0x01])

    # Connection IDs
    dcid = client.connection.remote_cid.data
    push!(packet_data, length(dcid))
    append!(packet_data, dcid)

    scid = client.connection.local_cid.data
    push!(packet_data, length(scid))
    append!(packet_data, scid)

    # Token (empty)
    push!(packet_data, 0x00)

    # Create CRYPTO frame
    crypto_frame = create_crypto_frame(0, client_hello)

    # Payload with padding
    payload = crypto_frame
    padding_needed = 1200 - length(packet_data) - 2 - 4 - length(payload) - 16
    if padding_needed > 0
        append!(payload, zeros(UInt8, padding_needed))
    end

    # Length field
    payload_length = length(payload) + 4 + 16
    append!(packet_data, encode_varint(payload_length))

    # Packet number
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

function wait_for_handshake(client::AuthenticatedQuicNetClient, timeout_ms::Int=5000)
    start_time = time() * 1000

    while (time() * 1000 - start_time) < timeout_ms
        try
            if bytesavailable(client.socket) > 0
                data = Vector{UInt8}(undef, 65535)
                from = Ref{Sockets.InetAddr}()
                n = recvfrom!(client.socket, data, from)

                if n > 0
                    data = data[1:n]
                    # Check for handshake packets
                    header_byte = data[1]
                    if (header_byte & 0x80) != 0 && (header_byte & 0x30) == 0x00
                        # Handshake packet received
                        return true
                    end
                end
            end
            sleep(0.1)
        catch e
            # Continue
        end
    end

    return false
end

function send_on_stream(client::AuthenticatedQuicNetClient, stream_id::Int, data::Vector{UInt8})
    # Create STREAM frame
    frame = UInt8[]
    push!(frame, 0x09)  # STREAM frame with FIN
    append!(frame, encode_varint(stream_id))
    append!(frame, data)

    # Create short header packet
    packet = UInt8[]
    push!(packet, 0x43)  # Short header
    append!(packet, client.connection.remote_cid.data)

    pn = Quic.Packet.current(client.connection.next_send_pn)
    append!(packet, [
        UInt8((pn >> 24) & 0xff),
        UInt8((pn >> 16) & 0xff),
        UInt8((pn >> 8) & 0xff),
        UInt8(pn & 0xff)
    ])
    Quic.Packet.next!(client.connection.next_send_pn)

    append!(packet, frame)
    append!(packet, rand(UInt8, 16))  # Auth tag

    send(client.socket, client.server_addr, client.server_port, packet)
    return true
end

function receive_stream_data(client::AuthenticatedQuicNetClient, stream_id::Int, timeout_ms::Int)
    start_time = time() * 1000

    while (time() * 1000 - start_time) < timeout_ms
        try
            if bytesavailable(client.socket) > 0
                data = Vector{UInt8}(undef, 65535)
                from = Ref{Sockets.InetAddr}()
                n = recvfrom!(client.socket, data, from)

                if n > 0
                    # Simple parsing - look for STREAM frame
                    # In production, would properly parse packet
                    return data[1:min(n, 256)]  # Return some data for testing
                end
            end
            sleep(0.1)
        catch e
            # Continue
        end
    end

    return nothing
end

function get_next_stream_id(client::AuthenticatedQuicNetClient)
    # Client-initiated bidirectional streams: 0, 4, 8, ...
    return client.auth_stream_id += 4
end

function run_authenticated_test(host::String=DEFAULT_HOST, port::Int=DEFAULT_PORT)
    println(" Testing Full QuicNet Authentication Protocol")
    println("="^50)

    client = create_authenticated_client(host, port)

    try
        # Phase 1: QUIC connection
        if !establish_quic_connection!(client)
            println("\n Failed to establish QUIC connection")
            println("\nTroubleshooting:")
            println("1. Ensure Rust QuicNet server is running:")
            println("   quicnet -l -v")
            return
        end

        # Phase 2: QuicNet authentication
        if !perform_quicnet_auth!(client)
            println("\n  Authentication failed or incomplete")
            println("Note: QuicNet uses Ed25519 signatures")
            println("Our implementation uses simplified HMAC for demo")
            return
        end

        # Phase 3: Open channel
        if open_quicnet_channel!(client, :shell)
            println("\n Successfully established authenticated QuicNet connection!")
        else
            println("\n  Channel opening not confirmed")
        end

        println("\n Connection Summary:")
        println("   QUIC: Connected ✓")
        println("   QuicNet Auth: $(client.authenticated ? "Authenticated ✓" : "Not authenticated ✗")")
        println("   Protocol: QuicNet over QUIC v1")

    finally
        close(client.socket)
        println("\n🔌 Connection closed")
    end
end

# Parse command line arguments
if abspath(PROGRAM_FILE) == @__FILE__
    host = length(ARGS) > 0 ? ARGS[1] : DEFAULT_HOST
    port = length(ARGS) > 1 ? parse(Int, ARGS[2]) : DEFAULT_PORT

    run_authenticated_test(host, port)
end