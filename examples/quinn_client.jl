#!/usr/bin/env julia

# Quinn-compatible QUIC client
# Connects to a Quinn server with proper handshake

using Sockets
push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic

"""
Quinn-compatible QUIC client implementation.
Tests against a standard Quinn server.

Usage:
    julia quinn_client.jl <host> <port>

Example:
    # Start Quinn server first:
    cargo run --example server 0.0.0.0:4433

    # Then run this client:
    julia quinn_client.jl localhost 4433
"""
function quinn_client(host::String="localhost", port::Int=4433)
    println("=== Quinn-Compatible QUIC Client ===")
    println("Target: $host:$port")
    println()

    # Create client endpoint
    client_addr = Sockets.InetAddr(ip"0.0.0.0", 0)
    config = Quic.EndpointModule.EndpointConfig()
    config.server_name = host
    config.alpn_protocols = ["h3", "h3-29", "hq-29"]

    endpoint = Quic.EndpointModule.Endpoint(client_addr, config, false)

    # Resolve server address
    server_addr = try
        Sockets.InetAddr(getaddrinfo(host), port)
    catch e
        println("Failed to resolve host: $e")
        return
    end

    println("Server address: $server_addr")

    # Create connection
    conn = Quic.EndpointModule.connect(endpoint, server_addr)
    println("Local CID:  $(bytes2hex(conn.local_cid.data))")
    println("Remote CID: $(bytes2hex(conn.remote_cid.data))")

    # Use ChaCha20-Poly1305 (Quinn's default)
    conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()
    println("Cipher suite: ChaCha20-Poly1305")

    # Derive initial keys
    Quic.Crypto.derive_initial_secrets!(conn.crypto, conn.remote_cid.data)
    println("Initial keys derived")

    # Start handshake
    println("\n=== Starting QUIC Handshake ===")
    Quic.ConnectionModule.initiate_handshake(conn, host)
    println("Initial packet sent with ClientHello")

    # Event loop to handle incoming packets
    handshake_complete = false
    max_iterations = 30
    iteration = 0
    last_ping_time = time()

    println("\n=== Waiting for Server Response ===")

    while !handshake_complete && iteration < max_iterations
        iteration += 1

        try
            # receive packet with timeout
            data = Vector{UInt8}(undef, 65536)
            nbytes, from_addr = try
                # non-blocking receive
                recvfrom(conn.socket, data)
            catch e
                if isa(e, Base.IOError) && e.code == -11  # EAGAIN/EWOULDBLOCK
                    # no data available
                    sleep(0.1)

                    # send periodic PING to keep connection alive
                    if time() - last_ping_time > 1.0
                        send_ping(conn)
                        last_ping_time = time()
                    end

                    continue
                else
                    rethrow(e)
                end
            end

            if nbytes > 0
                packet_data = data[1:nbytes]
                println("\n📥 Received packet: $nbytes bytes from $from_addr")

                # process the packet
                result = Quic.PacketReceiver.process_incoming_packet(conn, packet_data, from_addr)

                if result !== nothing
                    packet_type, payload = result

                    if packet_type == :version_negotiation
                        println("⚠️  Version negotiation required")
                        # would restart with new version
                        break

                    elseif packet_type == :retry
                        println("🔄 Retry required with token")
                        # would restart handshake with token
                        break

                    elseif packet_type == :initial
                        println("✅ Processed Initial packet")

                        # check if handshake progressed
                        if conn.handshake.state == :completed
                            handshake_complete = true
                            println("🎉 Handshake completed!")
                        elseif conn.handshake.state != :initial
                            println("   Handshake state: $(conn.handshake.state)")
                        end

                    elseif packet_type == :handshake
                        println("✅ Processed Handshake packet")

                    elseif packet_type == :short
                        println("✅ Processed 1-RTT packet")
                        handshake_complete = true
                    end
                else
                    println("⚠️  Failed to process packet")
                end
            end

        catch e
            if !isa(e, InterruptException)
                println("Error: $e")
                println("Stack trace:")
                for (exc, bt) in Base.catch_stack()
                    showerror(stdout, exc, bt)
                    println()
                end
            end
            break
        end
    end

    # Final status
    println("\n=== Connection Status ===")
    println("Handshake complete: $handshake_complete")
    println("Connected: $(conn.connected)")
    println("Packets sent: $(conn.next_send_pn.value)")
    println("Packets received: $(conn.next_recv_pn.value)")

    if handshake_complete
        println("\n=== Testing Application Data ===")

        # try to send stream data
        try
            stream_id = Quic.ConnectionModule.open_stream(conn, true)
            test_msg = "Hello from Julia QUIC client!"
            data = Vector{UInt8}(test_msg)

            bytes_sent = Quic.ConnectionModule.send_stream(conn, stream_id, data, true)
            println("Sent $bytes_sent bytes: \"$test_msg\"")

            # wait for response
            sleep(0.5)

            # try to receive response
            data = Vector{UInt8}(undef, 65536)
            nbytes, from_addr = recvfrom(conn.socket, data)

            if nbytes > 0
                println("Received response: $nbytes bytes")
                # would process 1-RTT packet here
            end

        catch e
            println("Failed to send application data: $e")
        end

        # send connection close
        println("\n=== Closing Connection ===")
        close_frame = Quic.Frame.ApplicationCloseFrame(0, "Client closing gracefully")
        Quic.ConnectionModule.send_frame(conn, close_frame)
        println("Connection close sent")
    end

    # cleanup
    close(endpoint.socket)
    println("\n✅ Client shutdown complete")
end

# Send PING frame to keep connection alive
function send_ping(conn)
    ping_frame = Quic.Frame.PingFrame()
    try
        Quic.ConnectionModule.send_frame(conn, ping_frame)
        println(".")  # progress indicator
    catch e
        # ignore send errors during handshake
    end
end

# Helper to set socket to non-blocking mode
function set_nonblocking(sock::UDPSocket)
    # This is platform-specific
    # On Unix-like systems, would use fcntl
    # For now, we'll use timeouts instead
    # (Julia's UDP sockets don't have great non-blocking support)
end

# Main entry point
if abspath(PROGRAM_FILE) == @__FILE__
    if length(ARGS) < 2
        println("Usage: julia quinn_client.jl <host> <port>")
        println("Example: julia quinn_client.jl localhost 4433")
        exit(1)
    end

    host = ARGS[1]
    port = parse(Int, ARGS[2])

    quinn_client(host, port)
end