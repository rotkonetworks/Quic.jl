#!/usr/bin/env julia

# Quinn interoperability test client
# Tests connectivity with a Quinn server implementation

using Sockets
push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic

"""
Connect to a Quinn server and perform basic QUIC operations.
This tests interoperability with the Rust Quinn implementation.

To test:
1. Start a Quinn server (e.g., using quinn examples)
   cargo run --example server 0.0.0.0:4433

2. Run this Julia client:
   julia examples/quinn_interop.jl localhost 4433
"""
function test_quinn_interop(host::String="localhost", port::Int=4433)
    println("=== Quinn Interoperability Test ===")
    println("Connecting to Quinn server at $host:$port")
    println()

    # Create endpoint with Quinn-compatible configuration
    client_addr = Sockets.InetAddr(ip"0.0.0.0", 0)
    config = Quic.EndpointModule.EndpointConfig()
    config.server_name = host
    config.alpn_protocols = ["h3", "h3-29", "hq-29"]  # HTTP/3 and HTTP/0.9 over QUIC

    endpoint = Quic.EndpointModule.Endpoint(client_addr, config, false)

    try
        # Resolve server address
        server_addr = Sockets.InetAddr(getaddrinfo(host), port)
        println("Server address resolved: $server_addr")

        # Create connection
        conn = Quic.EndpointModule.connect(endpoint, server_addr)
        println("Connection object created")

        # Use ChaCha20-Poly1305 for better Quinn compatibility
        conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()
        println("Cipher suite: ChaCha20-Poly1305")

        # Derive initial keys
        Quic.Crypto.derive_initial_secrets!(conn.crypto, conn.remote_cid.data)
        println("Initial keys derived")

        # Start handshake
        println("\nInitiating QUIC handshake...")
        Quic.ConnectionModule.initiate_handshake(conn, host)

        # Wait for handshake response
        println("Waiting for server response...")
        response_received = false
        max_attempts = 10

        for attempt in 1:max_attempts
            try
                data, addr = Sockets.recvfrom(conn.socket, 1500, timeout=1.0)

                if length(data) > 0
                    println("Received packet: $(length(data)) bytes")

                    # Check if it's a version negotiation packet
                    if Quic.VersionNegotiation.is_version_negotiation_packet(data)
                        println("Received version negotiation packet")
                        vn_data = Quic.VersionNegotiation.parse_version_negotiation(data)
                        if vn_data !== nothing
                            println("Server supports versions: $(vn_data.versions)")
                            chosen = Quic.VersionNegotiation.choose_version(vn_data.versions)
                            if chosen !== nothing
                                println("Selected version: 0x$(string(chosen, base=16))")
                            else
                                println("ERROR: No compatible version found")
                                break
                            end
                        end
                    else
                        # Try to parse as regular QUIC packet
                        header = Quic.PacketCodec.parse_packet_header(data, length(conn.remote_cid))

                        if header !== nothing
                            println("Packet type: $(header.type)")

                            if header.type == :retry
                                println("Received Retry packet")
                                println("Retry token length: $(length(header.retry_token))")
                                # Would need to restart handshake with token
                            elseif header.type == :initial
                                println("Received Initial packet")
                                response_received = true

                                # Try to decrypt if we have keys
                                if !isempty(conn.crypto.initial_secrets)
                                    println("Attempting to decrypt...")
                                    # Would decrypt and process frames here
                                end
                            elseif header.type == :handshake
                                println("Received Handshake packet")
                                response_received = true
                            end
                        else
                            println("Unable to parse packet header")
                        end
                    end
                end
            catch e
                if !isa(e, Sockets.TimeoutException)
                    println("Error receiving: $e")
                end
            end

            if response_received
                break
            end

            # Send PING to keep connection alive
            if attempt % 3 == 0
                println("Sending PING...")
                ping_frame = Quic.Frame.PingFrame()
                Quic.ConnectionModule.send_frame(conn, ping_frame)
            end

            sleep(0.5)
        end

        if response_received
            println("\n✓ Successfully exchanged packets with Quinn server!")
            println("  Interoperability test PASSED (initial handshake)")
        else
            println("\n✗ No valid response received from Quinn server")
            println("  This could mean:")
            println("  - The server is not running")
            println("  - Firewall is blocking UDP packets")
            println("  - Version negotiation failed")
            println("  - Crypto handshake incompatibility")
        end

        # Test sending stream data if connected
        if response_received
            println("\nAttempting to send stream data...")
            stream_id = Quic.ConnectionModule.open_stream(conn, true)
            test_data = Vector{UInt8}("Hello from Julia QUIC client!")

            try
                bytes_sent = Quic.ConnectionModule.send_stream(conn, stream_id, test_data, true)
                println("Sent $bytes_sent bytes on stream $(stream_id.value)")
            catch e
                println("Error sending stream data: $e")
            end
        end

    catch e
        println("\nError during test: $e")
        println("Stack trace:")
        for (exc, bt) in Base.catch_stack()
            showerror(stdout, exc, bt)
            println()
        end
    finally
        close(endpoint.socket)
        println("\nTest completed")
    end
end

# Parse command line arguments
if abspath(PROGRAM_FILE) == @__FILE__
    if length(ARGS) == 0
        println("Usage: julia quinn_interop.jl <host> [port]")
        println("Example: julia quinn_interop.jl localhost 4433")
        println("\nUsing default: localhost:4433")
        test_quinn_interop()
    else
        host = ARGS[1]
        port = length(ARGS) > 1 ? parse(Int, ARGS[2]) : 4433
        test_quinn_interop(host, port)
    end
end