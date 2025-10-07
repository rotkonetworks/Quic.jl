#!/usr/bin/env julia

# HTTP/3 Server Example
# Demonstrates HTTP/3 server functionality over QUIC

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Sockets
using Dates

mutable struct HTTP3Server
    quic_server::Any  # QuicServer from quic_server.jl
    routes::Dict{String, Function}
    stats::@NamedTuple{
        requests_processed::Int,
        responses_sent::Int,
        bytes_received::Int,
        bytes_sent::Int
    }

    function HTTP3Server(port::Int = 4433)
        # Use the QUIC server from our previous example
        include("quic_server.jl")
        quic_server = QuicServer(port)

        # Default routes
        routes = Dict{String, Function}(
            "/" => handle_root,
            "/api/test" => handle_api_test,
            "/api/data" => handle_api_data,
            "/large" => handle_large_response
        )

        new(quic_server, routes, (requests_processed=0, responses_sent=0, bytes_received=0, bytes_sent=0))
    end
end

# Default route handlers
function handle_root(request::Dict{String, Any})
    return (
        status = 200,
        headers = Dict("content-type" => "text/html; charset=utf-8"),
        body = """
        <!DOCTYPE html>
        <html>
        <head><title>Julia QUIC HTTP/3 Server</title></head>
        <body>
            <h1>🚀 Julia QUIC HTTP/3 Server</h1>
            <p>Welcome to the Julia QUIC implementation with HTTP/3 support!</p>
            <ul>
                <li><strong>Protocol:</strong> HTTP/3 over QUIC</li>
                <li><strong>Encryption:</strong> TLS 1.3 with ChaCha20-Poly1305</li>
                <li><strong>Features:</strong> Multiplexing, 0-RTT, Loss Recovery</li>
            </ul>
            <p>Try these endpoints:</p>
            <ul>
                <li><a href="/api/test">GET /api/test</a> - API test</li>
                <li><a href="/api/data">POST /api/data</a> - Data submission</li>
                <li><a href="/large">GET /large</a> - Large response test</li>
            </ul>
        </body>
        </html>
        """
    )
end

function handle_api_test(request::Dict{String, Any})
    return (
        status = 200,
        headers = Dict(
            "content-type" => "application/json",
            "x-powered-by" => "Julia-QUIC-HTTP3"
        ),
        body = """
        {
            "message": "Hello from Julia HTTP/3 server!",
            "timestamp": "$(now())",
            "method": "$(request["method"])",
            "path": "$(request["path"])",
            "protocol": "HTTP/3",
            "transport": "QUIC"
        }
        """
    )
end

function handle_api_data(request::Dict{String, Any})
    body_text = isempty(request["body"]) ? "{}" : String(request["body"])

    return (
        status = 201,
        headers = Dict(
            "content-type" => "application/json",
            "location" => "/api/data/$(rand(1000:9999))"
        ),
        body = """
        {
            "message": "Data received successfully",
            "timestamp": "$(now())",
            "received_body": $body_text,
            "body_size": $(length(request["body"])),
            "method": "$(request["method"])"
        }
        """
    )
end

function handle_large_response(request::Dict{String, Any})
    # Generate a large response for testing
    large_data = "Large response data: " * "X" * 10000 * " [End]"

    return (
        status = 200,
        headers = Dict(
            "content-type" => "text/plain",
            "content-length" => string(length(large_data))
        ),
        body = large_data
    )
end

# Enhanced connection handling with HTTP/3 support
function handle_http3_connection_events!(server::HTTP3Server, conn, event)
    # Enable HTTP/3 on the connection
    if conn.connected && conn.http3 === nothing
        Quic.ConnectionModule.enable_http3!(conn)
        println("🌐 HTTP/3 enabled for connection $(bytes2hex(conn.local_cid.data)[1:8])...")
    end

    # Process HTTP/3 requests
    if conn.http3 !== nothing
        for (stream_id, request_state) in conn.http3.request_streams
            if request_state.request_complete && !request_state.response_complete
                handle_http3_request!(server, conn, stream_id, request_state)
            end
        end
    end

    # Handle regular stream data as well
    for (stream_id, stream_state) in conn.streams
        if !isempty(stream_state.recv_buf)
            # Try to process as HTTP/3 data
            data = copy(stream_state.recv_buf)
            empty!(stream_state.recv_buf)  # Clear the buffer

            if conn.http3 !== nothing
                Quic.ConnectionModule.process_http3_data!(conn, stream_id, data)
            end
        end
    end
end

function handle_http3_request!(server::HTTP3Server, conn, stream_id::UInt64, request_state)
    println("🌐 Processing HTTP/3 request on stream $stream_id")
    println("   Method: $(request_state.method)")
    println("   Path: $(request_state.path)")

    # Create request object
    request = Dict{String, Any}(
        "method" => request_state.method,
        "path" => request_state.path,
        "headers" => request_state.headers,
        "body" => request_state.body
    )

    # Find matching route
    handler = get(server.routes, request_state.path, handle_not_found)

    # Call handler
    try
        response = handler(request)

        # Send HTTP/3 response
        stream_sid = Quic.Stream.StreamId(stream_id, :server, :bidi)
        success = Quic.ConnectionModule.send_http_response!(
            conn, stream_sid, response.status, response.headers, response.body
        )

        if success
            # Update statistics
            server.stats = (
                requests_processed = server.stats.requests_processed + 1,
                responses_sent = server.stats.responses_sent + 1,
                bytes_received = server.stats.bytes_received + length(request_state.body),
                bytes_sent = server.stats.bytes_sent + length(response.body)
            )

            println("✅ HTTP/3 response sent: $(response.status)")
        else
            println("❌ Failed to send HTTP/3 response")
        end

    catch e
        println("❌ Error processing HTTP/3 request: $e")

        # Send error response
        error_response = """
        {
            "error": "Internal Server Error",
            "message": "$(string(e))",
            "timestamp": "$(now())"
        }
        """

        stream_sid = Quic.Stream.StreamId(stream_id, :server, :bidi)
        Quic.ConnectionModule.send_http_response!(
            conn, stream_sid, 500,
            Dict("content-type" => "application/json"),
            error_response
        )
    end
end

function handle_not_found(request::Dict{String, Any})
    return (
        status = 404,
        headers = Dict("content-type" => "application/json"),
        body = """
        {
            "error": "Not Found",
            "message": "The requested path '$(request["path"])' was not found",
            "timestamp": "$(now())",
            "available_paths": ["/", "/api/test", "/api/data", "/large"]
        }
        """
    )
end

function start_http3_server!(server::HTTP3Server)
    println("🌐 Starting HTTP/3 server on port $(getsockname(server.quic_server.endpoint.socket)[2])...")
    println("📊 HTTP/3 capabilities:")
    println("   ✅ HTTP/3 over QUIC transport")
    println("   ✅ QPACK header compression")
    println("   ✅ Multiple concurrent streams")
    println("   ✅ Server push support (planned)")
    println("   ✅ TLS 1.3 with modern ciphers")
    println("   ✅ Automatic flow control")

    server.quic_server.running = true
    data = Vector{UInt8}(undef, 65536)

    while server.quic_server.running
        try
            # Receive packets
            nbytes, client_addr = recvfrom(server.quic_server.endpoint.socket, data, timeout=1.0)

            if nbytes > 0
                # Use the existing packet handling but with HTTP/3 integration
                handle_client_packet_http3!(server, data[1:nbytes], client_addr)
            end

            # Process active connections with HTTP/3 support
            process_active_connections_http3!(server)

        catch e
            if isa(e, Base.UVError) && e.code == Base.UV_ETIMEDOUT
                continue
            else
                println("❌ HTTP/3 server error: $e")
                break
            end
        end

        sleep(0.001)
    end

    println("🛑 HTTP/3 server stopped")
end

function handle_client_packet_http3!(server::HTTP3Server, packet_data::Vector{UInt8}, client_addr)
    # Use existing QUIC packet handling
    try
        dest_cid = extract_destination_cid(packet_data)

        if dest_cid !== nothing && haskey(server.quic_server.active_connections, dest_cid)
            conn = server.quic_server.active_connections[dest_cid]
            conn.remote_addr = client_addr

            result = Quic.PacketReceiver.process_incoming_packet(conn, packet_data, client_addr)

            if result !== nothing
                handle_http3_connection_events!(server, conn, result)
            end
        else
            # New connection
            handle_new_http3_connection!(server, packet_data, client_addr)
        end

    catch e
        println("⚠️ Error handling HTTP/3 packet from $client_addr: $e")
    end
end

function extract_destination_cid(packet_data::Vector{UInt8})
    # Simple CID extraction (reuse from quic_server.jl)
    if length(packet_data) >= 14 && (packet_data[1] & 0x80) != 0
        return Quic.Packet.ConnectionId(packet_data[7:14])
    elseif length(packet_data) >= 9 && (packet_data[1] & 0x80) == 0
        return Quic.Packet.ConnectionId(packet_data[2:9])
    end
    return nothing
end

function handle_new_http3_connection!(server::HTTP3Server, packet_data::Vector{UInt8}, client_addr)
    println("🌐 New HTTP/3 connection attempt from $client_addr")

    # Create new QUIC connection
    conn = Quic.ConnectionModule.Connection(server.quic_server.endpoint.socket, false)
    conn.remote_addr = client_addr
    conn.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()

    # Store connection
    server.quic_server.active_connections[conn.local_cid] = conn

    # Process initial packet
    result = Quic.PacketReceiver.process_incoming_packet(conn, packet_data, client_addr)

    if result !== nothing
        println("✅ Initial HTTP/3 packet processed: $result")
        handle_http3_connection_events!(server, conn, result)
    end
end

function process_active_connections_http3!(server::HTTP3Server)
    for (cid, conn) in server.quic_server.active_connections
        try
            Quic.ConnectionModule.process_timers(conn)
            Quic.ConnectionModule.maintain_connection_ids!(conn)

            # Handle HTTP/3 specific processing
            handle_http3_connection_events!(server, conn, nothing)

            if conn.closing
                println("👋 HTTP/3 connection $(bytes2hex(cid.data)[1:8])... closing")
                delete!(server.quic_server.active_connections, cid)
            end

        catch e
            println("⚠️ Error processing HTTP/3 connection: $e")
            delete!(server.quic_server.active_connections, cid)
        end
    end
end

function print_http3_server_stats(server::HTTP3Server)
    println("\n📊 HTTP/3 Server Statistics:")
    println("   Active connections: $(length(server.quic_server.active_connections))")
    println("   Requests processed: $(server.stats.requests_processed)")
    println("   Responses sent: $(server.stats.responses_sent)")
    println("   Bytes received: $(server.stats.bytes_received)")
    println("   Bytes sent: $(server.stats.bytes_sent)")

    # Print HTTP/3 connection details
    for (cid, conn) in server.quic_server.active_connections
        if conn.http3 !== nothing
            println("   HTTP/3 connection $(bytes2hex(cid.data)[1:8])...:")
            println("     Control stream: $(conn.http3.control_stream_id)")
            println("     Peer control: $(conn.http3.peer_control_stream_id)")
            println("     Active requests: $(length(conn.http3.request_streams))")
            println("     Settings exchanged: $(length(conn.http3.peer_settings) > 0)")
        end
    end
end

function stop_http3_server!(server::HTTP3Server)
    server.quic_server.running = false
    close(server.quic_server.endpoint.socket)
end

function main()
    server = HTTP3Server(4433)

    try
        start_http3_server!(server)
    catch InterruptException
        println("\n🛑 Received interrupt signal")
    finally
        stop_http3_server!(server)
        print_http3_server_stats(server)
    end

    return true
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end