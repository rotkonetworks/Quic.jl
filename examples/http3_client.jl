#!/usr/bin/env julia

# HTTP/3 Client Example
# Demonstrates HTTP/3 over QUIC with full request/response handling

push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic
using Sockets

mutable struct HTTP3Client
    endpoint::Quic.EndpointModule.Endpoint
    connection::Union{Quic.ConnectionModule.Connection, Nothing}
    requests::Dict{UInt64, @NamedTuple{
        method::String,
        path::String,
        headers::Dict{String, String},
        body::Vector{UInt8},
        response_status::Union{Int, Nothing},
        response_headers::Dict{String, String},
        response_body::Vector{UInt8},
        complete::Bool
    }}
    stats::@NamedTuple{
        requests_sent::Int,
        responses_received::Int,
        bytes_sent::Int,
        bytes_received::Int
    }

    function HTTP3Client()
        client_addr = Sockets.InetAddr(ip"0.0.0.0", 0)
        config = Quic.EndpointModule.EndpointConfig()
        config.server_name = "localhost"
        endpoint = Quic.EndpointModule.Endpoint(client_addr, config, false)

        new(endpoint, nothing, Dict(), (requests_sent=0, responses_received=0, bytes_sent=0, bytes_received=0))
    end
end

function connect_to_server!(client::HTTP3Client, server_host::String = "127.0.0.1", server_port::Int = 443)
    println(" Connecting to HTTP/3 server at $server_host:$server_port...")

    # Create QUIC connection
    server_addr = Sockets.InetAddr(ip"127.0.0.1", server_port)
    client.connection = Quic.EndpointModule.connect(client.endpoint, server_addr)

    # Setup crypto
    client.connection.crypto.cipher_suite = Quic.Crypto.ChaCha20Poly1305()
    Quic.Crypto.derive_initial_secrets!(client.connection.crypto, client.connection.remote_cid.data)

    println(" QUIC crypto initialized")

    # Complete QUIC handshake
    handshake_start = time_ns()
    println(" Starting QUIC handshake...")
    Quic.ConnectionModule.initiate_handshake(client.connection, server_host)

    # Wait for handshake completion
    data = Vector{UInt8}(undef, 65536)
    max_handshake_time = 10.0

    while !client.connection.connected && (time_ns() - handshake_start) / 1_000_000_000 < max_handshake_time
        try
            Quic.ConnectionModule.process_timers(client.connection)
            nbytes, from = recvfrom(client.connection.socket, data, timeout=1.0)

            if nbytes > 0
                result = Quic.PacketReceiver.process_incoming_packet(
                    client.connection, data[1:nbytes], from
                )

                if client.connection.connected
                    handshake_time = (time_ns() - handshake_start) / 1_000_000
                    println(" QUIC handshake completed in $(round(handshake_time, digits=2)) ms!")
                    break
                end
            end
        catch e
            if isa(e, Base.UVError) && e.code == Base.UV_ETIMEDOUT
                if Quic.LossDetection.should_send_probe_packets(client.connection.loss_detection)
                    Quic.ConnectionModule.handle_loss_detection_timeout(client.connection)
                end
            else
                println(" Handshake error: $e")
                return false
            end
        end
    end

    if !client.connection.connected
        println(" QUIC handshake failed")
        return false
    end

    # Enable HTTP/3
    println(" Enabling HTTP/3...")
    Quic.ConnectionModule.enable_http3!(client.connection)

    # Wait for HTTP/3 setup
    sleep(0.1)
    process_incoming_data!(client)

    return true
end

function process_incoming_data!(client::HTTP3Client)
    if client.connection === nothing
        return
    end

    data = Vector{UInt8}(undef, 65536)

    for i in 1:10  # Try multiple times to get all data
        try
            nbytes, from = recvfrom(client.connection.socket, data, timeout=0.2)

            if nbytes > 0
                Quic.PacketReceiver.process_incoming_packet(
                    client.connection, data[1:nbytes], from
                )

                # Update statistics
                client.stats = (
                    requests_sent = client.stats.requests_sent,
                    responses_received = client.stats.responses_received,
                    bytes_sent = client.stats.bytes_sent,
                    bytes_received = client.stats.bytes_received + nbytes
                )
            end
        catch e
            if !isa(e, Base.UVError) || e.code != Base.UV_ETIMEDOUT
                println(" Error receiving data: $e")
            end
            break
        end
    end
end

function send_http_request!(client::HTTP3Client, method::String, path::String,
                           headers::Dict{String, String} = Dict{String, String}(),
                           body::Union{Vector{UInt8}, String} = UInt8[])
    if client.connection === nothing || !client.connection.connected
        println(" No active QUIC connection")
        return nothing
    end

    # Ensure HTTP/3 is enabled
    if client.connection.http3 === nothing
        Quic.ConnectionModule.enable_http3!(client.connection)
    end

    # Add standard headers
    http_headers = copy(headers)
    if !haskey(http_headers, "user-agent")
        http_headers["user-agent"] = "Julia-QUIC-HTTP3/1.0"
    end
    if !haskey(http_headers, "accept")
        http_headers["accept"] = "*/*"
    end

    # Convert body to bytes
    body_data = body isa String ? Vector{UInt8}(body) : body

    # Send HTTP/3 request
    request_stream = Quic.ConnectionModule.send_http_request!(
        client.connection, method, path, http_headers, body_data
    )

    # Track request
    client.requests[request_stream.value] = (
        method = method,
        path = path,
        headers = http_headers,
        body = body_data,
        response_status = nothing,
        response_headers = Dict{String, String}(),
        response_body = UInt8[],
        complete = false
    )

    # Update statistics
    client.stats = (
        requests_sent = client.stats.requests_sent + 1,
        responses_received = client.stats.responses_received,
        bytes_sent = client.stats.bytes_sent + length(body_data),
        bytes_received = client.stats.bytes_received
    )

    println(" HTTP/3 request sent:")
    println("   $method $path")
    println("   Stream: $(request_stream.value)")

    return request_stream
end

function wait_for_response!(client::HTTP3Client, stream_id::UInt64; timeout_s::Float64 = 10.0)
    start_time = time_ns()

    while (time_ns() - start_time) / 1_000_000_000 < timeout_s
        process_incoming_data!(client)

        # Check if request is complete
        if haskey(client.requests, stream_id)
            request = client.requests[stream_id]
            if request.complete
                return request
            end
        end

        sleep(0.05)
    end

    println("⏰ Timeout waiting for response on stream $stream_id")
    return nothing
end

function make_http_request(client::HTTP3Client, method::String, path::String,
                          headers::Dict{String, String} = Dict{String, String}(),
                          body::Union{Vector{UInt8}, String} = UInt8[];
                          timeout_s::Float64 = 10.0)
    stream = send_http_request!(client, method, path, headers, body)
    if stream === nothing
        return nothing
    end

    return wait_for_response!(client, stream.value, timeout_s=timeout_s)
end

function demonstrate_http3_features!(client::HTTP3Client)
    println("\n Demonstrating HTTP/3 features...")

    # Test 1: Simple GET request
    println("\n📋 Test 1: Simple GET request")
    response1 = make_http_request(client, "GET", "/")
    if response1 !== nothing
        println(" GET / - Status: $(response1.response_status)")
        println("   Response body: $(length(response1.response_body)) bytes")
        if length(response1.response_body) < 500
            println("   Content: \"$(String(response1.response_body))\"")
        end
    end

    # Test 2: GET with headers
    println("\n📋 Test 2: GET with custom headers")
    custom_headers = Dict(
        "accept" => "application/json",
        "x-custom-header" => "Julia-QUIC-Test"
    )
    response2 = make_http_request(client, "GET", "/api/test", custom_headers)
    if response2 !== nothing
        println(" GET /api/test - Status: $(response2.response_status)")
    end

    # Test 3: POST with body
    println("\n📋 Test 3: POST with JSON body")
    post_headers = Dict(
        "content-type" => "application/json"
    )
    json_body = """{"message": "Hello from Julia HTTP/3 client!", "timestamp": "$(now())"}"""
    response3 = make_http_request(client, "POST", "/api/data", post_headers, json_body)
    if response3 !== nothing
        println(" POST /api/data - Status: $(response3.response_status)")
    end

    # Test 4: Multiple concurrent requests
    println("\n📋 Test 4: Multiple concurrent requests")
    concurrent_streams = []

    for i in 1:3
        stream = send_http_request!(client, "GET", "/api/stream$i")
        if stream !== nothing
            push!(concurrent_streams, stream.value)
        end
    end

    # Wait for all responses
    for stream_id in concurrent_streams
        response = wait_for_response!(client, stream_id, timeout_s=5.0)
        if response !== nothing
            println(" Concurrent request $stream_id - Status: $(response.response_status)")
        end
    end

    # Test 5: Large response
    println("\n📋 Test 5: Large response test")
    response5 = make_http_request(client, "GET", "/large", timeout_s=15.0)
    if response5 !== nothing
        println(" GET /large - Status: $(response5.response_status)")
        println("   Large response: $(length(response5.response_body)) bytes")
    end
end

function print_client_stats(client::HTTP3Client)
    println("\n HTTP/3 Client Statistics:")
    println("   Requests sent: $(client.stats.requests_sent)")
    println("   Responses received: $(client.stats.responses_received)")
    println("   Bytes sent: $(client.stats.bytes_sent)")
    println("   Bytes received: $(client.stats.bytes_received)")
    println("   Active requests: $(length(client.requests))")

    if client.connection !== nothing && client.connection.http3 !== nothing
        h3 = client.connection.http3
        println("\n HTTP/3 Connection State:")
        println("   Control stream: $(h3.control_stream_id)")
        println("   Peer control stream: $(h3.peer_control_stream_id)")
        println("   Local settings: $(length(h3.local_settings))")
        println("   Peer settings: $(length(h3.peer_settings))")

        # Print peer settings
        for (id, value) in h3.peer_settings
            setting_name = if id == Quic.HTTP3.HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY
                "QPACK_MAX_TABLE_CAPACITY"
            elseif id == Quic.HTTP3.HTTP3_SETTING_MAX_FIELD_SECTION_SIZE
                "MAX_FIELD_SECTION_SIZE"
            elseif id == Quic.HTTP3.HTTP3_SETTING_QPACK_BLOCKED_STREAMS
                "QPACK_BLOCKED_STREAMS"
            else
                "Unknown($id)"
            end
            println("   Peer $setting_name: $value")
        end
    end

    # Network statistics
    if client.connection !== nothing
        println("\n QUIC Network Statistics:")
        println("   RTT: $(client.connection.loss_detection.smoothed_rtt ÷ 1_000_000) ms")
        println("   CWND: $(client.connection.cwnd) bytes")

        pacing_stats = Quic.ConnectionModule.get_pacing_statistics(client.connection)
        println("   Pacing rate: $(Int(pacing_stats.pacing_rate)) bytes/sec")
    end
end

function disconnect!(client::HTTP3Client)
    if client.connection !== nothing && client.connection.http3 !== nothing
        # Send HTTP/3 GOAWAY
        goaway_frame = Quic.HTTP3.HTTP3GoAwayFrame(0)
        goaway_data = UInt8[]
        Quic.HTTP3.encode_http3_frame!(goaway_data, goaway_frame)

        if client.connection.http3.control_stream_id !== nothing
            control_sid = Quic.Stream.StreamId(client.connection.http3.control_stream_id, :client, :uni)
            Quic.ConnectionModule.send_stream(client.connection, control_sid, goaway_data, false)
        end

        # Send QUIC connection close
        close_frame = Quic.Frame.ConnectionCloseFrame(0, 0, "HTTP/3 client disconnect")
        Quic.ConnectionModule.queue_frame!(client.connection, close_frame, Quic.PacketCoalescing.Application)
        Quic.ConnectionModule.flush_packets!(client.connection)

        println(" Sent HTTP/3 GOAWAY and QUIC connection close")
    end

    close(client.endpoint.socket)
    println("🔌 Disconnected from server")
end

function main()
    client = HTTP3Client()

    try
        # Connect to server (change port as needed)
        server_port = 4433  # or 443 for HTTPS
        if !connect_to_server!(client, "127.0.0.1", server_port)
            println(" Failed to connect to HTTP/3 server")
            return false
        end

        # Demonstrate HTTP/3 features
        demonstrate_http3_features!(client)

        # Print final statistics
        print_client_stats(client)

        println("\n HTTP/3 over QUIC demonstration completed!")

    catch e
        println(" HTTP/3 client error: $e")
        return false
    finally
        disconnect!(client)
    end

    return true
end

if abspath(PROGRAM_FILE) == @__FILE__
    success = main()
    println("\n" * "="^70)
    println("HTTP/3 Client Test: $(success ? "PASSED" : "FAILED")")
    println("="^70)
    exit(success ? 0 : 1)
end