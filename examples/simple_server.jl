#!/usr/bin/env julia

using Sockets
push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic

function run_server(port::Int=4433)
    println("Starting QUIC server on port $port...")

    # create server endpoint
    server_addr = Sockets.InetAddr(ip"0.0.0.0", port)
    config = Quic.EndpointModule.EndpointConfig()
    config.server_name = "localhost"
    config.alpn_protocols = ["h3", "echo"]

    endpoint = Quic.EndpointModule.Endpoint(server_addr, config, true)
    println("Server listening on $server_addr")

    try
        while true
            # accept incoming connection
            println("Waiting for connection...")
            conn = Quic.EndpointModule.accept(endpoint)
            println("Connection accepted from $(conn.remote_addr)")

            # handle connection in a task
            @async handle_connection(conn)
        end
    catch e
        if isa(e, InterruptException)
            println("\nShutting down server...")
        else
            println("Server error: $e")
            rethrow(e)
        end
    finally
        close(endpoint.socket)
    end
end

function handle_connection(conn::Quic.ConnectionModule.Connection)
    println("Handling connection $(conn.local_cid)")

    try
        # simple echo server - receive and echo back data
        buffer = UInt8[]
        timeout_count = 0

        while !conn.closing
            # try to receive data with timeout
            data, addr = try
                Sockets.recvfrom(conn.socket, 1000)  # 1 second timeout
            catch e
                if isa(e, Sockets.TimeoutException) || timeout_count > 30
                    timeout_count += 1
                    if timeout_count > 30
                        println("Connection idle timeout")
                        break
                    end
                    continue
                else
                    rethrow(e)
                end
            end

            timeout_count = 0  # reset on successful receive

            # parse received packet (simplified)
            if length(data) > 0
                println("Received $(length(data)) bytes")

                # echo the data back (simplified - should parse frames properly)
                # for now, just send a simple response
                response = b"Echo: " * data[1:min(100, length(data))]

                # create a stream and send response
                stream_id = Quic.ConnectionModule.open_stream(conn, true)
                Quic.ConnectionModule.send_stream(conn, stream_id, response, true)

                println("Sent echo response")
            end
        end
    catch e
        println("Connection error: $e")
    finally
        conn.closing = true
        println("Connection closed")
    end
end

# run the server
if abspath(PROGRAM_FILE) == @__FILE__
    port = length(ARGS) > 0 ? parse(Int, ARGS[1]) : 4433
    run_server(port)
end