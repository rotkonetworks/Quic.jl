#!/usr/bin/env julia

using Sockets
push!(LOAD_PATH, joinpath(@__DIR__, ".."))
using Quic

function run_client(server_host::String="localhost", server_port::Int=4433)
    println("Starting QUIC client...")
    println("Connecting to $server_host:$server_port")

    # create client endpoint
    client_addr = Sockets.InetAddr(ip"0.0.0.0", 0)  # random port
    config = Quic.EndpointModule.EndpointConfig()
    config.server_name = server_host
    config.alpn_protocols = ["h3", "echo"]

    endpoint = Quic.EndpointModule.Endpoint(client_addr, config, false)

    try
        # connect to server
        server_addr = Sockets.InetAddr(getaddrinfo(server_host), server_port)
        conn = Quic.EndpointModule.connect(endpoint, server_addr)
        println("Connected to server")

        # initiate handshake
        Quic.ConnectionModule.initiate_handshake(conn, server_host)
        println("Handshake initiated")

        # send some test data
        messages = [
            "Hello, QUIC server!",
            "This is a test message",
            "Julia QUIC implementation",
            "Final message"
        ]

        for (i, msg) in enumerate(messages)
            println("\nSending message $i: $msg")

            # open a stream and send data
            stream_id = Quic.ConnectionModule.open_stream(conn, true)
            data = Vector{UInt8}(msg)
            bytes_sent = Quic.ConnectionModule.send_stream(conn, stream_id, data, true)
            println("Sent $bytes_sent bytes on stream $(stream_id.value)")

            # wait a bit for response
            sleep(0.5)

            # try to receive response (simplified)
            try
                recv_data, addr = Sockets.recvfrom(conn.socket, 1000)
                if length(recv_data) > 0
                    println("Received response: $(length(recv_data)) bytes")
                    # in real implementation, would parse QUIC packets/frames
                end
            catch e
                if !isa(e, Sockets.TimeoutException)
                    println("Receive error: $e")
                end
            end
        end

        # close connection gracefully
        println("\nClosing connection...")
        conn.closing = true

        # send connection close frame
        close_frame = Quic.Frame.ConnectionCloseFrame(0, 0, "Client closing")
        Quic.ConnectionModule.send_frame(conn, close_frame)

    catch e
        println("Client error: $e")
        rethrow(e)
    finally
        close(endpoint.socket)
        println("Client shutdown complete")
    end
end

# interactive client mode
function interactive_client(server_host::String="localhost", server_port::Int=4433)
    println("Starting interactive QUIC client...")
    println("Connecting to $server_host:$server_port")
    println("Type 'quit' to exit\n")

    # setup client
    client_addr = Sockets.InetAddr(ip"0.0.0.0", 0)
    config = Quic.EndpointModule.EndpointConfig()
    config.server_name = server_host

    endpoint = Quic.EndpointModule.Endpoint(client_addr, config, false)

    try
        # connect to server
        server_addr = Sockets.InetAddr(getaddrinfo(server_host), server_port)
        conn = Quic.EndpointModule.connect(endpoint, server_addr)
        println("Connected! You can now send messages.\n")

        # initiate handshake
        Quic.ConnectionModule.initiate_handshake(conn, server_host)

        while true
            print("> ")
            input = readline()

            if input == "quit"
                break
            elseif isempty(input)
                continue
            end

            # send the message
            stream_id = Quic.ConnectionModule.open_stream(conn, true)
            data = Vector{UInt8}(input)
            bytes_sent = Quic.ConnectionModule.send_stream(conn, stream_id, data, true)
            println("Sent: $bytes_sent bytes")

            # try to receive echo response
            try
                recv_data, addr = Sockets.recvfrom(conn.socket, 500)
                if length(recv_data) > 0
                    println("Server response received: $(length(recv_data)) bytes")
                end
            catch e
                if !isa(e, Sockets.TimeoutException)
                    println("Receive error: $e")
                end
            end
        end

        println("\nClosing connection...")
        conn.closing = true

    catch e
        println("Error: $e")
    finally
        close(endpoint.socket)
        println("Goodbye!")
    end
end

# run the client
if abspath(PROGRAM_FILE) == @__FILE__
    if length(ARGS) > 0
        if ARGS[1] == "interactive"
            host = length(ARGS) > 1 ? ARGS[2] : "localhost"
            port = length(ARGS) > 2 ? parse(Int, ARGS[3]) : 4433
            interactive_client(host, port)
        else
            host = ARGS[1]
            port = length(ARGS) > 1 ? parse(Int, ARGS[2]) : 4433
            run_client(host, port)
        end
    else
        # default: run simple test client
        run_client()
    end
end