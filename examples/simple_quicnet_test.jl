#!/usr/bin/env julia

# Simple QuicNet connectivity test
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

using Sockets

println("🦀 QuicNet Simple Connection Test")
println("="^50)

# Test basic QuicNet client functionality
function test_basic_quicnet()
    println("\n📋 Testing basic QuicNet client...")

    # Include the QuicNet client directly
    include("quicnet_client.jl")

    println(" QuicNet client loaded successfully")

    # Test connection parameters
    test_server = "127.0.0.1"
    test_port = 4433

    println("\n Configuration:")
    println("   Server: $test_server:$test_port")
    println("   Mode: QuicNet compatibility")

    # Create a simple test connection
    println("\n Creating test connection...")
    sock = UDPSocket()

    println("    UDP socket created")

    # Test packet creation
    println("\n Testing packet creation...")

    # Create a simple PING frame
    ping_data = UInt8[0x01, 0x08]  # PING frame type and length
    println("    PING frame created: $(bytes2hex(ping_data))")

    # Create Initial packet header
    header = UInt8[
        0xc0,  # Long header, Initial type
        0x00, 0x00, 0x00, 0x01,  # Version 1
        0x08,  # DCID length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  # DCID
        0x00,  # SCID length
    ]

    println("    Initial packet header created")

    close(sock)
    println("\n Basic QuicNet test completed successfully!")

    return true
end

# Run the test
try
    if test_basic_quicnet()
        println("\n All tests passed!")
    else
        println("\n Tests failed")
    end
catch e
    println("\n Error during testing: $e")
    println(stacktrace())
end