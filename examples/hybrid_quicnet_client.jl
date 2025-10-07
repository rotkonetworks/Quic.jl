#!/usr/bin/env julia

# Hybrid approach: Use existing libraries for QUIC/TLS, focus on QuicNet protocol
push!(LOAD_PATH, joinpath(@__DIR__, ".."))

using Quic
using Sockets
using LibCURL

const DEFAULT_PORT = 4433
const DEFAULT_HOST = "127.0.0.1"

# Unfortunately, LibCURL doesn't support QUIC yet in most builds
# So let's try a different approach - use command line tools

function test_with_curl_http3()
    println("🌐 Testing QUIC connection with curl (if HTTP/3 enabled)")

    # Check if curl has HTTP/3 support
    curl_version = read(`curl --version`, String)
    if contains(curl_version, "HTTP3") || contains(curl_version, "nghttp3")
        println("✅ curl has HTTP/3 support")

        # Try to connect
        try
            result = read(`curl --http3 https://127.0.0.1:4433/ -k`, String)
            println("Response: ", result)
        catch e
            println("❌ Connection failed: ", e)
        end
    else
        println("❌ curl doesn't have HTTP/3 support")
        println("   Install with: brew install curl --with-nghttp3")
    end
end

# Use openssl s_client for QUIC (if available in OpenSSL 3.2+)
function test_with_openssl_quic()
    println("\n🔐 Testing with OpenSSL QUIC (if available)")

    # Check OpenSSL version
    openssl_version = read(`openssl version`, String)
    println("   OpenSSL version: ", strip(openssl_version))

    if contains(openssl_version, "3.2") || contains(openssl_version, "3.3")
        println("   OpenSSL 3.2+ detected, may have QUIC support")

        # Generate client certificate
        println("\n   Generating Ed25519 client certificate...")
        run(`openssl genpkey -algorithm ED25519 -out /tmp/client.key`)
        run(`openssl req -new -x509 -key /tmp/client.key -days 365 -subj "/CN=QuicNet-Julia" -out /tmp/client.crt`)

        println("   ✅ Certificate generated")

        # Try QUIC connection with client cert
        # Note: OpenSSL QUIC support is experimental
        try
            cmd = ```openssl s_client -quic -connect 127.0.0.1:4433
                    -cert /tmp/client.crt -key /tmp/client.key
                    -alpn h3 -servername quicnet```

            # Run with timeout
            proc = run(cmd, wait=false)
            sleep(2)
            kill(proc)

            println("   Connection attempted")
        catch e
            println("   Note: OpenSSL QUIC is experimental")
        end
    else
        println("   ❌ OpenSSL 3.2+ required for QUIC support")
    end
end

# The real solution: Create a minimal QUIC client using picoquic C library
function create_picoquic_binding()
    println("\n📦 Ideal solution: Use picoquic C library")
    println("   This would require:")
    println("   1. Building picoquic as a shared library")
    println("   2. Creating Julia FFI bindings")
    println("   3. Handling Ed25519 certificates in picoquic")

    # Check if picoquic is available
    if isdir("/tmp/picoquic")
        println("   ✅ picoquic source available at /tmp/picoquic")
        println("   Next steps:")
        println("   - cd /tmp/picoquic && cmake . && make")
        println("   - Create Julia ccall bindings to picoquic functions")
    else
        println("   ℹ️  Clone picoquic first")
    end
end

# Our hybrid approach summary
function show_hybrid_strategy()
    println("\n🎯 Hybrid Strategy for QuicNet Compatibility")
    println("="^50)

    println("\n📊 Rust QuicNet uses:")
    println("   • quinn (QUIC protocol)")
    println("   • rustls (TLS 1.3 with client certs)")
    println("   • rcgen (X.509 certificate generation)")
    println("   • ed25519-dalek (Ed25519 crypto)")

    println("\n🔧 Our Julia options:")
    println("\n1. Use C library (recommended):")
    println("   • picoquic or ngtcp2 for QUIC")
    println("   • OpenSSL for TLS 1.3")
    println("   • Our Sodium.jl for Ed25519")

    println("\n2. Use existing Julia packages:")
    println("   • HTTP.jl with LibCURL backend")
    println("   • MbedTLS.jl (limited TLS 1.3)")
    println("   • Our Sodium.jl for Ed25519")

    println("\n3. Minimal implementation (current):")
    println("   • Our QUIC packet handling")
    println("   • OpenSSL for cert generation")
    println("   • Need to add Certificate message to handshake")

    println("\n✨ Best path forward:")
    println("   Create Julia bindings to picoquic (like Rust uses quinn)")
    println("   This gives us full QUIC + TLS 1.3 + client certs")
end

function main()
    println("🚀 Hybrid QuicNet Client Test")
    println("="^50)

    # Show our strategy
    show_hybrid_strategy()

    # Test available options
    test_with_curl_http3()
    test_with_openssl_quic()
    create_picoquic_binding()

    println("\n📌 Conclusion:")
    println("   The Rust approach is smart - they don't reinvent the wheel")
    println("   We should use picoquic (C) or similar for QUIC/TLS")
    println("   Then focus on the QuicNet protocol layer on top")
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end