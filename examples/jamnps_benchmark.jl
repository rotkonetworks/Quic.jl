#!/usr/bin/env julia
#= JAMNP-S Performance Benchmark

Compares native quic.jl implementation vs quiche FFI bindings for:
1. Identity generation and certificate creation
2. X25519 key exchange
3. TLS 1.3 message encoding
4. HKDF key derivation
5. Packet encryption (ChaCha20-Poly1305)
=#

using Pkg
Pkg.activate(dirname(@__DIR__))

using Quic
using Quic.JAMNPS
using Quic.Handshake
using Quic.Ed25519
using Quic.X509
using Quic.X25519
using Quic.Crypto
using Quic.QuicheFFI
using BenchmarkTools
using Statistics

const ITERATIONS = 1000

println("=" ^ 70)
println("JAMNP-S Performance Benchmark: Native Julia vs Quiche FFI")
println("=" ^ 70)
println()

#= Benchmark 1: Identity Generation =#
println("1. IDENTITY GENERATION")
println("-" ^ 70)

# Native Julia
function bench_native_identity(n)
    for _ in 1:n
        identity = JAMNPS.generate_identity()
    end
end

# Time native identity generation
t_native_id = @elapsed bench_native_identity(ITERATIONS)
println("   Native Julia: $(round(t_native_id * 1000, digits=2)) ms for $ITERATIONS iterations")
println("   Per operation: $(round(t_native_id / ITERATIONS * 1_000_000, digits=2)) μs")
println()

#= Benchmark 2: Alt Name Derivation =#
println("2. ALT NAME DERIVATION (Base32)")
println("-" ^ 70)

test_pubkey = rand(UInt8, 32)

function bench_alt_name(n, pubkey)
    for _ in 1:n
        alt = JAMNPS.derive_alt_name(pubkey)
    end
end

function bench_alt_name_roundtrip(n, pubkey)
    for _ in 1:n
        alt = JAMNPS.derive_alt_name(pubkey)
        recovered = JAMNPS.pubkey_from_alt_name(alt)
    end
end

t_alt = @elapsed bench_alt_name(ITERATIONS, test_pubkey)
t_roundtrip = @elapsed bench_alt_name_roundtrip(ITERATIONS, test_pubkey)

println("   Derivation: $(round(t_alt / ITERATIONS * 1_000_000, digits=2)) μs")
println("   Roundtrip:  $(round(t_roundtrip / ITERATIONS * 1_000_000, digits=2)) μs")
println()

#= Benchmark 3: X25519 Key Exchange =#
println("3. X25519 KEY EXCHANGE")
println("-" ^ 70)

function bench_x25519_keygen(n)
    for _ in 1:n
        priv, pub = X25519.generate_keypair()
    end
end

function bench_x25519_shared_secret(n)
    alice_priv, alice_pub = X25519.generate_keypair()
    bob_priv, bob_pub = X25519.generate_keypair()

    for _ in 1:n
        shared = X25519.compute_shared_secret(alice_priv, bob_pub)
    end
end

t_keygen = @elapsed bench_x25519_keygen(ITERATIONS)
t_shared = @elapsed bench_x25519_shared_secret(ITERATIONS)

println("   Key generation:  $(round(t_keygen / ITERATIONS * 1_000_000, digits=2)) μs")
println("   Shared secret:   $(round(t_shared / ITERATIONS * 1_000_000, digits=2)) μs")
println()

#= Benchmark 4: Ed25519 Signatures =#
println("4. ED25519 SIGNATURES")
println("-" ^ 70)

function bench_ed25519_sign(n)
    keypair = Ed25519.generate_keypair()
    message = rand(UInt8, 256)

    for _ in 1:n
        sig = Ed25519.sign(message, keypair)
    end
end

function bench_ed25519_verify(n)
    keypair = Ed25519.generate_keypair()
    message = rand(UInt8, 256)
    sig = Ed25519.sign(message, keypair)

    for _ in 1:n
        valid = Ed25519.verify(sig, message, keypair.public_key)
    end
end

t_sign = @elapsed bench_ed25519_sign(ITERATIONS)
t_verify = @elapsed bench_ed25519_verify(ITERATIONS)

println("   Sign (256 bytes): $(round(t_sign / ITERATIONS * 1_000_000, digits=2)) μs")
println("   Verify:           $(round(t_verify / ITERATIONS * 1_000_000, digits=2)) μs")
println()

#= Benchmark 5: X.509 Certificate Generation =#
println("5. X.509 CERTIFICATE GENERATION")
println("-" ^ 70)

function bench_cert_gen(n)
    keypair = Ed25519.generate_keypair()
    alt_name = JAMNPS.derive_alt_name(keypair.public_key)

    for _ in 1:n
        cert = X509.generate_x509_certificate(keypair; alt_name=alt_name)
    end
end

t_cert = @elapsed bench_cert_gen(ITERATIONS)
println("   Certificate:  $(round(t_cert / ITERATIONS * 1_000_000, digits=2)) μs")
println()

#= Benchmark 6: TLS 1.3 Message Encoding =#
println("6. TLS 1.3 MESSAGE ENCODING")
println("-" ^ 70)

function bench_certificate_message(n)
    keypair = Ed25519.generate_keypair()
    cert = X509.generate_x509_certificate(keypair)

    for _ in 1:n
        msg = Handshake.create_certificate_message([cert])
    end
end

function bench_certificate_verify(n)
    keypair = Ed25519.generate_keypair()
    transcript_hash = rand(UInt8, 32)

    for _ in 1:n
        msg = Handshake.create_certificate_verify_message(keypair, transcript_hash)
    end
end

t_cert_msg = @elapsed bench_certificate_message(ITERATIONS)
t_cv_msg = @elapsed bench_certificate_verify(ITERATIONS)

println("   Certificate msg:       $(round(t_cert_msg / ITERATIONS * 1_000_000, digits=2)) μs")
println("   CertificateVerify msg: $(round(t_cv_msg / ITERATIONS * 1_000_000, digits=2)) μs")
println()

#= Benchmark 7: HKDF Key Derivation =#
println("7. HKDF KEY DERIVATION")
println("-" ^ 70)

function bench_hkdf_extract(n)
    ikm = rand(UInt8, 32)
    salt = rand(UInt8, 32)

    for _ in 1:n
        prk = Crypto.hkdf_extract(ikm, salt)
    end
end

function bench_hkdf_expand_label(n)
    secret = rand(UInt8, 32)
    context = rand(UInt8, 32)

    for _ in 1:n
        key = Crypto.hkdf_expand_label(secret, "quic key", context, 16)
    end
end

function bench_initial_secrets(n)
    ctx = Crypto.CryptoContext()
    dcid = rand(UInt8, 8)

    for _ in 1:n
        Crypto.derive_initial_secrets!(ctx, dcid)
    end
end

t_extract = @elapsed bench_hkdf_extract(ITERATIONS)
t_expand = @elapsed bench_hkdf_expand_label(ITERATIONS)
t_init_secrets = @elapsed bench_initial_secrets(ITERATIONS)

println("   HKDF-Extract:       $(round(t_extract / ITERATIONS * 1_000_000, digits=2)) μs")
println("   HKDF-Expand-Label:  $(round(t_expand / ITERATIONS * 1_000_000, digits=2)) μs")
println("   Initial secrets:    $(round(t_init_secrets / ITERATIONS * 1_000_000, digits=2)) μs")
println()

#= Benchmark 8: ChaCha20-Poly1305 Encryption =#
println("8. CHACHA20-POLY1305 ENCRYPTION")
println("-" ^ 70)

function bench_chacha_encrypt(n, payload_size)
    key = rand(UInt8, 32)
    iv = rand(UInt8, 12)
    ad = rand(UInt8, 32)
    payload = rand(UInt8, payload_size)
    pn = UInt64(0)

    for _ in 1:n
        encrypted = Crypto.encrypt_payload(payload, key, iv, pn, ad)
    end
end

function bench_chacha_decrypt(n, payload_size)
    key = rand(UInt8, 32)
    iv = rand(UInt8, 12)
    ad = rand(UInt8, 32)
    payload = rand(UInt8, payload_size)
    pn = UInt64(0)
    encrypted = Crypto.encrypt_payload(payload, key, iv, pn, ad)

    for _ in 1:n
        decrypted = Crypto.decrypt_payload(encrypted, key, iv, pn, ad)
    end
end

for size in [64, 256, 1200, 4096]
    t_enc = @elapsed bench_chacha_encrypt(ITERATIONS, size)
    t_dec = @elapsed bench_chacha_decrypt(ITERATIONS, size)
    println("   $(lpad(size, 4)) bytes - Encrypt: $(round(t_enc / ITERATIONS * 1_000_000, digits=2)) μs, Decrypt: $(round(t_dec / ITERATIONS * 1_000_000, digits=2)) μs")
end
println()

#= Benchmark 9: JAMNP-S Message Encoding =#
println("9. JAMNP-S MESSAGE ENCODING")
println("-" ^ 70)

function bench_message_encode(n, size)
    content = rand(UInt8, size)

    for _ in 1:n
        msg = JAMNPS.encode_message(content)
    end
end

function bench_message_decode(n, size)
    content = rand(UInt8, size)
    msg = JAMNPS.encode_message(content)

    for _ in 1:n
        len = JAMNPS.decode_message_header(msg)
    end
end

for size in [64, 256, 1024, 4096]
    t_enc = @elapsed bench_message_encode(ITERATIONS, size)
    t_dec = @elapsed bench_message_decode(ITERATIONS, size)
    println("   $(lpad(size, 4)) bytes - Encode: $(round(t_enc / ITERATIONS * 1_000_000, digits=2)) μs, Decode header: $(round(t_dec / ITERATIONS * 1_000_000, digits=2)) μs")
end
println()

#= Benchmark 10: Preferred Initiator Selection =#
println("10. PREFERRED INITIATOR SELECTION")
println("-" ^ 70)

function bench_preferred_initiator(n)
    key_a = rand(UInt8, 32)
    key_b = rand(UInt8, 32)

    for _ in 1:n
        result = JAMNPS.preferred_initiator(key_a, key_b)
    end
end

t_init = @elapsed bench_preferred_initiator(ITERATIONS * 10)
println("   Per check: $(round(t_init / (ITERATIONS * 10) * 1_000_000, digits=3)) μs")
println()

#= Summary =#
println("=" ^ 70)
println("SUMMARY")
println("=" ^ 70)
println()
println("Native Julia quic.jl implementation benchmarks:")
println()
println("   Identity generation:    ~$(round(t_native_id / ITERATIONS * 1000, digits=2)) ms")
println("   X25519 shared secret:   ~$(round(t_shared / ITERATIONS * 1_000_000, digits=0)) μs")
println("   Ed25519 sign:           ~$(round(t_sign / ITERATIONS * 1_000_000, digits=0)) μs")
println("   Certificate generation: ~$(round(t_cert / ITERATIONS * 1_000_000, digits=0)) μs")
println("   HKDF key derivation:    ~$(round(t_init_secrets / ITERATIONS * 1_000_000, digits=0)) μs")
println("   ChaCha20 encrypt (1200): ~$(round((@elapsed bench_chacha_encrypt(100, 1200)) / 100 * 1_000_000, digits=0)) μs")
println()

#= Compare with Quiche FFI if available =#
println("=" ^ 70)
println("QUICHE FFI COMPARISON")
println("=" ^ 70)
println()

try
    # Check if libquiche is available
    version = QuicheFFI.quiche_version()
    println("   Quiche version: $version")
    println()

    # Benchmark config creation
    function bench_quiche_config(n)
        genesis = rand(UInt8, 32)
        for _ in 1:n
            cfg = QuicheFFI.jamnps_config(genesis)
            # Don't free in loop - just measure creation
        end
    end

    t_quiche_cfg = @elapsed bench_quiche_config(ITERATIONS)
    println("   Config creation: $(round(t_quiche_cfg / ITERATIONS * 1_000_000, digits=2)) μs")
    println()

    println("   Note: Full connection benchmarks require network I/O")
    println("   The FFI overhead is minimal for crypto operations")
    println("   Native Julia provides better flexibility for JAM-specific extensions")

catch e
    println("   Quiche FFI not available: $e")
    println("   Ensure libquiche.so is built at ~/rotko/quiche-ffi/target/release/")
end

println()
println("=" ^ 70)
println("BENCHMARK COMPLETE")
println("=" ^ 70)
