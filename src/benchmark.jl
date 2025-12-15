module Benchmark

#=
QUIC Performance Benchmarks

Compare native Julia implementation against theoretical quiche performance.
=#

using ..Perf
using ..Perf: PacketBuffer, WriteBuffer, benchmark, PACKET_POOL, acquire!, release!
using ..PacketFast
using ..Crypto

export run_benchmarks, compare_with_quiche

#=
================================================================================
PACKET PARSING BENCHMARKS
================================================================================
=#

# Sample Initial packet (typical client hello)
const SAMPLE_INITIAL = UInt8[
    0xc0,  # Long header, Initial
    0x00, 0x00, 0x00, 0x01,  # Version 1
    0x08,  # DCID length
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  # DCID
    0x08,  # SCID length
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,  # SCID
    0x00,  # Token length
    0x41, 0x00,  # Payload length (256 bytes as varint)
    0x00, 0x00, 0x00, 0x01,  # Packet number
    # Payload would follow...
]

# Sample short header packet
const SAMPLE_SHORT = UInt8[
    0x40,  # Short header
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  # DCID
    0x00, 0x00, 0x00, 0x01,  # Packet number
    # Payload would follow...
]

function bench_parse_long_header()
    buf = PacketBuffer(copy(SAMPLE_INITIAL))
    header = PacketFast.parse_header(buf)
    header
end

function bench_parse_short_header()
    buf = PacketBuffer(copy(SAMPLE_SHORT))
    header = PacketFast.parse_header(buf)
    header
end

#=
================================================================================
CRYPTO BENCHMARKS
================================================================================
=#

const BENCH_KEY = rand(UInt8, 32)
const BENCH_IV = rand(UInt8, 12)
const BENCH_AAD = rand(UInt8, 20)
const BENCH_PLAINTEXT = rand(UInt8, 1200)

# ChaCha20-Poly1305 (software optimized, good on ARM)
function bench_chacha20_encrypt()
    Crypto.encrypt_chacha20_poly1305(BENCH_PLAINTEXT, BENCH_KEY, BENCH_IV, UInt64(1), BENCH_AAD)
end

function bench_chacha20_decrypt()
    ct = Crypto.encrypt_chacha20_poly1305(BENCH_PLAINTEXT, BENCH_KEY, BENCH_IV, UInt64(1), BENCH_AAD)
    Crypto.decrypt_chacha20_poly1305(ct, BENCH_KEY, BENCH_IV, UInt64(1), BENCH_AAD)
end

# AES-128-GCM (hardware accelerated with AES-NI via mbedtls)
const BENCH_KEY_16 = rand(UInt8, 16)

function bench_aes_gcm_encrypt()
    Crypto.encrypt_aes_gcm(BENCH_PLAINTEXT, BENCH_KEY_16, BENCH_IV, UInt64(1), BENCH_AAD, Crypto.AES128GCM())
end

function bench_aes_gcm_decrypt()
    ct = Crypto.encrypt_aes_gcm(BENCH_PLAINTEXT, BENCH_KEY_16, BENCH_IV, UInt64(1), BENCH_AAD, Crypto.AES128GCM())
    Crypto.decrypt_aes_gcm(ct, BENCH_KEY_16, BENCH_IV, UInt64(1), BENCH_AAD, Crypto.AES128GCM())
end

#=
================================================================================
BUFFER POOL BENCHMARKS
================================================================================
=#

function bench_pool_acquire_release()
    buf, idx = acquire!(PACKET_POOL)
    buf[1] = 0x42  # Touch the buffer
    release!(PACKET_POOL, idx)
end

function bench_allocation()
    buf = Vector{UInt8}(undef, 1500)
    buf[1] = 0x42
    buf
end

#=
================================================================================
VARINT BENCHMARKS
================================================================================
=#

const VARINT_1BYTE = UInt8[0x25]
const VARINT_2BYTE = UInt8[0x40, 0x25]
const VARINT_4BYTE = UInt8[0x80, 0x00, 0x01, 0x00]
const VARINT_8BYTE = UInt8[0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]

function bench_varint_1byte()
    buf = PacketBuffer(copy(VARINT_1BYTE))
    Perf.read_varint!(buf)
end

function bench_varint_4byte()
    buf = PacketBuffer(copy(VARINT_4BYTE))
    Perf.read_varint!(buf)
end

#=
================================================================================
PACKET BUILDING BENCHMARKS
================================================================================
=#

const BUILD_DCID = UInt8[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
const BUILD_SCID = UInt8[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
const BUILD_DATA = rand(UInt8, 1000)

# Preallocated buffer for pool-free benchmark
const BUILD_BUFFER = Vector{UInt8}(undef, 2048)
const REUSABLE_WRITE_BUF = WriteBuffer(BUILD_BUFFER)

function bench_build_packet()
    buf = WriteBuffer()
    PacketFast.build_long_header!(buf, PacketFast.PACKET_TYPE_INITIAL, 0x00000001,
                                  BUILD_DCID, BUILD_SCID, UInt64(1), 4)
    PacketFast.build_crypto_frame!(buf, UInt64(0), BUILD_DATA)
    result = Perf.written(buf)
    Perf.release!(buf)
    length(result)
end

function bench_build_packet_nopool()
    # Reset reusable buffer instead of pool acquire/release
    Perf.reset!(REUSABLE_WRITE_BUF)
    PacketFast.build_long_header!(REUSABLE_WRITE_BUF, PacketFast.PACKET_TYPE_INITIAL, 0x00000001,
                                  BUILD_DCID, BUILD_SCID, UInt64(1), 4)
    PacketFast.build_crypto_frame!(REUSABLE_WRITE_BUF, UInt64(0), BUILD_DATA)
    REUSABLE_WRITE_BUF.pos - 1  # Return length written
end

#=
================================================================================
MAIN BENCHMARK RUNNER
================================================================================
=#

function run_benchmarks()
    println("=" ^ 60)
    println("QUIC.jl Performance Benchmarks")
    println("=" ^ 60)
    println()

    println("--- Packet Parsing ---")
    benchmark(bench_parse_long_header, "Long header parse")
    benchmark(bench_parse_short_header, "Short header parse")
    println()

    println("--- Varint Parsing ---")
    benchmark(bench_varint_1byte, "Varint 1-byte")
    benchmark(bench_varint_4byte, "Varint 4-byte")
    println()

    println("--- Buffer Pool ---")
    benchmark(bench_pool_acquire_release, "Pool acquire/release")
    benchmark(bench_allocation, "Fresh allocation")
    println()

    println("--- Packet Building ---")
    benchmark(bench_build_packet, "Build Initial packet (with pool)")
    benchmark(bench_build_packet_nopool, "Build Initial packet (no pool)")
    println()

    println("--- Crypto (libsodium ChaCha20) ---")
    benchmark(bench_chacha20_encrypt, "ChaCha20-Poly1305 encrypt 1200B")
    benchmark(bench_chacha20_decrypt, "ChaCha20-Poly1305 decrypt 1200B")
    println()

    println("--- Crypto (mbedtls AES-GCM with AES-NI) ---")
    benchmark(bench_aes_gcm_encrypt, "AES-128-GCM encrypt 1200B")
    benchmark(bench_aes_gcm_decrypt, "AES-128-GCM decrypt 1200B")
    println()

    println("=" ^ 60)
    println("Benchmark complete")
    println("=" ^ 60)
end

"""
Compare our performance with expected quiche numbers.
"""
function compare_with_quiche()
    println()
    println("=" ^ 60)
    println("Performance Comparison: QUIC.jl vs Quiche")
    println("=" ^ 60)
    println()

    # Run our benchmarks
    results = Dict{String, Float64}()

    results["parse_long"] = benchmark(bench_parse_long_header, "Parse long header"; iterations=100000)
    results["parse_short"] = benchmark(bench_parse_short_header, "Parse short header"; iterations=100000)
    results["crypto"] = benchmark(bench_chacha20_encrypt, "Crypto 1200B"; iterations=10000)
    results["build"] = benchmark(bench_build_packet_nopool, "Build packet (optimized)"; iterations=100000)

    println()
    println("--- Comparison with Quiche (estimated) ---")
    println()

    # Quiche reference numbers (approximate, from benchmarks)
    quiche_ref = Dict(
        "parse_long" => 50.0,    # ~50ns
        "parse_short" => 30.0,   # ~30ns
        "crypto" => 800.0,       # ~800ns for ChaCha20 1200B
        "build" => 100.0         # ~100ns
    )

    for (name, our_time) in results
        ref_time = quiche_ref[name]
        ratio = our_time / ref_time
        status = ratio < 2.0 ? "✓" : ratio < 5.0 ? "~" : "✗"
        println("  $name: $(round(our_time, digits=1))ns vs $(ref_time)ns ($(round(ratio, digits=1))x) $status")
    end

    println()
    println("Legend: ✓ < 2x, ~ < 5x, ✗ > 5x slower than quiche")
    println()

    # Overall assessment
    avg_ratio = sum(results[k] / quiche_ref[k] for k in keys(results)) / length(results)
    println("Average overhead: $(round(avg_ratio, digits=1))x")

    if avg_ratio < 2.0
        println("Status: Excellent - near quiche performance!")
    elseif avg_ratio < 3.0
        println("Status: Good - acceptable overhead")
    else
        println("Status: Needs optimization")
    end
end

end # module Benchmark
