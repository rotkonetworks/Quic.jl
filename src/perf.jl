module Perf

#=
Performance Optimizations for QUIC

Key strategies:
1. Buffer pooling - reuse allocations
2. Zero-copy views - parse in-place
3. Preallocated state - avoid runtime allocs
4. Type-stable hot paths - enable LLVM optimization
=#

export BufferPool, acquire!, release!, @view_bytes
export PreallocatedState, PacketBuffer
export WriteBuffer, reset!, write_u8!, write_u16!, write_u32!, write_u64!
export write_varint!, write_bytes!, written, WRITE_BUFFER_TLS

const DEFAULT_BUFFER_SIZE = 2048
const DEFAULT_POOL_SIZE = 64

#=
================================================================================
LOCK-FREE BUFFER POOLING
================================================================================
Use atomic operations instead of locks for minimal overhead.
=#

mutable struct BufferPool
    buffers::Vector{Vector{UInt8}}
    buffer_size::Int
    # Use atomic integer as bitmap for lock-free acquire/release
    available::Threads.Atomic{UInt64}
    pool_size::Int

    function BufferPool(pool_size::Int = DEFAULT_POOL_SIZE,
                       buffer_size::Int = DEFAULT_BUFFER_SIZE)
        @assert pool_size <= 64 "Pool size limited to 64 for atomic bitmap"
        buffers = [Vector{UInt8}(undef, buffer_size) for _ in 1:pool_size]
        # All bits set = all available
        available = Threads.Atomic{UInt64}((UInt64(1) << pool_size) - 1)
        new(buffers, buffer_size, available, pool_size)
    end
end

"""
Acquire a buffer from the pool (lock-free). Returns (buffer, index).
"""
@inline function acquire!(pool::BufferPool)::Tuple{Vector{UInt8}, Int}
    while true
        current = pool.available[]
        if current == 0
            # Pool exhausted - allocate new
            return (Vector{UInt8}(undef, pool.buffer_size), 0)
        end
        # Find first set bit
        idx = trailing_zeros(current) + 1
        # Clear that bit
        new_val = current & ~(UInt64(1) << (idx - 1))
        # Atomic compare-and-swap
        if Threads.atomic_cas!(pool.available, current, new_val) === current
            return (pool.buffers[idx], idx)
        end
        # CAS failed, retry
    end
end

"""
Release a buffer back to the pool (lock-free).
"""
@inline function release!(pool::BufferPool, idx::Int)
    if idx > 0 && idx <= pool.pool_size
        while true
            current = pool.available[]
            new_val = current | (UInt64(1) << (idx - 1))
            if Threads.atomic_cas!(pool.available, current, new_val) === current
                return
            end
        end
    end
end

# Global pools for common sizes
const PACKET_POOL = BufferPool(64, 1500)    # MTU-sized packets
const CRYPTO_POOL = BufferPool(64, 64)      # Keys, IVs, tags
const FRAME_POOL = BufferPool(64, 4096)     # Frame assembly

#=
================================================================================
ZERO-COPY PARSING
================================================================================
Use views and unsafe operations for hot-path parsing.
=#

"""
Packet buffer with zero-copy access.
Wraps a byte array with current position for streaming reads.
"""
mutable struct PacketBuffer
    data::Vector{UInt8}
    pos::Int
    len::Int
    pool_idx::Int  # For returning to pool

    PacketBuffer(data::Vector{UInt8}, pool_idx::Int = 0) = new(data, 1, length(data), pool_idx)
end

# Zero-copy read operations (no bounds checking in release mode)
@inline function read_u8!(buf::PacketBuffer)::UInt8
    @inbounds val = buf.data[buf.pos]
    buf.pos += 1
    val
end

@inline function read_u16!(buf::PacketBuffer)::UInt16
    ptr = pointer(buf.data, buf.pos)
    val = (UInt16(unsafe_load(ptr)) << 8) | UInt16(unsafe_load(ptr + 1))
    buf.pos += 2
    val
end

@inline function read_u32!(buf::PacketBuffer)::UInt32
    ptr = pointer(buf.data, buf.pos)
    val = (UInt32(unsafe_load(ptr)) << 24) |
          (UInt32(unsafe_load(ptr + 1)) << 16) |
          (UInt32(unsafe_load(ptr + 2)) << 8) |
          UInt32(unsafe_load(ptr + 3))
    buf.pos += 4
    val
end

@inline function read_u64!(buf::PacketBuffer)::UInt64
    ptr = pointer(buf.data, buf.pos)
    val = (UInt64(unsafe_load(ptr)) << 56) |
          (UInt64(unsafe_load(ptr + 1)) << 48) |
          (UInt64(unsafe_load(ptr + 2)) << 40) |
          (UInt64(unsafe_load(ptr + 3)) << 32) |
          (UInt64(unsafe_load(ptr + 4)) << 24) |
          (UInt64(unsafe_load(ptr + 5)) << 16) |
          (UInt64(unsafe_load(ptr + 6)) << 8) |
          UInt64(unsafe_load(ptr + 7))
    buf.pos += 8
    val
end

"""
Read QUIC variable-length integer (RFC 9000 Section 16).
Zero-copy, pointer-optimized.
"""
@inline function read_varint!(buf::PacketBuffer)::UInt64
    ptr = pointer(buf.data, buf.pos)
    first_byte = unsafe_load(ptr)
    len = 1 << (first_byte >> 6)

    val = UInt64(first_byte & 0x3f)

    # Unrolled for common cases
    if len >= 2
        val = (val << 8) | UInt64(unsafe_load(ptr + 1))
    end
    if len >= 4
        val = (val << 8) | UInt64(unsafe_load(ptr + 2))
        val = (val << 8) | UInt64(unsafe_load(ptr + 3))
    end
    if len == 8
        val = (val << 8) | UInt64(unsafe_load(ptr + 4))
        val = (val << 8) | UInt64(unsafe_load(ptr + 5))
        val = (val << 8) | UInt64(unsafe_load(ptr + 6))
        val = (val << 8) | UInt64(unsafe_load(ptr + 7))
    end

    buf.pos += len
    val
end

"""
Get a view into buffer without copying.
"""
@inline function view_bytes(buf::PacketBuffer, len::Int)::SubArray{UInt8, 1}
    start = buf.pos
    buf.pos += len
    @inbounds @view buf.data[start:start + len - 1]
end

"""
Skip bytes without reading.
"""
@inline function skip!(buf::PacketBuffer, len::Int)
    buf.pos += len
end

@inline remaining(buf::PacketBuffer) = buf.len - buf.pos + 1

#=
================================================================================
PREALLOCATED WRITE BUFFER
================================================================================
For building packets without intermediate allocations.
=#

mutable struct WriteBuffer
    data::Vector{UInt8}
    pos::Int
    pool_idx::Int

    function WriteBuffer(size::Int = DEFAULT_BUFFER_SIZE)
        buf, idx = acquire!(PACKET_POOL)
        new(buf, 1, idx)
    end

    # Constructor with pre-existing buffer (no pool)
    function WriteBuffer(data::Vector{UInt8})
        new(data, 1, 0)
    end
end

"""
Reset buffer for reuse without pool round-trip.
"""
@inline function reset!(buf::WriteBuffer)
    buf.pos = 1
end

# Thread-local preallocated write buffers for hot paths
const WRITE_BUFFER_TLS = Vector{UInt8}(undef, 2048)

@inline function write_u8!(buf::WriteBuffer, val::UInt8)
    @inbounds buf.data[buf.pos] = val
    buf.pos += 1
end

@inline function write_u16!(buf::WriteBuffer, val::UInt16)
    # Use pointer for single memory operation
    ptr = pointer(buf.data, buf.pos)
    unsafe_store!(ptr, UInt8((val >> 8) & 0xff))
    unsafe_store!(ptr + 1, UInt8(val & 0xff))
    buf.pos += 2
end

@inline function write_u32!(buf::WriteBuffer, val::UInt32)
    # Use pointer for single base calculation
    ptr = pointer(buf.data, buf.pos)
    unsafe_store!(ptr, UInt8((val >> 24) & 0xff))
    unsafe_store!(ptr + 1, UInt8((val >> 16) & 0xff))
    unsafe_store!(ptr + 2, UInt8((val >> 8) & 0xff))
    unsafe_store!(ptr + 3, UInt8(val & 0xff))
    buf.pos += 4
end

@inline function write_u64!(buf::WriteBuffer, val::UInt64)
    ptr = pointer(buf.data, buf.pos)
    unsafe_store!(ptr, UInt8((val >> 56) & 0xff))
    unsafe_store!(ptr + 1, UInt8((val >> 48) & 0xff))
    unsafe_store!(ptr + 2, UInt8((val >> 40) & 0xff))
    unsafe_store!(ptr + 3, UInt8((val >> 32) & 0xff))
    unsafe_store!(ptr + 4, UInt8((val >> 24) & 0xff))
    unsafe_store!(ptr + 5, UInt8((val >> 16) & 0xff))
    unsafe_store!(ptr + 6, UInt8((val >> 8) & 0xff))
    unsafe_store!(ptr + 7, UInt8(val & 0xff))
    buf.pos += 8
end

@inline function write_bytes!(buf::WriteBuffer, bytes::AbstractVector{UInt8})
    len = length(bytes)
    @inbounds copyto!(buf.data, buf.pos, bytes, 1, len)
    buf.pos += len
end

"""
Write QUIC variable-length integer.
"""
@inline function write_varint!(buf::WriteBuffer, val::UInt64)
    if val < 0x40
        write_u8!(buf, UInt8(val))
    elseif val < 0x4000
        write_u16!(buf, UInt16(val) | 0x4000)
    elseif val < 0x40000000
        write_u32!(buf, UInt32(val) | 0x80000000)
    else
        # 8-byte varint with 0xc0 prefix
        write_u64!(buf, val | 0xc000000000000000)
    end
end

"""
Get the written bytes as a view (zero-copy).
"""
@inline function written(buf::WriteBuffer)::SubArray{UInt8, 1}
    @view buf.data[1:buf.pos - 1]
end

"""
Release write buffer back to pool.
"""
function release!(buf::WriteBuffer)
    release!(PACKET_POOL, buf.pool_idx)
end

#=
================================================================================
OPTIMIZED CRYPTO WRAPPERS
================================================================================
Reduce FFI overhead by using preallocated output buffers.
=#

# Preallocated output buffers for crypto operations (thread-local would be better)
const CRYPTO_OUT = Vector{UInt8}(undef, 4096)
const CRYPTO_TAG = Vector{UInt8}(undef, 16)

"""
Encrypt in-place with preallocated tag buffer.
Returns view of ciphertext (no allocation).
"""
function encrypt_inplace!(plaintext::AbstractVector{UInt8},
                         key::AbstractVector{UInt8},
                         nonce::AbstractVector{UInt8},
                         aad::AbstractVector{UInt8})::Tuple{SubArray, SubArray}
    # Will be implemented to use libsodium with preallocated buffers
    pt_len = length(plaintext)

    # Copy to output buffer
    @inbounds copyto!(CRYPTO_OUT, 1, plaintext, 1, pt_len)

    # Encrypt (placeholder - actual impl uses libsodium)
    ct = @view CRYPTO_OUT[1:pt_len]
    tag = @view CRYPTO_TAG[1:16]

    (ct, tag)
end

#=
================================================================================
CONNECTION STATE PREALLOCATION
================================================================================
Avoid Dict lookups in hot paths.
=#

"""
Preallocated connection state for hot-path access.
Uses fixed-size arrays instead of Dicts where possible.
"""
mutable struct FastConnectionState
    # Packet number spaces (Initial, Handshake, Application)
    next_pn::NTuple{3, UInt64}
    largest_acked::NTuple{3, UInt64}

    # Keys (preallocated)
    tx_key::Vector{UInt8}
    tx_iv::Vector{UInt8}
    tx_hp::Vector{UInt8}
    rx_key::Vector{UInt8}
    rx_iv::Vector{UInt8}
    rx_hp::Vector{UInt8}

    # Buffers
    send_buf::WriteBuffer
    recv_buf::PacketBuffer

    function FastConnectionState()
        new(
            (UInt64(0), UInt64(0), UInt64(0)),
            (UInt64(0), UInt64(0), UInt64(0)),
            zeros(UInt8, 32),
            zeros(UInt8, 12),
            zeros(UInt8, 16),
            zeros(UInt8, 32),
            zeros(UInt8, 12),
            zeros(UInt8, 16),
            WriteBuffer(),
            PacketBuffer(UInt8[])
        )
    end
end

#=
================================================================================
BENCHMARKING UTILITIES
================================================================================
=#

"""
Run a micro-benchmark with warmup.
"""
function benchmark(f::Function, name::String; warmup::Int = 100, iterations::Int = 10000)
    # Warmup
    for _ in 1:warmup
        f()
    end

    # Measure
    GC.gc()
    start = time_ns()
    for _ in 1:iterations
        f()
    end
    elapsed = time_ns() - start

    avg_ns = elapsed / iterations
    println("$name: $(round(avg_ns, digits=1)) ns/op ($(round(1e9/avg_ns, digits=0)) ops/sec)")

    avg_ns
end

end # module Perf
