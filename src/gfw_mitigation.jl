module GFWMitigation

#=
GFW (Great Firewall) QUIC Censorship Mitigation Module

Based on research from "Exposing and Circumventing SNI-based QUIC Censorship
of the Great Firewall of China" (USENIX Security 2025).

Key findings exploited for circumvention:
1. GFW only inspects the first packet in a UDP flow (60s timeout)
2. GFW requires source_port > dest_port to trigger inspection
3. GFW doesn't reassemble QUIC Initial packets split across frames
4. GFW doesn't inspect QUIC Version 2 packets
5. GFW has computational overhead that can be exploited

Mitigation strategies implemented:
- Dummy packet prefix: Send random UDP before QUIC Initial
- SNI fragmentation: Split ClientHello across multiple CRYPTO frames
- Port selection: Choose source_port <= dest_port
- Version negotiation: Start with unsupported version
=#

using Random

export GFWMitigationConfig, MitigationStrategy
export MITIGATION_NONE, MITIGATION_DUMMY_PREFIX, MITIGATION_SNI_FRAGMENTATION
export MITIGATION_PORT_SELECTION, MITIGATION_VERSION_NEGOTIATION, MITIGATION_ALL
export should_fragment_sni, get_fragment_sizes, generate_dummy_packet
export select_source_port, apply_mitigations

# Mitigation strategy flags (can be combined with |)
@enum MitigationStrategy::UInt8 begin
    MITIGATION_NONE = 0x00
    MITIGATION_DUMMY_PREFIX = 0x01
    MITIGATION_SNI_FRAGMENTATION = 0x02
    MITIGATION_PORT_SELECTION = 0x04
    MITIGATION_VERSION_NEGOTIATION = 0x08
end

# Combined strategy for maximum evasion
const MITIGATION_ALL = UInt8(MITIGATION_DUMMY_PREFIX) |
                       UInt8(MITIGATION_SNI_FRAGMENTATION) |
                       UInt8(MITIGATION_PORT_SELECTION)

"""
    GFWMitigationConfig

Configuration for GFW censorship circumvention strategies.

# Fields
- `enabled::Bool`: Master switch for all mitigations
- `strategies::UInt8`: Bitmask of enabled strategies
- `dummy_packet_size_range::Tuple{Int,Int}`: Min/max size for dummy packets
- `dummy_packet_delay_ms::Int`: Delay after dummy packet (ms)
- `fragment_count::Int`: Number of fragments for SNI splitting
- `fragment_size_variance::Float64`: Randomize fragment sizes (0.0-1.0)
- `preferred_dest_port::UInt16`: High port for port selection strategy
- `version_negotiation_first::Bool`: Send bad version first
- `randomize_padding::Bool`: Vary padding instead of fixed 1200 bytes
- `chaos_mode::Bool`: Chrome-style frame shuffling
"""
mutable struct GFWMitigationConfig
    enabled::Bool
    strategies::UInt8

    # Dummy packet configuration
    dummy_packet_size_range::Tuple{Int,Int}
    dummy_packet_delay_ms::Int

    # SNI fragmentation configuration
    fragment_count::Int
    fragment_size_variance::Float64

    # Port selection configuration
    preferred_dest_port::UInt16
    force_source_port::Union{UInt16, Nothing}

    # Version negotiation
    version_negotiation_first::Bool

    # Padding and chaos
    randomize_padding::Bool
    padding_range::Tuple{Int,Int}
    chaos_mode::Bool  # Shuffle frames like Chrome

    function GFWMitigationConfig(;
        enabled::Bool = false,
        strategies::UInt8 = MITIGATION_ALL,
        dummy_packet_size_range::Tuple{Int,Int} = (10, 50),
        dummy_packet_delay_ms::Int = 0,
        fragment_count::Int = 3,
        fragment_size_variance::Float64 = 0.3,
        preferred_dest_port::UInt16 = UInt16(65535),
        force_source_port::Union{UInt16, Nothing} = nothing,
        version_negotiation_first::Bool = false,
        randomize_padding::Bool = true,
        padding_range::Tuple{Int,Int} = (100, 500),
        chaos_mode::Bool = true
    )
        new(enabled, strategies, dummy_packet_size_range, dummy_packet_delay_ms,
            fragment_count, fragment_size_variance, preferred_dest_port,
            force_source_port, version_negotiation_first, randomize_padding,
            padding_range, chaos_mode)
    end
end

# Default configs for different scenarios
"""
    default_config() -> GFWMitigationConfig

Returns default (disabled) configuration.
"""
default_config() = GFWMitigationConfig(enabled=false)

"""
    china_config() -> GFWMitigationConfig

Returns configuration optimized for China network conditions.
Enables all mitigations with conservative settings.
"""
function china_config()
    GFWMitigationConfig(
        enabled = true,
        strategies = MITIGATION_ALL,
        dummy_packet_size_range = (10, 64),
        dummy_packet_delay_ms = 1,
        fragment_count = 3,
        fragment_size_variance = 0.2,
        randomize_padding = true,
        chaos_mode = true
    )
end

"""
    aggressive_config() -> GFWMitigationConfig

Returns aggressive configuration for maximum evasion.
May have performance impact.
"""
function aggressive_config()
    GFWMitigationConfig(
        enabled = true,
        strategies = MITIGATION_ALL | UInt8(MITIGATION_VERSION_NEGOTIATION),
        dummy_packet_size_range = (16, 128),
        dummy_packet_delay_ms = 5,
        fragment_count = 5,
        fragment_size_variance = 0.4,
        version_negotiation_first = true,
        randomize_padding = true,
        padding_range = (137, 400),  # GFW allows packets as small as 137 bytes
        chaos_mode = true
    )
end

# Strategy checking helpers
has_strategy(config::GFWMitigationConfig, strategy::MitigationStrategy) =
    config.enabled && (config.strategies & UInt8(strategy)) != 0

should_send_dummy(config::GFWMitigationConfig) =
    has_strategy(config, MITIGATION_DUMMY_PREFIX)

should_fragment_sni(config::GFWMitigationConfig) =
    has_strategy(config, MITIGATION_SNI_FRAGMENTATION)

should_select_port(config::GFWMitigationConfig) =
    has_strategy(config, MITIGATION_PORT_SELECTION)

should_version_negotiate(config::GFWMitigationConfig) =
    has_strategy(config, MITIGATION_VERSION_NEGOTIATION)

#=
================================================================================
DUMMY PACKET PREFIX
================================================================================
The GFW only inspects the first packet in a UDP flow. By sending a random UDP
packet before the QUIC Initial, we make the GFW think this is not a QUIC flow.
The QUIC server will simply ignore the random data.
=#

"""
    generate_dummy_packet(config::GFWMitigationConfig) -> Vector{UInt8}

Generate a random UDP payload to send before QUIC Initial.
The packet is designed to NOT look like valid QUIC:
- Does not start with QUIC long header byte patterns
- Random length within configured range
- Random content
"""
function generate_dummy_packet(config::GFWMitigationConfig)
    min_size, max_size = config.dummy_packet_size_range
    size = rand(min_size:max_size)

    packet = rand(UInt8, size)

    # Ensure first byte doesn't look like QUIC long header (0xc0-0xff)
    # or short header with fixed bit (0x40-0x7f)
    # Use range 0x00-0x3f which is clearly not QUIC
    packet[1] = rand(UInt8(0x00):UInt8(0x3f))

    return packet
end

#=
================================================================================
SNI FRAGMENTATION
================================================================================
The GFW doesn't reassemble QUIC Initial packets when the TLS ClientHello is
split across multiple CRYPTO frames. By fragmenting the ClientHello so the
SNI extension spans multiple frames, we prevent the GFW from extracting it.

Chrome's "Chaos Protection" implements similar functionality.
=#

"""
    get_fragment_sizes(total_size::Int, config::GFWMitigationConfig) -> Vector{Int}

Calculate fragment sizes for splitting ClientHello data.
Fragments are randomized based on configuration to avoid fingerprinting.
"""
function get_fragment_sizes(total_size::Int, config::GFWMitigationConfig)
    n = config.fragment_count

    if total_size <= n
        # Too small to fragment meaningfully
        return [total_size]
    end

    # Calculate base size per fragment
    base_size = total_size ÷ n
    remainder = total_size % n

    sizes = fill(base_size, n)

    # Distribute remainder
    for i in 1:remainder
        sizes[i] += 1
    end

    # Apply variance if configured
    if config.fragment_size_variance > 0
        variance = config.fragment_size_variance
        for i in 1:(n-1)
            # Random adjustment within variance range
            max_adjust = ceil(Int, sizes[i] * variance)
            adjust = rand(-max_adjust:max_adjust)

            # Ensure positive sizes and total remains correct
            if sizes[i] + adjust > 0 && sizes[i+1] - adjust > 0
                sizes[i] += adjust
                sizes[i+1] -= adjust
            end
        end
    end

    # Shuffle if chaos mode enabled (Chrome-style)
    if config.chaos_mode
        # Note: We can't truly shuffle order without protocol changes,
        # but we can randomize which chunks are larger
        shuffle!(sizes)
    end

    return sizes
end

"""
    fragment_client_hello(data::Vector{UInt8}, config::GFWMitigationConfig)
        -> Vector{Tuple{UInt64, Vector{UInt8}}}

Fragment ClientHello data into multiple CRYPTO frame payloads.
Returns vector of (offset, data) tuples for constructing CryptoFrames.

The fragmentation strategy attempts to split the SNI extension across
frame boundaries, preventing GFW from extracting it from any single frame.
"""
function fragment_client_hello(data::Vector{UInt8}, config::GFWMitigationConfig)
    if !config.enabled || !should_fragment_sni(config)
        return [(UInt64(0), data)]
    end

    sizes = get_fragment_sizes(length(data), config)
    fragments = Tuple{UInt64, Vector{UInt8}}[]

    offset = UInt64(0)
    pos = 1

    for size in sizes
        if pos > length(data)
            break
        end

        end_pos = min(pos + size - 1, length(data))
        fragment_data = data[pos:end_pos]

        push!(fragments, (offset, fragment_data))

        offset += length(fragment_data)
        pos = end_pos + 1
    end

    return fragments
end

"""
    find_sni_position(client_hello::Vector{UInt8}) -> Union{Tuple{Int,Int}, Nothing}

Locate the SNI extension within a TLS ClientHello message.
Returns (start_position, length) or nothing if not found.

This helps with intelligent fragmentation to ensure SNI is split.
"""
function find_sni_position(client_hello::Vector{UInt8})
    # TLS ClientHello structure:
    # - Handshake type (1 byte): 0x01
    # - Length (3 bytes)
    # - Version (2 bytes)
    # - Random (32 bytes)
    # - Session ID length (1 byte) + data
    # - Cipher suites length (2 bytes) + data
    # - Compression methods length (1 byte) + data
    # - Extensions length (2 bytes)
    # - Extensions...

    if length(client_hello) < 44 || client_hello[1] != 0x01
        return nothing
    end

    pos = 1

    # Skip handshake type (1) + length (3) + version (2) + random (32)
    pos += 38

    if pos > length(client_hello)
        return nothing
    end

    # Skip session ID
    session_id_len = client_hello[pos]
    pos += 1 + session_id_len

    if pos + 1 > length(client_hello)
        return nothing
    end

    # Skip cipher suites
    cipher_suites_len = (UInt16(client_hello[pos]) << 8) | UInt16(client_hello[pos+1])
    pos += 2 + cipher_suites_len

    if pos > length(client_hello)
        return nothing
    end

    # Skip compression methods
    compression_len = client_hello[pos]
    pos += 1 + compression_len

    if pos + 1 > length(client_hello)
        return nothing
    end

    # Extensions length
    extensions_len = (UInt16(client_hello[pos]) << 8) | UInt16(client_hello[pos+1])
    pos += 2

    extensions_end = pos + extensions_len - 1

    # Search for SNI extension (type 0x0000)
    while pos + 3 < min(extensions_end, length(client_hello))
        ext_type = (UInt16(client_hello[pos]) << 8) | UInt16(client_hello[pos+1])
        ext_len = (UInt16(client_hello[pos+2]) << 8) | UInt16(client_hello[pos+3])

        if ext_type == 0x0000
            # Found SNI extension
            return (pos, 4 + ext_len)  # Include type and length fields
        end

        pos += 4 + ext_len
    end

    return nothing
end

"""
    fragment_around_sni(data::Vector{UInt8}, config::GFWMitigationConfig)
        -> Vector{Tuple{UInt64, Vector{UInt8}}}

Intelligently fragment ClientHello to split SNI across frame boundaries.
This is more effective than random fragmentation.
"""
function fragment_around_sni(data::Vector{UInt8}, config::GFWMitigationConfig)
    sni_pos = find_sni_position(data)

    if sni_pos === nothing
        # No SNI found, use regular fragmentation
        return fragment_client_hello(data, config)
    end

    sni_start, sni_len = sni_pos
    sni_mid = sni_start + sni_len ÷ 2

    # Create fragments that split the SNI in the middle
    fragments = Tuple{UInt64, Vector{UInt8}}[]

    # Fragment 1: Everything before SNI midpoint
    if sni_mid > 1
        push!(fragments, (UInt64(0), data[1:sni_mid-1]))
    end

    # Fragment 2: Second half of SNI and some after
    remaining_start = sni_mid
    remaining_end = min(sni_start + sni_len + 50, length(data))
    if remaining_start <= length(data)
        push!(fragments, (UInt64(sni_mid - 1), data[remaining_start:remaining_end]))
    end

    # Fragment 3: Rest of data (if any)
    if remaining_end < length(data)
        push!(fragments, (UInt64(remaining_end), data[remaining_end+1:end]))
    end

    return fragments
end

#=
================================================================================
PORT SELECTION
================================================================================
The GFW only inspects packets where source_port > dest_port. By ensuring
source_port <= dest_port, we can bypass inspection entirely.

Options:
1. Connect to high ports (e.g., 65535) - server needs to listen there
2. Force a specific low source port - may require privileges
=#

"""
    select_source_port(config::GFWMitigationConfig, dest_port::UInt16) -> Union{UInt16, Nothing}

Select an appropriate source port for GFW evasion.
Returns a port number or nothing to use system default.

Strategy: Ensure source_port <= dest_port

Note: For standard QUIC port 443, this means using source ports 1-443.
      Ports below 1024 typically require root/admin privileges.
      For best results, use high destination ports (e.g., 65535).
"""
function select_source_port(config::GFWMitigationConfig, dest_port::UInt16)
    if !config.enabled || !should_select_port(config)
        return nothing
    end

    if config.force_source_port !== nothing
        return config.force_source_port
    end

    # Choose a source port <= destination port
    # For low dest ports (< 1024), we have limited choices:
    # - Use the dest_port itself (source == dest evades GFW)
    # - Use a lower privileged port if available

    if dest_port <= UInt16(1024)
        # Low destination port - best option is source = dest
        # This equals the condition source_port <= dest_port
        return dest_port
    end

    # For high dest ports, we have more flexibility
    # Prefer non-privileged ports (1024+) but <= dest_port
    min_port = UInt16(1024)
    max_port = dest_port

    return rand(min_port:max_port)
end

"""
    get_recommended_dest_port(config::GFWMitigationConfig) -> UInt16

Get the recommended destination port for maximum evasion.
Using high ports allows low source ports, bypassing GFW inspection.
"""
function get_recommended_dest_port(config::GFWMitigationConfig)
    if config.enabled && should_select_port(config)
        return config.preferred_dest_port
    end
    return UInt16(443)  # Standard QUIC port
end

#=
================================================================================
VERSION NEGOTIATION
================================================================================
The GFW only inspects QUIC Version 1 (0x00000001) packets with the corresponding
initial salt. By first sending a packet with an unknown version, we can trigger
version negotiation and make subsequent packets undetectable.
=#

const QUIC_VERSION_UNKNOWN = UInt32(0xbabababa)  # Invalid version for negotiation

"""
    create_version_probe_packet(dest_cid::Vector{UInt8}, src_cid::Vector{UInt8}) -> Vector{UInt8}

Create a QUIC Initial packet with an unknown version to trigger version negotiation.
The GFW cannot decrypt this packet as it uses an unknown salt.
"""
function create_version_probe_packet(dest_cid::Vector{UInt8}, src_cid::Vector{UInt8})
    buf = UInt8[]

    # Long header with Initial type
    push!(buf, 0xc0)  # Long header, Initial packet type

    # Unknown version (triggers negotiation, evades GFW)
    append!(buf, reinterpret(UInt8, [hton(QUIC_VERSION_UNKNOWN)]))

    # Connection IDs
    push!(buf, UInt8(length(dest_cid)))
    append!(buf, dest_cid)
    push!(buf, UInt8(length(src_cid)))
    append!(buf, src_cid)

    # Token (empty)
    push!(buf, 0x00)

    # Minimal payload (just needs to be valid structure)
    # Length (varint) + packet number + padding
    payload_len = 50
    encode_varint!(buf, VarInt(payload_len))

    # Packet number (2 bytes)
    append!(buf, [0x00, 0x00])

    # Random payload (will be ignored anyway)
    append!(buf, rand(UInt8, payload_len - 2))

    return buf
end

#=
================================================================================
PADDING STRATEGIES
================================================================================
The GFW doesn't require 1200-byte minimum padding. We can vary packet sizes
to reduce fingerprinting and potentially evade detection.
=#

"""
    calculate_padding(config::GFWMitigationConfig, current_size::Int) -> Int

Calculate padding bytes to add to a packet.
Returns number of padding bytes needed.
"""
function calculate_padding(config::GFWMitigationConfig, current_size::Int)
    if !config.enabled || !config.randomize_padding
        # Standard QUIC requires 1200 bytes minimum for Initial
        return max(0, 1200 - current_size)
    end

    min_pad, max_pad = config.padding_range

    # Ensure minimum viable packet size
    # GFW research shows packets as small as 137 bytes can trigger blocking
    target_size = rand(max(137, min_pad):max_pad)

    return max(0, target_size - current_size)
end

#=
================================================================================
HIGH-LEVEL API
================================================================================
=#

"""
    apply_mitigations(config::GFWMitigationConfig, actions::Dict{Symbol,Any})

Apply all configured mitigations and return actions to take.
This is the main entry point for the mitigation system.

Returns a Dict with:
- :send_dummy => Vector{UInt8} or nothing
- :fragments => Vector of (offset, data) tuples
- :source_port => UInt16 or nothing
- :version_probe => Vector{UInt8} or nothing
- :padding_size => Int
"""
function apply_mitigations(config::GFWMitigationConfig;
                          client_hello::Union{Vector{UInt8}, Nothing} = nothing,
                          dest_port::UInt16 = UInt16(443),
                          dest_cid::Vector{UInt8} = UInt8[],
                          src_cid::Vector{UInt8} = UInt8[],
                          current_packet_size::Int = 0)

    result = Dict{Symbol, Any}(
        :send_dummy => nothing,
        :fragments => nothing,
        :source_port => nothing,
        :version_probe => nothing,
        :padding_size => 0
    )

    if !config.enabled
        return result
    end

    # Dummy packet
    if should_send_dummy(config)
        result[:send_dummy] = generate_dummy_packet(config)
    end

    # SNI fragmentation
    if client_hello !== nothing && should_fragment_sni(config)
        result[:fragments] = fragment_around_sni(client_hello, config)
    end

    # Port selection
    if should_select_port(config)
        result[:source_port] = select_source_port(config, dest_port)
    end

    # Version negotiation probe
    if should_version_negotiate(config) && !isempty(dest_cid)
        result[:version_probe] = create_version_probe_packet(dest_cid, src_cid)
    end

    # Padding
    result[:padding_size] = calculate_padding(config, current_packet_size)

    return result
end

# Helper for varint encoding (matches Protocol module)
struct VarInt
    value::UInt64
end

function encode_varint!(buf::Vector{UInt8}, v::VarInt)
    val = v.value
    if val < 64
        push!(buf, UInt8(val))
    elseif val < 16384
        push!(buf, UInt8(0x40 | (val >> 8)))
        push!(buf, UInt8(val & 0xff))
    elseif val < 1073741824
        push!(buf, UInt8(0x80 | (val >> 24)))
        push!(buf, UInt8((val >> 16) & 0xff))
        push!(buf, UInt8((val >> 8) & 0xff))
        push!(buf, UInt8(val & 0xff))
    else
        push!(buf, UInt8(0xc0 | (val >> 56)))
        for i in 6:-1:0
            push!(buf, UInt8((val >> (i*8)) & 0xff))
        end
    end
end

export default_config, china_config, aggressive_config
export has_strategy, should_send_dummy, should_fragment_sni
export should_select_port, should_version_negotiate
export generate_dummy_packet, fragment_client_hello, fragment_around_sni
export find_sni_position, create_version_probe_packet
export calculate_padding, get_recommended_dest_port

end # module GFWMitigation
