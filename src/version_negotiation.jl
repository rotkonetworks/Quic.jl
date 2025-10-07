module VersionNegotiation

using ..Protocol
using ..Packet

# Supported QUIC versions
const QUIC_VERSION_1 = 0x00000001
const QUIC_VERSION_DRAFT_29 = 0xff00001d
const QUIC_VERSION_DRAFT_32 = 0x00000020

# List of supported versions in preference order
const SUPPORTED_VERSIONS = [QUIC_VERSION_1, QUIC_VERSION_DRAFT_32, QUIC_VERSION_DRAFT_29]

# Check if a version is supported
function is_supported_version(version::UInt32)
    return version in SUPPORTED_VERSIONS
end

# Get preferred version
function get_preferred_version()
    return SUPPORTED_VERSIONS[1]
end

# Create version negotiation packet
function create_version_negotiation_packet(dcid::ConnectionId, scid::ConnectionId,
                                          supported_versions::Vector{UInt32}=SUPPORTED_VERSIONS)
    buf = UInt8[]

    # Random first byte with high bit set (long header) and unused bits randomized
    push!(buf, 0x80 | rand(UInt8) & 0x7f)

    # Version field set to 0 for version negotiation
    append!(buf, zeros(UInt8, 4))

    # Destination CID (original source CID from client)
    push!(buf, UInt8(length(dcid)))
    append!(buf, dcid.data)

    # Source CID (original destination CID from client)
    push!(buf, UInt8(length(scid)))
    append!(buf, scid.data)

    # Supported versions list
    for version in supported_versions
        append!(buf, reinterpret(UInt8, [hton(version)]))
    end

    return buf
end

# Parse version negotiation packet
function parse_version_negotiation(data::Vector{UInt8})
    if length(data) < 7
        return nothing
    end

    pos = 1

    # Check first byte (should have high bit set)
    if (data[pos] & 0x80) == 0
        return nothing
    end
    pos += 1

    # Version should be 0
    version = UInt32(0)
    for i in 0:3
        version = (version << 8) | data[pos + i]
    end
    if version != 0
        return nothing
    end
    pos += 4

    # Destination CID
    dcid_len = data[pos]
    pos += 1
    if length(data) < pos + dcid_len
        return nothing
    end
    dcid = data[pos:pos + dcid_len - 1]
    pos += dcid_len

    # Source CID
    scid_len = data[pos]
    pos += 1
    if length(data) < pos + scid_len
        return nothing
    end
    scid = data[pos:pos + scid_len - 1]
    pos += scid_len

    # Parse supported versions
    versions = UInt32[]
    while pos + 3 < length(data)
        v = UInt32(0)
        for i in 0:3
            v = (v << 8) | data[pos + i]
        end
        push!(versions, ntoh(v))
        pos += 4
    end

    return (
        dcid = dcid,
        scid = scid,
        versions = versions
    )
end

# Choose compatible version from list
function choose_version(offered_versions::Vector{UInt32})
    for preferred in SUPPORTED_VERSIONS
        if preferred in offered_versions
            return preferred
        end
    end
    return nothing
end

# Handle incoming packet with unsupported version
function handle_version_mismatch(packet_version::UInt32, dcid::ConnectionId, scid::ConnectionId)
    if packet_version == 0
        # This is already a version negotiation packet
        return nothing
    end

    if is_supported_version(packet_version)
        # Version is actually supported
        return nothing
    end

    # Create version negotiation response
    return create_version_negotiation_packet(scid, dcid)
end

# Check if packet is version negotiation
function is_version_negotiation_packet(data::Vector{UInt8})
    if length(data) < 6
        return false
    end

    # Long header bit must be set
    if (data[1] & 0x80) == 0
        return false
    end

    # Version field must be 0
    version = UInt32(0)
    for i in 2:5
        version = (version << 8) | data[i]
    end

    return version == 0
end

export QUIC_VERSION_1, QUIC_VERSION_DRAFT_29, QUIC_VERSION_DRAFT_32
export SUPPORTED_VERSIONS
export is_supported_version, get_preferred_version
export create_version_negotiation_packet, parse_version_negotiation
export choose_version, handle_version_mismatch
export is_version_negotiation_packet

end # module VersionNegotiation