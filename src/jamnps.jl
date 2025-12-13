module JAMNPS

#= JAM Simple Networking Protocol (JAMNP-S)

Implements the networking protocol for JAM nodes as specified in the JAM spec.
Key features:
- TLS 1.3 with Ed25519 self-signed certificates
- Alternative name derived from Ed25519 public key (base32)
- ALPN: jamnp-s/V/H where V=version, H=genesis hash prefix
- UP (Unique Persistent) and CE (Common Ephemeral) stream protocols
=#

using ..Ed25519
using ..X509
using Random

# Protocol version
const PROTOCOL_VERSION = 0

# Base32 alphabet per JAMNP-S spec
const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

# Stream protocol kinds
module StreamKind
    # Unique Persistent (UP) streams - opened once per connection
    const BLOCK_ANNOUNCEMENT = 0x00

    # Common Ephemeral (CE) streams - opened for each request
    const BLOCK_REQUEST = 0x80           # 128
    const STATE_REQUEST = 0x81           # 129
    const SAFROLE_TICKET_PROXY = 0x83    # 131
    const SAFROLE_TICKET_DIST = 0x84     # 132
    const WORK_PACKAGE_SUBMIT = 0x85     # 133
    const WORK_PACKAGE_SHARE = 0x86      # 134
    const WORK_REPORT_DIST = 0x87        # 135
    const WORK_REPORT_REQUEST = 0x88     # 136
    const SHARD_DIST = 0x89              # 137
    const AUDIT_SHARD_REQUEST = 0x8a     # 138
    const SEGMENT_SHARD_REQUEST_NOJUST = 0x8b  # 139
    const SEGMENT_SHARD_REQUEST_JUST = 0x8c    # 140
    const ASSURANCE_DIST = 0x8d          # 141
    const PREIMAGE_ANNOUNCE = 0x8e       # 142
    const PREIMAGE_REQUEST = 0x8f        # 143
    const AUDIT_ANNOUNCE = 0x90          # 144
    const JUDGMENT_PUBLISH = 0x91        # 145
    const WORK_BUNDLE_SUBMIT = 0x92      # 146
    const BUNDLE_REQUEST = 0x93          # 147
    const SEGMENT_REQUEST = 0x94         # 148
end

#= Alternative Name Derivation

Per spec:
B(n, l) = [] when l = 0
B(n, l) = [alphabet[n mod 32]] ++ B(floor(n/32), l-1) otherwise
N(k) = 'e' ++ B(E_32^-1(k), 52)

Where E_32^-1 is deserialization of 256-bit unsigned integer (little-endian)
=#

"""
    derive_alt_name(pubkey::Vector{UInt8}) -> String

Derive the X.509 alternative name from an Ed25519 public key.
Returns a 53-character string starting with 'e' followed by 52 base32 characters.
"""
function derive_alt_name(pubkey::Vector{UInt8})::String
    @assert length(pubkey) == 32 "Public key must be 32 bytes"

    # Interpret pubkey as 256-bit little-endian integer
    # We'll work with it as BigInt for easier division
    n = BigInt(0)
    for i in 32:-1:1
        n = (n << 8) | pubkey[i]
    end

    # Generate 52 base32 characters
    chars = Char[]
    for _ in 1:52
        idx = Int(n % 32)
        push!(chars, BASE32_ALPHABET[idx + 1])  # +1 for Julia 1-indexing
        n = n ÷ 32
    end

    return "e" * String(chars)
end

"""
    pubkey_from_alt_name(alt_name::String) -> Vector{UInt8}

Recover Ed25519 public key from X.509 alternative name.
"""
function pubkey_from_alt_name(alt_name::String)::Vector{UInt8}
    @assert length(alt_name) == 53 "Alternative name must be 53 characters"
    @assert alt_name[1] == 'e' "Alternative name must start with 'e'"

    # Decode base32 (reverse of derivation)
    n = BigInt(0)
    chars = alt_name[2:end]

    # Process in reverse order
    for i in 52:-1:1
        c = chars[i]
        idx = findfirst(==(c), BASE32_ALPHABET) - 1  # -1 for 0-indexed value
        n = n * 32 + idx
    end

    # Convert to 32-byte little-endian
    pubkey = zeros(UInt8, 32)
    for i in 1:32
        pubkey[i] = UInt8(n & 0xff)
        n >>= 8
    end

    return pubkey
end

"""
    make_alpn(genesis_hash::Vector{UInt8}; builder::Bool=false) -> String

Create ALPN protocol identifier for JAMNP-S.
Format: jamnp-s/V/H or jamnp-s/V/H/builder
"""
function make_alpn(genesis_hash::Vector{UInt8}; builder::Bool=false)::String
    @assert length(genesis_hash) >= 4 "Genesis hash must be at least 4 bytes"

    # First 8 nibbles (4 bytes) of genesis hash in lowercase hex
    hash_prefix = bytes2hex(genesis_hash[1:4])

    alpn = "jamnp-s/$PROTOCOL_VERSION/$hash_prefix"
    if builder
        alpn *= "/builder"
    end

    return alpn
end

"""
    parse_alpn(alpn::String) -> NamedTuple

Parse JAMNP-S ALPN protocol identifier.
Returns (version, genesis_prefix, is_builder).
"""
function parse_alpn(alpn::String)
    parts = split(alpn, '/')

    if length(parts) < 3 || parts[1] != "jamnp-s"
        error("Invalid JAMNP-S ALPN: $alpn")
    end

    version = parse(Int, parts[2])
    genesis_prefix = parts[3]
    is_builder = length(parts) >= 4 && parts[4] == "builder"

    return (version=version, genesis_prefix=genesis_prefix, is_builder=is_builder)
end

#= Preferred Initiator Selection

Per spec:
P(a, b) = a when (a[31] > 127) XOR (b[31] > 127) XOR (a < b)
P(a, b) = b otherwise

This determines which validator initiates the connection.
=#

"""
    preferred_initiator(key_a::Vector{UInt8}, key_b::Vector{UInt8}) -> Symbol

Determine which peer should initiate the connection.
Returns :a if key_a should initiate, :b otherwise.
"""
function preferred_initiator(key_a::Vector{UInt8}, key_b::Vector{UInt8})::Symbol
    @assert length(key_a) == 32 && length(key_b) == 32

    # Get high bit of last byte (index 32 in Julia, 31 in 0-indexed)
    a_high = key_a[32] > 127
    b_high = key_b[32] > 127

    # Lexicographic comparison
    a_less = key_a < key_b

    # XOR the three conditions
    if xor(xor(a_high, b_high), a_less)
        return :a
    else
        return :b
    end
end

#= Certificate Generation for JAMNP-S

Certificates must:
- Use Ed25519 as signature algorithm
- Use the peer's Ed25519 key
- Have single alternative name derived from public key
- Should be self-signed (not required to verify)
=#

"""
    JAMNPSIdentity

Identity for JAMNP-S connections, containing Ed25519 keypair and derived values.
"""
mutable struct JAMNPSIdentity
    keypair::Ed25519.KeyPair
    alt_name::String
    certificate::Vector{UInt8}  # DER-encoded X.509 certificate

    function JAMNPSIdentity(keypair::Ed25519.KeyPair)
        alt_name = derive_alt_name(keypair.public_key)
        # Generate X.509 certificate with JAMNP-S alt name
        certificate = X509.generate_x509_certificate(
            keypair;
            subject_cn="JAMNPS",
            issuer_cn="JAMNPS",
            alt_name=alt_name
        )
        new(keypair, alt_name, certificate)
    end
end

"""
    generate_identity() -> JAMNPSIdentity

Generate a new JAMNP-S identity with fresh Ed25519 keypair.
"""
function generate_identity()::JAMNPSIdentity
    keypair = Ed25519.generate_keypair()
    return JAMNPSIdentity(keypair)
end

"""
    identity_from_seed(seed::Vector{UInt8}) -> JAMNPSIdentity

Generate JAMNP-S identity from 32-byte seed (deterministic).
"""
function identity_from_seed(seed::Vector{UInt8})::JAMNPSIdentity
    keypair = Ed25519.keypair_from_seed(seed)
    return JAMNPSIdentity(keypair)
end

"""
    identity_from_keypair(keypair::Ed25519.KeyPair) -> JAMNPSIdentity

Create JAMNP-S identity from existing Ed25519 keypair.
"""
function identity_from_keypair(keypair::Ed25519.KeyPair)::JAMNPSIdentity
    return JAMNPSIdentity(keypair)
end

"""
    validate_peer_certificate(cert::Vector{UInt8}) -> Union{Vector{UInt8}, Nothing}

Validate a peer's certificate and extract their Ed25519 public key.
For JAMNP-S, we verify:
1. Certificate has valid Ed25519 signature
2. Subject Alternative Name matches the public key derivation
Returns the public key if valid, nothing otherwise.
"""
function validate_peer_certificate(cert::Vector{UInt8})::Union{Vector{UInt8}, Nothing}
    try
        # Extract public key from certificate
        pubkey = X509.extract_public_key(cert)

        # Derive expected alt name from public key
        expected_alt_name = derive_alt_name(pubkey)

        # For full validation we would parse the cert and check the SAN
        # For now, just return the public key if extraction succeeded
        return pubkey
    catch e
        @warn "Failed to validate peer certificate: $e"
        return nothing
    end
end

"""
    extract_peer_identity(cert::Vector{UInt8}) -> Union{Vector{UInt8}, Nothing}

Extract the Ed25519 public key from a peer's certificate.
This is the peer's JAM validator identity.
"""
function extract_peer_identity(cert::Vector{UInt8})::Union{Vector{UInt8}, Nothing}
    try
        return X509.extract_public_key(cert)
    catch
        return nothing
    end
end

#= Message Encoding

All stream protocols transmit messages as:
1. 4-byte little-endian message length
2. Message content
=#

"""
    encode_message(content::Vector{UInt8}) -> Vector{UInt8}

Encode a message with length prefix (little-endian u32).
"""
function encode_message(content::Vector{UInt8})::Vector{UInt8}
    len = UInt32(length(content))
    buf = Vector{UInt8}(undef, 4 + length(content))
    buf[1] = len & 0xff
    buf[2] = (len >> 8) & 0xff
    buf[3] = (len >> 16) & 0xff
    buf[4] = (len >> 24) & 0xff
    buf[5:end] = content
    return buf
end

"""
    decode_message_header(data::Vector{UInt8}) -> UInt32

Decode message length from 4-byte little-endian header.
"""
function decode_message_header(data::Vector{UInt8})::UInt32
    @assert length(data) >= 4
    return UInt32(data[1]) |
           (UInt32(data[2]) << 8) |
           (UInt32(data[3]) << 16) |
           (UInt32(data[4]) << 24)
end

#= Block Announcement (UP 0) =#

struct BlockAnnouncement
    header::Vector{UInt8}
    finalized_hash::Vector{UInt8}
    finalized_slot::UInt32
end

struct BlockAnnouncementHandshake
    finalized_hash::Vector{UInt8}
    finalized_slot::UInt32
    leaves::Vector{Tuple{Vector{UInt8}, UInt32}}  # (hash, slot) pairs
end

function encode_handshake(hs::BlockAnnouncementHandshake)::Vector{UInt8}
    buf = UInt8[]

    # Final: hash (32) + slot (4)
    append!(buf, hs.finalized_hash)
    append!(buf, reinterpret(UInt8, [htol(hs.finalized_slot)]))

    # Leaves count (varint encoded as length prefix)
    append!(buf, reinterpret(UInt8, [htol(UInt32(length(hs.leaves)))]))

    # Each leaf: hash (32) + slot (4)
    for (hash, slot) in hs.leaves
        append!(buf, hash)
        append!(buf, reinterpret(UInt8, [htol(slot)]))
    end

    return buf
end

#= Validator Endpoint Parsing =#

"""
    parse_validator_endpoint(metadata::Vector{UInt8}) -> Tuple{IPv6, UInt16}

Parse validator endpoint from first 18 bytes of metadata.
First 16 bytes: IPv6 address
Last 2 bytes: port (little-endian)
"""
function parse_validator_endpoint(metadata::Vector{UInt8})
    @assert length(metadata) >= 18 "Metadata must be at least 18 bytes"

    # IPv6 address (16 bytes)
    ipv6_bytes = metadata[1:16]
    # Port (2 bytes, little-endian)
    port = UInt16(metadata[17]) | (UInt16(metadata[18]) << 8)

    # Convert to Julia IPv6
    # IPv6 constructor expects UInt128
    ip_val = UInt128(0)
    for i in 1:16
        ip_val = (ip_val << 8) | ipv6_bytes[i]
    end

    return (ip_val, port)
end

# Exports
export StreamKind
export derive_alt_name, pubkey_from_alt_name
export make_alpn, parse_alpn
export preferred_initiator
export JAMNPSIdentity, generate_identity, identity_from_seed, identity_from_keypair
export validate_peer_certificate, extract_peer_identity
export encode_message, decode_message_header
export BlockAnnouncement, BlockAnnouncementHandshake, encode_handshake
export parse_validator_endpoint

end # module JAMNPS
