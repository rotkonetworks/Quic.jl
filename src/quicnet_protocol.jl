module QuicNetProtocol

using ..Packet
using ..Frame
using ..Stream
using ..Ed25519
using Random
using SHA

# QuicNet protocol constants
const AUTH_MAGIC = b"QUICNET1"
const PEER_ID_LENGTH = 32

# QuicNet Peer Identity
struct PeerId
    pubkey::Vector{UInt8}  # 32-byte Ed25519 public key

    PeerId(pubkey::Vector{UInt8}) = begin
        @assert length(pubkey) == PEER_ID_LENGTH "PeerId requires 32-byte public key"
        new(pubkey)
    end
end

# Generate peer ID from public key
function peer_id_from_pubkey(pubkey::Vector{UInt8})::String
    # QuicNet uses base58 encoding of the public key
    # For simplicity, we'll use hex encoding
    return bytes2hex(pubkey)
end

# QuicNet Identity using real Ed25519
mutable struct QuicNetIdentity
    keypair::Ed25519.KeyPair
    peer_id::PeerId

    function QuicNetIdentity()
        # Generate Ed25519 keypair
        keypair = Ed25519.generate_keypair()
        peer_id = PeerId(keypair.public_key)
        new(keypair, peer_id)
    end

    function QuicNetIdentity(seed::Vector{UInt8})
        # Generate deterministic keypair from seed
        keypair = Ed25519.keypair_from_seed(seed)
        peer_id = PeerId(keypair.public_key)
        new(keypair, peer_id)
    end
end

# Sign data with Ed25519
function sign_challenge(identity::QuicNetIdentity, challenge::Vector{UInt8})::Vector{UInt8}
    # Use real Ed25519 signature (64 bytes)
    return Ed25519.sign(challenge, identity.keypair)
end

# Simple HMAC-SHA256
function hmac_sha256(key::Vector{UInt8}, data::Vector{UInt8})::Vector{UInt8}
    block_size = 64

    if length(key) > block_size
        key = SHA.sha256(key)
    end

    if length(key) < block_size
        key = vcat(key, zeros(UInt8, block_size - length(key)))
    end

    o_key_pad = key .⊻ 0x5c
    i_key_pad = key .⊻ 0x36

    inner_hash = SHA.sha256(vcat(i_key_pad, data))
    return SHA.sha256(vcat(o_key_pad, inner_hash))
end

# QuicNet authentication handshake
mutable struct QuicNetAuth
    identity::QuicNetIdentity
    is_initiator::Bool
    our_challenge::Vector{UInt8}
    their_challenge::Vector{UInt8}
    peer_id::Union{PeerId, Nothing}
    authenticated::Bool

    QuicNetAuth(identity::QuicNetIdentity, is_initiator::Bool) =
        new(identity, is_initiator, UInt8[], UInt8[], nothing, false)
end

# Create authentication handshake initial message
function create_auth_init(auth::QuicNetAuth)::Vector{UInt8}
    buf = UInt8[]

    # Protocol magic
    append!(buf, AUTH_MAGIC)

    # Generate and store our challenge
    auth.our_challenge = rand(UInt8, 32)
    append!(buf, auth.our_challenge)

    return buf
end

# Process received auth message and create response
function process_auth_message(auth::QuicNetAuth, data::Vector{UInt8})::Union{Vector{UInt8}, Nothing}
    offset = 1

    # Check if this is the initial message
    if length(data) >= 8 && data[1:8] == AUTH_MAGIC
        offset = 9

        # Read their challenge
        if length(data) >= offset + 31
            auth.their_challenge = data[offset:offset+31]
            offset += 32

            # Create response with our challenge and signature
            response = UInt8[]

            # Send our challenge if we haven't yet (responder side)
            if !auth.is_initiator && isempty(auth.our_challenge)
                append!(response, AUTH_MAGIC)
                auth.our_challenge = rand(UInt8, 32)
                append!(response, auth.our_challenge)
            end

            # Sign their challenge
            signature = sign_challenge(auth.identity, auth.their_challenge)
            append!(response, signature)

            # Send our public key
            append!(response, auth.identity.keypair.public_key)

            return response
        end
    end

    # Check if this is signature response
    if length(data) >= 96  # 64 bytes signature + 32 bytes public key
        their_signature = data[1:64]
        their_pubkey = data[65:96]

        # Verify Ed25519 signature
        if Ed25519.verify(their_signature, auth.our_challenge, their_pubkey)
            auth.peer_id = PeerId(their_pubkey)
            auth.authenticated = true
        else
            # Signature verification failed
            return nothing
        end

        # If we're responder and haven't sent our signature yet
        if !auth.is_initiator
            response = UInt8[]
            signature = sign_challenge(auth.identity, auth.their_challenge)
            append!(response, signature)
            append!(response, auth.identity.keypair.public_key)
            return response
        end

        return nothing  # Auth complete
    end

    return nothing
end

# QuicNet control messages
struct ChannelType
    type::Symbol  # :shell, :exec, :forward
    data::Dict{Symbol, Any}
end

struct ControlMsg
    type::Symbol  # :resize, :exit, :signal, :channel_open
    data::Dict{Symbol, Any}
end

# Create channel open message
function create_channel_open_msg(channel_type::Symbol, data::Dict{Symbol, Any}=Dict())::Vector{UInt8}
    # Simplified binary encoding
    # Format: [type_byte][data_length][data]

    type_byte = if channel_type == :shell
        0x01
    elseif channel_type == :exec
        0x02
    elseif channel_type == :forward
        0x03
    else
        0x00
    end

    buf = UInt8[type_byte]

    # Encode additional data if present
    if channel_type == :exec && haskey(data, :command)
        cmd_bytes = Vector{UInt8}(data[:command])
        push!(buf, UInt8(length(cmd_bytes)))
        append!(buf, cmd_bytes)
    elseif channel_type == :forward && haskey(data, :host) && haskey(data, :port)
        host_bytes = Vector{UInt8}(data[:host])
        push!(buf, UInt8(length(host_bytes)))
        append!(buf, host_bytes)
        push!(buf, UInt8(data[:port] >> 8))
        push!(buf, UInt8(data[:port] & 0xff))
    else
        push!(buf, 0x00)  # No additional data
    end

    return buf
end

# Export types and functions
export PeerId, QuicNetIdentity, QuicNetAuth
export create_auth_init, process_auth_message, create_channel_open_msg
export peer_id_from_pubkey, AUTH_MAGIC

end # module