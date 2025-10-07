module ZeroRTT

using ..Protocol
using ..Packet
using ..Frame
using ..Crypto
using SHA
using MbedTLS

# 0-RTT session state
mutable struct SessionState
    # Session ticket from NewSessionTicket message
    ticket::Vector{UInt8}
    ticket_age_add::UInt32
    ticket_lifetime::UInt32
    ticket_nonce::Vector{UInt8}

    # Resumption master secret from previous connection
    resumption_master_secret::Vector{UInt8}

    # Server transport parameters from previous connection
    server_transport_params::Vector{UInt8}

    # Application protocol negotiated
    alpn::String

    # Server name indication
    server_name::String

    # Timestamp when ticket was received
    ticket_received_time::UInt64

    # Cipher suite used
    cipher_suite::UInt16

    # Maximum early data size allowed
    max_early_data_size::UInt32

    SessionState() = new(
        UInt8[], 0, 0, UInt8[],
        UInt8[], UInt8[],
        "", "",
        0,
        0x1301,  # TLS_AES_128_GCM_SHA256
        0xffffffff  # Default max early data (2^32 - 1)
    )
end

# 0-RTT packet for early data
struct ZeroRTTPacket
    dest_cid::Packet.ConnectionId
    src_cid::Packet.ConnectionId
    packet_number::Packet.PacketNumber
    payload::Vector{UInt8}
end

# Session cache for storing resumption state
mutable struct SessionCache
    # Map from server address to session states
    sessions::Dict{String, Vector{SessionState}}

    # Maximum number of sessions per server
    max_sessions_per_server::Int

    # Maximum total sessions
    max_total_sessions::Int

    SessionCache(max_per_server::Int = 10, max_total::Int = 100) =
        new(Dict{String, Vector{SessionState}}(), max_per_server, max_total)
end

# Global session cache instance
const GLOBAL_SESSION_CACHE = SessionCache()

# Store a new session for resumption
function store_session!(cache::SessionCache, server_addr::String, state::SessionState)
    if !haskey(cache.sessions, server_addr)
        cache.sessions[server_addr] = SessionState[]
    end

    sessions = cache.sessions[server_addr]

    # Remove expired sessions
    current_time = time_ns()
    filter!(s -> is_session_valid(s, current_time), sessions)

    # Add new session
    push!(sessions, state)

    # Limit sessions per server
    if length(sessions) > cache.max_sessions_per_server
        popfirst!(sessions)
    end

    # Limit total sessions
    total_sessions = sum(length(v) for v in values(cache.sessions))
    if total_sessions > cache.max_total_sessions
        # Remove oldest server's sessions
        oldest_server = argmin(server -> minimum(s.ticket_received_time for s in cache.sessions[server]),
                               keys(cache.sessions))
        delete!(cache.sessions, oldest_server)
    end
end

# Get a valid session for resumption
function get_resumption_session(cache::SessionCache, server_addr::String)::Union{SessionState, Nothing}
    if !haskey(cache.sessions, server_addr)
        return nothing
    end

    sessions = cache.sessions[server_addr]
    current_time = time_ns()

    # Find most recent valid session
    valid_sessions = filter(s -> is_session_valid(s, current_time), sessions)

    if isempty(valid_sessions)
        return nothing
    end

    # Return most recent session
    return valid_sessions[end]
end

# Check if a session is still valid
function is_session_valid(session::SessionState, current_time::UInt64)::Bool
    if isempty(session.ticket)
        return false
    end

    # Check ticket age (convert lifetime from seconds to nanoseconds)
    ticket_age = current_time - session.ticket_received_time
    max_age = UInt64(session.ticket_lifetime) * 1_000_000_000

    if ticket_age >= max_age
        return false
    end

    # Check for reasonable age (not more than 7 days)
    seven_days_ns = UInt64(7 * 24 * 3600) * 1_000_000_000
    if ticket_age > seven_days_ns
        return false
    end

    return true
end

# Calculate PSK binder for ClientHello
function calculate_psk_binder(session::SessionState, client_hello_hash::Vector{UInt8})::Vector{UInt8}
    # Derive binder key from resumption master secret
    binder_key = derive_binder_key(session.resumption_master_secret, session.cipher_suite)

    # Calculate HMAC over partial ClientHello
    if session.cipher_suite == 0x1301  # TLS_AES_128_GCM_SHA256
        hmac = MbedTLS.digest(MbedTLS.MD_SHA256, client_hello_hash, binder_key)
    else  # TLS_AES_256_GCM_SHA384
        hmac = MbedTLS.digest(MbedTLS.MD_SHA384, client_hello_hash, binder_key)
    end

    return hmac
end

# Derive binder key from resumption master secret
function derive_binder_key(resumption_secret::Vector{UInt8}, cipher_suite::UInt16)::Vector{UInt8}
    if cipher_suite == 0x1301  # TLS_AES_128_GCM_SHA256
        hash_len = 32
        hash_fn = SHA.sha256
    else  # TLS_AES_256_GCM_SHA384
        hash_len = 48
        hash_fn = SHA.sha384
    end

    # Derive early secret from PSK
    early_secret = hkdf_extract(hash_fn, resumption_secret, zeros(UInt8, hash_len))

    # Derive binder key
    binder_key = hkdf_expand_label(hash_fn, early_secret, "res binder", UInt8[], hash_len)

    return binder_key
end

# HKDF-Extract
function hkdf_extract(hash_fn, ikm::Vector{UInt8}, salt::Vector{UInt8})::Vector{UInt8}
    if isempty(salt)
        salt = zeros(UInt8, length(hash_fn(UInt8[])))
    end
    return hmac(hash_fn, salt, ikm)
end

# HKDF-Expand-Label for TLS 1.3
function hkdf_expand_label(hash_fn, secret::Vector{UInt8}, label::String,
                          context::Vector{UInt8}, target_length::Int)::Vector{UInt8}
    # Construct HkdfLabel struct
    tls13_label = "tls13 " * label
    label_bytes = Vector{UInt8}(tls13_label)

    # Length (2 bytes)
    hkdf_label = UInt8[
        (target_length >> 8) & 0xff,
        target_length & 0xff,
        # Label length (1 byte)
        length(label_bytes),
    ]
    append!(hkdf_label, label_bytes)

    # Context length (1 byte)
    push!(hkdf_label, length(context))
    append!(hkdf_label, context)

    # HKDF-Expand
    return hkdf_expand(hash_fn, secret, hkdf_label, target_length)
end

# HKDF-Expand
function hkdf_expand(hash_fn, prk::Vector{UInt8}, info::Vector{UInt8}, target_length::Int)::Vector{UInt8}
    hash_len = length(hash_fn(UInt8[]))
    n = ceil(Int, target_length / hash_len)

    okm = UInt8[]
    previous = UInt8[]

    for i in 1:n
        data = vcat(previous, info, UInt8[i])
        previous = hmac(hash_fn, prk, data)
        append!(okm, previous)
    end

    return okm[1:target_length]
end

# Simple HMAC implementation
function hmac(hash_fn, key::Vector{UInt8}, data::Vector{UInt8})::Vector{UInt8}
    block_size = 64  # For SHA-256
    if length(hash_fn(UInt8[])) == 48
        block_size = 128  # For SHA-384
    end

    if length(key) > block_size
        key = hash_fn(key)
    end

    if length(key) < block_size
        key = vcat(key, zeros(UInt8, block_size - length(key)))
    end

    o_key_pad = key .⊻ 0x5c
    i_key_pad = key .⊻ 0x36

    return hash_fn(vcat(o_key_pad, hash_fn(vcat(i_key_pad, data))))
end

# Create 0-RTT packet with early data
function create_zero_rtt_packet(session::SessionState,
                                dest_cid::Packet.ConnectionId,
                                src_cid::Packet.ConnectionId,
                                packet_number::Packet.PacketNumber,
                                frames::Vector{<:Frame.QuicFrame})::ZeroRTTPacket
    # Serialize frames (simplified - in real implementation would serialize properly)
    payload = UInt8[]
    # for frame in frames
    #     append!(payload, Frame.serialize_frame(frame))
    # end
    # For demo, just use a placeholder
    append!(payload, [0x08, 0x00, 0x00, 0x00, 0x00])  # STREAM frame header

    # Encrypt payload with early data keys
    encrypted_payload = encrypt_early_data(session, packet_number.value, payload)

    return ZeroRTTPacket(dest_cid, src_cid, packet_number, encrypted_payload)
end

# Encrypt early data
function encrypt_early_data(session::SessionState, packet_number::UInt64,
                           plaintext::Vector{UInt8})::Vector{UInt8}
    # Derive early data keys from session
    if session.cipher_suite == 0x1301  # TLS_AES_128_GCM_SHA256
        key_length = 16
        hash_fn = SHA.sha256
    else  # TLS_AES_256_GCM_SHA384
        key_length = 32
        hash_fn = SHA.sha384
    end

    # Derive early secret
    early_secret = hkdf_extract(hash_fn, session.resumption_master_secret,
                               zeros(UInt8, length(hash_fn(UInt8[]))))

    # Derive client early traffic secret
    client_early_secret = hkdf_expand_label(hash_fn, early_secret,
                                           "c e traffic", UInt8[], length(hash_fn(UInt8[])))

    # Derive key and IV
    key = hkdf_expand_label(hash_fn, client_early_secret, "quic key", UInt8[], key_length)
    iv = hkdf_expand_label(hash_fn, client_early_secret, "quic iv", UInt8[], 12)

    # Construct nonce with packet number XOR
    nonce = copy(iv)
    pn_bytes = UInt8[
        (packet_number >> 56) & 0xff,
        (packet_number >> 48) & 0xff,
        (packet_number >> 40) & 0xff,
        (packet_number >> 32) & 0xff,
        (packet_number >> 24) & 0xff,
        (packet_number >> 16) & 0xff,
        (packet_number >> 8) & 0xff,
        packet_number & 0xff
    ]
    for i in 1:8
        nonce[end - 8 + i] ⊻= pn_bytes[i]
    end

    # Simplified encryption for demo (would use AES-GCM in real implementation)
    # In a real implementation, this would:
    # 1. Set up AES-GCM cipher with key and nonce
    # 2. Encrypt plaintext with AAD
    # 3. Return ciphertext with auth tag

    # For demo, just XOR with key material as placeholder
    ciphertext = copy(plaintext)
    for i in 1:length(ciphertext)
        ciphertext[i] ⊻= key[(i-1) % length(key) + 1]
    end

    # Append a fake 16-byte auth tag
    append!(ciphertext, zeros(UInt8, 16))

    return ciphertext
end

# Process NewSessionTicket message
function process_new_session_ticket!(resumption_secret::Vector{UInt8},
                                    cipher_suite::UInt16,
                                    alpn::String,
                                    server_name::String,
                                    ticket_data::Vector{UInt8})::SessionState
    # Parse NewSessionTicket message
    offset = 1

    # Ticket lifetime (4 bytes)
    lifetime = UInt32(ticket_data[offset]) << 24 |
               UInt32(ticket_data[offset+1]) << 16 |
               UInt32(ticket_data[offset+2]) << 8 |
               UInt32(ticket_data[offset+3])
    offset += 4

    # Ticket age add (4 bytes)
    age_add = UInt32(ticket_data[offset]) << 24 |
              UInt32(ticket_data[offset+1]) << 16 |
              UInt32(ticket_data[offset+2]) << 8 |
              UInt32(ticket_data[offset+3])
    offset += 4

    # Ticket nonce length (1 byte)
    nonce_len = ticket_data[offset]
    offset += 1

    # Ticket nonce
    nonce = ticket_data[offset:offset+nonce_len-1]
    offset += nonce_len

    # Ticket length (2 bytes)
    ticket_len = UInt16(ticket_data[offset]) << 8 | UInt16(ticket_data[offset+1])
    offset += 2

    # Ticket
    ticket = ticket_data[offset:offset+ticket_len-1]
    offset += ticket_len

    # Extensions length (2 bytes)
    ext_len = UInt16(ticket_data[offset]) << 8 | UInt16(ticket_data[offset+1])
    offset += 2

    # Parse extensions for max_early_data_size
    max_early_data = UInt32(0xffffffff)
    if ext_len > 0
        ext_end = offset + ext_len
        while offset < ext_end
            ext_type = UInt16(ticket_data[offset]) << 8 | UInt16(ticket_data[offset+1])
            offset += 2
            ext_data_len = UInt16(ticket_data[offset]) << 8 | UInt16(ticket_data[offset+1])
            offset += 2

            if ext_type == 0x002a  # early_data extension
                if ext_data_len >= 4
                    max_early_data = UInt32(ticket_data[offset]) << 24 |
                                   UInt32(ticket_data[offset+1]) << 16 |
                                   UInt32(ticket_data[offset+2]) << 8 |
                                   UInt32(ticket_data[offset+3])
                end
            end
            offset += ext_data_len
        end
    end

    # Create session state
    session = SessionState()
    session.ticket = ticket
    session.ticket_age_add = age_add
    session.ticket_lifetime = lifetime
    session.ticket_nonce = nonce
    session.ticket_received_time = time_ns()
    session.max_early_data_size = max_early_data

    # Copy session parameters
    session.resumption_master_secret = copy(resumption_secret)
    session.cipher_suite = cipher_suite
    session.alpn = alpn
    session.server_name = server_name

    return session
end

# Add PSK extension to ClientHello for 0-RTT
function add_psk_extension!(client_hello::Vector{UInt8}, session::SessionState)::Vector{UInt8}
    # Calculate ticket age in milliseconds
    current_time = time_ns()
    ticket_age_ms = (current_time - session.ticket_received_time) ÷ 1_000_000
    obfuscated_age = (ticket_age_ms + session.ticket_age_add) & 0xffffffff

    # Build PSK identity
    identity = UInt8[]

    # Identity length (2 bytes)
    push!(identity, (length(session.ticket) >> 8) & 0xff)
    push!(identity, length(session.ticket) & 0xff)

    # Identity (the ticket)
    append!(identity, session.ticket)

    # Obfuscated ticket age (4 bytes)
    push!(identity, (obfuscated_age >> 24) & 0xff)
    push!(identity, (obfuscated_age >> 16) & 0xff)
    push!(identity, (obfuscated_age >> 8) & 0xff)
    push!(identity, obfuscated_age & 0xff)

    # Build identities list
    identities = UInt8[]
    push!(identities, (length(identity) >> 8) & 0xff)
    push!(identities, length(identity) & 0xff)
    append!(identities, identity)

    # Calculate binder (placeholder for now, will be updated)
    binder_length = session.cipher_suite == 0x1301 ? 32 : 48  # SHA256 or SHA384
    binder = zeros(UInt8, binder_length + 1)  # +1 for length prefix
    binder[1] = binder_length

    # Build binders list
    binders = UInt8[]
    push!(binders, (length(binder) >> 8) & 0xff)
    push!(binders, length(binder) & 0xff)
    append!(binders, binder)

    # Build complete PSK extension
    psk_extension = UInt8[]

    # Extension type: pre_shared_key (41)
    push!(psk_extension, 0x00)
    push!(psk_extension, 0x29)

    # Extension length
    ext_data_length = length(identities) + length(binders)
    push!(psk_extension, (ext_data_length >> 8) & 0xff)
    push!(psk_extension, ext_data_length & 0xff)

    # Extension data
    append!(psk_extension, identities)
    append!(psk_extension, binders)

    return psk_extension
end

# Check if 0-RTT is available for a server
function is_zero_rtt_available(server_addr::String)::Bool
    session = get_resumption_session(GLOBAL_SESSION_CACHE, server_addr)
    return session !== nothing && session.max_early_data_size > 0
end

# Get max early data size for a server
function get_max_early_data_size(server_addr::String)::UInt32
    session = get_resumption_session(GLOBAL_SESSION_CACHE, server_addr)
    if session === nothing
        return 0
    end
    return session.max_early_data_size
end

# Export functions and types
export SessionState, SessionCache, ZeroRTTPacket,
       store_session!, get_resumption_session, is_session_valid,
       create_zero_rtt_packet, process_new_session_ticket!,
       add_psk_extension!, is_zero_rtt_available, get_max_early_data_size,
       GLOBAL_SESSION_CACHE

end # module