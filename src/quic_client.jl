#= QUIC Client Module

High-level API for establishing QUIC connections with TLS 1.3.
Handles the complete handshake flow including:
- Initial packet encryption/decryption
- Handshake packet encryption/decryption
- Coalesced packet processing
- TLS 1.3 state machine (ServerHello → Finished)

This module provides a simple connect() API that handles all the complexity.
=#

module QuicClient

using ..Protocol
using ..Protocol: VarInt, encode_varint!, decode_varint
using ..Packet
using ..Packet: ConnectionId
using ..Frame
using ..Frame: CryptoFrame, StreamFrame
using ..Crypto
using ..Crypto: AES128GCM
using ..Handshake
using ..Handshake: HandshakeState
using ..X25519
using ..Ed25519
using ..X509
using Sockets
using SHA

export QuicConnection, QuicConfig
export connect!, process_packet!, send_stream_data!
export ConnectionState, DISCONNECTED, CONNECTING, HANDSHAKING, CONNECTED, CLOSED

# Connection states
@enum ConnectionState begin
    DISCONNECTED
    CONNECTING
    HANDSHAKING
    CONNECTED
    CLOSING
    CLOSED
end

# Configuration for QUIC connection
struct QuicConfig
    alpn::String                    # ALPN protocol identifier
    server_name::Union{String, Nothing}  # SNI for TLS
    idle_timeout_ms::UInt64        # Idle timeout
    max_streams::UInt64            # Max concurrent streams

    # Optional: Ed25519 identity for mutual TLS
    ed25519_keypair::Union{Ed25519.KeyPair, Nothing}
    certificate::Union{Vector{UInt8}, Nothing}
end

function QuicConfig(alpn::String;
                    server_name::Union{String, Nothing}=nothing,
                    idle_timeout_ms::UInt64=UInt64(30000),
                    max_streams::UInt64=UInt64(100),
                    ed25519_keypair::Union{Ed25519.KeyPair, Nothing}=nothing,
                    certificate::Union{Vector{UInt8}, Nothing}=nothing)
    QuicConfig(alpn, server_name, idle_timeout_ms, max_streams, ed25519_keypair, certificate)
end

# QUIC Connection
mutable struct QuicConnection
    config::QuicConfig
    state::ConnectionState
    socket::UDPSocket
    remote_addr::Union{Sockets.InetAddr, Nothing}
    is_client::Bool

    # Connection IDs
    local_cid::ConnectionId
    remote_cid::ConnectionId

    # TLS 1.3 handshake state
    handshake::HandshakeState
    x25519_private::Vector{UInt8}
    x25519_public::Vector{UInt8}
    peer_x25519_public::Union{Vector{UInt8}, Nothing}
    shared_secret::Union{Vector{UInt8}, Nothing}

    # Peer identity (from certificate)
    peer_pubkey::Union{Vector{UInt8}, Nothing}

    # Crypto secrets for each packet space
    initial_secrets::Dict{Symbol, Vector{UInt8}}
    handshake_secrets::Dict{Symbol, Vector{UInt8}}
    application_secrets::Dict{Symbol, Vector{UInt8}}

    # Streams
    next_stream_id::UInt64

    # Packet tracking
    next_pn::UInt64
    recv_pn::UInt64

    # Buffered packets (for out-of-order handshake data)
    pending_handshake_packets::Vector{Vector{UInt8}}

    # Callbacks
    on_connected::Union{Function, Nothing}
    on_stream_data::Union{Function, Nothing}

    # Timing
    last_activity::UInt64
end

function QuicConnection(config::QuicConfig, socket::UDPSocket, is_client::Bool)
    # Generate X25519 key pair for ECDHE
    x25519_priv, x25519_pub = X25519.generate_keypair()

    QuicConnection(
        config,
        DISCONNECTED,
        socket,
        nothing,
        is_client,
        ConnectionId(),              # local_cid - generated
        ConnectionId(),              # remote_cid - will be set
        HandshakeState(is_client ? :client : :server),
        x25519_priv,
        x25519_pub,
        nothing,                     # peer_x25519_public
        nothing,                     # shared_secret
        nothing,                     # peer_pubkey
        Dict{Symbol, Vector{UInt8}}(),  # initial_secrets
        Dict{Symbol, Vector{UInt8}}(),  # handshake_secrets
        Dict{Symbol, Vector{UInt8}}(),  # application_secrets
        is_client ? UInt64(0) : UInt64(1),  # next_stream_id
        UInt64(0),                   # next_pn
        UInt64(0),                   # recv_pn
        Vector{Vector{UInt8}}(),     # pending_handshake_packets
        nothing,                     # on_connected
        nothing,                     # on_stream_data
        time_ns()                    # last_activity
    )
end

#= High-Level API =#

"""
    connect!(conn::QuicConnection, host::String, port::UInt16)

Initiate a QUIC connection to a remote server.
"""
function connect!(conn::QuicConnection, host::String, port::UInt16)
    # Resolve host
    addr = getaddrinfo(host)
    conn.remote_addr = Sockets.InetAddr(addr, port)

    # Generate connection IDs
    conn.remote_cid = ConnectionId(rand(UInt8, 8))  # DCID for server
    conn.local_cid = ConnectionId(rand(UInt8, 8))   # Our SCID

    # Derive initial secrets from DCID
    derive_initial_secrets!(conn, conn.remote_cid.data)

    # Create and send ClientHello
    conn.state = HANDSHAKING
    send_client_hello!(conn)

    return conn
end

#= TLS 1.3 Handshake =#

function send_client_hello!(conn::QuicConnection)
    # Build ClientHello message
    client_hello = create_client_hello(conn)

    # Add to transcript
    push!(conn.handshake.messages, client_hello)

    # Wrap in CRYPTO frame and send as Initial packet
    crypto_frame = CryptoFrame(0, client_hello)
    send_initial_packet!(conn, crypto_frame)

    conn.handshake.state = :wait_sh
    println("QUIC: Sent ClientHello with ALPN: $(conn.config.alpn)")
end

function create_client_hello(conn::QuicConnection)::Vector{UInt8}
    buf = UInt8[]

    # Handshake type: ClientHello (1)
    push!(buf, 0x01)

    # Length placeholder (3 bytes)
    len_pos = length(buf) + 1
    append!(buf, zeros(UInt8, 3))

    # Legacy version (TLS 1.2)
    append!(buf, [0x03, 0x03])

    # Client random (32 bytes)
    client_random = rand(UInt8, 32)
    conn.handshake.client_random = client_random
    append!(buf, client_random)

    # Legacy session ID (32 bytes for compatibility)
    push!(buf, 32)
    append!(buf, rand(UInt8, 32))

    # Cipher suites - prefer ChaCha20-Poly1305 (common in Rust QUIC)
    cipher_suites = [
        0x13, 0x03,  # TLS_CHACHA20_POLY1305_SHA256
        0x13, 0x01,  # TLS_AES_128_GCM_SHA256
    ]
    push!(buf, 0x00, UInt8(length(cipher_suites)))
    append!(buf, cipher_suites)

    # Compression methods (null only)
    append!(buf, [0x01, 0x00])

    # Extensions
    ext_buf = UInt8[]

    # Supported versions (TLS 1.3 only)
    append!(ext_buf, [0x00, 0x2b])  # extension type
    append!(ext_buf, [0x00, 0x03])  # length
    append!(ext_buf, [0x02])        # list length
    append!(ext_buf, [0x03, 0x04])  # TLS 1.3

    # Supported groups (X25519)
    append!(ext_buf, [0x00, 0x0a])  # extension type
    append!(ext_buf, [0x00, 0x04])  # length
    append!(ext_buf, [0x00, 0x02])  # list length
    append!(ext_buf, [0x00, 0x1d])  # x25519

    # Key share (X25519 public key)
    append!(ext_buf, [0x00, 0x33])  # extension type
    ks_len = 2 + 2 + 32  # group + key_len + key
    append!(ext_buf, [0x00, UInt8(ks_len + 2)])  # extension length
    append!(ext_buf, [0x00, UInt8(ks_len)])  # key share length
    append!(ext_buf, [0x00, 0x1d])  # x25519 group
    append!(ext_buf, [0x00, 0x20])  # key length (32)
    append!(ext_buf, conn.x25519_public)

    # Signature algorithms (Ed25519 first - required for JAMNP-S)
    append!(ext_buf, [0x00, 0x0d])  # extension type
    append!(ext_buf, [0x00, 0x04])  # length
    append!(ext_buf, [0x00, 0x02])  # list length
    append!(ext_buf, [0x08, 0x07])  # Ed25519

    # ALPN
    alpn_bytes = Vector{UInt8}(conn.config.alpn)
    alpn_data_len = 1 + length(alpn_bytes)
    append!(ext_buf, [0x00, 0x10])  # extension type
    append!(ext_buf, [0x00, UInt8(alpn_data_len + 2)])  # extension length
    append!(ext_buf, [0x00, UInt8(alpn_data_len)])  # ALPN list length
    push!(ext_buf, UInt8(length(alpn_bytes)))
    append!(ext_buf, alpn_bytes)

    # QUIC transport parameters
    tp_buf = encode_transport_params(conn)
    append!(ext_buf, [0x00, 0x39])  # extension type
    append!(ext_buf, [UInt8((length(tp_buf) >> 8) & 0xff), UInt8(length(tp_buf) & 0xff)])
    append!(ext_buf, tp_buf)

    # Add extensions to message
    append!(buf, [UInt8((length(ext_buf) >> 8) & 0xff), UInt8(length(ext_buf) & 0xff)])
    append!(buf, ext_buf)

    # Update message length
    msg_len = length(buf) - 4
    buf[len_pos:len_pos+2] = [
        UInt8((msg_len >> 16) & 0xff),
        UInt8((msg_len >> 8) & 0xff),
        UInt8(msg_len & 0xff)
    ]

    return buf
end

function encode_transport_params(conn::QuicConnection)::Vector{UInt8}
    buf = UInt8[]

    function encode_param!(buf, id::UInt64, value::Vector{UInt8})
        encode_varint!(buf, VarInt(id))
        encode_varint!(buf, VarInt(length(value)))
        append!(buf, value)
    end

    function encode_varint_value(v::UInt64)
        b = UInt8[]
        encode_varint!(b, VarInt(v))
        return b
    end

    # initial_max_data (0x04)
    encode_param!(buf, UInt64(0x04), encode_varint_value(UInt64(10485760)))

    # initial_max_stream_data_bidi_local (0x05)
    encode_param!(buf, UInt64(0x05), encode_varint_value(UInt64(1048576)))

    # initial_max_stream_data_bidi_remote (0x06)
    encode_param!(buf, UInt64(0x06), encode_varint_value(UInt64(1048576)))

    # initial_max_stream_data_uni (0x07)
    encode_param!(buf, UInt64(0x07), encode_varint_value(UInt64(1048576)))

    # initial_max_streams_bidi (0x08)
    encode_param!(buf, UInt64(0x08), encode_varint_value(conn.config.max_streams))

    # initial_max_streams_uni (0x09)
    encode_param!(buf, UInt64(0x09), encode_varint_value(conn.config.max_streams))

    # max_idle_timeout (0x01)
    encode_param!(buf, UInt64(0x01), encode_varint_value(conn.config.idle_timeout_ms))

    # initial_source_connection_id (0x0f)
    encode_param!(buf, UInt64(0x0f), conn.local_cid.data)

    return buf
end

#= Packet Processing =#

"""
    process_packet!(conn::QuicConnection, data::Vector{UInt8})

Process a received QUIC datagram, which may contain coalesced packets.
"""
function process_packet!(conn::QuicConnection, data::Vector{UInt8})
    conn.last_activity = time_ns()

    if isempty(data)
        return
    end

    # Process coalesced packets
    offset = 1
    packet_num = 0

    while offset <= length(data)
        packet_num += 1
        remaining = @view data[offset:end]

        if isempty(remaining)
            break
        end

        first_byte = remaining[1]
        is_long_header = (first_byte & 0x80) != 0

        if is_long_header
            bytes_consumed = process_long_header_packet!(conn, remaining)
            if bytes_consumed <= 0
                break
            end
            offset += bytes_consumed
        else
            # Short header packets consume the rest
            process_short_header_packet!(conn, remaining)
            break
        end
    end
end

function process_long_header_packet!(conn::QuicConnection, data::AbstractVector{UInt8})::Int
    if length(data) < 7
        return 0
    end

    first_byte = data[1]
    packet_type = (first_byte & 0x30) >> 4

    # Version (4 bytes)
    version = ntoh(reinterpret(UInt32, collect(data[2:5]))[1])

    # DCID
    dcid_len = Int(data[6])
    if 7 + dcid_len > length(data)
        return 0
    end
    dcid = collect(data[7:6+dcid_len])

    # SCID
    scid_len = Int(data[7+dcid_len])
    if 8 + dcid_len + scid_len > length(data)
        return 0
    end
    scid = collect(data[8+dcid_len:7+dcid_len+scid_len])

    offset = 8 + dcid_len + scid_len

    if packet_type == 0  # Initial
        # Token length (varint)
        token_len_vi, token_next_pos = decode_varint(collect(data[offset:end]))
        if isnothing(token_len_vi)
            return 0
        end
        token_len = token_len_vi.value
        offset += token_next_pos - 1

        # Skip token
        offset += Int(token_len)

        # Payload length (varint)
        payload_len_vi, len_next_pos = decode_varint(collect(data[offset:end]))
        if isnothing(payload_len_vi)
            return 0
        end
        payload_len = payload_len_vi.value
        offset += len_next_pos - 1

        total_consumed = offset - 1 + Int(payload_len)

        # Update remote CID if needed
        if conn.remote_cid.data != scid
            conn.remote_cid = ConnectionId(scid)
        end

        # Decrypt and process
        if !isempty(conn.initial_secrets)
            process_initial_payload!(conn, collect(data), offset, payload_len)
        else
            derive_initial_secrets!(conn, dcid)
            process_initial_payload!(conn, collect(data), offset, payload_len)
        end

        return total_consumed

    elseif packet_type == 2  # Handshake
        # Payload length (varint) - no token for Handshake
        payload_len_vi, len_next_pos = decode_varint(collect(data[offset:end]))
        if isnothing(payload_len_vi)
            return 0
        end
        payload_len = payload_len_vi.value
        offset += len_next_pos - 1

        total_consumed = offset - 1 + Int(payload_len)

        if !isempty(conn.handshake_secrets)
            process_handshake_payload!(conn, collect(data), offset, payload_len)
        else
            # Buffer for later
            push!(conn.pending_handshake_packets, collect(data))
        end

        return total_consumed
    else
        return 0
    end
end

function process_initial_payload!(conn::QuicConnection, packet::Vector{UInt8}, pn_offset::Int, payload_len::UInt64)
    if pn_offset + payload_len - 1 > length(packet)
        return
    end

    # Get decryption keys
    key = conn.is_client ? conn.initial_secrets[:server_key] : conn.initial_secrets[:client_key]
    iv = conn.is_client ? conn.initial_secrets[:server_iv] : conn.initial_secrets[:client_iv]
    hp_key = conn.is_client ? conn.initial_secrets[:server_hp] : conn.initial_secrets[:client_hp]

    # Sample for header protection
    sample_offset = pn_offset + 4
    if sample_offset + 15 > length(packet)
        return
    end
    sample = packet[sample_offset:sample_offset+15]

    # Compute HP mask
    mask = Crypto.aes_header_protection_mask(hp_key, sample, AES128GCM())

    # Unprotect first byte
    first_byte_unprotected = packet[1] ⊻ (mask[1] & 0x0f)
    pn_len = 1 + (first_byte_unprotected & 0x03)

    # Unprotect packet number
    pn = UInt64(0)
    for i in 1:pn_len
        pn_byte = packet[pn_offset + i - 1] ⊻ mask[1 + i]
        pn = (pn << 8) | UInt64(pn_byte)
    end

    # Build AAD
    aad = copy(packet[1:pn_offset + pn_len - 1])
    aad[1] = first_byte_unprotected
    for i in 1:pn_len
        aad[pn_offset + i - 1] = packet[pn_offset + i - 1] ⊻ mask[1 + i]
    end

    # Decrypt
    ciphertext_start = pn_offset + pn_len
    ciphertext_end = pn_offset + Int(payload_len) - 1
    if ciphertext_end > length(packet)
        ciphertext_end = length(packet)
    end
    ciphertext = packet[ciphertext_start:ciphertext_end]

    try
        plaintext = Crypto.decrypt_aes_gcm(ciphertext, key, iv, pn, aad, AES128GCM())
        process_frames!(conn, plaintext)
    catch e
        @warn "QUIC: Initial decryption failed" exception=e
    end
end

function process_handshake_payload!(conn::QuicConnection, packet::Vector{UInt8}, pn_offset::Int, payload_len::UInt64)
    if pn_offset + payload_len - 1 > length(packet)
        return
    end

    key = conn.is_client ? conn.handshake_secrets[:server_key] : conn.handshake_secrets[:client_key]
    iv = conn.is_client ? conn.handshake_secrets[:server_iv] : conn.handshake_secrets[:client_iv]
    hp_key = conn.is_client ? conn.handshake_secrets[:server_hp] : conn.handshake_secrets[:client_hp]

    sample_offset = pn_offset + 4
    if sample_offset + 15 > length(packet)
        return
    end
    sample = packet[sample_offset:sample_offset+15]

    mask = Crypto.aes_header_protection_mask(hp_key, sample, AES128GCM())

    first_byte_unprotected = packet[1] ⊻ (mask[1] & 0x0f)
    pn_len = 1 + (first_byte_unprotected & 0x03)

    pn = UInt64(0)
    for i in 1:pn_len
        pn_byte = packet[pn_offset + i - 1] ⊻ mask[1 + i]
        pn = (pn << 8) | UInt64(pn_byte)
    end

    aad = copy(packet[1:pn_offset + pn_len - 1])
    aad[1] = first_byte_unprotected
    for i in 1:pn_len
        aad[pn_offset + i - 1] = packet[pn_offset + i - 1] ⊻ mask[1 + i]
    end

    ciphertext_start = pn_offset + pn_len
    ciphertext_end = pn_offset + Int(payload_len) - 1
    if ciphertext_end > length(packet)
        ciphertext_end = length(packet)
    end
    ciphertext = packet[ciphertext_start:ciphertext_end]

    try
        plaintext = Crypto.decrypt_aes_gcm(ciphertext, key, iv, pn, aad, AES128GCM())
        process_frames!(conn, plaintext)
    catch e
        @warn "QUIC: Handshake decryption failed" exception=e
    end
end

function process_short_header_packet!(conn::QuicConnection, data::Vector{UInt8})
    # 1-RTT packet processing
    if conn.state != CONNECTED
        return
    end
    # TODO: decrypt with application keys
end

function process_frames!(conn::QuicConnection, data::Vector{UInt8})
    offset = 1

    while offset <= length(data)
        frame_type = data[offset]

        if frame_type == 0x00  # PADDING
            offset += 1
        elseif frame_type == 0x06  # CRYPTO
            crypto_offset, offset = decode_varint_at(data, offset + 1)
            crypto_len, offset = decode_varint_at(data, offset)

            if offset + crypto_len - 1 <= length(data)
                crypto_data = data[offset:offset+Int(crypto_len)-1]
                offset += Int(crypto_len)
                process_crypto_frame!(conn, crypto_data)
            else
                break
            end
        elseif frame_type == 0x02  # ACK
            break  # Skip ACK for now
        else
            break
        end
    end
end

function decode_varint_at(data::Vector{UInt8}, offset::Int)
    val, next_pos = decode_varint(data[offset:end])
    return val.value, offset + next_pos - 1
end

function process_crypto_frame!(conn::QuicConnection, data::Vector{UInt8})
    if isempty(data)
        return
    end

    msg_type = data[1]

    if msg_type == 0x02  # ServerHello
        process_server_hello!(conn, data)
    elseif msg_type == 0x08  # EncryptedExtensions
        process_encrypted_extensions!(conn, data)
    elseif msg_type == 0x0d  # CertificateRequest
        process_certificate_request!(conn, data)
    elseif msg_type == 0x0b  # Certificate
        process_certificate!(conn, data)
    elseif msg_type == 0x0f  # CertificateVerify
        process_certificate_verify!(conn, data)
    elseif msg_type == 0x14  # Finished
        process_finished!(conn, data)
    end
end

function process_server_hello!(conn::QuicConnection, data::Vector{UInt8})
    push!(conn.handshake.messages, data)

    msg_len = (UInt32(data[2]) << 16) | (UInt32(data[3]) << 8) | UInt32(data[4])

    conn.handshake.server_random = data[7:38]

    # Find key_share extension
    offset = 39
    session_id_len = data[offset]
    offset += 1 + session_id_len
    offset += 2  # cipher_suite
    offset += 1  # compression

    ext_len = (UInt16(data[offset]) << 8) | UInt16(data[offset+1])
    offset += 2

    while offset < 4 + msg_len
        ext_type = (UInt16(data[offset]) << 8) | UInt16(data[offset+1])
        offset += 2
        ext_data_len = (UInt16(data[offset]) << 8) | UInt16(data[offset+1])
        offset += 2

        if ext_type == 0x0033  # key_share
            group = (UInt16(data[offset]) << 8) | UInt16(data[offset+1])
            key_len = (UInt16(data[offset+2]) << 8) | UInt16(data[offset+3])
            conn.peer_x25519_public = data[offset+4:offset+3+key_len]

            conn.shared_secret = X25519.compute_shared_secret(conn.x25519_private, conn.peer_x25519_public)
            println("QUIC: Computed ECDHE shared secret")
        end

        offset += ext_data_len
    end

    if conn.shared_secret !== nothing
        derive_handshake_secrets!(conn)
    end

    conn.handshake.state = :wait_ee
    println("QUIC: Processed ServerHello")
end

function process_encrypted_extensions!(conn::QuicConnection, data::Vector{UInt8})
    push!(conn.handshake.messages, data)
    conn.handshake.state = :wait_cert
    println("QUIC: Processed EncryptedExtensions")
end

function process_certificate_request!(conn::QuicConnection, data::Vector{UInt8})
    push!(conn.handshake.messages, data)
    println("QUIC: Server requested client certificate")
end

function process_certificate!(conn::QuicConnection, data::Vector{UInt8})
    push!(conn.handshake.messages, data)

    certs = Handshake.process_server_certificate(data[5:end])

    if !isempty(certs)
        # Extract peer's public key from certificate
        conn.peer_pubkey = X509.extract_public_key(certs[1])
        if conn.peer_pubkey !== nothing
            println("QUIC: Extracted peer public key from certificate")
        end
    end

    conn.handshake.state = :wait_cv
    println("QUIC: Processed server Certificate")
end

function process_certificate_verify!(conn::QuicConnection, data::Vector{UInt8})
    push!(conn.handshake.messages, data)

    sig_algo, signature = Handshake.process_server_certificate_verify(data[5:end])

    # Verify signature
    cv_msg = pop!(conn.handshake.messages)
    transcript_hash = Handshake.compute_transcript_hash(conn.handshake)
    push!(conn.handshake.messages, cv_msg)

    if conn.peer_pubkey !== nothing
        context = b"TLS 1.3, server CertificateVerify"
        signed_content = vcat(
            fill(0x20, 64),
            context,
            [0x00],
            transcript_hash
        )

        valid = Ed25519.verify(signature, signed_content, conn.peer_pubkey)
        if !valid
            error("QUIC: CertificateVerify signature verification failed")
        end
    end

    conn.handshake.state = :wait_fin
    println("QUIC: Verified server CertificateVerify")
end

function process_finished!(conn::QuicConnection, data::Vector{UInt8})
    push!(conn.handshake.messages, data)

    received_verify_data = data[5:end]

    fin_msg = pop!(conn.handshake.messages)
    transcript_hash = Handshake.compute_transcript_hash(conn.handshake)
    push!(conn.handshake.messages, fin_msg)

    server_secret = conn.handshake_secrets[:server_secret]
    finished_key = Crypto.hkdf_expand_label(server_secret, "finished", UInt8[], 32)
    expected_verify_data = Crypto.hmac_sha256(finished_key, transcript_hash)

    # Constant-time comparison
    if length(received_verify_data) != length(expected_verify_data)
        error("QUIC: Finished message length mismatch")
    end

    diff = UInt8(0)
    for i in 1:length(expected_verify_data)
        diff |= received_verify_data[i] ⊻ expected_verify_data[i]
    end
    if diff != 0
        error("QUIC: Finished message verification failed")
    end

    # Derive application secrets
    derive_application_secrets!(conn)

    # Send client auth if we have a certificate
    if conn.config.ed25519_keypair !== nothing && conn.config.certificate !== nothing
        send_client_auth!(conn)
    end

    # Connection established
    conn.state = CONNECTED

    println("QUIC: Connection established!")

    if conn.on_connected !== nothing
        conn.on_connected(conn)
    end
end

#= Client Authentication =#

function send_client_auth!(conn::QuicConnection)
    # Certificate message
    cert_msg = Handshake.create_certificate_message([conn.config.certificate])
    push!(conn.handshake.messages, cert_msg)

    # CertificateVerify message
    transcript_hash = Handshake.compute_transcript_hash(conn.handshake)
    cv_msg = Handshake.create_certificate_verify_message(
        conn.config.ed25519_keypair,
        transcript_hash;
        is_server=false
    )
    push!(conn.handshake.messages, cv_msg)

    # Finished message
    client_secret = conn.handshake_secrets[:client_secret]
    transcript_hash = Handshake.compute_transcript_hash(conn.handshake)
    fin_msg = Handshake.create_finished_message(client_secret, transcript_hash)
    push!(conn.handshake.messages, fin_msg)

    # Send all in Handshake packet
    all_data = vcat(cert_msg, cv_msg, fin_msg)
    crypto_frame = CryptoFrame(0, all_data)
    send_handshake_packet!(conn, crypto_frame)

    println("QUIC: Sent client Certificate, CertificateVerify, Finished")
end

#= Key Derivation =#

function derive_initial_secrets!(conn::QuicConnection, dcid::Vector{UInt8})
    initial_salt = hex2bytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

    initial_secret = Crypto.hkdf_extract(dcid, initial_salt)

    client_secret = Crypto.hkdf_expand_label(initial_secret, "client in", UInt8[], 32)
    server_secret = Crypto.hkdf_expand_label(initial_secret, "server in", UInt8[], 32)

    conn.initial_secrets[:client_key] = Crypto.hkdf_expand_label(client_secret, "quic key", UInt8[], 16)
    conn.initial_secrets[:client_iv] = Crypto.hkdf_expand_label(client_secret, "quic iv", UInt8[], 12)
    conn.initial_secrets[:client_hp] = Crypto.hkdf_expand_label(client_secret, "quic hp", UInt8[], 16)

    conn.initial_secrets[:server_key] = Crypto.hkdf_expand_label(server_secret, "quic key", UInt8[], 16)
    conn.initial_secrets[:server_iv] = Crypto.hkdf_expand_label(server_secret, "quic iv", UInt8[], 12)
    conn.initial_secrets[:server_hp] = Crypto.hkdf_expand_label(server_secret, "quic hp", UInt8[], 16)
end

function derive_handshake_secrets!(conn::QuicConnection)
    early_secret = Crypto.hkdf_extract(zeros(UInt8, 32), zeros(UInt8, 32))
    derived = Crypto.hkdf_expand_label(early_secret, "derived", sha256(UInt8[]), 32)
    handshake_secret = Crypto.hkdf_extract(conn.shared_secret, derived)

    transcript_hash = Handshake.compute_transcript_hash(conn.handshake)

    client_secret = Crypto.hkdf_expand_label(handshake_secret, "c hs traffic", transcript_hash, 32)
    server_secret = Crypto.hkdf_expand_label(handshake_secret, "s hs traffic", transcript_hash, 32)

    conn.handshake_secrets[:client_key] = Crypto.hkdf_expand_label(client_secret, "quic key", UInt8[], 16)
    conn.handshake_secrets[:client_iv] = Crypto.hkdf_expand_label(client_secret, "quic iv", UInt8[], 12)
    conn.handshake_secrets[:client_hp] = Crypto.hkdf_expand_label(client_secret, "quic hp", UInt8[], 16)
    conn.handshake_secrets[:client_secret] = client_secret

    conn.handshake_secrets[:server_key] = Crypto.hkdf_expand_label(server_secret, "quic key", UInt8[], 16)
    conn.handshake_secrets[:server_iv] = Crypto.hkdf_expand_label(server_secret, "quic iv", UInt8[], 12)
    conn.handshake_secrets[:server_hp] = Crypto.hkdf_expand_label(server_secret, "quic hp", UInt8[], 16)
    conn.handshake_secrets[:server_secret] = server_secret

    conn.handshake_secrets[:handshake_secret] = handshake_secret

    println("QUIC: Derived handshake secrets")

    # Process buffered packets
    if !isempty(conn.pending_handshake_packets)
        println("QUIC: Processing $(length(conn.pending_handshake_packets)) buffered Handshake packets")
        for packet in conn.pending_handshake_packets
            process_buffered_handshake_packet!(conn, packet)
        end
        empty!(conn.pending_handshake_packets)
    end
end

function process_buffered_handshake_packet!(conn::QuicConnection, data::Vector{UInt8})
    if length(data) < 7
        return
    end

    first_byte = data[1]
    packet_type = (first_byte & 0x30) >> 4

    if packet_type != 2
        return
    end

    dcid_len = Int(data[6])
    scid_len = Int(data[7 + dcid_len])
    offset = 8 + dcid_len + scid_len

    payload_len_vi, len_next_pos = decode_varint(data[offset:end])
    if isnothing(payload_len_vi)
        return
    end
    payload_len = payload_len_vi.value
    offset += len_next_pos - 1

    process_handshake_payload!(conn, data, offset, payload_len)
end

function derive_application_secrets!(conn::QuicConnection)
    handshake_secret = conn.handshake_secrets[:handshake_secret]
    derived = Crypto.hkdf_expand_label(handshake_secret, "derived", sha256(UInt8[]), 32)
    master_secret = Crypto.hkdf_extract(zeros(UInt8, 32), derived)

    transcript_hash = Handshake.compute_transcript_hash(conn.handshake)

    client_secret = Crypto.hkdf_expand_label(master_secret, "c ap traffic", transcript_hash, 32)
    server_secret = Crypto.hkdf_expand_label(master_secret, "s ap traffic", transcript_hash, 32)

    conn.application_secrets[:client_key] = Crypto.hkdf_expand_label(client_secret, "quic key", UInt8[], 16)
    conn.application_secrets[:client_iv] = Crypto.hkdf_expand_label(client_secret, "quic iv", UInt8[], 12)
    conn.application_secrets[:client_hp] = Crypto.hkdf_expand_label(client_secret, "quic hp", UInt8[], 16)

    conn.application_secrets[:server_key] = Crypto.hkdf_expand_label(server_secret, "quic key", UInt8[], 16)
    conn.application_secrets[:server_iv] = Crypto.hkdf_expand_label(server_secret, "quic iv", UInt8[], 12)
    conn.application_secrets[:server_hp] = Crypto.hkdf_expand_label(server_secret, "quic hp", UInt8[], 16)
end

#= Packet Sending =#

function send_initial_packet!(conn::QuicConnection, frame::CryptoFrame)
    header = UInt8[]

    # Long header: Initial
    push!(header, 0xc1)  # Long header + Initial + 2-byte PN

    # Version
    append!(header, reinterpret(UInt8, [hton(UInt32(0x00000001))]))

    # DCID
    push!(header, UInt8(length(conn.remote_cid.data)))
    append!(header, conn.remote_cid.data)

    # SCID
    push!(header, UInt8(length(conn.local_cid.data)))
    append!(header, conn.local_cid.data)

    # Token (empty for client)
    push!(header, 0x00)

    # Encode frame
    payload = UInt8[]
    Frame.encode_frame!(payload, frame)

    # Pad to 1200 bytes
    while length(header) + 2 + 2 + length(payload) + 16 < 1200
        push!(payload, 0x00)
    end

    # Get keys
    key = conn.is_client ? conn.initial_secrets[:client_key] : conn.initial_secrets[:server_key]
    iv = conn.is_client ? conn.initial_secrets[:client_iv] : conn.initial_secrets[:server_iv]
    hp_key = conn.is_client ? conn.initial_secrets[:client_hp] : conn.initial_secrets[:server_hp]

    # Packet number
    pn = conn.next_pn
    conn.next_pn += 1
    pn_len = 2

    # Length field
    length_value = pn_len + length(payload) + 16
    len_buf = UInt8[]
    encode_varint!(len_buf, VarInt(length_value))
    append!(header, len_buf)

    # Packet number offset
    pn_offset = length(header) + 1

    # Append PN
    push!(header, UInt8((pn >> 8) & 0xff))
    push!(header, UInt8(pn & 0xff))

    # AAD
    aad = copy(header)

    # Encrypt
    ciphertext_with_tag = Crypto.encrypt_aes_gcm(payload, key, iv, pn, aad, AES128GCM())

    # Build packet
    packet = vcat(header, ciphertext_with_tag)

    # Apply header protection
    sample_start_idx = pn_offset + 4
    if sample_start_idx + 15 <= length(packet)
        sample = packet[sample_start_idx : sample_start_idx + 15]
        mask = Crypto.aes_header_protection_mask(hp_key, sample, AES128GCM())

        packet[1] ⊻= mask[1] & 0x0f
        for i in 1:pn_len
            packet[pn_offset + i - 1] ⊻= mask[i + 1]
        end
    end

    # Send
    if conn.remote_addr !== nothing
        send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, packet)
        println("QUIC: Sent Initial packet ($(length(packet)) bytes)")
    end
end

function send_handshake_packet!(conn::QuicConnection, frame::CryptoFrame)
    header = UInt8[]

    # Long header: Handshake
    push!(header, 0xe1)  # Long header + Handshake + 2-byte PN

    # Version
    append!(header, reinterpret(UInt8, [hton(UInt32(0x00000001))]))

    # DCID
    push!(header, UInt8(length(conn.remote_cid.data)))
    append!(header, conn.remote_cid.data)

    # SCID
    push!(header, UInt8(length(conn.local_cid.data)))
    append!(header, conn.local_cid.data)

    # Encode frame
    payload = UInt8[]
    Frame.encode_frame!(payload, frame)

    # Get keys
    key = conn.is_client ? conn.handshake_secrets[:client_key] : conn.handshake_secrets[:server_key]
    iv = conn.is_client ? conn.handshake_secrets[:client_iv] : conn.handshake_secrets[:server_iv]
    hp_key = conn.is_client ? conn.handshake_secrets[:client_hp] : conn.handshake_secrets[:server_hp]

    # Packet number
    pn = conn.next_pn
    conn.next_pn += 1
    pn_len = 2

    # Length field
    length_value = pn_len + length(payload) + 16
    len_buf = UInt8[]
    encode_varint!(len_buf, VarInt(length_value))
    append!(header, len_buf)

    pn_offset = length(header) + 1

    push!(header, UInt8((pn >> 8) & 0xff))
    push!(header, UInt8(pn & 0xff))

    aad = copy(header)

    ciphertext_with_tag = Crypto.encrypt_aes_gcm(payload, key, iv, pn, aad, AES128GCM())

    packet = vcat(header, ciphertext_with_tag)

    sample_start_idx = pn_offset + 4
    if sample_start_idx + 15 <= length(packet)
        sample = packet[sample_start_idx : sample_start_idx + 15]
        mask = Crypto.aes_header_protection_mask(hp_key, sample, AES128GCM())

        packet[1] ⊻= mask[1] & 0x0f
        for i in 1:pn_len
            packet[pn_offset + i - 1] ⊻= mask[i + 1]
        end
    end

    if conn.remote_addr !== nothing
        send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, packet)
        println("QUIC: Sent Handshake packet ($(length(packet)) bytes)")
    end
end

#= Stream API =#

"""
    open_stream!(conn::QuicConnection, bidirectional::Bool=true) -> UInt64

Open a new QUIC stream and return the stream ID.
"""
function open_stream!(conn::QuicConnection, bidirectional::Bool=true)::UInt64
    stream_id = conn.next_stream_id
    conn.next_stream_id += 4  # Increment by 4 for next client-initiated stream
    return stream_id
end

"""
    send_stream_data!(conn::QuicConnection, stream_id::UInt64, data::Vector{UInt8}, fin::Bool=false)

Send data on a stream.
"""
function send_stream_data!(conn::QuicConnection, stream_id::UInt64, data::Vector{UInt8}, fin::Bool=false)
    if conn.state != CONNECTED
        error("Connection not established")
    end

    frame = StreamFrame(stream_id, 0, data, fin)
    send_application_packet!(conn, frame)
end

function send_application_packet!(conn::QuicConnection, frame::Frame.QuicFrame)
    buf = UInt8[]

    # Short header
    push!(buf, 0x41)  # Fixed bit + 2-byte PN
    append!(buf, conn.remote_cid.data)

    # Packet number
    pn = conn.next_pn
    conn.next_pn += 1
    push!(buf, UInt8((pn >> 8) & 0xff))
    push!(buf, UInt8(pn & 0xff))

    # Encode frame
    payload = UInt8[]
    Frame.encode_frame!(payload, frame)

    # Get keys
    key = conn.is_client ? conn.application_secrets[:client_key] : conn.application_secrets[:server_key]
    iv = conn.is_client ? conn.application_secrets[:client_iv] : conn.application_secrets[:server_iv]
    hp_key = conn.is_client ? conn.application_secrets[:client_hp] : conn.application_secrets[:server_hp]

    pn_offset = 1 + length(conn.remote_cid.data) + 1  # First byte + DCID + 1

    aad = copy(buf)
    ciphertext_with_tag = Crypto.encrypt_aes_gcm(payload, key, iv, pn, aad, AES128GCM())

    packet = vcat(buf, ciphertext_with_tag)

    # Apply header protection
    sample_start_idx = pn_offset + 4
    if sample_start_idx + 15 <= length(packet)
        sample = packet[sample_start_idx : sample_start_idx + 15]
        mask = Crypto.aes_header_protection_mask(hp_key, sample, AES128GCM())

        packet[1] ⊻= mask[1] & 0x1f  # 5 bits for short header
        for i in 1:2
            packet[pn_offset + i - 1] ⊻= mask[i + 1]
        end
    end

    if conn.remote_addr !== nothing
        send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, packet)
    end
end

"""
    close!(conn::QuicConnection)

Close the QUIC connection.
"""
function close!(conn::QuicConnection)
    if conn.state == CONNECTED || conn.state == HANDSHAKING
        conn.state = CLOSING
        # TODO: Send CONNECTION_CLOSE frame
        conn.state = CLOSED
        Base.close(conn.socket)
    end
end

end # module QuicClient
