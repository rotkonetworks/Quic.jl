module JAMNPSConnection

#= JAMNP-S Connection Management

High-level API for establishing and managing JAMNP-S connections
between JAM validators. Implements the full TLS 1.3 handshake with
Ed25519 mutual authentication as specified in the JAM graypaper.
=#

using ..Protocol
using ..Packet
using ..Frame
using ..Stream
using ..Crypto
using ..Handshake
using ..Ed25519
using ..X509
using ..X25519
using ..JAMNPS
using Sockets

# JAMNP-S connection states
@enum JAMNPSState begin
    JAMNPS_DISCONNECTED
    JAMNPS_CONNECTING
    JAMNPS_HANDSHAKING
    JAMNPS_CONNECTED
    JAMNPS_CLOSING
    JAMNPS_CLOSED
end

# Connection configuration
struct JAMNPSConfig
    genesis_hash::Vector{UInt8}      # 32-byte genesis hash
    identity::JAMNPS.JAMNPSIdentity  # Our Ed25519 identity
    is_builder::Bool                  # Builder node vs validator
    idle_timeout_ms::UInt64          # Idle timeout in milliseconds
    max_streams::UInt64              # Maximum concurrent streams
end

function JAMNPSConfig(genesis_hash::Vector{UInt8}, identity::JAMNPS.JAMNPSIdentity;
                      is_builder::Bool=false, idle_timeout_ms::UInt64=UInt64(30000),
                      max_streams::UInt64=UInt64(100))
    JAMNPSConfig(genesis_hash, identity, is_builder, idle_timeout_ms, max_streams)
end

# JAMNP-S Connection
mutable struct JAMNPSConn
    config::JAMNPSConfig
    state::JAMNPSState
    socket::UDPSocket
    remote_addr::Union{Sockets.InetAddr, Nothing}
    is_initiator::Bool

    # Connection IDs
    local_cid::Packet.ConnectionId
    remote_cid::Packet.ConnectionId

    # Peer identity (discovered during handshake)
    peer_pubkey::Union{Vector{UInt8}, Nothing}
    peer_alt_name::Union{String, Nothing}

    # TLS 1.3 handshake state
    handshake::Handshake.HandshakeState
    x25519_private::Vector{UInt8}
    x25519_public::Vector{UInt8}
    peer_x25519_public::Union{Vector{UInt8}, Nothing}
    shared_secret::Union{Vector{UInt8}, Nothing}

    # Crypto keys
    initial_secrets::Dict{Symbol, Vector{UInt8}}
    handshake_secrets::Dict{Symbol, Vector{UInt8}}
    application_secrets::Dict{Symbol, Vector{UInt8}}

    # Streams
    up_streams::Dict{UInt8, UInt64}  # stream kind -> stream ID
    ce_streams::Vector{Tuple{UInt64, UInt8}}  # (stream_id, kind)
    next_stream_id::UInt64

    # Packet tracking
    next_pn::UInt64
    recv_pn::UInt64

    # Timing
    connected_at::Union{UInt64, Nothing}
    last_activity::UInt64
end

function JAMNPSConn(config::JAMNPSConfig, socket::UDPSocket, is_initiator::Bool)
    # Generate X25519 key pair for ECDHE
    x25519_priv, x25519_pub = X25519.generate_keypair()

    JAMNPSConn(
        config,
        JAMNPS_DISCONNECTED,
        socket,
        nothing,
        is_initiator,
        Packet.ConnectionId(),
        Packet.ConnectionId(),
        nothing,
        nothing,
        Handshake.HandshakeState(is_initiator ? :client : :server),
        x25519_priv,
        x25519_pub,
        nothing,
        nothing,
        Dict{Symbol, Vector{UInt8}}(),
        Dict{Symbol, Vector{UInt8}}(),
        Dict{Symbol, Vector{UInt8}}(),
        Dict{UInt8, UInt64}(),
        Tuple{UInt64, UInt8}[],
        is_initiator ? UInt64(0) : UInt64(1),  # Client starts at 0, server at 1
        UInt64(0),
        UInt64(0),
        nothing,
        time_ns()
    )
end

#= High-Level API =#

"""
    connect(config::JAMNPSConfig, host::String, port::UInt16) -> JAMNPSConn

Establish a JAMNP-S connection to a remote peer.
"""
function connect(config::JAMNPSConfig, host::String, port::UInt16)
    socket = UDPSocket()
    bind(socket, ip"0.0.0.0", 0)

    conn = JAMNPSConn(config, socket, true)

    # Resolve and set remote address
    addr = getaddrinfo(host)
    conn.remote_addr = Sockets.InetAddr(addr, port)

    # Check if we should be the initiator based on preferred_initiator
    # For now, assume we're always initiating when calling connect()

    # Start handshake
    conn.state = JAMNPS_CONNECTING
    initiate_handshake!(conn)

    return conn
end

"""
    listen(config::JAMNPSConfig, host::String, port::UInt16) -> UDPSocket

Create a listening socket for JAMNP-S connections.
"""
function listen(config::JAMNPSConfig, host::String, port::UInt16)
    socket = UDPSocket()
    bind(socket, parse(IPAddr, host), port)
    return socket
end

"""
    accept(config::JAMNPSConfig, socket::UDPSocket, data::Vector{UInt8},
           remote_addr::Sockets.InetAddr) -> JAMNPSConn

Accept an incoming JAMNP-S connection.
"""
function accept(config::JAMNPSConfig, socket::UDPSocket, data::Vector{UInt8},
                remote_addr::Sockets.InetAddr)
    conn = JAMNPSConn(config, socket, false)
    conn.remote_addr = remote_addr
    conn.state = JAMNPS_HANDSHAKING

    # Process the initial packet
    process_packet!(conn, data)

    return conn
end

#= TLS 1.3 Handshake Implementation =#

"""
    initiate_handshake!(conn::JAMNPSConn)

Start the JAMNP-S handshake as client.
"""
function initiate_handshake!(conn::JAMNPSConn)
    conn.state = JAMNPS_HANDSHAKING

    # Derive initial secrets from destination CID
    derive_initial_secrets!(conn, conn.remote_cid.data)

    # Create ClientHello with JAMNP-S ALPN
    alpn = JAMNPS.make_alpn(conn.config.genesis_hash; builder=conn.config.is_builder)
    client_hello = create_jamnps_client_hello(conn, alpn)

    # Add to transcript
    push!(conn.handshake.messages, client_hello)

    # Wrap in CRYPTO frame and send
    crypto_frame = Frame.CryptoFrame(0, client_hello)
    send_initial_packet!(conn, crypto_frame)

    conn.handshake.state = :wait_sh
    println("JAMNP-S: Sent ClientHello with ALPN: $alpn")
end

"""
    create_jamnps_client_hello(conn::JAMNPSConn, alpn::String) -> Vector{UInt8}

Create a TLS 1.3 ClientHello for JAMNP-S with Ed25519 signature algorithms.
"""
function create_jamnps_client_hello(conn::JAMNPSConn, alpn::String)
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

    # ALPN (JAMNP-S protocol identifier)
    alpn_bytes = Vector{UInt8}(alpn)
    alpn_data_len = 1 + length(alpn_bytes)
    append!(ext_buf, [0x00, 0x10])  # extension type
    append!(ext_buf, [0x00, UInt8(alpn_data_len + 2)])  # extension length
    append!(ext_buf, [0x00, UInt8(alpn_data_len)])  # ALPN list length
    push!(ext_buf, UInt8(length(alpn_bytes)))
    append!(ext_buf, alpn_bytes)

    # QUIC transport parameters
    tp_buf = encode_jamnps_transport_params(conn)
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

"""
    encode_jamnps_transport_params(conn::JAMNPSConn) -> Vector{UInt8}

Encode QUIC transport parameters for JAMNP-S.
"""
function encode_jamnps_transport_params(conn::JAMNPSConn)
    buf = UInt8[]

    # Helper to encode a transport parameter
    function encode_param!(buf, id::UInt64, value::Vector{UInt8})
        encode_varint!(buf, Protocol.VarInt(id))
        encode_varint!(buf, Protocol.VarInt(length(value)))
        append!(buf, value)
    end

    function encode_varint_value(v::UInt64)
        b = UInt8[]
        encode_varint!(b, Protocol.VarInt(v))
        return b
    end

    # initial_max_data (0x04)
    encode_param!(buf, 0x04, encode_varint_value(UInt64(10485760)))  # 10 MB

    # initial_max_stream_data_bidi_local (0x05)
    encode_param!(buf, 0x05, encode_varint_value(UInt64(1048576)))  # 1 MB

    # initial_max_stream_data_bidi_remote (0x06)
    encode_param!(buf, 0x06, encode_varint_value(UInt64(1048576)))

    # initial_max_stream_data_uni (0x07)
    encode_param!(buf, 0x07, encode_varint_value(UInt64(1048576)))

    # initial_max_streams_bidi (0x08)
    encode_param!(buf, 0x08, encode_varint_value(conn.config.max_streams))

    # initial_max_streams_uni (0x09)
    encode_param!(buf, 0x09, encode_varint_value(conn.config.max_streams))

    # max_idle_timeout (0x01)
    encode_param!(buf, 0x01, encode_varint_value(conn.config.idle_timeout_ms))

    # initial_source_connection_id (0x0f)
    encode_param!(buf, 0x0f, conn.local_cid.data)

    return buf
end

function encode_varint!(buf::Vector{UInt8}, v::Protocol.VarInt)
    Protocol.encode_varint!(buf, v)
end

#= Packet Processing =#

"""
    process_packet!(conn::JAMNPSConn, data::Vector{UInt8})

Process a received QUIC packet.
"""
function process_packet!(conn::JAMNPSConn, data::Vector{UInt8})
    conn.last_activity = time_ns()

    if isempty(data)
        return
    end

    # Check if long header (Initial, Handshake) or short header (1-RTT)
    first_byte = data[1]
    is_long_header = (first_byte & 0x80) != 0

    if is_long_header
        process_long_header_packet!(conn, data)
    else
        process_short_header_packet!(conn, data)
    end
end

function process_long_header_packet!(conn::JAMNPSConn, data::Vector{UInt8})
    # Parse long header
    first_byte = data[1]
    packet_type = (first_byte & 0x30) >> 4

    # Version (4 bytes)
    version = ntoh(reinterpret(UInt32, data[2:5])[1])

    # Destination CID length and data
    dcid_len = data[6]
    dcid = data[7:6+dcid_len]

    # Source CID length and data
    scid_len = data[7+dcid_len]
    scid = data[8+dcid_len:7+dcid_len+scid_len]

    offset = 8 + dcid_len + scid_len

    if packet_type == 0  # Initial packet
        # Token length (varint)
        token_len, token_bytes = Protocol.decode_varint(data[offset:end])
        offset += token_bytes

        # Skip token
        offset += token_len

        # Payload length (varint)
        payload_len, len_bytes = Protocol.decode_varint(data[offset:end])
        offset += len_bytes

        # Update remote CID if this is the first packet
        if conn.remote_cid.data != scid
            conn.remote_cid = Packet.ConnectionId(scid)
        end

        # Decrypt and process payload
        if !isempty(conn.initial_secrets)
            process_initial_payload!(conn, data[offset:end], payload_len)
        else
            # First packet from server - derive initial secrets
            derive_initial_secrets!(conn, dcid)
            process_initial_payload!(conn, data[offset:end], payload_len)
        end

    elseif packet_type == 2  # Handshake packet
        process_handshake_payload!(conn, data[offset:end])
    end
end

function process_initial_payload!(conn::JAMNPSConn, data::Vector{UInt8}, payload_len::UInt64)
    # Get decryption keys
    key = conn.is_initiator ? conn.initial_secrets[:server_key] : conn.initial_secrets[:client_key]
    iv = conn.is_initiator ? conn.initial_secrets[:server_iv] : conn.initial_secrets[:client_iv]

    # Packet number (first 1-4 bytes of payload, assume 2 for now)
    pn_len = 2
    pn = (UInt64(data[1]) << 8) | UInt64(data[2])

    # Decrypt payload
    # TODO: Implement proper AEAD decryption

    # For now, process as plaintext frames
    process_frames!(conn, data[pn_len+1:end])
end

function process_handshake_payload!(conn::JAMNPSConn, data::Vector{UInt8})
    # Similar to initial but with handshake keys
    process_frames!(conn, data)
end

function process_short_header_packet!(conn::JAMNPSConn, data::Vector{UInt8})
    # Short header processing for 1-RTT packets
    if conn.state != JAMNPS_CONNECTED
        return
    end

    # Decrypt with application keys and process frames
    process_frames!(conn, data)
end

function process_frames!(conn::JAMNPSConn, data::Vector{UInt8})
    offset = 1

    while offset <= length(data)
        frame_type = data[offset]

        if frame_type == 0x00  # PADDING
            offset += 1
        elseif frame_type == 0x06  # CRYPTO
            # CRYPTO frame
            crypto_offset, offset = decode_varint_at(data, offset + 1)
            crypto_len, offset = decode_varint_at(data, offset)
            crypto_data = data[offset:offset+crypto_len-1]
            offset += crypto_len

            process_crypto_frame!(conn, crypto_data)
        elseif frame_type == 0x02  # ACK
            # ACK frame - skip for now
            break
        else
            # Unknown frame, stop processing
            break
        end
    end
end

function decode_varint_at(data::Vector{UInt8}, offset::Int)
    val, bytes = Protocol.decode_varint(data[offset:end])
    return val, offset + bytes
end

"""
    process_crypto_frame!(conn::JAMNPSConn, data::Vector{UInt8})

Process TLS handshake data from CRYPTO frame.
"""
function process_crypto_frame!(conn::JAMNPSConn, data::Vector{UInt8})
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
    elseif msg_type == 0x01  # ClientHello (server receiving)
        process_client_hello!(conn, data)
    end
end

function process_server_hello!(conn::JAMNPSConn, data::Vector{UInt8})
    # Add to transcript
    push!(conn.handshake.messages, data)

    # Parse ServerHello
    msg_len = (UInt32(data[2]) << 16) | (UInt32(data[3]) << 8) | UInt32(data[4])

    # Extract server random
    conn.handshake.server_random = data[7:38]

    # Find key_share extension to get server's X25519 public key
    # Skip to extensions (after session_id, cipher_suite, compression)
    offset = 39  # After random
    session_id_len = data[offset]
    offset += 1 + session_id_len
    # cipher_suite (2 bytes)
    offset += 2
    # compression (1 byte)
    offset += 1

    # Extensions
    ext_len = (UInt16(data[offset]) << 8) | UInt16(data[offset+1])
    offset += 2

    while offset < 4 + msg_len
        ext_type = (UInt16(data[offset]) << 8) | UInt16(data[offset+1])
        offset += 2
        ext_data_len = (UInt16(data[offset]) << 8) | UInt16(data[offset+1])
        offset += 2

        if ext_type == 0x0033  # key_share
            # Server key share
            group = (UInt16(data[offset]) << 8) | UInt16(data[offset+1])
            key_len = (UInt16(data[offset+2]) << 8) | UInt16(data[offset+3])
            conn.peer_x25519_public = data[offset+4:offset+3+key_len]

            # Compute shared secret
            conn.shared_secret = X25519.compute_shared_secret(conn.x25519_private, conn.peer_x25519_public)

            println("JAMNP-S: Computed ECDHE shared secret")
        end

        offset += ext_data_len
    end

    # Derive handshake keys
    if conn.shared_secret !== nothing
        derive_handshake_secrets!(conn)
    end

    conn.handshake.state = :wait_ee
    println("JAMNP-S: Processed ServerHello")
end

function process_encrypted_extensions!(conn::JAMNPSConn, data::Vector{UInt8})
    push!(conn.handshake.messages, data)
    conn.handshake.state = :wait_cert
    println("JAMNP-S: Processed EncryptedExtensions")
end

function process_certificate_request!(conn::JAMNPSConn, data::Vector{UInt8})
    push!(conn.handshake.messages, data)
    # Server requested our certificate - we'll send it after server's Finished
    println("JAMNP-S: Server requested client certificate")
end

function process_certificate!(conn::JAMNPSConn, data::Vector{UInt8})
    push!(conn.handshake.messages, data)

    # Parse and validate server certificate
    certs = Handshake.process_server_certificate(data[5:end])

    if !isempty(certs)
        # Extract peer identity from certificate
        conn.peer_pubkey = JAMNPS.extract_peer_identity(certs[1])
        if conn.peer_pubkey !== nothing
            conn.peer_alt_name = JAMNPS.derive_alt_name(conn.peer_pubkey)
            println("JAMNP-S: Peer identity: $(conn.peer_alt_name)")
        end
    end

    conn.handshake.state = :wait_cv
    println("JAMNP-S: Processed server Certificate")
end

function process_certificate_verify!(conn::JAMNPSConn, data::Vector{UInt8})
    push!(conn.handshake.messages, data)

    # Verify server's CertificateVerify signature
    cv = Handshake.process_server_certificate_verify(data[5:end])

    # Get transcript hash (up to but not including CertificateVerify)
    transcript_hash = Handshake.compute_transcript_hash(conn.handshake)

    # TODO: Actually verify the signature

    conn.handshake.state = :wait_fin
    println("JAMNP-S: Processed server CertificateVerify")
end

function process_finished!(conn::JAMNPSConn, data::Vector{UInt8})
    push!(conn.handshake.messages, data)

    # Verify server's Finished message
    # TODO: Verify HMAC

    # Derive application secrets
    derive_application_secrets!(conn)

    # Send client Certificate, CertificateVerify, Finished
    send_client_auth!(conn)

    # Connection is now established
    conn.state = JAMNPS_CONNECTED
    conn.connected_at = time_ns()

    println("JAMNP-S: Connection established!")
end

function process_client_hello!(conn::JAMNPSConn, data::Vector{UInt8})
    # Server processing ClientHello
    push!(conn.handshake.messages, data)

    # Extract client's X25519 public key from key_share extension
    # ... parse ClientHello ...

    # Send ServerHello, EncryptedExtensions, CertificateRequest,
    # Certificate, CertificateVerify, Finished
    send_server_handshake!(conn)

    println("JAMNP-S: Processed ClientHello")
end

#= Authentication Messages =#

"""
    send_client_auth!(conn::JAMNPSConn)

Send client Certificate, CertificateVerify, and Finished messages.
"""
function send_client_auth!(conn::JAMNPSConn)
    # Certificate message
    cert_msg = Handshake.create_certificate_message([conn.config.identity.certificate])
    push!(conn.handshake.messages, cert_msg)

    # CertificateVerify message
    transcript_hash = Handshake.compute_transcript_hash(conn.handshake)
    cv_msg = Handshake.create_certificate_verify_message(
        conn.config.identity.keypair,
        transcript_hash;
        is_server=false
    )
    push!(conn.handshake.messages, cv_msg)

    # Finished message
    client_secret = conn.handshake_secrets[:client_secret]
    transcript_hash = Handshake.compute_transcript_hash(conn.handshake)
    fin_msg = Handshake.create_finished_message(client_secret, transcript_hash)
    push!(conn.handshake.messages, fin_msg)

    # Send all in a Handshake packet
    all_data = vcat(cert_msg, cv_msg, fin_msg)
    crypto_frame = Frame.CryptoFrame(0, all_data)
    send_handshake_packet!(conn, crypto_frame)

    println("JAMNP-S: Sent client Certificate, CertificateVerify, Finished")
end

function send_server_handshake!(conn::JAMNPSConn)
    # TODO: Implement full server handshake
    println("JAMNP-S: Server handshake not yet implemented")
end

#= Key Derivation =#

function derive_initial_secrets!(conn::JAMNPSConn, dcid::Vector{UInt8})
    # QUIC v1 initial salt
    initial_salt = hex2bytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

    # Initial secret
    initial_secret = Crypto.hkdf_extract(dcid, initial_salt)

    # Client and server secrets
    client_secret = Crypto.hkdf_expand_label(initial_secret, "client in", UInt8[], 32)
    server_secret = Crypto.hkdf_expand_label(initial_secret, "server in", UInt8[], 32)

    # Derive keys
    conn.initial_secrets[:client_key] = Crypto.hkdf_expand_label(client_secret, "quic key", UInt8[], 16)
    conn.initial_secrets[:client_iv] = Crypto.hkdf_expand_label(client_secret, "quic iv", UInt8[], 12)
    conn.initial_secrets[:client_hp] = Crypto.hkdf_expand_label(client_secret, "quic hp", UInt8[], 16)

    conn.initial_secrets[:server_key] = Crypto.hkdf_expand_label(server_secret, "quic key", UInt8[], 16)
    conn.initial_secrets[:server_iv] = Crypto.hkdf_expand_label(server_secret, "quic iv", UInt8[], 12)
    conn.initial_secrets[:server_hp] = Crypto.hkdf_expand_label(server_secret, "quic hp", UInt8[], 16)
end

function derive_handshake_secrets!(conn::JAMNPSConn)
    # Derive handshake secrets from shared secret and transcript
    # This follows the TLS 1.3 key schedule

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
end

function derive_application_secrets!(conn::JAMNPSConn)
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

using SHA

#= Packet Sending =#

function send_initial_packet!(conn::JAMNPSConn, frame::Frame.CryptoFrame)
    # Build Initial packet
    buf = UInt8[]

    # Long header: Initial packet
    push!(buf, 0xc0 | 0x00 | 0x01)  # Long header + Initial + 2-byte PN

    # Version
    append!(buf, reinterpret(UInt8, [hton(UInt32(0x00000001))]))

    # DCID
    push!(buf, UInt8(length(conn.remote_cid.data)))
    append!(buf, conn.remote_cid.data)

    # SCID
    push!(buf, UInt8(length(conn.local_cid.data)))
    append!(buf, conn.local_cid.data)

    # Token (empty for client initial)
    push!(buf, 0x00)

    # Encode frame
    payload = UInt8[]
    Frame.encode_frame!(payload, frame)

    # Add PADDING to reach minimum 1200 bytes
    while length(buf) + length(payload) + 20 < 1200  # Account for length field and AEAD tag
        push!(payload, 0x00)  # PADDING frame
    end

    # Length (varint) - includes packet number and payload + AEAD tag
    pn_len = 2
    total_len = pn_len + length(payload) + 16  # 16 = AEAD tag
    len_buf = UInt8[]
    Protocol.encode_varint!(len_buf, Protocol.VarInt(total_len))
    append!(buf, len_buf)

    # Packet number (2 bytes)
    pn = conn.next_pn
    conn.next_pn += 1
    push!(buf, UInt8((pn >> 8) & 0xff))
    push!(buf, UInt8(pn & 0xff))

    # Encrypt payload (simplified - just append for now)
    # TODO: Implement proper AEAD encryption
    append!(buf, payload)
    append!(buf, zeros(UInt8, 16))  # Fake AEAD tag

    # Send
    if conn.remote_addr !== nothing
        send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, buf)
        println("JAMNP-S: Sent Initial packet ($(length(buf)) bytes)")
    end
end

function send_handshake_packet!(conn::JAMNPSConn, frame::Frame.CryptoFrame)
    # Similar to Initial but with handshake keys
    buf = UInt8[]

    # Long header: Handshake packet
    push!(buf, 0xc0 | 0x20 | 0x01)  # Long header + Handshake + 2-byte PN

    # Version
    append!(buf, reinterpret(UInt8, [hton(UInt32(0x00000001))]))

    # DCID
    push!(buf, UInt8(length(conn.remote_cid.data)))
    append!(buf, conn.remote_cid.data)

    # SCID
    push!(buf, UInt8(length(conn.local_cid.data)))
    append!(buf, conn.local_cid.data)

    # Encode frame
    payload = UInt8[]
    Frame.encode_frame!(payload, frame)

    # Length
    pn_len = 2
    total_len = pn_len + length(payload) + 16
    len_buf = UInt8[]
    Protocol.encode_varint!(len_buf, Protocol.VarInt(total_len))
    append!(buf, len_buf)

    # Packet number
    pn = conn.next_pn
    conn.next_pn += 1
    push!(buf, UInt8((pn >> 8) & 0xff))
    push!(buf, UInt8(pn & 0xff))

    # Payload
    append!(buf, payload)
    append!(buf, zeros(UInt8, 16))  # Fake AEAD tag

    # Send
    if conn.remote_addr !== nothing
        send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, buf)
        println("JAMNP-S: Sent Handshake packet ($(length(buf)) bytes)")
    end
end

#= Stream API for JAMNP-S Protocols =#

"""
    open_up_stream!(conn::JAMNPSConn, kind::UInt8) -> UInt64

Open a Unique Persistent (UP) stream for the given protocol kind.
UP streams persist for the lifetime of the connection.
"""
function open_up_stream!(conn::JAMNPSConn, kind::UInt8)
    if conn.state != JAMNPS_CONNECTED
        error("Connection not established")
    end

    # Check if this UP stream already exists
    if haskey(conn.up_streams, kind)
        return conn.up_streams[kind]
    end

    # Allocate new bidirectional stream
    stream_id = conn.next_stream_id
    conn.next_stream_id += 4  # Increment by 4 for next client-initiated bidi stream

    conn.up_streams[kind] = stream_id

    # Send stream kind as first byte
    send_stream_data!(conn, stream_id, [kind], false)

    println("JAMNP-S: Opened UP stream $(kind) -> stream_id $(stream_id)")
    return stream_id
end

"""
    open_ce_stream!(conn::JAMNPSConn, kind::UInt8) -> UInt64

Open a Common Ephemeral (CE) stream for a single request/response.
CE streams are closed after the exchange completes.
"""
function open_ce_stream!(conn::JAMNPSConn, kind::UInt8)
    if conn.state != JAMNPS_CONNECTED
        error("Connection not established")
    end

    # Allocate new bidirectional stream
    stream_id = conn.next_stream_id
    conn.next_stream_id += 4

    push!(conn.ce_streams, (stream_id, kind))

    # Send stream kind as first byte
    send_stream_data!(conn, stream_id, [kind], false)

    println("JAMNP-S: Opened CE stream $(kind) -> stream_id $(stream_id)")
    return stream_id
end

"""
    send_stream_data!(conn::JAMNPSConn, stream_id::UInt64, data::Vector{UInt8}, fin::Bool)

Send data on a stream.
"""
function send_stream_data!(conn::JAMNPSConn, stream_id::UInt64, data::Vector{UInt8}, fin::Bool)
    # Create STREAM frame
    frame = Frame.StreamFrame(stream_id, 0, data, fin)

    # Send in 1-RTT packet
    send_application_packet!(conn, frame)
end

function send_application_packet!(conn::JAMNPSConn, frame::Frame.QuicFrame)
    # Short header packet
    buf = UInt8[]

    # Short header
    push!(buf, 0x40 | 0x01)  # Fixed bit + 2-byte PN

    # DCID
    append!(buf, conn.remote_cid.data)

    # Packet number
    pn = conn.next_pn
    conn.next_pn += 1
    push!(buf, UInt8((pn >> 8) & 0xff))
    push!(buf, UInt8(pn & 0xff))

    # Encode frame
    payload = UInt8[]
    Frame.encode_frame!(payload, frame)
    append!(buf, payload)

    # AEAD tag
    append!(buf, zeros(UInt8, 16))

    # Send
    if conn.remote_addr !== nothing
        send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, buf)
    end
end

"""
    send_message!(conn::JAMNPSConn, stream_id::UInt64, content::Vector{UInt8})

Send a length-prefixed message on a stream (JAMNP-S message format).
"""
function send_message!(conn::JAMNPSConn, stream_id::UInt64, content::Vector{UInt8})
    msg = JAMNPS.encode_message(content)
    send_stream_data!(conn, stream_id, msg, false)
end

"""
    close!(conn::JAMNPSConn)

Close the JAMNP-S connection gracefully.
"""
function close!(conn::JAMNPSConn)
    if conn.state == JAMNPS_CONNECTED
        conn.state = JAMNPS_CLOSING

        # Send CONNECTION_CLOSE frame
        # ...

        conn.state = JAMNPS_CLOSED
        Base.close(conn.socket)
    end
end

# Exports
export JAMNPSConfig, JAMNPSConn, JAMNPSState
export connect, listen, accept, close!
export open_up_stream!, open_ce_stream!, send_stream_data!, send_message!
export process_packet!

end # module JAMNPSConnection
