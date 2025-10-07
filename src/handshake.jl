module Handshake

using ..Protocol
using ..Packet
using ..Frame
using ..Crypto
using ..Ed25519
using ..X509
using ..X25519
using ..ZeroRTT
using MbedTLS
using SHA
using Random

mutable struct HandshakeState
    role::Symbol  # :client or :server
    state::Symbol # :initial, :wait_sh, :wait_ee, :wait_cert, :wait_cv, :wait_fin, :completed

    # crypto state
    cipher_suite::UInt16  # TLS cipher suite ID

    # key exchange
    client_random::Vector{UInt8}
    server_random::Vector{UInt8}
    ecdhe_secret::Vector{UInt8}  # shared secret from ECDHE

    # handshake messages for transcript
    messages::Vector{Vector{UInt8}}

    # crypto keys for each packet space
    initial_keys::Dict{Symbol, Vector{UInt8}}
    handshake_keys::Dict{Symbol, Vector{UInt8}}
    application_keys::Dict{Symbol, Vector{UInt8}}

    # QUIC transport parameters
    local_transport_params::Vector{UInt8}
    peer_transport_params::Vector{UInt8}

    # 0-RTT and session resumption
    resumption_master_secret::Vector{UInt8}
    alpn::String
    server_name::String

    # Client certificate (for QuicNet compatibility)
    client_keypair::Union{Ed25519.KeyPair, Nothing}
    client_cert_chain::Vector{Vector{UInt8}}

    HandshakeState(role::Symbol) = new(
        role, :initial,
        0x1301,  # TLS_AES_128_GCM_SHA256 by default
        rand(UInt8, 32), UInt8[], UInt8[],
        Vector{Vector{UInt8}}(),
        Dict(), Dict(), Dict(),
        UInt8[], UInt8[],
        UInt8[], "", "",
        nothing, Vector{Vector{UInt8}}()
    )
end

# initialize TLS context for QUIC
function init_tls_context(hs::HandshakeState, server_name::Union{String, Nothing}=nothing)
    config = MbedTLS.SSLConfig()

    if hs.role == :client
        MbedTLS.config_defaults!(config,
            MbedTLS.MBEDTLS_SSL_IS_CLIENT,
            MbedTLS.MBEDTLS_SSL_TRANSPORT_DATAGRAM,
            MbedTLS.MBEDTLS_SSL_PRESET_DEFAULT)

        # set ALPN protocols for QUIC
        MbedTLS.set_alpn!(config, ["h3", "h3-29"])

        if server_name !== nothing
            # set server name for SNI
            MbedTLS.set_hostname!(config, server_name)
        end
    else
        MbedTLS.config_defaults!(config,
            MbedTLS.MBEDTLS_SSL_IS_SERVER,
            MbedTLS.MBEDTLS_SSL_TRANSPORT_DATAGRAM,
            MbedTLS.MBEDTLS_SSL_PRESET_DEFAULT)
    end

    # set TLS 1.3 only
    MbedTLS.set_min_version!(config, MbedTLS.MBEDTLS_SSL_VERSION_TLS1_3)
    MbedTLS.set_max_version!(config, MbedTLS.MBEDTLS_SSL_VERSION_TLS1_3)

    # create SSL context
    ctx = MbedTLS.SSLContext()
    MbedTLS.setup!(ctx, config)

    hs.tls_ctx = ctx
    hs.tls_config = config
end

# Set client certificate for mutual TLS (QuicNet compatibility)
function set_client_certificate(hs::HandshakeState, keypair::Ed25519.KeyPair)
    hs.client_keypair = keypair
    hs.client_cert_chain = X509.generate_certificate_chain(keypair)
end

# derive QUIC initial keys from client connection ID
function derive_initial_keys!(hs::HandshakeState, client_cid::ConnectionId)
    # QUIC initial salt for v1
    initial_salt = hex2bytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

    # derive initial secret
    initial_secret = Crypto.hkdf_extract(client_cid.data, initial_salt)

    # derive client and server initial secrets
    client_label = b"client in"
    server_label = b"server in"

    client_secret = Crypto.hkdf_expand_label(initial_secret, "client in", UInt8[], 32)
    server_secret = Crypto.hkdf_expand_label(initial_secret, "server in", UInt8[], 32)

    # derive keys and IVs
    hs.initial_keys[:client_key] = derive_packet_key(client_secret)
    hs.initial_keys[:client_iv] = derive_packet_iv(client_secret)
    hs.initial_keys[:client_hp] = derive_header_key(client_secret)

    hs.initial_keys[:server_key] = derive_packet_key(server_secret)
    hs.initial_keys[:server_iv] = derive_packet_iv(server_secret)
    hs.initial_keys[:server_hp] = derive_header_key(server_secret)
end

# derive packet protection key
function derive_packet_key(secret::Vector{UInt8})
    key_label = b"quic key"
    Crypto.hkdf_expand_label(secret, "quic key", UInt8[], 16)
end

# derive packet IV
function derive_packet_iv(secret::Vector{UInt8})
    iv_label = b"quic iv"
    Crypto.hkdf_expand_label(secret, "quic iv", UInt8[], 12)
end

# derive header protection key
function derive_header_key(secret::Vector{UInt8})
    hp_label = b"quic hp"
    Crypto.hkdf_expand_label(secret, "quic hp", UInt8[], 16)
end

# start client handshake
function start_client_handshake(hs::HandshakeState, dest_cid::ConnectionId, src_cid::ConnectionId,
                                server_name::Union{String, Nothing}=nothing)
    hs.state = :wait_sh  # waiting for ServerHello

    # update transport params with actual source connection ID
    update_transport_params_scid!(hs, src_cid)

    # create CRYPTO frame with ClientHello
    client_hello = create_client_hello(hs, dest_cid, server_name)

    return CryptoFrame(0, client_hello)
end

# update transport params with source connection ID
function update_transport_params_scid!(hs::HandshakeState, scid::ConnectionId)
    # rebuild transport params with actual SCID
    buf = UInt8[]

    # copy existing params
    append!(buf, hs.local_transport_params)

    # add initial_source_connection_id
    encode_transport_param!(buf, UInt64(0x0f), scid.data)

    hs.local_transport_params = buf
end

# create TLS ClientHello message compatible with Quinn
function create_client_hello(hs::HandshakeState, server_cid::ConnectionId,
                            server_name::Union{String, Nothing}=nothing,
                            enable_zero_rtt::Bool=false)
    buf = UInt8[]

    # TLS handshake type: ClientHello (1)
    push!(buf, 0x01)

    # length placeholder (3 bytes)
    len_pos = length(buf) + 1
    append!(buf, zeros(UInt8, 3))

    # legacy version (TLS 1.2 for compatibility)
    append!(buf, [0x03, 0x03])

    # client random (32 bytes) - save for key derivation
    append!(buf, hs.client_random)

    # legacy session ID (32 bytes for compatibility mode)
    push!(buf, 32)
    append!(buf, rand(UInt8, 32))

    # cipher suites (in order of preference)
    cipher_suites = [
        0x13, 0x03,  # TLS_CHACHA20_POLY1305_SHA256 (Quinn's preferred)
        0x13, 0x01,  # TLS_AES_128_GCM_SHA256
        0x13, 0x02,  # TLS_AES_256_GCM_SHA384
    ]
    append!(buf, [UInt8((length(cipher_suites) >> 8) & 0xff), UInt8(length(cipher_suites) & 0xff)])
    append!(buf, cipher_suites)

    # compression methods (null only for TLS 1.3)
    append!(buf, [0x01, 0x00])

    # extensions
    ext_buf = UInt8[]

    # server name indication (SNI)
    if server_name !== nothing
        sni_ext = create_sni_extension(server_name)
        append!(ext_buf, sni_ext)
    end

    # supported versions (mandatory for TLS 1.3)
    append!(ext_buf, [0x00, 0x2b])  # extension type
    append!(ext_buf, [0x00, 0x03])  # length
    append!(ext_buf, [0x02])        # list length
    append!(ext_buf, [0x03, 0x04])  # TLS 1.3

    # supported groups (key exchange)
    append!(ext_buf, [0x00, 0x0a])  # extension type
    append!(ext_buf, [0x00, 0x08])  # length
    append!(ext_buf, [0x00, 0x06])  # list length
    append!(ext_buf, [0x00, 0x1d])  # x25519 (most common)
    append!(ext_buf, [0x00, 0x17])  # secp256r1
    append!(ext_buf, [0x00, 0x18])  # secp384r1

    # key share extension (required for TLS 1.3)
    key_share_ext = create_key_share_extension(hs)
    append!(ext_buf, key_share_ext)

    # signature algorithms (including Ed25519 for QuicNet)
    append!(ext_buf, [0x00, 0x0d])  # extension type
    append!(ext_buf, [0x00, 0x10])  # length (increased for Ed25519)
    append!(ext_buf, [0x00, 0x0e])  # list length
    append!(ext_buf, [0x08, 0x07])  # Ed25519 (required for QuicNet)
    append!(ext_buf, [0x04, 0x03])  # ECDSA_SECP256R1_SHA256
    append!(ext_buf, [0x08, 0x04])  # RSA_PSS_RSAE_SHA256
    append!(ext_buf, [0x04, 0x01])  # RSA_PKCS1_SHA256
    append!(ext_buf, [0x05, 0x03])  # ECDSA_SECP384R1_SHA384
    append!(ext_buf, [0x08, 0x05])  # RSA_PSS_RSAE_SHA384
    append!(ext_buf, [0x05, 0x01])  # RSA_PKCS1_SHA384

    # ALPN extension
    append!(ext_buf, [0x00, 0x10])  # extension type
    alpn_data = create_alpn_extension(["h3", "h3-29"])
    append!(ext_buf, [UInt8((length(alpn_data) >> 8) & 0xff), UInt8(length(alpn_data) & 0xff)])
    append!(ext_buf, alpn_data)

    # PSK key exchange modes (required for resumption)
    append!(ext_buf, [0x00, 0x2d])  # extension type
    append!(ext_buf, [0x00, 0x02])  # length
    append!(ext_buf, [0x01])        # modes length
    append!(ext_buf, [0x01])        # PSK with (EC)DHE key establishment

    # QUIC transport parameters
    append!(ext_buf, [0x00, 0x39])  # extension type (final value for QUIC v1)
    tp_buf = encode_transport_params_v1(hs)
    append!(ext_buf, [UInt8((length(tp_buf) >> 8) & 0xff), UInt8(length(tp_buf) & 0xff)])
    append!(ext_buf, tp_buf)

    # Early data indication (for 0-RTT) if enabled
    if enable_zero_rtt
        # Get session from cache
        server_addr = server_name !== nothing ? server_name : "default"
        session = ZeroRTT.get_resumption_session(ZeroRTT.GLOBAL_SESSION_CACHE, server_addr)

        if session !== nothing && ZeroRTT.is_session_valid(session, time_ns())
            # Add early_data extension
            append!(ext_buf, [0x00, 0x2a])  # extension type
            append!(ext_buf, [0x00, 0x00])  # length (empty for ClientHello)

            # Add pre_shared_key extension (must be last)
            psk_ext = ZeroRTT.add_psk_extension!(buf, session)
            append!(ext_buf, psk_ext)

            # Store session info in handshake state for later use
            hs.resumption_master_secret = session.resumption_master_secret
        end
    end

    # add extensions length and data
    append!(buf, [UInt8((length(ext_buf) >> 8) & 0xff), UInt8(length(ext_buf) & 0xff)])
    append!(buf, ext_buf)

    # update message length
    msg_len = length(buf) - 4
    buf[len_pos:len_pos+2] = [
        UInt8((msg_len >> 16) & 0xff),
        UInt8((msg_len >> 8) & 0xff),
        UInt8(msg_len & 0xff)
    ]

    # save message for transcript
    push!(hs.messages, copy(buf))

    return buf
end

# create SNI extension
function create_sni_extension(server_name::String)
    ext = UInt8[]
    append!(ext, [0x00, 0x00])  # extension type (server_name)

    sni_data = UInt8[]
    # server name list length
    name_bytes = Vector{UInt8}(server_name)
    list_len = 3 + length(name_bytes)  # type (1) + len (2) + name
    append!(sni_data, [UInt8((list_len >> 8) & 0xff), UInt8(list_len & 0xff)])

    # server name type: hostname (0)
    push!(sni_data, 0x00)

    # hostname length and data
    append!(sni_data, [UInt8((length(name_bytes) >> 8) & 0xff), UInt8(length(name_bytes) & 0xff)])
    append!(sni_data, name_bytes)

    # extension length
    append!(ext, [UInt8((length(sni_data) >> 8) & 0xff), UInt8(length(sni_data) & 0xff)])
    append!(ext, sni_data)

    return ext
end

# create key share extension with x25519
function create_key_share_extension(hs::HandshakeState)
    ext = UInt8[]
    append!(ext, [0x00, 0x33])  # extension type (key_share)

    # generate x25519 key pair using our implementation
    private_key, public_key = X25519.generate_keypair()

    # save private key for ECDHE
    hs.ecdhe_secret = private_key

    # build key share data
    ks_data = UInt8[]
    # client key share length
    ks_len = 2 + 2 + length(public_key)  # group (2) + key_len (2) + key
    append!(ks_data, [UInt8((ks_len >> 8) & 0xff), UInt8(ks_len & 0xff)])

    # named group: x25519
    append!(ks_data, [0x00, 0x1d])

    # key exchange length and data
    append!(ks_data, [UInt8((length(public_key) >> 8) & 0xff), UInt8(length(public_key) & 0xff)])
    append!(ks_data, public_key)

    # extension length
    append!(ext, [UInt8((length(ks_data) >> 8) & 0xff), UInt8(length(ks_data) & 0xff)])
    append!(ext, ks_data)

    println("X25519 public key generated: $(bytes2hex(public_key))")

    return ext
end

# create ALPN extension data
function create_alpn_extension(protocols::Vector{String})
    data = UInt8[]

    # calculate total length
    total_len = sum(1 + length(p) for p in protocols)
    append!(data, [UInt8((total_len >> 8) & 0xff), UInt8(total_len & 0xff)])

    # add each protocol
    for proto in protocols
        push!(data, UInt8(length(proto)))
        append!(data, Vector{UInt8}(proto))
    end

    return data
end

# encode QUIC v1 transport parameters
function encode_transport_params_v1(hs::HandshakeState)
    buf = UInt8[]

    # initial_max_stream_data_bidi_local (0x00)
    encode_transport_param!(buf, UInt64(0x00),encode_varint_bytes(UInt64(1048576)))

    # initial_max_data (0x01)
    encode_transport_param!(buf, UInt64(0x01),encode_varint_bytes(UInt64(10485760)))

    # initial_max_stream_data_bidi_remote (0x02)
    encode_transport_param!(buf, UInt64(0x02),encode_varint_bytes(UInt64(1048576)))

    # initial_max_stream_data_uni (0x03)
    encode_transport_param!(buf, UInt64(0x03),encode_varint_bytes(UInt64(1048576)))

    # idle_timeout (0x04) - 30 seconds
    encode_transport_param!(buf, UInt64(0x04),encode_varint_bytes(UInt64(30000)))

    # initial_max_streams_bidi (0x08)
    encode_transport_param!(buf, UInt64(0x08),encode_varint_bytes(UInt64(100)))

    # initial_max_streams_uni (0x09)
    encode_transport_param!(buf, UInt64(0x09),encode_varint_bytes(UInt64(100)))

    # max_udp_payload_size (0x0b) - 65527 bytes (max UDP payload)
    encode_transport_param!(buf, UInt64(0x0b),encode_varint_bytes(UInt64(65527)))

    # initial_source_connection_id (0x0f) - required for clients
    if hs.role == :client
        # will be filled in by connection
        encode_transport_param!(buf, UInt64(0x0f), UInt8[])
    end

    # disable_active_migration (0x0c) - optional
    encode_transport_param!(buf, UInt64(0x0c), UInt8[])  # empty = true

    # grease_quic_bit (0x2ab2) - optional, helps with middlebox traversal
    encode_transport_param!(buf, UInt64(0x2ab2), UInt8[0x01])

    # save for later
    hs.local_transport_params = copy(buf)

    return buf
end

function encode_transport_param!(buf::Vector{UInt8}, id::UInt64, value::Vector{UInt8})
    encode_varint!(buf, VarInt(id))
    encode_varint!(buf, VarInt(length(value)))
    append!(buf, value)
end

function encode_varint_bytes(val::UInt64)
    buf = UInt8[]
    encode_varint!(buf, VarInt(val))
    return buf
end

# process server handshake message
function process_server_hello(hs::HandshakeState, data::Vector{UInt8})
    # parse ServerHello and derive handshake keys
    hs.server_hello = data

    # update transcript hash
    hs.transcript_hash = sha256([hs.client_hello; hs.server_hello])

    # derive handshake keys from shared secret
    # (simplified - real implementation needs ECDHE)
    handshake_secret = sha256(hs.transcript_hash)

    client_hs_label = b"c hs traffic"
    server_hs_label = b"s hs traffic"

    client_hs_secret = Crypto.hkdf_expand_label(handshake_secret,
                                           "c hs traffic", hs.transcript_hash, 32)
    server_hs_secret = Crypto.hkdf_expand_label(handshake_secret,
                                           "s hs traffic", hs.transcript_hash, 32)

    hs.handshake_keys[:client_key] = derive_packet_key(client_hs_secret)
    hs.handshake_keys[:client_iv] = derive_packet_iv(client_hs_secret)
    hs.handshake_keys[:server_key] = derive_packet_key(server_hs_secret)
    hs.handshake_keys[:server_iv] = derive_packet_iv(server_hs_secret)
end

# complete handshake and derive application keys
function complete_handshake(hs::HandshakeState)
    hs.state = :completed

    # derive application keys
    # (simplified - needs full transcript)
    master_secret = sha256([hs.transcript_hash; b"master"])

    client_app_label = b"c ap traffic"
    server_app_label = b"s ap traffic"

    client_app_secret = Crypto.hkdf_expand_label(master_secret,
                                            "c ap traffic", hs.transcript_hash, 32)
    server_app_secret = Crypto.hkdf_expand_label(master_secret,
                                            "s ap traffic", hs.transcript_hash, 32)

    hs.application_keys[:client_key] = derive_packet_key(client_app_secret)
    hs.application_keys[:client_iv] = derive_packet_iv(client_app_secret)
    hs.application_keys[:server_key] = derive_packet_key(server_app_secret)
    hs.application_keys[:server_iv] = derive_packet_iv(server_app_secret)
end

export HandshakeState, init_tls_context, start_client_handshake, set_client_certificate
export process_server_hello, complete_handshake, derive_initial_keys!

end # module Handshake