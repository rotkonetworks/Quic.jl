module QuicMLS

#=
QUIC-MLS Integration (draft-tian-quic-quicmls)

This module integrates MLS with QUIC, replacing TLS 1.3 for key establishment.
It provides:
- MLS message transport via QUIC CRYPTO frames
- Traffic key derivation for QUIC packet protection
- Handshake state machine for QUIC-MLS connections

Key differences from TLS-based QUIC:
1. KeyPackage sent in first CRYPTO frame (instead of ClientHello)
2. Welcome + Commit sent by server (instead of ServerHello + Finished)
3. Keys derived from MLS epoch secret (instead of TLS master secret)
4. Group membership allows future multi-party QUIC
=#

using ..MLSTypes
using ..MLSTypes: DEFAULT_CIPHER_SUITE
using ..MLSCrypto
using ..MLSTree
using ..MLSKeySchedule
using ..MLSHandshake

export QuicMLSConnection, QuicMLSConfig
export QuicMLSRole, QUIC_MLS_CLIENT, QUIC_MLS_SERVER
export init_quic_mls_client, init_quic_mls_server
export process_crypto_data, get_crypto_data_to_send
export is_handshake_complete, get_quic_keys
export QuicMLSKeys

#=
================================================================================
TYPES
================================================================================
=#

"""
Role in QUIC-MLS connection
"""
@enum QuicMLSRole begin
    QUIC_MLS_CLIENT
    QUIC_MLS_SERVER
end

"""
Handshake state for QUIC-MLS
"""
@enum QuicMLSState begin
    QUICMLS_STATE_INITIAL
    QUICMLS_STATE_KEY_PACKAGE_SENT      # Client: sent KeyPackage
    QUICMLS_STATE_KEY_PACKAGE_RECEIVED  # Server: received KeyPackage
    QUICMLS_STATE_WELCOME_SENT          # Server: sent Welcome
    QUICMLS_STATE_WELCOME_RECEIVED      # Client: received Welcome
    QUICMLS_STATE_ESTABLISHED           # Handshake complete
    QUICMLS_STATE_ERROR
end

"""
QUIC-MLS message types (in CRYPTO frame)
"""
@enum QuicMLSMessageType::UInt8 begin
    QUICMLS_MSG_KEY_PACKAGE = 0x01
    QUICMLS_MSG_WELCOME = 0x02
    QUICMLS_MSG_COMMIT = 0x03
    QUICMLS_MSG_APPLICATION = 0x04
end

"""
Configuration for QUIC-MLS
"""
struct QuicMLSConfig
    cipher_suite::CipherSuite
    identity::Vector{UInt8}
    # Pre-generated KeyPackage for clients (optional)
    key_package::Union{KeyPackage, Nothing}
    key_package_private::Union{KeyPackagePrivate, Nothing}
end

function QuicMLSConfig(identity::Vector{UInt8};
                      cipher_suite::CipherSuite = DEFAULT_CIPHER_SUITE)
    QuicMLSConfig(cipher_suite, identity, nothing, nothing)
end

function QuicMLSConfig(identity::Vector{UInt8}, kp::KeyPackage, kp_priv::KeyPackagePrivate;
                      cipher_suite::CipherSuite = DEFAULT_CIPHER_SUITE)
    QuicMLSConfig(cipher_suite, identity, kp, kp_priv)
end

"""
QUIC keys derived from MLS
"""
struct QuicMLSKeys
    client_key::Vector{UInt8}
    client_iv::Vector{UInt8}
    client_hp::Vector{UInt8}
    server_key::Vector{UInt8}
    server_iv::Vector{UInt8}
    server_hp::Vector{UInt8}
end

"""
QUIC-MLS Connection State
"""
mutable struct QuicMLSConnection
    role::QuicMLSRole
    state::QuicMLSState
    config::QuicMLSConfig

    # MLS state (initialized after handshake)
    mls_state::Union{MLSGroupState, Nothing}

    # Key material
    my_key_package::Union{KeyPackage, Nothing}
    my_key_package_private::Union{KeyPackagePrivate, Nothing}

    # Received peer data
    peer_key_package::Union{KeyPackage, Nothing}
    received_welcome::Union{Welcome, Nothing}

    # Outbound message queue
    outbound_data::Vector{UInt8}

    # Derived QUIC keys
    keys::Union{QuicMLSKeys, Nothing}

    # Error message if state == ERROR
    error_message::String
end

#=
================================================================================
INITIALIZATION
================================================================================
=#

"""
Initialize QUIC-MLS for client role
"""
function init_quic_mls_client(config::QuicMLSConfig)
    # Generate KeyPackage if not provided
    kp, kp_priv = if config.key_package !== nothing
        (config.key_package, config.key_package_private)
    else
        MLSHandshake.create_key_package(config.identity; cipher_suite=config.cipher_suite)
    end

    conn = QuicMLSConnection(
        QUIC_MLS_CLIENT,
        QUICMLS_STATE_INITIAL,
        config,
        nothing,
        kp,
        kp_priv,
        nothing,
        nothing,
        UInt8[],
        nothing,
        ""
    )

    # Queue KeyPackage for sending
    queue_key_package!(conn)

    return conn
end

"""
Initialize QUIC-MLS for server role
"""
function init_quic_mls_server(config::QuicMLSConfig)
    QuicMLSConnection(
        QUIC_MLS_SERVER,
        QUICMLS_STATE_INITIAL,
        config,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        UInt8[],
        nothing,
        ""
    )
end

# Convenience methods with default configs
function init_quic_mls_client(identity::Vector{UInt8} = UInt8[])
    init_quic_mls_client(QuicMLSConfig(identity))
end

function init_quic_mls_server(identity::Vector{UInt8} = UInt8[])
    init_quic_mls_server(QuicMLSConfig(identity))
end

#=
================================================================================
MESSAGE PROCESSING
================================================================================
=#

"""
Process incoming CRYPTO frame data

Returns true if handshake progressed, false on error.
"""
function process_crypto_data(conn::QuicMLSConnection, data::Vector{UInt8})
    if isempty(data) || conn.state == QUICMLS_STATE_ERROR
        return false
    end

    # Parse message type
    msg_type = QuicMLSMessageType(data[1])
    payload = data[2:end]

    try
        if conn.role == QUIC_MLS_CLIENT
            process_client_message!(conn, msg_type, payload)
        else
            process_server_message!(conn, msg_type, payload)
        end
        return true
    catch e
        conn.state = QUICMLS_STATE_ERROR
        conn.error_message = string(e)
        return false
    end
end

"""
Process message on client side
"""
function process_client_message!(conn::QuicMLSConnection, msg_type::QuicMLSMessageType,
                                 payload::Vector{UInt8})
    if msg_type == QUICMLS_MSG_WELCOME
        # Parse Welcome message
        welcome = parse_welcome(payload, conn.config.cipher_suite)
        conn.received_welcome = welcome

        # Join the group
        if conn.my_key_package === nothing || conn.my_key_package_private === nothing
            error("No KeyPackage available")
        end

        # Use full RFC 9420 compliant join_group
        conn.mls_state = MLSHandshake.join_group(welcome, conn.my_key_package,
                                                  conn.my_key_package_private)
        conn.state = QUICMLS_STATE_WELCOME_RECEIVED

        # Derive QUIC keys
        derive_quic_keys!(conn)

        conn.state = QUICMLS_STATE_ESTABLISHED

    else
        error("Unexpected message type for client: $msg_type")
    end
end

"""
Process message on server side
"""
function process_server_message!(conn::QuicMLSConnection, msg_type::QuicMLSMessageType,
                                 payload::Vector{UInt8})
    if msg_type == QUICMLS_MSG_KEY_PACKAGE
        # Parse KeyPackage
        key_package = parse_key_package(payload)

        # Validate
        if !MLSHandshake.validate_key_package(key_package)
            error("Invalid KeyPackage")
        end

        conn.peer_key_package = key_package
        conn.state = QUICMLS_STATE_KEY_PACKAGE_RECEIVED

        # Create two-party group and Welcome
        create_group_and_welcome!(conn)

    else
        error("Unexpected message type for server: $msg_type")
    end
end

"""
Create MLS group and Welcome for client
"""
function create_group_and_welcome!(conn::QuicMLSConnection)
    if conn.peer_key_package === nothing
        error("No peer KeyPackage")
    end

    # Create two-party group
    mls_state, welcome = MLSHandshake.create_two_party_group(
        conn.config.identity,
        conn.peer_key_package;
        cipher_suite=conn.config.cipher_suite
    )

    conn.mls_state = mls_state

    # Queue Welcome for sending
    queue_welcome!(conn, welcome)

    # Derive QUIC keys
    derive_quic_keys!(conn)

    conn.state = QUICMLS_STATE_ESTABLISHED
end

#=
================================================================================
MESSAGE SERIALIZATION
================================================================================
=#

"""
Queue KeyPackage message for sending
"""
function queue_key_package!(conn::QuicMLSConnection)
    if conn.my_key_package === nothing
        error("No KeyPackage to send")
    end

    # Serialize: type || KeyPackage
    msg = UInt8[UInt8(QUICMLS_MSG_KEY_PACKAGE)]
    append!(msg, serialize_key_package_wire(conn.my_key_package))

    append!(conn.outbound_data, msg)
    conn.state = QUICMLS_STATE_KEY_PACKAGE_SENT
end

"""
Queue Welcome message for sending
"""
function queue_welcome!(conn::QuicMLSConnection, welcome::Welcome)
    # Serialize: type || Welcome
    msg = UInt8[UInt8(QUICMLS_MSG_WELCOME)]
    append!(msg, serialize_welcome_wire(welcome))

    append!(conn.outbound_data, msg)
    conn.state = QUICMLS_STATE_WELCOME_SENT
end

"""
Get data to send in CRYPTO frame

Returns data and clears the outbound buffer.
"""
function get_crypto_data_to_send(conn::QuicMLSConnection)
    data = copy(conn.outbound_data)
    empty!(conn.outbound_data)
    return data
end

#=
================================================================================
KEY DERIVATION
================================================================================
=#

"""
Derive QUIC keys from MLS state
"""
function derive_quic_keys!(conn::QuicMLSConnection)
    if conn.mls_state === nothing
        error("MLS state not initialized")
    end

    traffic_keys = MLSHandshake.get_traffic_keys(conn.mls_state)

    conn.keys = QuicMLSKeys(
        traffic_keys.client.key,
        traffic_keys.client.iv,
        traffic_keys.client.hp_key,
        traffic_keys.server.key,
        traffic_keys.server.iv,
        traffic_keys.server.hp_key
    )
end

"""
Check if handshake is complete
"""
function is_handshake_complete(conn::QuicMLSConnection)
    conn.state == QUICMLS_STATE_ESTABLISHED
end

"""
Get QUIC keys (client/server key, iv, hp)
"""
function get_quic_keys(conn::QuicMLSConnection)
    if conn.keys === nothing
        error("Keys not yet derived")
    end
    return conn.keys
end

"""
Get encryption key for sending packets
"""
function get_send_key(conn::QuicMLSConnection)
    keys = get_quic_keys(conn)
    if conn.role == QUIC_MLS_CLIENT
        return (keys.client_key, keys.client_iv, keys.client_hp)
    else
        return (keys.server_key, keys.server_iv, keys.server_hp)
    end
end

"""
Get decryption key for receiving packets
"""
function get_recv_key(conn::QuicMLSConnection)
    keys = get_quic_keys(conn)
    if conn.role == QUIC_MLS_CLIENT
        return (keys.server_key, keys.server_iv, keys.server_hp)
    else
        return (keys.client_key, keys.client_iv, keys.client_hp)
    end
end

#=
================================================================================
WIRE FORMAT SERIALIZATION
================================================================================
=#

"""
Serialize KeyPackage for wire format
"""
function serialize_key_package_wire(kp::KeyPackage)
    buf = UInt8[]

    # version (2 bytes)
    push!(buf, UInt8((kp.version >> 8) & 0xff))
    push!(buf, UInt8(kp.version & 0xff))

    # cipher_suite (2 bytes)
    suite_val = UInt16(kp.cipher_suite)
    push!(buf, UInt8((suite_val >> 8) & 0xff))
    push!(buf, UInt8(suite_val & 0xff))

    # init_key (length-prefixed)
    push!(buf, UInt8(length(kp.init_key.data)))
    append!(buf, kp.init_key.data)

    # leaf_node - encryption_key
    push!(buf, UInt8(length(kp.leaf_node.encryption_key.data)))
    append!(buf, kp.leaf_node.encryption_key.data)

    # leaf_node - signature_key
    push!(buf, UInt8(length(kp.leaf_node.signature_key.data)))
    append!(buf, kp.leaf_node.signature_key.data)

    # leaf_node - credential type
    cred_type = UInt16(kp.leaf_node.credential.credential_type)
    push!(buf, UInt8((cred_type >> 8) & 0xff))
    push!(buf, UInt8(cred_type & 0xff))

    # credential identity (if basic)
    if kp.leaf_node.credential.basic !== nothing
        push!(buf, UInt8(length(kp.leaf_node.credential.basic.identity)))
        append!(buf, kp.leaf_node.credential.basic.identity)
    else
        push!(buf, 0x00)
    end

    # leaf_node signature
    push!(buf, UInt8(length(kp.leaf_node.signature)))
    append!(buf, kp.leaf_node.signature)

    # KeyPackage signature
    push!(buf, UInt8(length(kp.signature)))
    append!(buf, kp.signature)

    return buf
end

"""
Parse KeyPackage from wire format
"""
function parse_key_package(data::Vector{UInt8})
    pos = 1

    # version
    version = (UInt16(data[pos]) << 8) | UInt16(data[pos+1])
    pos += 2

    # cipher_suite
    suite_val = (UInt16(data[pos]) << 8) | UInt16(data[pos+1])
    cipher_suite = CipherSuite(suite_val)
    pos += 2

    # init_key
    init_key_len = data[pos]
    pos += 1
    init_key = HPKEPublicKey(data[pos:pos+init_key_len-1])
    pos += init_key_len

    # encryption_key
    enc_key_len = data[pos]
    pos += 1
    encryption_key = HPKEPublicKey(data[pos:pos+enc_key_len-1])
    pos += enc_key_len

    # signature_key
    sig_key_len = data[pos]
    pos += 1
    signature_key = SignaturePublicKey(data[pos:pos+sig_key_len-1])
    pos += sig_key_len

    # credential type
    cred_type = CredentialType((UInt16(data[pos]) << 8) | UInt16(data[pos+1]))
    pos += 2

    # identity
    identity_len = data[pos]
    pos += 1
    identity = identity_len > 0 ? data[pos:pos+identity_len-1] : UInt8[]
    pos += identity_len

    credential = Credential(identity)

    # leaf signature
    leaf_sig_len = data[pos]
    pos += 1
    leaf_signature = data[pos:pos+leaf_sig_len-1]
    pos += leaf_sig_len

    # KeyPackage signature
    kp_sig_len = data[pos]
    pos += 1
    kp_signature = data[pos:pos+kp_sig_len-1]

    # Construct leaf node
    leaf_node = LeafNode(
        encryption_key,
        signature_key,
        credential,
        default_capabilities(),
        UInt8(1),  # key_package source
        Extension[],
        leaf_signature
    )

    return KeyPackage(version, cipher_suite, init_key, leaf_node, Extension[], kp_signature)
end

"""
Serialize Welcome for wire format
"""
function serialize_welcome_wire(welcome::Welcome)
    buf = UInt8[]

    # cipher_suite (2 bytes)
    suite_val = UInt16(welcome.cipher_suite)
    push!(buf, UInt8((suite_val >> 8) & 0xff))
    push!(buf, UInt8(suite_val & 0xff))

    # Number of encrypted secrets
    push!(buf, UInt8(length(welcome.secrets)))

    # Each encrypted secret
    for es in welcome.secrets
        # KeyPackage ref
        push!(buf, UInt8(length(es.new_member.data)))
        append!(buf, es.new_member.data)

        # Encrypted group secrets (2-byte length prefix for potentially large data)
        egs_len = length(es.encrypted_group_secrets)
        push!(buf, UInt8((egs_len >> 8) & 0xff))
        push!(buf, UInt8(egs_len & 0xff))
        append!(buf, es.encrypted_group_secrets)
    end

    # Encrypted group info (2-byte length prefix)
    egi_len = length(welcome.encrypted_group_info)
    push!(buf, UInt8((egi_len >> 8) & 0xff))
    push!(buf, UInt8(egi_len & 0xff))
    append!(buf, welcome.encrypted_group_info)

    return buf
end

"""
Parse Welcome from wire format
"""
function parse_welcome(data::Vector{UInt8}, expected_suite::CipherSuite)
    pos = 1

    # cipher_suite
    suite_val = (UInt16(data[pos]) << 8) | UInt16(data[pos+1])
    cipher_suite = CipherSuite(suite_val)
    pos += 2

    if cipher_suite != expected_suite
        error("Cipher suite mismatch")
    end

    # Number of secrets
    num_secrets = data[pos]
    pos += 1

    secrets = EncryptedGroupSecrets[]
    for _ in 1:num_secrets
        # KeyPackage ref
        ref_len = data[pos]
        pos += 1
        kp_ref = KeyPackageRef(data[pos:pos+ref_len-1])
        pos += ref_len

        # Encrypted group secrets
        egs_len = (UInt16(data[pos]) << 8) | UInt16(data[pos+1])
        pos += 2
        encrypted_gs = data[pos:pos+egs_len-1]
        pos += egs_len

        push!(secrets, EncryptedGroupSecrets(kp_ref, encrypted_gs))
    end

    # Encrypted group info
    egi_len = (UInt16(data[pos]) << 8) | UInt16(data[pos+1])
    pos += 2
    encrypted_group_info = data[pos:pos+egi_len-1]

    return Welcome(cipher_suite, secrets, encrypted_group_info)
end

#=
================================================================================
EPOCH UPDATE (for key refresh)
================================================================================
=#

"""
Update to new epoch (after group changes)
"""
function update_epoch!(conn::QuicMLSConnection)
    if conn.mls_state === nothing
        error("MLS state not initialized")
    end

    # Re-derive keys for new epoch
    derive_quic_keys!(conn)
end

"""
Get current epoch
"""
function get_epoch(conn::QuicMLSConnection)
    if conn.mls_state === nothing
        return UInt64(0)
    end
    return conn.mls_state.epoch
end

"""
Export secret for application use (e.g., application-level encryption)
"""
function export_secret(conn::QuicMLSConnection, label::String,
                       context::Vector{UInt8}, length::Int)
    if conn.mls_state === nothing
        error("MLS state not initialized")
    end
    return MLSHandshake.export_secret(conn.mls_state, label, context, length)
end

end # module QuicMLS
