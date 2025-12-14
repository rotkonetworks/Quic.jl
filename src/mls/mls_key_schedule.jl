module MLSKeySchedule

#=
MLS Key Schedule (RFC 9420 Section 8)

The key schedule derives all cryptographic keys used in MLS from the
group's epoch secret. For QUIC-MLS, we derive traffic keys for packet
protection similar to how TLS would.

Key Schedule Overview:
                         init_secret_[n-1]
                               |
                               v
    commit_secret -> KDF.Extract = joiner_secret
                               |
                               v
                         Derive-Secret(., "member")
                               |
                               v
    psk_secret (or 0) -> KDF.Extract = member_secret
                               |
                               +--> Derive-Secret(., "welcome")
                               |    = welcome_secret
                               |
                               v
                         Derive-Secret(., "epoch")
                               |
                               v
    GroupContext -> KDF.Extract = epoch_secret
                               |
                               +--> Derive-Secret(., "init")
                               |    = init_secret_[n]
                               |
                               +--> Derive-Secret(., "sender data")
                               |    = sender_data_secret
                               |
                               +--> Derive-Secret(., "encryption")
                               |    = encryption_secret
                               |
                               +--> Derive-Secret(., "exporter")
                               |    = exporter_secret
                               |
                               +--> Derive-Secret(., "external")
                               |    = external_secret
                               |
                               +--> Derive-Secret(., "confirm")
                               |    = confirmation_key
                               |
                               +--> Derive-Secret(., "membership")
                                    = membership_key
=#

using ..MLSTypes
using ..MLSTypes: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                 MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
using ..MLSCrypto

export KeyScheduleState, EpochSecrets, TrafficKeys
export init_key_schedule, advance_epoch!, derive_traffic_keys
export derive_welcome_secret, derive_exporter_secret
export derive_quic_keys

#=
================================================================================
KEY SCHEDULE STATE
================================================================================
=#

"""
Epoch secrets derived from the key schedule
"""
struct EpochSecrets
    init_secret::Vector{UInt8}
    sender_data_secret::Vector{UInt8}
    encryption_secret::Vector{UInt8}
    exporter_secret::Vector{UInt8}
    external_secret::Vector{UInt8}
    confirmation_key::Vector{UInt8}
    membership_key::Vector{UInt8}
end

"""
Traffic keys for a single sender (client or server)
"""
struct TrafficKeys
    key::Vector{UInt8}
    iv::Vector{UInt8}
    hp_key::Vector{UInt8}  # Header protection key
end

"""
Sender secret tree for per-sender ratchets
"""
mutable struct SenderSecretTree
    cipher_suite::CipherSuite
    handshake_secret::Vector{UInt8}
    application_secret::Vector{UInt8}
    handshake_generation::UInt32
    application_generation::UInt32
end

"""
Key schedule state maintained across epochs
"""
mutable struct KeyScheduleState
    cipher_suite::CipherSuite
    epoch::UInt64

    # Current epoch secrets
    epoch_secret::Vector{UInt8}
    secrets::Union{EpochSecrets, Nothing}

    # For next epoch
    init_secret::Vector{UInt8}

    # Secret tree for sender ratchets (per-leaf)
    sender_trees::Dict{UInt32, SenderSecretTree}

    # Derived traffic keys cache
    client_traffic_keys::Union{TrafficKeys, Nothing}
    server_traffic_keys::Union{TrafficKeys, Nothing}
end

#=
================================================================================
KEY SCHEDULE INITIALIZATION
================================================================================
=#

"""
Initialize key schedule for a new group
"""
function init_key_schedule(suite::CipherSuite)
    hash_len = MLSCrypto.hash_length(suite)

    # Initial init_secret is all zeros
    init_secret = zeros(UInt8, hash_len)

    KeyScheduleState(
        suite,
        UInt64(0),
        UInt8[],
        nothing,
        init_secret,
        Dict{UInt32, SenderSecretTree}(),
        nothing,
        nothing
    )
end

"""
Initialize key schedule from a Welcome message
"""
function init_from_welcome(suite::CipherSuite, joiner_secret::Vector{UInt8},
                          psk_secret::Vector{UInt8}, group_context::GroupContext)
    ks = init_key_schedule(suite)

    # Derive member secret
    member_secret = derive_member_secret(suite, joiner_secret)

    # Welcome secret (for GroupInfo decryption)
    # welcome_secret = Derive-Secret(member_secret, "welcome")

    # Continue with epoch derivation
    advance_from_member_secret!(ks, member_secret, psk_secret, group_context)

    return ks
end

#=
================================================================================
EPOCH ADVANCEMENT
================================================================================
=#

"""
Advance to next epoch with new commit secret
"""
function advance_epoch!(ks::KeyScheduleState, commit_secret::Vector{UInt8},
                       psk_secret::Vector{UInt8}, group_context::GroupContext)
    suite = ks.cipher_suite
    hash_len = MLSCrypto.hash_length(suite)

    # joiner_secret = KDF.Extract(init_secret, commit_secret)
    joiner_secret = MLSCrypto.kdf_extract(suite, ks.init_secret, commit_secret)

    # member_secret
    member_secret = derive_member_secret(suite, joiner_secret)

    advance_from_member_secret!(ks, member_secret, psk_secret, group_context)
end

"""
Continue key schedule from member secret
"""
function advance_from_member_secret!(ks::KeyScheduleState, member_secret::Vector{UInt8},
                                    psk_secret::Vector{UInt8}, group_context::GroupContext)
    suite = ks.cipher_suite
    hash_len = MLSCrypto.hash_length(suite)

    # If no PSK, use zeros
    actual_psk = isempty(psk_secret) ? zeros(UInt8, hash_len) : psk_secret

    # epoch_secret_input = KDF.Extract(member_secret, psk_secret)
    epoch_secret_input = MLSCrypto.kdf_extract(suite, member_secret, actual_psk)

    # Derive-Secret(., "epoch")
    epoch_derived = MLSCrypto.derive_secret(suite, epoch_secret_input, "epoch")

    # epoch_secret = KDF.Extract(epoch_derived, GroupContext)
    gc_bytes = serialize_group_context(group_context)
    epoch_secret = MLSCrypto.kdf_extract(suite, epoch_derived, gc_bytes)

    # Store epoch secret
    ks.epoch_secret = epoch_secret
    ks.epoch = group_context.epoch

    # Derive all epoch secrets
    ks.secrets = derive_epoch_secrets(suite, epoch_secret)

    # Update init_secret for next epoch
    ks.init_secret = ks.secrets.init_secret

    # Clear traffic key cache
    ks.client_traffic_keys = nothing
    ks.server_traffic_keys = nothing

    # Clear sender trees (new epoch = new secrets)
    empty!(ks.sender_trees)
end

"""
Derive all epoch secrets from epoch_secret
"""
function derive_epoch_secrets(suite::CipherSuite, epoch_secret::Vector{UInt8})
    EpochSecrets(
        MLSCrypto.derive_secret(suite, epoch_secret, "init"),
        MLSCrypto.derive_secret(suite, epoch_secret, "sender data"),
        MLSCrypto.derive_secret(suite, epoch_secret, "encryption"),
        MLSCrypto.derive_secret(suite, epoch_secret, "exporter"),
        MLSCrypto.derive_secret(suite, epoch_secret, "external"),
        MLSCrypto.derive_secret(suite, epoch_secret, "confirm"),
        MLSCrypto.derive_secret(suite, epoch_secret, "membership")
    )
end

"""
Derive member secret from joiner secret
"""
function derive_member_secret(suite::CipherSuite, joiner_secret::Vector{UInt8})
    MLSCrypto.derive_secret(suite, joiner_secret, "member")
end

"""
Derive welcome secret from member secret (for encrypting GroupInfo)
"""
function derive_welcome_secret(suite::CipherSuite, joiner_secret::Vector{UInt8})
    member_secret = derive_member_secret(suite, joiner_secret)
    MLSCrypto.derive_secret(suite, member_secret, "welcome")
end

"""
Derive exporter secret for application use
"""
function derive_exporter_secret(ks::KeyScheduleState, label::String,
                               context::Vector{UInt8}, length::Int)
    if ks.secrets === nothing
        error("Key schedule not initialized")
    end

    derived = MLSCrypto.expand_with_label(ks.cipher_suite, ks.secrets.exporter_secret,
                                          label, context, length)
    return derived
end

#=
================================================================================
TRAFFIC KEYS (FOR QUIC-MLS)
================================================================================
=#

"""
Derive QUIC traffic keys from MLS epoch secret

Following draft-tian-quic-quicmls, traffic keys are derived similarly to TLS
but using the MLS epoch secret instead of the TLS master secret.
"""
function derive_quic_keys(ks::KeyScheduleState, is_client::Bool)
    if ks.secrets === nothing
        error("Key schedule not initialized")
    end

    suite = ks.cipher_suite

    # Use encryption secret as the base
    base_secret = ks.secrets.encryption_secret

    # Role-specific labels (similar to TLS)
    role = is_client ? "client" : "server"

    # Derive traffic secret
    # traffic_secret = ExpandWithLabel(base_secret, "<role> traffic", "", hash_len)
    traffic_secret = MLSCrypto.expand_with_label(
        suite, base_secret, "$role traffic",
        UInt8[], MLSCrypto.hash_length(suite)
    )

    # Derive key and IV
    key_len = get_key_length(suite)
    iv_len = 12  # Standard QUIC IV length

    # key = HKDF-Expand-Label(traffic_secret, "quic key", "", key_len)
    key = hkdf_expand_label_quic(suite, traffic_secret, "quic key", UInt8[], key_len)

    # iv = HKDF-Expand-Label(traffic_secret, "quic iv", "", 12)
    iv = hkdf_expand_label_quic(suite, traffic_secret, "quic iv", UInt8[], iv_len)

    # hp = HKDF-Expand-Label(traffic_secret, "quic hp", "", key_len)
    hp_key = hkdf_expand_label_quic(suite, traffic_secret, "quic hp", UInt8[], key_len)

    return TrafficKeys(key, iv, hp_key)
end

"""
Get derived traffic keys, caching the result
"""
function derive_traffic_keys(ks::KeyScheduleState)
    if ks.client_traffic_keys === nothing
        ks.client_traffic_keys = derive_quic_keys(ks, true)
    end
    if ks.server_traffic_keys === nothing
        ks.server_traffic_keys = derive_quic_keys(ks, false)
    end

    return (client=ks.client_traffic_keys, server=ks.server_traffic_keys)
end

"""
HKDF-Expand-Label for QUIC (uses "tls13 " prefix)
"""
function hkdf_expand_label_quic(suite::CipherSuite, secret::Vector{UInt8},
                               label::String, context::Vector{UInt8}, length::Int)
    # QUIC uses TLS 1.3 labels
    full_label = Vector{UInt8}("tls13 $label")

    info = UInt8[]

    # Length (2 bytes, big-endian)
    push!(info, UInt8((length >> 8) & 0xff))
    push!(info, UInt8(length & 0xff))

    # Label length and label
    push!(info, UInt8(Base.length(full_label)))
    append!(info, full_label)

    # Context length and context
    push!(info, UInt8(Base.length(context)))
    append!(info, context)

    return MLSCrypto.kdf_expand(suite, secret, info, length)
end

#=
================================================================================
SENDER RATCHETS (Secret Tree)
================================================================================
RFC 9420 Section 9 - Per-sender key derivation for encryption
=#

"""
Get or create sender secret tree for a leaf
"""
function get_sender_tree!(ks::KeyScheduleState, leaf_index::UInt32)
    if !haskey(ks.sender_trees, leaf_index)
        if ks.secrets === nothing
            error("Key schedule not initialized")
        end

        # Derive leaf-specific secrets from encryption secret
        suite = ks.cipher_suite
        enc_secret = ks.secrets.encryption_secret

        # tree_secret[leaf] = DeriveTreeSecret(encryption_secret, "tree", leaf_index, Hash.Length)
        handshake_secret = MLSCrypto.derive_tree_secret(
            suite, enc_secret, "handshake", leaf_index,
            MLSCrypto.hash_length(suite)
        )

        application_secret = MLSCrypto.derive_tree_secret(
            suite, enc_secret, "application", leaf_index,
            MLSCrypto.hash_length(suite)
        )

        ks.sender_trees[leaf_index] = SenderSecretTree(
            suite,
            handshake_secret,
            application_secret,
            UInt32(0),
            UInt32(0)
        )
    end

    return ks.sender_trees[leaf_index]
end

"""
Get next handshake key for a sender (advances ratchet)
"""
function get_handshake_key!(ks::KeyScheduleState, leaf_index::UInt32)
    tree = get_sender_tree!(ks, leaf_index)
    suite = tree.cipher_suite
    gen = tree.handshake_generation

    # Derive key and nonce for this generation
    key = MLSCrypto.derive_tree_secret(suite, tree.handshake_secret, "key", gen, get_key_length(suite))
    nonce = MLSCrypto.derive_tree_secret(suite, tree.handshake_secret, "nonce", gen, 12)

    # Advance ratchet
    tree.handshake_secret = MLSCrypto.derive_tree_secret(
        suite, tree.handshake_secret, "secret", gen,
        MLSCrypto.hash_length(suite)
    )
    tree.handshake_generation += 1

    return (key=key, nonce=nonce, generation=gen)
end

"""
Get next application key for a sender (advances ratchet)
"""
function get_application_key!(ks::KeyScheduleState, leaf_index::UInt32)
    tree = get_sender_tree!(ks, leaf_index)
    suite = tree.cipher_suite
    gen = tree.application_generation

    # Derive key and nonce for this generation
    key = MLSCrypto.derive_tree_secret(suite, tree.application_secret, "key", gen, get_key_length(suite))
    nonce = MLSCrypto.derive_tree_secret(suite, tree.application_secret, "nonce", gen, 12)

    # Advance ratchet
    tree.application_secret = MLSCrypto.derive_tree_secret(
        suite, tree.application_secret, "secret", gen,
        MLSCrypto.hash_length(suite)
    )
    tree.application_generation += 1

    return (key=key, nonce=nonce, generation=gen)
end

#=
================================================================================
HELPERS
================================================================================
=#

"""
Get AEAD key length for cipher suite
"""
function get_key_length(suite::CipherSuite)
    if suite in (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                 MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        return 16  # 128-bit key (but ChaCha20 uses 32)
    else
        return 32  # 256-bit key
    end
end

"""
Serialize GroupContext for key derivation
"""
function serialize_group_context(gc::GroupContext)
    buf = UInt8[]

    # version (2 bytes)
    push!(buf, UInt8((gc.version >> 8) & 0xff))
    push!(buf, UInt8(gc.version & 0xff))

    # cipher_suite (2 bytes)
    push!(buf, UInt8((UInt16(gc.cipher_suite) >> 8) & 0xff))
    push!(buf, UInt8(UInt16(gc.cipher_suite) & 0xff))

    # group_id (variable, with length prefix)
    push!(buf, UInt8(length(gc.group_id)))
    append!(buf, gc.group_id)

    # epoch (8 bytes)
    for i in 7:-1:0
        push!(buf, UInt8((gc.epoch >> (i*8)) & 0xff))
    end

    # tree_hash (variable, with length prefix)
    push!(buf, UInt8(length(gc.tree_hash)))
    append!(buf, gc.tree_hash)

    # confirmed_transcript_hash (variable, with length prefix)
    push!(buf, UInt8(length(gc.confirmed_transcript_hash)))
    append!(buf, gc.confirmed_transcript_hash)

    # extensions (variable)
    # Simplified: just count
    push!(buf, UInt8(length(gc.extensions)))

    return buf
end

#=
================================================================================
CONFIRMATION TAG
================================================================================
=#

"""
Compute confirmation tag for a Commit message
"""
function compute_confirmation_tag(ks::KeyScheduleState, confirmed_transcript_hash::Vector{UInt8})
    if ks.secrets === nothing
        error("Key schedule not initialized")
    end

    MLSCrypto.mls_hmac(ks.cipher_suite, ks.secrets.confirmation_key, confirmed_transcript_hash)
end

"""
Compute membership tag for a message
"""
function compute_membership_tag(ks::KeyScheduleState, content::Vector{UInt8})
    if ks.secrets === nothing
        error("Key schedule not initialized")
    end

    MLSCrypto.mls_hmac(ks.cipher_suite, ks.secrets.membership_key, content)
end

end # module MLSKeySchedule
