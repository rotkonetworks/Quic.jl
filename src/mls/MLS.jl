module MLS

#=
MLS (Messaging Layer Security) for QUIC

This module implements RFC 9420 MLS protocol for use with QUIC, following
draft-tian-quic-quicmls. MLS provides authenticated key exchange with
forward secrecy and post-compromise security.

Architecture:
- MLSTypes: Core data structures (KeyPackage, Welcome, Commit, etc.)
- MLSCrypto: Cryptographic operations (HPKE, signatures, KDF)
- MLSTree: Ratchet tree for group key management
- MLSKeySchedule: Key derivation for traffic secrets
- MLSHandshake: Group state machine
- QuicMLS: QUIC integration layer

Usage for QUIC-MLS:

    # Server side
    server_config = QuicMLSConfig(b"server.example.com")
    server = init_quic_mls_server(server_config)

    # Process client's KeyPackage from CRYPTO frame
    process_crypto_data(server, client_crypto_data)

    # Get Welcome to send back
    welcome_data = get_crypto_data_to_send(server)
    # Send welcome_data in CRYPTO frame

    # Get derived QUIC keys
    keys = get_quic_keys(server)

    # Client side
    client_config = QuicMLSConfig(b"client.example.com")
    client = init_quic_mls_client(client_config)

    # Get KeyPackage to send
    kp_data = get_crypto_data_to_send(client)
    # Send kp_data in CRYPTO frame

    # Process Welcome from server
    process_crypto_data(client, welcome_from_server)

    # Get derived QUIC keys
    keys = get_quic_keys(client)
=#

# Core types must be loaded first
include("mls_types.jl")
using .MLSTypes

# Cryptographic primitives
include("mls_crypto.jl")
using .MLSCrypto

# Ratchet tree
include("mls_tree.jl")
using .MLSTree

# Key schedule
include("mls_key_schedule.jl")
using .MLSKeySchedule

# Handshake state machine
include("mls_handshake.jl")
using .MLSHandshake

# QUIC integration
include("quic_mls.jl")
using .QuicMLS

# Re-export main types and functions
export CipherSuite, DEFAULT_CIPHER_SUITE
export MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
export MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

# KeyPackage creation
export create_key_package, KeyPackage, KeyPackagePrivate

# Group operations
export create_group, join_group, MLSGroupState

# QUIC-MLS API
export QuicMLSConnection, QuicMLSConfig, QuicMLSKeys
export QuicMLSRole, QUIC_MLS_CLIENT, QUIC_MLS_SERVER
export init_quic_mls_client, init_quic_mls_server
export process_crypto_data, get_crypto_data_to_send
export is_handshake_complete, get_quic_keys
export get_send_key, get_recv_key
export get_epoch, update_epoch!

# Re-export QuicMLS.export_secret (for QuicMLSConnection)
const export_secret = QuicMLS.export_secret
export export_secret

end # module MLS
