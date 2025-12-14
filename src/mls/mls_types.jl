module MLSTypes

#=
MLS Core Types (RFC 9420)

This module defines the fundamental data structures for Messaging Layer Security.
These types are used throughout the MLS implementation for QUIC-MLS integration.
=#

export CipherSuite, ProtocolVersion, ContentType, SenderType, WireFormat, DEFAULT_CIPHER_SUITE
export HPKEPublicKey, SignaturePublicKey, Credential, CredentialType
export LeafNode, KeyPackage, GroupInfo, GroupContext
export Proposal, ProposalType, Commit, Welcome, ProposalOrRef
export UpdatePath, UpdatePathNode
export AddProposal, UpdateProposal, RemoveProposal, PSKProposal, ReInitProposal, ExternalInitProposal
export GroupSecrets, EncryptedGroupSecrets, KeyPackageRef
export MLSMessage, FramedContent, AuthenticatedContent
export BasicCredential, Extension, Capabilities, Lifetime
export default_capabilities, default_lifetime, MLS_VERSION_1_0
export EXTENSION_TYPE_APPLICATION_ID, EXTENSION_TYPE_RATCHET_TREE
export EXTENSION_TYPE_REQUIRED_CAPABILITIES, EXTENSION_TYPE_EXTERNAL_PUB
export EXTENSION_TYPE_EXTERNAL_SENDERS

# Protocol version for MLS 1.0
const MLS_VERSION_1_0 = UInt16(0x0001)

# Wire format types
@enum WireFormat::UInt16 begin
    WIRE_FORMAT_RESERVED = 0x0000
    WIRE_FORMAT_MLS_PUBLIC_MESSAGE = 0x0001
    WIRE_FORMAT_MLS_PRIVATE_MESSAGE = 0x0002
    WIRE_FORMAT_MLS_WELCOME = 0x0003
    WIRE_FORMAT_MLS_GROUP_INFO = 0x0004
    WIRE_FORMAT_MLS_KEY_PACKAGE = 0x0005
end

# Content types for MLS messages
@enum ContentType::UInt8 begin
    CONTENT_TYPE_RESERVED = 0x00
    CONTENT_TYPE_APPLICATION = 0x01
    CONTENT_TYPE_PROPOSAL = 0x02
    CONTENT_TYPE_COMMIT = 0x03
end

# Sender types
@enum SenderType::UInt8 begin
    SENDER_TYPE_RESERVED = 0x00
    SENDER_TYPE_MEMBER = 0x01
    SENDER_TYPE_EXTERNAL = 0x02
    SENDER_TYPE_NEW_MEMBER_PROPOSAL = 0x03
    SENDER_TYPE_NEW_MEMBER_COMMIT = 0x04
end

# Credential types
@enum CredentialType::UInt16 begin
    CREDENTIAL_TYPE_RESERVED = 0x0000
    CREDENTIAL_TYPE_BASIC = 0x0001
    CREDENTIAL_TYPE_X509 = 0x0002
end

# Proposal types
@enum ProposalType::UInt16 begin
    PROPOSAL_TYPE_RESERVED = 0x0000
    PROPOSAL_TYPE_ADD = 0x0001
    PROPOSAL_TYPE_UPDATE = 0x0002
    PROPOSAL_TYPE_REMOVE = 0x0003
    PROPOSAL_TYPE_PSK = 0x0004
    PROPOSAL_TYPE_REINIT = 0x0005
    PROPOSAL_TYPE_EXTERNAL_INIT = 0x0006
    PROPOSAL_TYPE_GROUP_CONTEXT_EXTENSIONS = 0x0007
end

# MLS Cipher Suites (RFC 9420 Section 17.1)
@enum CipherSuite::UInt16 begin
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007
end

# Default cipher suite for QUIC-MLS (X25519 + ChaCha20-Poly1305)
const DEFAULT_CIPHER_SUITE = MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

#=
================================================================================
CRYPTOGRAPHIC TYPES
================================================================================
=#

"""
HPKE Public Key - used for encryption in the ratchet tree
"""
struct HPKEPublicKey
    data::Vector{UInt8}
end

HPKEPublicKey() = HPKEPublicKey(UInt8[])
Base.isempty(k::HPKEPublicKey) = isempty(k.data)
Base.length(k::HPKEPublicKey) = length(k.data)

"""
Signature Public Key - used for authentication
"""
struct SignaturePublicKey
    data::Vector{UInt8}
end

SignaturePublicKey() = SignaturePublicKey(UInt8[])
Base.isempty(k::SignaturePublicKey) = isempty(k.data)
Base.length(k::SignaturePublicKey) = length(k.data)

#=
================================================================================
CREDENTIALS
================================================================================
=#

"""
Basic Credential - simple identity string
"""
struct BasicCredential
    identity::Vector{UInt8}
end

"""
X.509 Credential - certificate chain
"""
struct X509Credential
    cert_chain::Vector{Vector{UInt8}}  # DER-encoded certificates
end

"""
Credential - identifies a member
"""
struct Credential
    credential_type::CredentialType
    basic::Union{BasicCredential, Nothing}
    x509::Union{X509Credential, Nothing}
end

function Credential(identity::Vector{UInt8})
    Credential(CREDENTIAL_TYPE_BASIC, BasicCredential(identity), nothing)
end

function Credential(cert_chain::Vector{Vector{UInt8}})
    Credential(CREDENTIAL_TYPE_X509, nothing, X509Credential(cert_chain))
end

#=
================================================================================
LEAF NODE & KEY PACKAGE
================================================================================
=#

"""
Capabilities - what a client supports
"""
struct Capabilities
    versions::Vector{UInt16}
    cipher_suites::Vector{CipherSuite}
    extensions::Vector{UInt16}
    proposals::Vector{ProposalType}
    credentials::Vector{CredentialType}
end

function default_capabilities()
    Capabilities(
        [MLS_VERSION_1_0],
        [DEFAULT_CIPHER_SUITE, MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
        UInt16[],
        [PROPOSAL_TYPE_ADD, PROPOSAL_TYPE_UPDATE, PROPOSAL_TYPE_REMOVE],
        [CREDENTIAL_TYPE_BASIC, CREDENTIAL_TYPE_X509]
    )
end

"""
Lifetime - validity period for KeyPackage
"""
struct Lifetime
    not_before::UInt64  # Unix timestamp
    not_after::UInt64   # Unix timestamp
end

function default_lifetime()
    now = UInt64(time())
    # Valid for 90 days
    Lifetime(now, now + 90 * 24 * 60 * 60)
end

# Extension types (RFC 9420 Section 17.3)
const EXTENSION_TYPE_APPLICATION_ID = UInt16(0x0001)
const EXTENSION_TYPE_RATCHET_TREE = UInt16(0x0002)
const EXTENSION_TYPE_REQUIRED_CAPABILITIES = UInt16(0x0003)
const EXTENSION_TYPE_EXTERNAL_PUB = UInt16(0x0004)
const EXTENSION_TYPE_EXTERNAL_SENDERS = UInt16(0x0005)

"""
Extension - generic extension container
"""
struct Extension
    extension_type::UInt16
    extension_data::Vector{UInt8}
end

"""
LeafNode - represents a member in the ratchet tree
"""
struct LeafNode
    encryption_key::HPKEPublicKey
    signature_key::SignaturePublicKey
    credential::Credential
    capabilities::Capabilities
    leaf_node_source::UInt8  # 1=key_package, 2=update, 3=commit
    extensions::Vector{Extension}
    signature::Vector{UInt8}
end

"""
KeyPackage - used to add members to a group
"""
struct KeyPackage
    version::UInt16
    cipher_suite::CipherSuite
    init_key::HPKEPublicKey  # For encrypting Welcome
    leaf_node::LeafNode
    extensions::Vector{Extension}
    signature::Vector{UInt8}
end

"""
KeyPackageRef - hash of KeyPackage for referencing
"""
struct KeyPackageRef
    data::Vector{UInt8}  # Hash output
end

#=
================================================================================
GROUP CONTEXT
================================================================================
=#

"""
GroupContext - defines the current state of a group
"""
struct GroupContext
    version::UInt16
    cipher_suite::CipherSuite
    group_id::Vector{UInt8}
    epoch::UInt64
    tree_hash::Vector{UInt8}
    confirmed_transcript_hash::Vector{UInt8}
    extensions::Vector{Extension}
end

function GroupContext(group_id::Vector{UInt8}, cipher_suite::CipherSuite = DEFAULT_CIPHER_SUITE)
    GroupContext(
        MLS_VERSION_1_0,
        cipher_suite,
        group_id,
        UInt64(0),
        UInt8[],
        UInt8[],
        Extension[]
    )
end

#=
================================================================================
PROPOSALS
================================================================================
=#

"""
Add Proposal - add a new member
"""
struct AddProposal
    key_package::KeyPackage
end

"""
Update Proposal - update own leaf node
"""
struct UpdateProposal
    leaf_node::LeafNode
end

"""
Remove Proposal - remove a member
"""
struct RemoveProposal
    removed::UInt32  # Leaf index
end

"""
PreSharedKey Proposal - inject external PSK
"""
struct PSKProposal
    psk_type::UInt8  # 1=external, 2=resumption
    psk_id::Vector{UInt8}
    psk_nonce::Vector{UInt8}
end

"""
ReInit Proposal - reinitialize group with new parameters
"""
struct ReInitProposal
    group_id::Vector{UInt8}
    version::UInt16
    cipher_suite::CipherSuite
    extensions::Vector{Extension}
end

"""
ExternalInit Proposal - for external joins
"""
struct ExternalInitProposal
    kem_output::Vector{UInt8}
end

"""
Proposal - union of all proposal types
"""
struct Proposal
    proposal_type::ProposalType
    add::Union{AddProposal, Nothing}
    update::Union{UpdateProposal, Nothing}
    remove::Union{RemoveProposal, Nothing}
    psk::Union{PSKProposal, Nothing}
    reinit::Union{ReInitProposal, Nothing}
    external_init::Union{ExternalInitProposal, Nothing}
end

# Constructors for each proposal type
Proposal(add::AddProposal) = Proposal(PROPOSAL_TYPE_ADD, add, nothing, nothing, nothing, nothing, nothing)
Proposal(update::UpdateProposal) = Proposal(PROPOSAL_TYPE_UPDATE, nothing, update, nothing, nothing, nothing, nothing)
Proposal(remove::RemoveProposal) = Proposal(PROPOSAL_TYPE_REMOVE, nothing, nothing, remove, nothing, nothing, nothing)
Proposal(psk::PSKProposal) = Proposal(PROPOSAL_TYPE_PSK, nothing, nothing, nothing, psk, nothing, nothing)
Proposal(reinit::ReInitProposal) = Proposal(PROPOSAL_TYPE_REINIT, nothing, nothing, nothing, nothing, reinit, nothing)
Proposal(ext::ExternalInitProposal) = Proposal(PROPOSAL_TYPE_EXTERNAL_INIT, nothing, nothing, nothing, nothing, nothing, ext)

#=
================================================================================
COMMIT
================================================================================
=#

"""
ProposalOrRef - either inline proposal or reference to cached proposal
"""
struct ProposalOrRef
    is_reference::Bool
    proposal::Union{Proposal, Nothing}
    reference::Union{Vector{UInt8}, Nothing}  # ProposalRef hash
end

ProposalOrRef(p::Proposal) = ProposalOrRef(false, p, nothing)
ProposalOrRef(ref::Vector{UInt8}) = ProposalOrRef(true, nothing, ref)

"""
UpdatePath - path update for commits
"""
struct UpdatePathNode
    encryption_key::HPKEPublicKey
    encrypted_path_secret::Vector{Vector{UInt8}}  # One per resolution
end

struct UpdatePath
    leaf_node::LeafNode
    nodes::Vector{UpdatePathNode}
end

"""
Commit - applies proposals and updates group state
"""
struct Commit
    proposals::Vector{ProposalOrRef}
    path::Union{UpdatePath, Nothing}
end

#=
================================================================================
WELCOME MESSAGE
================================================================================
=#

"""
GroupSecrets - encrypted secrets for new member
"""
struct GroupSecrets
    joiner_secret::Vector{UInt8}
    path_secret::Union{Vector{UInt8}, Nothing}
    psks::Vector{Tuple{UInt8, Vector{UInt8}}}  # (type, id) pairs
end

"""
EncryptedGroupSecrets - for specific KeyPackage
"""
struct EncryptedGroupSecrets
    new_member::KeyPackageRef
    encrypted_group_secrets::Vector{UInt8}  # HPKE ciphertext
end

"""
GroupInfo - public group information
"""
struct GroupInfo
    group_context::GroupContext
    extensions::Vector{Extension}
    confirmation_tag::Vector{UInt8}
    signer::UInt32  # Leaf index of signer
    signature::Vector{UInt8}
end

"""
Welcome - message to add new members
"""
struct Welcome
    cipher_suite::CipherSuite
    secrets::Vector{EncryptedGroupSecrets}
    encrypted_group_info::Vector{UInt8}
end

#=
================================================================================
FRAMED CONTENT & MLS MESSAGE
================================================================================
=#

"""
Sender - identifies message sender
"""
struct Sender
    sender_type::SenderType
    leaf_index::Union{UInt32, Nothing}  # For member sender
    sender_index::Union{UInt32, Nothing}  # For external sender
end

Sender(leaf_index::UInt32) = Sender(SENDER_TYPE_MEMBER, leaf_index, nothing)

"""
FramedContent - the content being authenticated
"""
struct FramedContent
    group_id::Vector{UInt8}
    epoch::UInt64
    sender::Sender
    authenticated_data::Vector{UInt8}
    content_type::ContentType
    # Content (one of):
    application_data::Union{Vector{UInt8}, Nothing}
    proposal::Union{Proposal, Nothing}
    commit::Union{Commit, Nothing}
end

"""
FramedContentAuthData - authentication for FramedContent
"""
struct FramedContentAuthData
    signature::Vector{UInt8}
    confirmation_tag::Union{Vector{UInt8}, Nothing}  # Only for Commit
end

"""
AuthenticatedContent - signed content
"""
struct AuthenticatedContent
    wire_format::WireFormat
    content::FramedContent
    auth::FramedContentAuthData
end

"""
PublicMessage - unencrypted authenticated message
"""
struct PublicMessage
    content::FramedContent
    auth::FramedContentAuthData
    membership_tag::Union{Vector{UInt8}, Nothing}
end

"""
PrivateMessage - encrypted authenticated message
"""
struct PrivateMessage
    group_id::Vector{UInt8}
    epoch::UInt64
    content_type::ContentType
    authenticated_data::Vector{UInt8}
    encrypted_sender_data::Vector{UInt8}
    ciphertext::Vector{UInt8}
end

"""
MLSMessage - top-level MLS message container
"""
struct MLSMessage
    version::UInt16
    wire_format::WireFormat
    # One of:
    public_message::Union{PublicMessage, Nothing}
    private_message::Union{PrivateMessage, Nothing}
    welcome::Union{Welcome, Nothing}
    group_info::Union{GroupInfo, Nothing}
    key_package::Union{KeyPackage, Nothing}
end

# Constructors
MLSMessage(msg::PublicMessage) = MLSMessage(MLS_VERSION_1_0, WIRE_FORMAT_MLS_PUBLIC_MESSAGE, msg, nothing, nothing, nothing, nothing)
MLSMessage(msg::PrivateMessage) = MLSMessage(MLS_VERSION_1_0, WIRE_FORMAT_MLS_PRIVATE_MESSAGE, nothing, msg, nothing, nothing, nothing)
MLSMessage(msg::Welcome) = MLSMessage(MLS_VERSION_1_0, WIRE_FORMAT_MLS_WELCOME, nothing, nothing, msg, nothing, nothing)
MLSMessage(msg::GroupInfo) = MLSMessage(MLS_VERSION_1_0, WIRE_FORMAT_MLS_GROUP_INFO, nothing, nothing, nothing, msg, nothing)
MLSMessage(msg::KeyPackage) = MLSMessage(MLS_VERSION_1_0, WIRE_FORMAT_MLS_KEY_PACKAGE, nothing, nothing, nothing, nothing, msg)

end # module MLSTypes
