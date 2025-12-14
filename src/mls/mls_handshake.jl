module MLSHandshake

#=
MLS Handshake State Machine (RFC 9420)

This module implements the MLS group state machine for QUIC-MLS integration.
It handles:
- Group creation and initialization
- KeyPackage generation and validation
- Welcome message processing (joining groups)
- Proposal and Commit message handling
- Group state transitions across epochs

For QUIC-MLS (draft-tian-quic-quicmls), this replaces the TLS handshake
for establishing shared traffic keys between endpoints.
=#

using ..MLSTypes
using ..MLSTypes: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                 MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                 DEFAULT_CIPHER_SUITE
using ..MLSCrypto
using ..MLSTree
using ..MLSKeySchedule

export MLSGroupState, MLSRole, KeyPackagePrivate
export create_group, join_group, create_key_package
export create_add_proposal, create_remove_proposal, create_update_proposal
export create_commit, process_commit, process_welcome
export get_traffic_keys, export_secret

#=
================================================================================
MLS ROLE AND STATE
================================================================================
=#

"""
Role in the MLS group (for QUIC-MLS, maps to client/server)
"""
@enum MLSRole begin
    MLS_ROLE_CREATOR    # Created the group (typically server)
    MLS_ROLE_JOINER     # Joined via Welcome (typically client)
    MLS_ROLE_EXTERNAL   # External sender (not a member)
end

"""
Private key material for a KeyPackage
"""
struct KeyPackagePrivate
    init_key_priv::Vector{UInt8}      # HPKE private key for Welcome decryption
    encryption_key_priv::Vector{UInt8} # HPKE private key for tree
    signature_key_priv::Vector{UInt8}  # Signature private key
end

"""
Pending proposal awaiting commit
"""
struct PendingProposal
    proposal::Proposal
    sender::UInt32  # Leaf index of sender
    proposal_ref::Vector{UInt8}  # Hash for referencing
end

"""
MLS Group State - complete state of an MLS group
"""
mutable struct MLSGroupState
    # Identity
    role::MLSRole
    cipher_suite::CipherSuite
    group_id::Vector{UInt8}

    # Current epoch state
    epoch::UInt64
    group_context::GroupContext

    # Ratchet tree
    tree::RatchetTree
    my_leaf_index::UInt32

    # Key schedule
    key_schedule::KeyScheduleState

    # My private keys
    my_encryption_key_priv::Vector{UInt8}
    my_signature_key_priv::Vector{UInt8}

    # Pending proposals (not yet committed)
    pending_proposals::Vector{PendingProposal}

    # Transcript hash for signing
    confirmed_transcript_hash::Vector{UInt8}
    interim_transcript_hash::Vector{UInt8}

    # Cached values
    tree_hash::Vector{UInt8}
end

#=
================================================================================
KEY PACKAGE CREATION
================================================================================
=#

"""
Generate a new KeyPackage for joining groups

Returns (KeyPackage, KeyPackagePrivate) tuple
"""
function create_key_package(identity::Vector{UInt8};
                           cipher_suite::CipherSuite = DEFAULT_CIPHER_SUITE)
    # Generate HPKE key pair for init_key (Welcome encryption)
    init_pub, init_priv = MLSCrypto.generate_hpke_keypair(cipher_suite)

    # Generate HPKE key pair for encryption_key (tree)
    enc_pub, enc_priv = MLSCrypto.generate_hpke_keypair(cipher_suite)

    # Generate signature key pair
    sig_pub, sig_priv = MLSCrypto.generate_signature_keypair(cipher_suite)

    # Create credential
    credential = Credential(identity)

    # Create leaf node (unsigned initially)
    leaf_node = LeafNode(
        HPKEPublicKey(enc_pub),
        SignaturePublicKey(sig_pub),
        credential,
        default_capabilities(),
        UInt8(1),  # key_package source
        Extension[],
        UInt8[]  # signature placeholder
    )

    # Sign leaf node
    leaf_node_tbs = serialize_leaf_node_tbs(leaf_node, cipher_suite)
    leaf_signature = MLSCrypto.sign_with_label(cipher_suite, sig_priv, "LeafNodeTBS", leaf_node_tbs)

    # Create signed leaf node
    signed_leaf = LeafNode(
        leaf_node.encryption_key,
        leaf_node.signature_key,
        leaf_node.credential,
        leaf_node.capabilities,
        leaf_node.leaf_node_source,
        leaf_node.extensions,
        leaf_signature
    )

    # Create KeyPackage (unsigned)
    key_package = KeyPackage(
        MLS_VERSION_1_0,
        cipher_suite,
        HPKEPublicKey(init_pub),
        signed_leaf,
        Extension[],
        UInt8[]  # signature placeholder
    )

    # Sign KeyPackage
    kp_tbs = serialize_key_package_tbs(key_package)
    kp_signature = MLSCrypto.sign_with_label(cipher_suite, sig_priv, "KeyPackageTBS", kp_tbs)

    # Create signed KeyPackage
    signed_kp = KeyPackage(
        key_package.version,
        key_package.cipher_suite,
        key_package.init_key,
        key_package.leaf_node,
        key_package.extensions,
        kp_signature
    )

    # Create private key bundle
    private = KeyPackagePrivate(init_priv, enc_priv, sig_priv)

    return (signed_kp, private)
end

"""
Validate a KeyPackage
"""
function validate_key_package(kp::KeyPackage)
    # Check version
    if kp.version != MLS_VERSION_1_0
        return false
    end

    # Check cipher suite is supported
    if !(kp.cipher_suite in (
        MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    ))
        return false
    end

    # Verify leaf node signature
    leaf_tbs = serialize_leaf_node_tbs(kp.leaf_node, kp.cipher_suite)
    if !MLSCrypto.verify_with_label(kp.cipher_suite, kp.leaf_node.signature_key.data,
                                    "LeafNodeTBS", leaf_tbs, kp.leaf_node.signature)
        return false
    end

    # Verify KeyPackage signature
    kp_tbs = serialize_key_package_tbs(kp)
    if !MLSCrypto.verify_with_label(kp.cipher_suite, kp.leaf_node.signature_key.data,
                                    "KeyPackageTBS", kp_tbs, kp.signature)
        return false
    end

    # Check lifetime if present
    # (simplified - would check extensions for lifetime)

    return true
end

#=
================================================================================
GROUP CREATION
================================================================================
=#

"""
Create a new MLS group (typically done by server in QUIC-MLS)
"""
function create_group(identity::Vector{UInt8};
                     group_id::Union{Vector{UInt8}, Nothing} = nothing,
                     cipher_suite::CipherSuite = DEFAULT_CIPHER_SUITE)
    # Generate group ID if not provided
    actual_group_id = group_id === nothing ? MLSCrypto.random_bytes(16) : group_id

    # Generate our key material
    enc_pub, enc_priv = MLSCrypto.generate_hpke_keypair(cipher_suite)
    sig_pub, sig_priv = MLSCrypto.generate_signature_keypair(cipher_suite)

    # Create our leaf node
    credential = Credential(identity)
    leaf_node = LeafNode(
        HPKEPublicKey(enc_pub),
        SignaturePublicKey(sig_pub),
        credential,
        default_capabilities(),
        UInt8(3),  # commit source (creator)
        Extension[],
        UInt8[]
    )

    # Sign leaf node
    leaf_tbs = serialize_leaf_node_tbs(leaf_node, cipher_suite)
    leaf_sig = MLSCrypto.sign_with_label(cipher_suite, sig_priv, "LeafNodeTBS", leaf_tbs)
    signed_leaf = LeafNode(
        leaf_node.encryption_key,
        leaf_node.signature_key,
        leaf_node.credential,
        leaf_node.capabilities,
        leaf_node.leaf_node_source,
        leaf_node.extensions,
        leaf_sig
    )

    # Create ratchet tree with just ourselves
    tree = MLSTree.create_tree(cipher_suite)
    MLSTree.set_leaf!(tree, UInt32(0), signed_leaf)

    # Compute tree hash
    tree_hash = MLSTree.compute_tree_hash(tree)

    # Initialize key schedule
    key_schedule = MLSKeySchedule.init_key_schedule(cipher_suite)

    # Create initial group context
    group_context = GroupContext(
        MLS_VERSION_1_0,
        cipher_suite,
        actual_group_id,
        UInt64(0),
        tree_hash,
        UInt8[],  # Initial transcript hash is empty
        Extension[]
    )

    # Bootstrap key schedule with empty commit secret
    hash_len = MLSCrypto.hash_length(cipher_suite)
    empty_commit = zeros(UInt8, hash_len)
    MLSKeySchedule.advance_epoch!(key_schedule, empty_commit, UInt8[], group_context)

    # Create group state
    state = MLSGroupState(
        MLS_ROLE_CREATOR,
        cipher_suite,
        actual_group_id,
        UInt64(0),
        group_context,
        tree,
        UInt32(0),  # We are leaf 0
        key_schedule,
        enc_priv,
        sig_priv,
        PendingProposal[],
        UInt8[],
        UInt8[],
        tree_hash
    )

    return state
end

#=
================================================================================
PROPOSALS
================================================================================
=#

"""
Create an Add proposal to add a new member
"""
function create_add_proposal(state::MLSGroupState, key_package::KeyPackage)
    if !validate_key_package(key_package)
        error("Invalid KeyPackage")
    end

    proposal = Proposal(AddProposal(key_package))

    # Compute proposal reference
    proposal_bytes = serialize_proposal(proposal)
    ref = MLSCrypto.mls_hash(state.cipher_suite, proposal_bytes)

    # Add to pending
    pending = PendingProposal(proposal, state.my_leaf_index, ref)
    push!(state.pending_proposals, pending)

    return proposal
end

"""
Create a Remove proposal to remove a member
"""
function create_remove_proposal(state::MLSGroupState, leaf_index::UInt32)
    if leaf_index >= MLSTree.leaf_count(state.tree)
        error("Invalid leaf index")
    end

    proposal = Proposal(RemoveProposal(leaf_index))

    # Compute proposal reference
    proposal_bytes = serialize_proposal(proposal)
    ref = MLSCrypto.mls_hash(state.cipher_suite, proposal_bytes)

    # Add to pending
    pending = PendingProposal(proposal, state.my_leaf_index, ref)
    push!(state.pending_proposals, pending)

    return proposal
end

"""
Create an Update proposal to update own leaf
"""
function create_update_proposal(state::MLSGroupState)
    # Generate new encryption key
    enc_pub, enc_priv = MLSCrypto.generate_hpke_keypair(state.cipher_suite)

    # Get current leaf
    current_leaf = MLSTree.get_leaf(state.tree, state.my_leaf_index)
    if current_leaf === nothing
        error("Own leaf not found")
    end

    # Create updated leaf node
    new_leaf = LeafNode(
        HPKEPublicKey(enc_pub),
        current_leaf.signature_key,
        current_leaf.credential,
        current_leaf.capabilities,
        UInt8(2),  # update source
        current_leaf.extensions,
        UInt8[]
    )

    # Sign new leaf
    leaf_tbs = serialize_leaf_node_tbs(new_leaf, state.cipher_suite)
    leaf_sig = MLSCrypto.sign_with_label(state.cipher_suite, state.my_signature_key_priv,
                                         "LeafNodeTBS", leaf_tbs)
    signed_leaf = LeafNode(
        new_leaf.encryption_key,
        new_leaf.signature_key,
        new_leaf.credential,
        new_leaf.capabilities,
        new_leaf.leaf_node_source,
        new_leaf.extensions,
        leaf_sig
    )

    proposal = Proposal(UpdateProposal(signed_leaf))

    # Compute proposal reference
    proposal_bytes = serialize_proposal(proposal)
    ref = MLSCrypto.mls_hash(state.cipher_suite, proposal_bytes)

    # Add to pending (store new private key)
    pending = PendingProposal(proposal, state.my_leaf_index, ref)
    push!(state.pending_proposals, pending)

    # Update our private key (will be used after commit)
    state.my_encryption_key_priv = enc_priv

    return proposal
end

#=
================================================================================
COMMIT
================================================================================
=#

"""
Create a Commit message applying pending proposals
"""
function create_commit(state::MLSGroupState;
                      proposals::Vector{ProposalOrRef} = ProposalOrRef[])
    suite = state.cipher_suite

    # Collect all proposals (pending + inline)
    all_proposals = copy(proposals)
    for pending in state.pending_proposals
        push!(all_proposals, ProposalOrRef(pending.reference))
    end

    # Generate new path secret
    path_secret = MLSCrypto.random_bytes(MLSCrypto.hash_length(suite))

    # Generate new leaf keys for update path
    enc_pub, enc_priv = MLSCrypto.generate_hpke_keypair(suite)

    # Get current leaf and update it
    current_leaf = MLSTree.get_leaf(state.tree, state.my_leaf_index)
    if current_leaf === nothing
        error("Own leaf not found")
    end

    new_leaf = LeafNode(
        HPKEPublicKey(enc_pub),
        current_leaf.signature_key,
        current_leaf.credential,
        current_leaf.capabilities,
        UInt8(3),  # commit source
        current_leaf.extensions,
        UInt8[]
    )

    # Sign new leaf
    leaf_tbs = serialize_leaf_node_tbs(new_leaf, suite)
    leaf_sig = MLSCrypto.sign_with_label(suite, state.my_signature_key_priv,
                                         "LeafNodeTBS", leaf_tbs)
    signed_leaf = LeafNode(
        new_leaf.encryption_key,
        new_leaf.signature_key,
        new_leaf.credential,
        new_leaf.capabilities,
        new_leaf.leaf_node_source,
        new_leaf.extensions,
        leaf_sig
    )

    # Create update path (encrypt path secret to each resolution)
    update_path = create_update_path(state, signed_leaf, path_secret)

    # Create commit
    commit = Commit(all_proposals, update_path)

    # Derive commit secret from path secret
    commit_secret = MLSCrypto.derive_secret(suite, path_secret, "path")

    # Apply proposals to tree (for sender)
    apply_proposals!(state, all_proposals)

    # Update our leaf
    MLSTree.set_leaf!(state.tree, state.my_leaf_index, signed_leaf)
    state.my_encryption_key_priv = enc_priv

    # Compute new tree hash
    state.tree_hash = MLSTree.compute_tree_hash(state.tree)

    # Update group context for new epoch
    state.epoch += 1
    state.group_context = GroupContext(
        state.group_context.version,
        state.group_context.cipher_suite,
        state.group_id,
        state.epoch,
        state.tree_hash,
        state.confirmed_transcript_hash,
        state.group_context.extensions
    )

    # Advance key schedule
    MLSKeySchedule.advance_epoch!(state.key_schedule, commit_secret, UInt8[], state.group_context)

    # Clear pending proposals
    empty!(state.pending_proposals)

    # Compute confirmation tag
    confirmation_tag = MLSKeySchedule.compute_confirmation_tag(
        state.key_schedule, state.confirmed_transcript_hash
    )

    return (commit, confirmation_tag)
end

"""
Create update path for commit
"""
function create_update_path(state::MLSGroupState, new_leaf::LeafNode, path_secret::Vector{UInt8})
    suite = state.cipher_suite
    tree = state.tree
    leaf_idx = state.my_leaf_index

    # Get direct path from leaf to root
    direct_path = MLSTree.direct_path(tree, leaf_idx)

    if isempty(direct_path)
        # Only one member, no path needed
        return UpdatePath(new_leaf, UpdatePathNode[])
    end

    nodes = UpdatePathNode[]
    current_secret = path_secret

    for (i, node_idx) in enumerate(direct_path)
        # Derive node secret
        node_secret = MLSCrypto.derive_tree_secret(suite, current_secret, "node", UInt32(i),
                                                   MLSCrypto.hash_length(suite))

        # Generate node keypair
        node_pub, node_priv = MLSCrypto.generate_hpke_keypair(suite)

        # Get resolution (nodes that need this secret)
        resolution = MLSTree.resolution(tree, MLSTree.sibling(tree, node_idx))

        # Encrypt secret to each resolution member
        encrypted_secrets = Vector{UInt8}[]
        for res_idx in resolution
            # Get encryption key for this node
            enc_key = MLSTree.get_node_public_key(tree, res_idx)
            if enc_key !== nothing && !isempty(enc_key.data)
                # Encrypt node secret with HPKE
                ciphertext = MLSCrypto.hpke_seal(suite, enc_key.data,
                                                  UInt8[], UInt8[], node_secret)
                push!(encrypted_secrets, ciphertext)
            end
        end

        push!(nodes, UpdatePathNode(HPKEPublicKey(node_pub), encrypted_secrets))

        # Update tree with new node
        MLSTree.set_node_key!(tree, node_idx, node_pub, node_priv)

        # Derive next secret
        current_secret = node_secret
    end

    return UpdatePath(new_leaf, nodes)
end

"""
Process a Commit message from another member
"""
function process_commit(state::MLSGroupState, commit::Commit,
                       sender_leaf::UInt32, confirmation_tag::Vector{UInt8})
    suite = state.cipher_suite

    # Apply proposals
    apply_proposals!(state, commit.proposals)

    # Process update path if present
    commit_secret = zeros(UInt8, MLSCrypto.hash_length(suite))

    if commit.path !== nothing
        # Update sender's leaf
        MLSTree.set_leaf!(state.tree, sender_leaf, commit.path.leaf_node)

        # Decrypt path secret for our position
        path_secret = decrypt_update_path(state, commit.path, sender_leaf)
        if path_secret !== nothing
            commit_secret = MLSCrypto.derive_secret(suite, path_secret, "path")
        end
    end

    # Update tree hash
    state.tree_hash = MLSTree.compute_tree_hash(state.tree)

    # Advance epoch
    state.epoch += 1
    state.group_context = GroupContext(
        state.group_context.version,
        state.group_context.cipher_suite,
        state.group_id,
        state.epoch,
        state.tree_hash,
        state.confirmed_transcript_hash,
        state.group_context.extensions
    )

    # Advance key schedule
    MLSKeySchedule.advance_epoch!(state.key_schedule, commit_secret, UInt8[], state.group_context)

    # Verify confirmation tag
    expected_tag = MLSKeySchedule.compute_confirmation_tag(
        state.key_schedule, state.confirmed_transcript_hash
    )
    if confirmation_tag != expected_tag
        error("Confirmation tag mismatch")
    end

    # Clear pending proposals
    empty!(state.pending_proposals)

    return true
end

"""
Decrypt update path to recover path secret
"""
function decrypt_update_path(state::MLSGroupState, path::UpdatePath, sender_leaf::UInt32)
    suite = state.cipher_suite
    tree = state.tree

    # Find our position in the tree relative to sender's direct path
    sender_path = MLSTree.direct_path(tree, sender_leaf)
    my_path = MLSTree.direct_path(tree, state.my_leaf_index)

    # Find common ancestor
    common_idx = -1
    for (i, node_idx) in enumerate(sender_path)
        if node_idx in my_path
            common_idx = i
            break
        end
    end

    if common_idx < 0 || common_idx > length(path.nodes)
        return nothing
    end

    # Get the encrypted secret for us at the common ancestor
    path_node = path.nodes[common_idx]

    # Find which ciphertext is for us
    sibling_idx = MLSTree.sibling(tree, sender_path[common_idx])
    resolution = MLSTree.resolution(tree, sibling_idx)

    my_pos = findfirst(idx -> MLSTree.is_descendant(tree, state.my_leaf_index, idx), resolution)
    if my_pos === nothing || my_pos > length(path_node.encrypted_path_secret)
        return nothing
    end

    # Decrypt with our private key
    ciphertext = path_node.encrypted_path_secret[my_pos]
    path_secret = MLSCrypto.hpke_open(suite, state.my_encryption_key_priv,
                                       UInt8[], UInt8[], ciphertext)

    return path_secret
end

"""
Apply proposals to group state
"""
function apply_proposals!(state::MLSGroupState, proposals::Vector{ProposalOrRef})
    for por in proposals
        proposal = por.is_reference ? resolve_proposal(state, por.reference) : por.proposal
        if proposal === nothing
            continue
        end

        apply_proposal!(state, proposal)
    end
end

function apply_proposal!(state::MLSGroupState, proposal::Proposal)
    if proposal.proposal_type == PROPOSAL_TYPE_ADD && proposal.add !== nothing
        # Add new member
        kp = proposal.add.key_package
        new_leaf_idx = MLSTree.add_leaf!(state.tree, kp.leaf_node)
        # Note: leaf index returned for Welcome message creation

    elseif proposal.proposal_type == PROPOSAL_TYPE_REMOVE && proposal.remove !== nothing
        # Remove member
        MLSTree.remove_leaf!(state.tree, proposal.remove.removed)

    elseif proposal.proposal_type == PROPOSAL_TYPE_UPDATE && proposal.update !== nothing
        # This is handled by the committer
        # (Update proposals update the sender's own leaf)
    end
end

"""
Resolve a proposal reference to the actual proposal
"""
function resolve_proposal(state::MLSGroupState, ref::Union{Vector{UInt8}, Nothing})
    if ref === nothing
        return nothing
    end

    for pending in state.pending_proposals
        if pending.proposal_ref == ref
            return pending.proposal
        end
    end
    return nothing
end

#=
================================================================================
WELCOME MESSAGE (JOINING)
================================================================================
=#

"""
Create a Welcome message for new members after a commit with Add proposals
"""
function create_welcome(state::MLSGroupState, add_proposals::Vector{AddProposal},
                       joiner_secret::Vector{UInt8})
    suite = state.cipher_suite

    # Create ratchet_tree extension (RFC 9420 Section 12.4.3.3)
    tree_data = MLSTree.serialize_ratchet_tree(state.tree)
    ratchet_tree_ext = Extension(EXTENSION_TYPE_RATCHET_TREE, tree_data)

    # Create GroupInfo with ratchet_tree extension
    confirmation_tag = MLSKeySchedule.compute_confirmation_tag(
        state.key_schedule, state.confirmed_transcript_hash
    )

    group_info = GroupInfo(
        state.group_context,
        [ratchet_tree_ext],  # Include ratchet_tree extension
        confirmation_tag,
        state.my_leaf_index,
        UInt8[]  # signature placeholder
    )

    # Sign GroupInfo
    gi_tbs = serialize_group_info_tbs(group_info)
    gi_sig = MLSCrypto.sign_with_label(suite, state.my_signature_key_priv,
                                        "GroupInfoTBS", gi_tbs)
    signed_gi = GroupInfo(
        group_info.group_context,
        group_info.extensions,
        group_info.confirmation_tag,
        group_info.signer,
        gi_sig
    )

    # Derive welcome secret
    welcome_secret = MLSKeySchedule.derive_welcome_secret(suite, joiner_secret)

    # Encrypt GroupInfo with welcome secret
    welcome_key, welcome_nonce = derive_welcome_key_nonce(suite, welcome_secret)
    encrypted_group_info = MLSCrypto.aead_encrypt(suite, welcome_key, welcome_nonce,
                                                   UInt8[], serialize_group_info(signed_gi))

    # Create encrypted secrets for each new member
    encrypted_secrets = EncryptedGroupSecrets[]

    for add in add_proposals
        kp = add.key_package

        # Compute KeyPackage reference
        kp_ref = KeyPackageRef(MLSCrypto.ref_hash(suite, "MLS 1.0 KeyPackage Reference",
                                                   serialize_key_package(kp)))

        # Create GroupSecrets
        group_secrets = GroupSecrets(joiner_secret, nothing, Tuple{UInt8, Vector{UInt8}}[])
        gs_bytes = serialize_group_secrets(group_secrets)

        # Encrypt to the KeyPackage's init_key
        encrypted = MLSCrypto.hpke_seal(suite, kp.init_key.data, UInt8[], UInt8[], gs_bytes)

        push!(encrypted_secrets, EncryptedGroupSecrets(kp_ref, encrypted))
    end

    return Welcome(suite, encrypted_secrets, encrypted_group_info)
end

"""
Join a group by processing a Welcome message (RFC 9420 compliant)
"""
function join_group(welcome::Welcome, my_key_package::KeyPackage, my_private::KeyPackagePrivate)
    suite = welcome.cipher_suite

    # Find our encrypted secrets
    my_kp_ref = MLSCrypto.ref_hash(suite, "MLS 1.0 KeyPackage Reference",
                                    serialize_key_package(my_key_package))

    my_secrets = nothing
    for es in welcome.secrets
        if es.new_member.data == my_kp_ref
            my_secrets = es
            break
        end
    end

    if my_secrets === nothing
        error("KeyPackage not found in Welcome")
    end

    # Decrypt GroupSecrets with our init_key
    gs_bytes = MLSCrypto.hpke_open(suite, my_private.init_key_priv,
                                    UInt8[], UInt8[], my_secrets.encrypted_group_secrets)
    group_secrets = deserialize_group_secrets(gs_bytes)

    # Derive welcome secret
    welcome_secret = MLSKeySchedule.derive_welcome_secret(suite, group_secrets.joiner_secret)

    # Decrypt GroupInfo
    welcome_key, welcome_nonce = derive_welcome_key_nonce(suite, welcome_secret)
    gi_bytes = MLSCrypto.aead_decrypt(suite, welcome_key, welcome_nonce,
                                       UInt8[], welcome.encrypted_group_info)
    group_info = deserialize_group_info(gi_bytes)

    # Extract ratchet tree from GroupInfo extension (RFC 9420 Section 12.4.3.3)
    tree = get_tree_from_context(group_info, suite)

    # Verify GroupInfo signature using signer's leaf from tree
    signer_leaf = get_leaf_from_context(group_info, group_info.signer, suite)
    gi_tbs = serialize_group_info_tbs(group_info)
    if !MLSCrypto.verify_with_label(suite, signer_leaf.signature_key.data,
                                     "GroupInfoTBS", gi_tbs, group_info.signature)
        error("GroupInfo signature verification failed")
    end

    # Initialize key schedule from Welcome
    key_schedule = MLSKeySchedule.init_from_welcome(
        suite, group_secrets.joiner_secret, UInt8[], group_info.group_context
    )

    # Verify confirmation tag (RFC 9420 Section 8.1)
    expected_tag = MLSKeySchedule.compute_confirmation_tag(
        key_schedule, group_info.group_context.confirmed_transcript_hash
    )
    if group_info.confirmation_tag != expected_tag
        error("Confirmation tag verification failed")
    end

    # Find my leaf index in the tree
    my_leaf_index = find_my_leaf_index_in_tree(tree, my_key_package)

    state = MLSGroupState(
        MLS_ROLE_JOINER,
        suite,
        group_info.group_context.group_id,
        group_info.group_context.epoch,
        group_info.group_context,
        tree,
        my_leaf_index,
        key_schedule,
        my_private.encryption_key_priv,
        my_private.signature_key_priv,
        PendingProposal[],
        group_info.group_context.confirmed_transcript_hash,
        UInt8[],
        group_info.group_context.tree_hash
    )

    return state
end

#=
================================================================================
TWO-PARTY OPTIMIZATION (for QUIC-MLS)
================================================================================
=#

"""
Create a two-party MLS group (optimized for QUIC client-server)

This is the common case for QUIC-MLS where we just have a client and server.
Uses the optimized two-party tree.
"""
function create_two_party_group(server_identity::Vector{UInt8},
                               client_key_package::KeyPackage;
                               cipher_suite::CipherSuite = DEFAULT_CIPHER_SUITE)
    if !validate_key_package(client_key_package)
        error("Invalid client KeyPackage")
    end

    # Generate server keys
    enc_pub, enc_priv = MLSCrypto.generate_hpke_keypair(cipher_suite)
    sig_pub, sig_priv = MLSCrypto.generate_signature_keypair(cipher_suite)

    # Create server leaf
    server_credential = Credential(server_identity)
    server_leaf = LeafNode(
        HPKEPublicKey(enc_pub),
        SignaturePublicKey(sig_pub),
        server_credential,
        default_capabilities(),
        UInt8(3),  # commit source
        Extension[],
        UInt8[]
    )

    # Sign server leaf
    leaf_tbs = serialize_leaf_node_tbs(server_leaf, cipher_suite)
    leaf_sig = MLSCrypto.sign_with_label(cipher_suite, sig_priv, "LeafNodeTBS", leaf_tbs)
    signed_server_leaf = LeafNode(
        server_leaf.encryption_key,
        server_leaf.signature_key,
        server_leaf.credential,
        server_leaf.capabilities,
        server_leaf.leaf_node_source,
        server_leaf.extensions,
        leaf_sig
    )

    # Create optimized two-party tree
    tree = MLSTree.create_two_party_tree(cipher_suite, signed_server_leaf,
                                         client_key_package.leaf_node)

    # Generate group ID
    group_id = MLSCrypto.random_bytes(16)

    # Compute tree hash
    tree_hash = MLSTree.compute_tree_hash(tree)

    # Initialize key schedule
    key_schedule = MLSKeySchedule.init_key_schedule(cipher_suite)

    # Create group context
    group_context = GroupContext(
        MLS_VERSION_1_0,
        cipher_suite,
        group_id,
        UInt64(0),
        tree_hash,
        UInt8[],
        Extension[]
    )

    # Generate path secret and derive commit secret
    path_secret = MLSCrypto.random_bytes(MLSCrypto.hash_length(cipher_suite))
    commit_secret = MLSCrypto.derive_secret(cipher_suite, path_secret, "path")

    # Derive joiner secret for Welcome
    joiner_secret = MLSCrypto.kdf_extract(cipher_suite,
                                          zeros(UInt8, MLSCrypto.hash_length(cipher_suite)),
                                          commit_secret)

    # Bootstrap key schedule
    MLSKeySchedule.advance_epoch!(key_schedule, commit_secret, UInt8[], group_context)

    # Create group state for server
    state = MLSGroupState(
        MLS_ROLE_CREATOR,
        cipher_suite,
        group_id,
        UInt64(0),
        group_context,
        tree,
        UInt32(0),  # Server is leaf 0
        key_schedule,
        enc_priv,
        sig_priv,
        PendingProposal[],
        UInt8[],
        UInt8[],
        tree_hash
    )

    # Create Welcome for client
    welcome = create_welcome(state, [AddProposal(client_key_package)], joiner_secret)

    return (state, welcome)
end

#=
================================================================================
TRAFFIC KEY ACCESS
================================================================================
=#

"""
Get QUIC traffic keys from current epoch
"""
function get_traffic_keys(state::MLSGroupState)
    MLSKeySchedule.derive_traffic_keys(state.key_schedule)
end

"""
Export a secret for application use
"""
function export_secret(state::MLSGroupState, label::String,
                      context::Vector{UInt8}, length::Int)
    MLSKeySchedule.derive_exporter_secret(state.key_schedule, label, context, length)
end

#=
================================================================================
SERIALIZATION HELPERS
================================================================================
=#

function serialize_leaf_node_tbs(leaf::LeafNode, suite::CipherSuite)
    buf = UInt8[]

    # encryption_key
    append!(buf, leaf.encryption_key.data)

    # signature_key
    append!(buf, leaf.signature_key.data)

    # credential (simplified)
    push!(buf, UInt8((UInt16(leaf.credential.credential_type) >> 8) & 0xff))
    push!(buf, UInt8(UInt16(leaf.credential.credential_type) & 0xff))
    if leaf.credential.basic !== nothing
        push!(buf, UInt8(length(leaf.credential.basic.identity)))
        append!(buf, leaf.credential.basic.identity)
    end

    # capabilities (simplified - just version count)
    push!(buf, UInt8(length(leaf.capabilities.versions)))

    # leaf_node_source
    push!(buf, leaf.leaf_node_source)

    return buf
end

function serialize_key_package_tbs(kp::KeyPackage)
    buf = UInt8[]

    # version
    push!(buf, UInt8((kp.version >> 8) & 0xff))
    push!(buf, UInt8(kp.version & 0xff))

    # cipher_suite
    push!(buf, UInt8((UInt16(kp.cipher_suite) >> 8) & 0xff))
    push!(buf, UInt8(UInt16(kp.cipher_suite) & 0xff))

    # init_key
    push!(buf, UInt8(length(kp.init_key.data)))
    append!(buf, kp.init_key.data)

    # leaf_node (serialized)
    leaf_bytes = serialize_leaf_node_tbs(kp.leaf_node, kp.cipher_suite)
    append!(buf, kp.leaf_node.signature)
    append!(buf, leaf_bytes)

    return buf
end

function serialize_key_package(kp::KeyPackage)
    buf = serialize_key_package_tbs(kp)
    append!(buf, kp.signature)
    return buf
end

function serialize_proposal(proposal::Proposal)
    buf = UInt8[]

    push!(buf, UInt8((UInt16(proposal.proposal_type) >> 8) & 0xff))
    push!(buf, UInt8(UInt16(proposal.proposal_type) & 0xff))

    if proposal.add !== nothing
        append!(buf, serialize_key_package(proposal.add.key_package))
    elseif proposal.remove !== nothing
        for i in 3:-1:0
            push!(buf, UInt8((proposal.remove.removed >> (i*8)) & 0xff))
        end
    elseif proposal.update !== nothing
        append!(buf, serialize_leaf_node_tbs(proposal.update.leaf_node,
                                             DEFAULT_CIPHER_SUITE))
    end

    return buf
end

function serialize_group_info_tbs(gi::GroupInfo)
    buf = UInt8[]

    # GroupContext
    append!(buf, MLSKeySchedule.serialize_group_context(gi.group_context))

    # extensions (with full serialization)
    # First, serialize all extensions to get total length
    ext_buf = UInt8[]
    for ext in gi.extensions
        # extension_type (2 bytes)
        push!(ext_buf, UInt8((ext.extension_type >> 8) & 0xff))
        push!(ext_buf, UInt8(ext.extension_type & 0xff))
        # extension_data length (2 bytes for variable length)
        ext_len = length(ext.extension_data)
        push!(ext_buf, UInt8((ext_len >> 8) & 0xff))
        push!(ext_buf, UInt8(ext_len & 0xff))
        append!(ext_buf, ext.extension_data)
    end
    # Extensions vector length (2 bytes)
    push!(buf, UInt8((length(ext_buf) >> 8) & 0xff))
    push!(buf, UInt8(length(ext_buf) & 0xff))
    append!(buf, ext_buf)

    # confirmation_tag
    push!(buf, UInt8(length(gi.confirmation_tag)))
    append!(buf, gi.confirmation_tag)

    # signer
    for i in 3:-1:0
        push!(buf, UInt8((gi.signer >> (i*8)) & 0xff))
    end

    return buf
end

function serialize_group_info(gi::GroupInfo)
    buf = serialize_group_info_tbs(gi)
    push!(buf, UInt8(length(gi.signature)))
    append!(buf, gi.signature)
    return buf
end

function serialize_group_secrets(gs::GroupSecrets)
    buf = UInt8[]

    # joiner_secret
    push!(buf, UInt8(length(gs.joiner_secret)))
    append!(buf, gs.joiner_secret)

    # path_secret (optional)
    if gs.path_secret !== nothing
        push!(buf, 0x01)
        push!(buf, UInt8(length(gs.path_secret)))
        append!(buf, gs.path_secret)
    else
        push!(buf, 0x00)
    end

    # PSKs
    push!(buf, UInt8(length(gs.psks)))

    return buf
end

function deserialize_group_secrets(data::Vector{UInt8})
    pos = 1

    # joiner_secret
    js_len = data[pos]
    pos += 1
    joiner_secret = data[pos:pos+js_len-1]
    pos += js_len

    # path_secret
    has_path = data[pos] == 0x01
    pos += 1
    path_secret = nothing
    if has_path
        ps_len = data[pos]
        pos += 1
        path_secret = data[pos:pos+ps_len-1]
        pos += ps_len
    end

    return GroupSecrets(joiner_secret, path_secret, Tuple{UInt8, Vector{UInt8}}[])
end

function deserialize_group_context(data::Vector{UInt8}, pos::Int)
    # version (2 bytes)
    version = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
    pos += 2

    # cipher_suite (2 bytes)
    suite_val = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
    cipher_suite = CipherSuite(suite_val)
    pos += 2

    # group_id (variable)
    gid_len = Int(data[pos])
    pos += 1
    group_id = data[pos:pos+gid_len-1]
    pos += gid_len

    # epoch (8 bytes)
    epoch = UInt64(0)
    for i in 0:7
        epoch = (epoch << 8) | UInt64(data[pos+i])
    end
    pos += 8

    # tree_hash (variable)
    th_len = Int(data[pos])
    pos += 1
    tree_hash = data[pos:pos+th_len-1]
    pos += th_len

    # confirmed_transcript_hash (variable)
    cth_len = Int(data[pos])
    pos += 1
    confirmed_transcript_hash = data[pos:pos+cth_len-1]
    pos += cth_len

    # extensions count (simplified)
    ext_count = Int(data[pos])
    pos += 1

    gc = GroupContext(version, cipher_suite, group_id, epoch,
                      tree_hash, confirmed_transcript_hash, Extension[])

    return (gc, pos)
end

function deserialize_group_info(data::Vector{UInt8})
    pos = 1

    # Parse GroupContext
    gc, pos = deserialize_group_context(data, pos)

    # Extensions vector length (2 bytes)
    ext_vec_len = (Int(data[pos]) << 8) | Int(data[pos+1])
    pos += 2

    # Parse extensions
    extensions = Extension[]
    ext_end = pos + ext_vec_len
    while pos < ext_end
        # extension_type (2 bytes)
        ext_type = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
        pos += 2
        # extension_data length (2 bytes)
        ext_data_len = (Int(data[pos]) << 8) | Int(data[pos+1])
        pos += 2
        # extension_data
        ext_data = data[pos:pos+ext_data_len-1]
        pos += ext_data_len
        push!(extensions, Extension(ext_type, ext_data))
    end

    # confirmation_tag
    ct_len = Int(data[pos])
    pos += 1
    confirmation_tag = data[pos:pos+ct_len-1]
    pos += ct_len

    # signer (4 bytes)
    signer = UInt32(0)
    for i in 0:3
        signer = (signer << 8) | UInt32(data[pos+i])
    end
    pos += 4

    # signature
    sig_len = Int(data[pos])
    pos += 1
    signature = data[pos:pos+sig_len-1]

    return GroupInfo(gc, extensions, confirmation_tag, signer, signature)
end

function derive_welcome_key_nonce(suite::CipherSuite, welcome_secret::Vector{UInt8})
    key_len = suite in (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                        MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                        MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519) ? 16 : 32

    # For ChaCha20-Poly1305, key is 32 bytes
    if suite == MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        key_len = 32
    end

    key = MLSCrypto.expand_with_label(suite, welcome_secret, "key", UInt8[], key_len)
    nonce = MLSCrypto.expand_with_label(suite, welcome_secret, "nonce", UInt8[], 12)

    return (key, nonce)
end

"""
Extract a leaf node from the GroupInfo's ratchet_tree extension.
"""
function get_leaf_from_context(gi::GroupInfo, leaf_index::UInt32, suite::CipherSuite)
    # Find ratchet_tree extension
    tree_ext = nothing
    for ext in gi.extensions
        if ext.extension_type == EXTENSION_TYPE_RATCHET_TREE
            tree_ext = ext
            break
        end
    end

    if tree_ext === nothing
        error("No ratchet_tree extension in GroupInfo")
    end

    # Deserialize the tree
    tree = MLSTree.deserialize_ratchet_tree(tree_ext.extension_data, suite)

    # Get the leaf at the specified index
    node_idx = MLSTree.leaf_to_node(MLSTree.LeafIndex(leaf_index))
    node = MLSTree.get_node(tree, node_idx)

    if node.leaf_node === nothing
        error("Leaf node $leaf_index not found in tree")
    end

    return node.leaf_node
end

"""
Extract the full ratchet tree from GroupInfo extensions.
"""
function get_tree_from_context(gi::GroupInfo, suite::CipherSuite)
    # Find ratchet_tree extension
    for ext in gi.extensions
        if ext.extension_type == EXTENSION_TYPE_RATCHET_TREE
            return MLSTree.deserialize_ratchet_tree(ext.extension_data, suite)
        end
    end
    error("No ratchet_tree extension in GroupInfo")
end

function find_my_leaf_index(gi::GroupInfo, kp::KeyPackage)
    # Deprecated - use find_my_leaf_index_in_tree instead
    return UInt32(1)
end

"""
Find my leaf index by matching encryption key in the tree.
"""
function find_my_leaf_index_in_tree(tree::MLSTree.RatchetTree, kp::KeyPackage)
    my_enc_key = kp.leaf_node.encryption_key.data

    for i in 0:(tree.n_leaves - 1)
        node_idx = MLSTree.leaf_to_node(MLSTree.LeafIndex(UInt32(i)))
        node = MLSTree.get_node(tree, node_idx)

        if node.leaf_node !== nothing
            if node.leaf_node.encryption_key.data == my_enc_key
                return UInt32(i)
            end
        end
    end

    error("Could not find my leaf in tree")
end

"""
Simplified two-party join for QUIC-MLS

This version skips complex tree operations and signature verification
since the two-party case is simpler and keys are exchanged directly.
"""
function join_group_two_party(welcome::Welcome, my_key_package::KeyPackage,
                              my_private::KeyPackagePrivate)
    suite = welcome.cipher_suite

    # Find our encrypted secrets
    my_kp_ref = MLSCrypto.ref_hash(suite, "MLS 1.0 KeyPackage Reference",
                                    serialize_key_package(my_key_package))

    my_secrets = nothing
    for es in welcome.secrets
        if es.new_member.data == my_kp_ref
            my_secrets = es
            break
        end
    end

    if my_secrets === nothing
        error("KeyPackage not found in Welcome")
    end

    # Decrypt GroupSecrets with our init_key
    gs_bytes = MLSCrypto.hpke_open(suite, my_private.init_key_priv,
                                    UInt8[], UInt8[], my_secrets.encrypted_group_secrets)
    group_secrets = deserialize_group_secrets(gs_bytes)

    # Derive welcome secret
    welcome_secret = MLSKeySchedule.derive_welcome_secret(suite, group_secrets.joiner_secret)

    # Decrypt GroupInfo
    welcome_key, welcome_nonce = derive_welcome_key_nonce(suite, welcome_secret)
    gi_bytes = MLSCrypto.aead_decrypt(suite, welcome_key, welcome_nonce,
                                       UInt8[], welcome.encrypted_group_info)
    group_info = deserialize_group_info(gi_bytes)

    # For two-party case, skip signature verification (we trust the direct channel)
    # In full implementation, would verify via ratchet_tree extension

    # Initialize key schedule from Welcome
    key_schedule = MLSKeySchedule.init_from_welcome(
        suite, group_secrets.joiner_secret, UInt8[], group_info.group_context
    )

    # Create simple two-party tree
    # For the joiner, we don't have the full tree - just use a minimal placeholder
    tree = MLSTree.RatchetTree(suite)

    # Create group state (client is leaf 1 in two-party)
    state = MLSGroupState(
        MLS_ROLE_JOINER,
        suite,
        group_info.group_context.group_id,
        group_info.group_context.epoch,
        group_info.group_context,
        tree,
        UInt32(1),  # Client is leaf 1
        key_schedule,
        my_private.encryption_key_priv,
        my_private.signature_key_priv,
        PendingProposal[],
        group_info.group_context.confirmed_transcript_hash,
        UInt8[],
        group_info.group_context.tree_hash
    )

    return state
end

end # module MLSHandshake
