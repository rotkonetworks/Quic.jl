module MLSTree

#=
MLS Ratchet Tree (RFC 9420 Section 7)

The ratchet tree is a left-balanced binary tree that enables efficient
group key updates. Each leaf represents a group member, and internal
nodes store derived encryption keys.

For QUIC-MLS two-party case, this simplifies significantly.
=#

using ..MLSTypes
using ..MLSTypes: CREDENTIAL_TYPE_BASIC, CREDENTIAL_TYPE_X509,
                 CREDENTIAL_TYPE_RESERVED
using ..MLSCrypto

export RatchetTree, TreeNode, LeafIndex, NodeIndex
export create_tree, add_member!, remove_member!, update_path!
export root_index, leaf_count, node_count
export get_resolution, get_copath, get_direct_path
export compute_tree_hash, compute_parent_hash

#=
================================================================================
TREE INDEXING
================================================================================
Left-balanced binary tree indexing:
- Leaves are at even indices: 0, 2, 4, ...
- Internal nodes are at odd indices: 1, 3, 5, ...
- Root is at index 2^(n-1) - 1 for n levels
=#

"""
Leaf index (position in leaf array)
"""
struct LeafIndex
    value::UInt32
end

"""
Node index (position in full tree array)
"""
struct NodeIndex
    value::UInt32
end

# Convert leaf index to node index
leaf_to_node(leaf::LeafIndex) = NodeIndex(leaf.value * 2)

# Convert node index to leaf index (if leaf)
function node_to_leaf(node::NodeIndex)
    @assert node.value % 2 == 0 "Not a leaf node"
    LeafIndex(node.value ÷ 2)
end

# Check if node is a leaf
is_leaf(node::NodeIndex) = node.value % 2 == 0

# Level of a node (0 for leaves)
function level(node::NodeIndex)
    x = node.value
    if x % 2 == 0
        return 0
    end
    k = 0
    while (x >> k) % 2 == 1
        k += 1
    end
    return k
end

# Number of leaves for tree with n nodes
function leaf_count_for_nodes(n::Int)
    (n + 1) ÷ 2
end

# Number of nodes for tree with n leaves
function node_count_for_leaves(n::Int)
    n == 0 ? 0 : 2 * n - 1
end

# Root index for tree with n leaves
function root_for_leaves(n::Int)
    if n == 0
        return NodeIndex(0)
    end
    # Root is at index 2^(ceil(log2(n))) - 1
    w = 1
    while w < n
        w *= 2
    end
    NodeIndex(w - 1)
end

# Left child
function left(node::NodeIndex)
    lvl = level(node)
    @assert lvl > 0 "Leaves have no children"
    NodeIndex(node.value - (1 << (lvl - 1)))
end

# Right child
function right(node::NodeIndex)
    lvl = level(node)
    @assert lvl > 0 "Leaves have no children"
    NodeIndex(node.value + (1 << (lvl - 1)))
end

# Parent
function parent(node::NodeIndex, n_leaves::Int)
    root = root_for_leaves(n_leaves)
    if node.value == root.value
        return nothing
    end

    lvl = level(node)
    parent_lvl = lvl + 1

    # Parent is at node ± 2^lvl depending on position
    if (node.value >> parent_lvl) % 2 == 0
        # Left child - parent is to the right
        return NodeIndex(node.value + (1 << lvl))
    else
        # Right child - parent is to the left
        return NodeIndex(node.value - (1 << lvl))
    end
end

# Sibling
function sibling(node::NodeIndex, n_leaves::Int)
    p = parent(node, n_leaves)
    if p === nothing
        return nothing
    end

    if left(p).value == node.value
        return right(p)
    else
        return left(p)
    end
end

#=
================================================================================
TREE NODES
================================================================================
=#

"""
Tree node - either leaf or intermediate
"""
mutable struct TreeNode
    # Public key (HPKE for encryption)
    public_key::Union{HPKEPublicKey, Nothing}

    # Private key (only for own nodes)
    private_key::Union{Vector{UInt8}, Nothing}

    # For leaf nodes only
    leaf_node::Union{LeafNode, Nothing}

    # Parent hash (for intermediate nodes)
    parent_hash::Vector{UInt8}

    # Unmerged leaves (indices of leaves with path secrets above this node)
    unmerged_leaves::Vector{LeafIndex}
end

# Empty node
TreeNode() = TreeNode(nothing, nothing, nothing, UInt8[], LeafIndex[])

# Leaf node
function TreeNode(leaf::LeafNode)
    TreeNode(leaf.encryption_key, nothing, leaf, UInt8[], LeafIndex[])
end

# Intermediate node with public key
function TreeNode(pk::HPKEPublicKey)
    TreeNode(pk, nothing, nothing, UInt8[], LeafIndex[])
end

Base.isempty(n::TreeNode) = n.public_key === nothing && n.leaf_node === nothing

#=
================================================================================
RATCHET TREE
================================================================================
=#

"""
Ratchet Tree - the core MLS group key structure
"""
mutable struct RatchetTree
    cipher_suite::CipherSuite
    nodes::Vector{TreeNode}
    n_leaves::Int

    function RatchetTree(suite::CipherSuite = DEFAULT_CIPHER_SUITE)
        new(suite, TreeNode[], 0)
    end
end

# Accessors
root_index(tree::RatchetTree) = root_for_leaves(tree.n_leaves)
leaf_count(tree::RatchetTree) = tree.n_leaves
node_count(tree::RatchetTree) = length(tree.nodes)

# Get node at index (may be empty)
function get_node(tree::RatchetTree, idx::NodeIndex)
    if idx.value >= length(tree.nodes)
        return TreeNode()
    end
    return tree.nodes[idx.value + 1]  # Julia 1-indexed
end

# Set node at index
function set_node!(tree::RatchetTree, idx::NodeIndex, node::TreeNode)
    # Ensure nodes array is large enough
    while length(tree.nodes) <= idx.value
        push!(tree.nodes, TreeNode())
    end
    tree.nodes[idx.value + 1] = node
end

#=
================================================================================
TREE OPERATIONS
================================================================================
=#

"""
Create a new tree with a single member (the creator)
"""
function create_tree(suite::CipherSuite, leaf::LeafNode)
    tree = RatchetTree(suite)
    tree.n_leaves = 1
    set_node!(tree, NodeIndex(0), TreeNode(leaf))
    return tree
end

"""
Add a member to the tree

Returns the leaf index of the new member
"""
function add_member!(tree::RatchetTree, leaf::LeafNode)
    # Find first empty leaf or extend tree
    new_leaf_idx = nothing

    for i in 0:tree.n_leaves-1
        node = get_node(tree, leaf_to_node(LeafIndex(i)))
        if isempty(node)
            new_leaf_idx = LeafIndex(i)
            break
        end
    end

    if new_leaf_idx === nothing
        # Extend tree
        new_leaf_idx = LeafIndex(tree.n_leaves)
        tree.n_leaves += 1

        # Ensure tree has enough nodes
        n_nodes = node_count_for_leaves(tree.n_leaves)
        while length(tree.nodes) < n_nodes
            push!(tree.nodes, TreeNode())
        end
    end

    # Set the leaf
    set_node!(tree, leaf_to_node(new_leaf_idx), TreeNode(leaf))

    # Blank the direct path
    for p_idx in get_direct_path(tree, new_leaf_idx)
        set_node!(tree, p_idx, TreeNode())
    end

    return new_leaf_idx
end

"""
Remove a member from the tree
"""
function remove_member!(tree::RatchetTree, leaf_idx::LeafIndex)
    # Blank the leaf
    set_node!(tree, leaf_to_node(leaf_idx), TreeNode())

    # Blank the direct path
    for p_idx in get_direct_path(tree, leaf_idx)
        set_node!(tree, p_idx, TreeNode())
    end
end

"""
Get the direct path from a leaf to the root (excluding the leaf itself)
"""
function get_direct_path(tree::RatchetTree, leaf_idx::LeafIndex)
    path = NodeIndex[]

    current = parent(leaf_to_node(leaf_idx), tree.n_leaves)

    while current !== nothing
        push!(path, current)
        current = parent(current, tree.n_leaves)
    end

    return path
end

"""
Get the copath (siblings along the direct path)
"""
function get_copath(tree::RatchetTree, leaf_idx::LeafIndex)
    copath = NodeIndex[]

    current = leaf_to_node(leaf_idx)

    while true
        sib = sibling(current, tree.n_leaves)
        if sib === nothing
            break
        end
        push!(copath, sib)
        current = parent(current, tree.n_leaves)
        if current === nothing
            break
        end
    end

    return copath
end

"""
Get the resolution of a node (leaf public keys that can decrypt secrets at this node)
"""
function get_resolution(tree::RatchetTree, idx::NodeIndex)
    node = get_node(tree, idx)

    # If node has a public key and no unmerged leaves, resolution is just this node
    if node.public_key !== nothing && isempty(node.unmerged_leaves)
        return [idx]
    end

    # If leaf with no key, resolution is empty
    if is_leaf(idx)
        return NodeIndex[]
    end

    # Otherwise, resolution is union of children's resolutions
    l = get_resolution(tree, left(idx))
    r = get_resolution(tree, right(idx))

    return vcat(l, r)
end

#=
================================================================================
PATH UPDATES
================================================================================
=#

"""
Update the path from a leaf to the root

Returns (path_secret, update_path) for encryption to other members
"""
function update_path!(tree::RatchetTree, leaf_idx::LeafIndex,
                     leaf_node::LeafNode, path_secret::Vector{UInt8})
    suite = tree.cipher_suite

    # Update the leaf
    set_node!(tree, leaf_to_node(leaf_idx), TreeNode(leaf_node))

    path = get_direct_path(tree, leaf_idx)
    copath = get_copath(tree, leaf_idx)

    update_nodes = UpdatePathNode[]
    current_secret = path_secret

    for (i, path_node_idx) in enumerate(path)
        # Derive node secret
        node_secret = MLSCrypto.derive_secret(suite, current_secret, "node")

        # Generate node key pair
        pk, sk = MLSCrypto.hpke_generate_keypair()

        # Set the node
        new_node = TreeNode(pk)
        new_node.private_key = sk
        set_node!(tree, path_node_idx, new_node)

        # Get resolution of copath sibling for encryption targets
        if i <= length(copath)
            resolution = get_resolution(tree, copath[i])

            # Encrypt path secret to each resolved node
            encrypted_secrets = Vector{UInt8}[]
            for res_idx in resolution
                res_node = get_node(tree, res_idx)
                if res_node.public_key !== nothing
                    # HPKE encrypt the path secret
                    info = vcat(
                        reinterpret(UInt8, [hton(UInt32(path_node_idx.value))]),
                        reinterpret(UInt8, [hton(UInt32(res_idx.value))])
                    )
                    ct = MLSCrypto.hpke_seal(suite, res_node.public_key, info, UInt8[], current_secret)
                    push!(encrypted_secrets, ct)
                end
            end

            push!(update_nodes, UpdatePathNode(pk, encrypted_secrets))
        end

        # Derive next path secret
        current_secret = MLSCrypto.derive_secret(suite, current_secret, "path")
    end

    return UpdatePath(leaf_node, update_nodes)
end

"""
Apply an update path received from another member
"""
function apply_update_path!(tree::RatchetTree, sender_leaf::LeafIndex,
                           update_path::UpdatePath, my_leaf::LeafIndex)
    suite = tree.cipher_suite

    # Update sender's leaf
    set_node!(tree, leaf_to_node(sender_leaf), TreeNode(update_path.leaf_node))

    sender_path = get_direct_path(tree, sender_leaf)
    my_path = get_direct_path(tree, my_leaf)

    # Find common ancestor
    common_ancestor_idx = nothing
    for (i, p) in enumerate(sender_path)
        if p in my_path
            common_ancestor_idx = i
            break
        end
    end

    if common_ancestor_idx === nothing
        error("No common ancestor found")
    end

    # Decrypt at common ancestor
    path_node = update_path.nodes[common_ancestor_idx]

    # Find which encrypted secret is for us
    my_resolution_pos = -1
    copath_node = get_copath(tree, sender_leaf)[common_ancestor_idx]
    resolution = get_resolution(tree, copath_node)

    my_node_idx = leaf_to_node(my_leaf)
    for (i, res_idx) in enumerate(resolution)
        if res_idx.value == my_node_idx.value
            my_resolution_pos = i
            break
        end
    end

    if my_resolution_pos < 0
        error("Cannot find our position in resolution")
    end

    # Get our private key
    my_node = get_node(tree, my_node_idx)
    if my_node.private_key === nothing
        error("No private key for decryption")
    end

    # Decrypt path secret
    encrypted = path_node.encrypted_path_secret[my_resolution_pos]
    enc = encrypted[1:32]  # X25519 public key
    ct = encrypted[33:end]

    info = vcat(
        reinterpret(UInt8, [hton(UInt32(sender_path[common_ancestor_idx].value))]),
        reinterpret(UInt8, [hton(UInt32(my_node_idx.value))])
    )

    path_secret = MLSCrypto.hpke_open(suite, enc, my_node.private_key,
                                       HPKEPublicKey(my_node.public_key.data),
                                       info, UInt8[], ct)

    # Apply path updates from common ancestor to root
    current_secret = path_secret
    for i in common_ancestor_idx:length(sender_path)
        # Update node public key
        node = TreeNode(update_path.nodes[i].encryption_key)
        set_node!(tree, sender_path[i], node)

        # If this node is on our path too, derive private key
        if sender_path[i] in my_path
            node_secret = MLSCrypto.derive_secret(suite, current_secret, "node")
            # TODO: Derive private key from node secret
        end

        current_secret = MLSCrypto.derive_secret(suite, current_secret, "path")
    end

    return path_secret
end

#=
================================================================================
TREE HASHING
================================================================================
=#

"""
Compute tree hash for entire tree (from root)
"""
function compute_tree_hash(tree::RatchetTree)
    compute_tree_hash(tree, root_index(tree))
end

"""
Compute tree hash for a subtree rooted at given node
"""
function compute_tree_hash(tree::RatchetTree, idx::NodeIndex)
    suite = tree.cipher_suite
    node = get_node(tree, idx)

    if is_leaf(idx)
        # LeafNodeHashInput
        if isempty(node)
            input = UInt8[0x01]  # Empty leaf
        else
            # Serialize leaf node
            leaf_data = serialize_leaf_node(node.leaf_node)
            input = vcat([0x02], leaf_data)  # Non-empty leaf
        end
    else
        # ParentNodeHashInput
        left_hash = compute_tree_hash(tree, left(idx))
        right_hash = compute_tree_hash(tree, right(idx))

        if isempty(node)
            input = vcat([0x01], left_hash, right_hash)  # Empty parent
        else
            # Serialize parent node (public key + parent hash + unmerged leaves)
            parent_data = serialize_parent_node(node)
            input = vcat([0x02], parent_data, left_hash, right_hash)
        end
    end

    return MLSCrypto.mls_hash(suite, input)
end

"""
Compute parent hash for a node
"""
function compute_parent_hash(tree::RatchetTree, idx::NodeIndex)
    suite = tree.cipher_suite
    node = get_node(tree, idx)

    p = parent(idx, tree.n_leaves)
    if p === nothing
        return UInt8[]
    end

    parent_node = get_node(tree, p)
    if isempty(parent_node)
        # Original sibling resolution
        sib = sibling(idx, tree.n_leaves)
        return compute_parent_hash(tree, p)
    end

    # ParentHashInput
    input = vcat(
        parent_node.public_key.data,
        parent_node.parent_hash,
        # Original sibling tree hash
        compute_tree_hash(tree, sibling(idx, tree.n_leaves))
    )

    return MLSCrypto.mls_hash(suite, input)
end

# Note: Full serialize_leaf_node and serialize_parent_node are defined below
# in the RATCHET TREE SERIALIZATION section

#=
================================================================================
TWO-PARTY SPECIALIZATION
================================================================================
For QUIC-MLS, we optimize for the two-party case
=#

"""
Create a two-party tree (simplified for QUIC-MLS)
"""
function create_two_party_tree(suite::CipherSuite, my_leaf::LeafNode, peer_leaf::LeafNode)
    tree = RatchetTree(suite)
    tree.n_leaves = 2

    # Ensure tree has 3 nodes (2 leaves + 1 parent)
    tree.nodes = [TreeNode(), TreeNode(), TreeNode()]

    # Set leaves
    set_node!(tree, NodeIndex(0), TreeNode(my_leaf))
    set_node!(tree, NodeIndex(2), TreeNode(peer_leaf))

    # Root will be computed from path secrets
    return tree
end

"""
Simple path update for two-party case
"""
function two_party_update!(tree::RatchetTree, my_idx::LeafIndex,
                          new_leaf::LeafNode, path_secret::Vector{UInt8})
    suite = tree.cipher_suite

    # Update my leaf
    set_node!(tree, leaf_to_node(my_idx), TreeNode(new_leaf))

    # Derive root key
    node_secret = MLSCrypto.derive_secret(suite, path_secret, "node")
    pk, sk = MLSCrypto.hpke_generate_keypair()

    root_node = TreeNode(pk)
    root_node.private_key = sk
    set_node!(tree, NodeIndex(1), root_node)  # Root is at index 1 for 2 leaves

    # Encrypt path secret to peer
    peer_idx = my_idx.value == 0 ? NodeIndex(2) : NodeIndex(0)
    peer_node = get_node(tree, peer_idx)

    info = vcat(
        reinterpret(UInt8, [hton(UInt32(1))]),  # Root index
        reinterpret(UInt8, [hton(peer_idx.value)])
    )

    encrypted = MLSCrypto.hpke_seal(suite, peer_node.public_key, info, UInt8[], path_secret)

    return UpdatePath(new_leaf, [UpdatePathNode(pk, [encrypted])])
end

#=
================================================================================
RATCHET TREE SERIALIZATION (RFC 9420 Section 7.8)
================================================================================
=#

export serialize_ratchet_tree, deserialize_ratchet_tree

"""
Serialize a ratchet tree for the ratchet_tree extension.

Format (RFC 9420):
    optional<Node> ratchet_tree<V>;

Each node is:
    0x00 = blank node
    0x01 = leaf node
    0x02 = parent node
"""
function serialize_ratchet_tree(tree::RatchetTree)
    buf = UInt8[]

    # Number of nodes (4 bytes, big-endian for variable length encoding)
    n_nodes = length(tree.nodes)
    push!(buf, UInt8((n_nodes >> 24) & 0xff))
    push!(buf, UInt8((n_nodes >> 16) & 0xff))
    push!(buf, UInt8((n_nodes >> 8) & 0xff))
    push!(buf, UInt8(n_nodes & 0xff))

    for i in 1:n_nodes
        node = tree.nodes[i]
        node_idx = NodeIndex(UInt32(i - 1))

        # Check if node is blank (no public key and no leaf node)
        is_blank = (node.public_key === nothing || isempty(node.public_key)) &&
                   node.leaf_node === nothing

        if is_blank
            # Blank node
            push!(buf, 0x00)
        elseif is_leaf(node_idx) && node.leaf_node !== nothing
            # Leaf node
            push!(buf, 0x01)
            append!(buf, serialize_leaf_node(node.leaf_node))
        else
            # Parent node
            push!(buf, 0x02)
            append!(buf, serialize_parent_node(node))
        end
    end

    return buf
end

"""
Serialize a leaf node for tree serialization.
"""
function serialize_leaf_node(leaf::LeafNode)
    buf = UInt8[]

    # encryption_key (with length prefix)
    push!(buf, UInt8(length(leaf.encryption_key.data)))
    append!(buf, leaf.encryption_key.data)

    # signature_key (with length prefix)
    push!(buf, UInt8(length(leaf.signature_key.data)))
    append!(buf, leaf.signature_key.data)

    # credential
    append!(buf, serialize_credential(leaf.credential))

    # capabilities
    append!(buf, serialize_capabilities(leaf.capabilities))

    # leaf_node_source
    push!(buf, leaf.leaf_node_source)

    # extensions count
    push!(buf, UInt8(length(leaf.extensions)))
    for ext in leaf.extensions
        # extension_type (2 bytes)
        push!(buf, UInt8((ext.extension_type >> 8) & 0xff))
        push!(buf, UInt8(ext.extension_type & 0xff))
        # extension_data (with length)
        push!(buf, UInt8(length(ext.extension_data)))
        append!(buf, ext.extension_data)
    end

    # signature (with length prefix)
    push!(buf, UInt8(length(leaf.signature)))
    append!(buf, leaf.signature)

    return buf
end

"""
Serialize credential for tree serialization.
"""
function serialize_credential(cred::Credential)
    buf = UInt8[]

    # credential_type (2 bytes)
    push!(buf, UInt8((UInt16(cred.credential_type) >> 8) & 0xff))
    push!(buf, UInt8(UInt16(cred.credential_type) & 0xff))

    if cred.credential_type == CREDENTIAL_TYPE_BASIC && cred.basic !== nothing
        # identity length and data
        push!(buf, UInt8(length(cred.basic.identity)))
        append!(buf, cred.basic.identity)
    elseif cred.credential_type == CREDENTIAL_TYPE_X509 && cred.x509 !== nothing
        # cert chain count
        push!(buf, UInt8(length(cred.x509.cert_chain)))
        for cert in cred.x509.cert_chain
            # cert length (2 bytes) and data
            push!(buf, UInt8((length(cert) >> 8) & 0xff))
            push!(buf, UInt8(length(cert) & 0xff))
            append!(buf, cert)
        end
    end

    return buf
end

"""
Serialize capabilities for tree serialization.
"""
function serialize_capabilities(caps::Capabilities)
    buf = UInt8[]

    # versions
    push!(buf, UInt8(length(caps.versions)))
    for v in caps.versions
        push!(buf, UInt8((v >> 8) & 0xff))
        push!(buf, UInt8(v & 0xff))
    end

    # cipher_suites
    push!(buf, UInt8(length(caps.cipher_suites)))
    for cs in caps.cipher_suites
        push!(buf, UInt8((UInt16(cs) >> 8) & 0xff))
        push!(buf, UInt8(UInt16(cs) & 0xff))
    end

    # extensions
    push!(buf, UInt8(length(caps.extensions)))
    for e in caps.extensions
        push!(buf, UInt8((e >> 8) & 0xff))
        push!(buf, UInt8(e & 0xff))
    end

    # proposals
    push!(buf, UInt8(length(caps.proposals)))
    for p in caps.proposals
        push!(buf, UInt8((UInt16(p) >> 8) & 0xff))
        push!(buf, UInt8(UInt16(p) & 0xff))
    end

    # credentials
    push!(buf, UInt8(length(caps.credentials)))
    for c in caps.credentials
        push!(buf, UInt8((UInt16(c) >> 8) & 0xff))
        push!(buf, UInt8(UInt16(c) & 0xff))
    end

    return buf
end

"""
Serialize a parent node for tree serialization.
"""
function serialize_parent_node(node::TreeNode)
    buf = UInt8[]

    # encryption_key (with length prefix)
    push!(buf, UInt8(length(node.public_key.data)))
    append!(buf, node.public_key.data)

    # parent_hash (with length prefix)
    push!(buf, UInt8(length(node.parent_hash)))
    append!(buf, node.parent_hash)

    # unmerged_leaves count (simplified - empty for now)
    push!(buf, 0x00)

    return buf
end

"""
Deserialize a ratchet tree from the ratchet_tree extension.
"""
function deserialize_ratchet_tree(data::Vector{UInt8}, suite::CipherSuite)
    pos = 1

    # Number of nodes (4 bytes)
    n_nodes = (Int(data[pos]) << 24) | (Int(data[pos+1]) << 16) |
              (Int(data[pos+2]) << 8) | Int(data[pos+3])
    pos += 4

    tree = RatchetTree(suite)
    tree.nodes = Vector{TreeNode}(undef, n_nodes)
    tree.n_leaves = (n_nodes + 1) ÷ 2

    for i in 1:n_nodes
        node_type = data[pos]
        pos += 1

        if node_type == 0x00
            # Blank node
            tree.nodes[i] = TreeNode()
        elseif node_type == 0x01
            # Leaf node
            leaf, pos = deserialize_leaf_node(data, pos)
            tree.nodes[i] = TreeNode(leaf)
        elseif node_type == 0x02
            # Parent node
            node, pos = deserialize_parent_node(data, pos)
            tree.nodes[i] = node
        else
            error("Invalid node type: $node_type")
        end
    end

    return tree
end

"""
Deserialize a leaf node.
"""
function deserialize_leaf_node(data::Vector{UInt8}, pos::Int)
    # encryption_key
    ek_len = Int(data[pos])
    pos += 1
    encryption_key = HPKEPublicKey(data[pos:pos+ek_len-1])
    pos += ek_len

    # signature_key
    sk_len = Int(data[pos])
    pos += 1
    signature_key = SignaturePublicKey(data[pos:pos+sk_len-1])
    pos += sk_len

    # credential
    credential, pos = deserialize_credential(data, pos)

    # capabilities
    capabilities, pos = deserialize_capabilities(data, pos)

    # leaf_node_source
    leaf_node_source = data[pos]
    pos += 1

    # extensions
    ext_count = Int(data[pos])
    pos += 1
    extensions = Extension[]
    for _ in 1:ext_count
        ext_type = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
        pos += 2
        ext_len = Int(data[pos])
        pos += 1
        ext_data = data[pos:pos+ext_len-1]
        pos += ext_len
        push!(extensions, Extension(ext_type, ext_data))
    end

    # signature
    sig_len = Int(data[pos])
    pos += 1
    signature = data[pos:pos+sig_len-1]
    pos += sig_len

    leaf = LeafNode(encryption_key, signature_key, credential, capabilities,
                    leaf_node_source, extensions, signature)

    return (leaf, pos)
end

"""
Deserialize a credential.
"""
function deserialize_credential(data::Vector{UInt8}, pos::Int)
    cred_type_val = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
    cred_type = CredentialType(cred_type_val)
    pos += 2

    if cred_type == CREDENTIAL_TYPE_BASIC
        id_len = Int(data[pos])
        pos += 1
        identity = data[pos:pos+id_len-1]
        pos += id_len
        return (Credential(identity), pos)
    elseif cred_type == CREDENTIAL_TYPE_X509
        chain_len = Int(data[pos])
        pos += 1
        cert_chain = Vector{Vector{UInt8}}()
        for _ in 1:chain_len
            cert_len = (Int(data[pos]) << 8) | Int(data[pos+1])
            pos += 2
            push!(cert_chain, data[pos:pos+cert_len-1])
            pos += cert_len
        end
        return (Credential(cert_chain), pos)
    else
        error("Unknown credential type: $cred_type")
    end
end

"""
Deserialize capabilities.
"""
function deserialize_capabilities(data::Vector{UInt8}, pos::Int)
    # versions
    v_count = Int(data[pos])
    pos += 1
    versions = UInt16[]
    for _ in 1:v_count
        push!(versions, UInt16(data[pos]) << 8 | UInt16(data[pos+1]))
        pos += 2
    end

    # cipher_suites
    cs_count = Int(data[pos])
    pos += 1
    cipher_suites = CipherSuite[]
    for _ in 1:cs_count
        cs_val = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
        push!(cipher_suites, CipherSuite(cs_val))
        pos += 2
    end

    # extensions
    e_count = Int(data[pos])
    pos += 1
    extensions = UInt16[]
    for _ in 1:e_count
        push!(extensions, UInt16(data[pos]) << 8 | UInt16(data[pos+1]))
        pos += 2
    end

    # proposals
    p_count = Int(data[pos])
    pos += 1
    proposals = ProposalType[]
    for _ in 1:p_count
        p_val = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
        push!(proposals, ProposalType(p_val))
        pos += 2
    end

    # credentials
    c_count = Int(data[pos])
    pos += 1
    credentials = CredentialType[]
    for _ in 1:c_count
        c_val = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
        push!(credentials, CredentialType(c_val))
        pos += 2
    end

    return (Capabilities(versions, cipher_suites, extensions, proposals, credentials), pos)
end

"""
Deserialize a parent node.
"""
function deserialize_parent_node(data::Vector{UInt8}, pos::Int)
    # encryption_key
    pk_len = Int(data[pos])
    pos += 1
    public_key = HPKEPublicKey(data[pos:pos+pk_len-1])
    pos += pk_len

    # parent_hash
    ph_len = Int(data[pos])
    pos += 1
    parent_hash = data[pos:pos+ph_len-1]
    pos += ph_len

    # unmerged_leaves (skip for now)
    ul_count = Int(data[pos])
    pos += 1
    for _ in 1:ul_count
        pos += 4  # Skip leaf index
    end

    node = TreeNode(public_key)
    node.parent_hash = parent_hash

    return (node, pos)
end

end # module MLSTree
