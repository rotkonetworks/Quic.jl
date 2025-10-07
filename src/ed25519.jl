module Ed25519

using Sodium

# Initialize libsodium
function __init__()
    Sodium.sodium_init()
end

# Ed25519 key pair
struct KeyPair
    public_key::Vector{UInt8}  # 32 bytes
    secret_key::Vector{UInt8}  # 64 bytes (32 byte seed + 32 byte public key)

    function KeyPair(pub::Vector{UInt8}, sec::Vector{UInt8})
        @assert length(pub) == Sodium.crypto_sign_ed25519_PUBLICKEYBYTES "Public key must be 32 bytes"
        @assert length(sec) == Sodium.crypto_sign_ed25519_SECRETKEYBYTES "Secret key must be 64 bytes"
        new(pub, sec)
    end
end

# Generate new Ed25519 key pair
function generate_keypair()
    public_key = Vector{UInt8}(undef, Sodium.crypto_sign_ed25519_PUBLICKEYBYTES)
    secret_key = Vector{UInt8}(undef, Sodium.crypto_sign_ed25519_SECRETKEYBYTES)

    Sodium.crypto_sign_ed25519_keypair(public_key, secret_key)

    return KeyPair(public_key, secret_key)
end

# Generate key pair from seed
function keypair_from_seed(seed::Vector{UInt8})
    @assert length(seed) == Sodium.crypto_sign_ed25519_SEEDBYTES "Seed must be 32 bytes"

    public_key = Vector{UInt8}(undef, Sodium.crypto_sign_ed25519_PUBLICKEYBYTES)
    secret_key = Vector{UInt8}(undef, Sodium.crypto_sign_ed25519_SECRETKEYBYTES)

    Sodium.crypto_sign_ed25519_seed_keypair(public_key, secret_key, seed)

    return KeyPair(public_key, secret_key)
end

# Sign a message
function sign(message::Vector{UInt8}, keypair::KeyPair)
    signature = Vector{UInt8}(undef, Sodium.crypto_sign_ed25519_BYTES)

    Sodium.crypto_sign_ed25519_detached(
        signature,
        C_NULL,  # signature length output (optional)
        message,
        length(message),
        keypair.secret_key
    )

    return signature
end

# Verify a signature
function verify(signature::Vector{UInt8}, message::Vector{UInt8}, public_key::Vector{UInt8})
    @assert length(signature) == Sodium.crypto_sign_ed25519_BYTES "Signature must be 64 bytes"
    @assert length(public_key) == Sodium.crypto_sign_ed25519_PUBLICKEYBYTES "Public key must be 32 bytes"

    result = Sodium.crypto_sign_ed25519_verify_detached(
        signature,
        message,
        length(message),
        public_key
    )

    return result == 0  # 0 means success, -1 means failure
end

# Convert Ed25519 public key to X25519 (for key exchange)
function ed25519_pk_to_x25519(ed25519_pk::Vector{UInt8})
    @assert length(ed25519_pk) == Sodium.crypto_sign_ed25519_PUBLICKEYBYTES

    x25519_pk = Vector{UInt8}(undef, Sodium.crypto_box_PUBLICKEYBYTES)

    Sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk)

    return x25519_pk
end

# Convert Ed25519 secret key to X25519 (for key exchange)
function ed25519_sk_to_x25519(ed25519_sk::Vector{UInt8})
    @assert length(ed25519_sk) == Sodium.crypto_sign_ed25519_SECRETKEYBYTES

    x25519_sk = Vector{UInt8}(undef, Sodium.crypto_box_SECRETKEYBYTES)

    Sodium.crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_sk)

    return x25519_sk
end

# Generate self-signed X.509 certificate from Ed25519 key
# This is a simplified version - real implementation would use proper ASN.1 encoding
function generate_self_signed_cert(keypair::KeyPair, subject_name::String="CN=QuicNet")
    # For now, we'll create a minimal certificate structure
    # In production, you'd use a proper X.509 library

    cert = Dict{String, Any}(
        "version" => 3,
        "serial" => rand(UInt32),
        "subject" => subject_name,
        "issuer" => subject_name,
        "not_before" => time(),
        "not_after" => time() + (365 * 24 * 60 * 60),  # 1 year
        "public_key" => keypair.public_key,
        "signature_algorithm" => "Ed25519"
    )

    # Create TBS (To Be Signed) certificate
    tbs_data = Vector{UInt8}(string(cert))

    # Sign the certificate
    signature = sign(tbs_data, keypair)

    cert["signature"] = signature

    # For QuicNet compatibility, we'd need proper ASN.1 DER encoding
    # This is a placeholder that returns the cert data
    return cert
end

# Helper to get peer ID from public key (QuicNet compatible)
function peer_id_from_pubkey(pubkey::Vector{UInt8})
    # QuicNet uses base58 encoding, we'll use hex for simplicity
    return bytes2hex(pubkey)
end

export KeyPair, generate_keypair, keypair_from_seed
export sign, verify
export ed25519_pk_to_x25519, ed25519_sk_to_x25519
export generate_self_signed_cert, peer_id_from_pubkey

end # module