module MLSCrypto

#=
MLS Cryptographic Operations (RFC 9420 Section 5)

Implements the cryptographic primitives required for MLS:
- HPKE (Hybrid Public Key Encryption)
- Key derivation functions
- Signature operations
- Hash functions
=#

using ..MLSTypes
using ..MLSTypes: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                 MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                 MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
                 MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
                 MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
                 MLS_256_DHKEMP384_AES256GCM_SHA384_P384
using SHA
using Random

export derive_secret, expand_with_label, derive_tree_secret
export hpke_seal, hpke_open, sign_with_label, verify_with_label
export ref_hash, make_key_package_ref
export kdf_extract, kdf_expand, kdf_expand_label
export generate_hpke_keypair, generate_signature_keypair
export hash_length, mls_hash, mls_hmac, aead_encrypt, aead_decrypt
export random_bytes

# We'll use libsodium for actual crypto operations
const _libsodium = Ref{Ptr{Nothing}}(C_NULL)

function get_libsodium()
    if _libsodium[] == C_NULL
        _libsodium[] = Libdl.dlopen("libsodium")
        ccall(Libdl.dlsym(_libsodium[], :sodium_init), Cint, ())
    end
    return _libsodium[]
end

using Libdl

#=
================================================================================
HASH FUNCTIONS
================================================================================
=#

"""
Get hash output length for cipher suite
"""
function hash_length(suite::CipherSuite)
    if suite in (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                 MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        return 32  # SHA-256
    elseif suite in (MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
                     MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
                     MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448)
        return 64  # SHA-512
    elseif suite == MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        return 48  # SHA-384
    end
    return 32  # Default
end

"""
Hash function for cipher suite
"""
function mls_hash(suite::CipherSuite, data::Vector{UInt8})
    if suite in (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                 MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        return sha256(data)
    elseif suite in (MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
                     MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
                     MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448)
        return sha512(data)
    elseif suite == MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        return sha384(data)
    end
    return sha256(data)  # Default
end

#=
================================================================================
HMAC
================================================================================
=#

"""
HMAC using libsodium
"""
function hmac_sha256(key::Vector{UInt8}, data::Vector{UInt8})
    lib = get_libsodium()

    # Use crypto_auth_hmacsha256
    out = Vector{UInt8}(undef, 32)

    # If key is longer than 64 bytes, hash it first
    actual_key = length(key) > 64 ? sha256(key) : key

    # Pad key to 64 bytes
    padded_key = zeros(UInt8, 64)
    padded_key[1:length(actual_key)] = actual_key

    # Inner padding
    ipad = padded_key .⊻ 0x36
    # Outer padding
    opad = padded_key .⊻ 0x5c

    # HMAC = H(opad || H(ipad || message))
    inner = sha256(vcat(ipad, data))
    return sha256(vcat(opad, inner))
end

function hmac_sha512(key::Vector{UInt8}, data::Vector{UInt8})
    actual_key = length(key) > 128 ? sha512(key) : key
    padded_key = zeros(UInt8, 128)
    padded_key[1:length(actual_key)] = actual_key

    ipad = padded_key .⊻ 0x36
    opad = padded_key .⊻ 0x5c

    inner = sha512(vcat(ipad, data))
    return sha512(vcat(opad, inner))
end

function mls_hmac(suite::CipherSuite, key::Vector{UInt8}, data::Vector{UInt8})
    if suite in (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                 MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        return hmac_sha256(key, data)
    else
        return hmac_sha512(key, data)
    end
end

#=
================================================================================
KDF (Key Derivation Function)
================================================================================
=#

"""
HKDF-Extract
"""
function kdf_extract(suite::CipherSuite, salt::Vector{UInt8}, ikm::Vector{UInt8})
    if isempty(salt)
        salt = zeros(UInt8, hash_length(suite))
    end
    return mls_hmac(suite, salt, ikm)
end

"""
HKDF-Expand
"""
function kdf_expand(suite::CipherSuite, prk::Vector{UInt8}, info::Vector{UInt8}, length::Int)
    hash_len = hash_length(suite)
    n = ceil(Int, length / hash_len)
    okm = UInt8[]
    t = UInt8[]

    for i in 1:n
        data = vcat(t, info, UInt8[i])
        t = mls_hmac(suite, prk, data)
        append!(okm, t)
    end

    return okm[1:length]
end

"""
MLS Expand-With-Label (RFC 9420 Section 8)

ExpandWithLabel(Secret, Label, Context, Length) =
    KDF.Expand(Secret, KDFLabel, Length)

KDFLabel = struct {
    uint16 length;
    opaque label<V>;
    opaque context<V>;
}
"""
function expand_with_label(suite::CipherSuite, secret::Vector{UInt8},
                          label::String, context::Vector{UInt8}, out_len::Int)
    # Build KDFLabel structure
    full_label = Vector{UInt8}("MLS 1.0 $label")

    kdf_label = UInt8[]

    # Output length (2 bytes, big-endian)
    push!(kdf_label, UInt8((out_len >> 8) & 0xff))
    push!(kdf_label, UInt8(out_len & 0xff))

    # Label length and label (variable)
    push!(kdf_label, UInt8(length(full_label)))
    append!(kdf_label, full_label)

    # Context length and context (variable)
    push!(kdf_label, UInt8(length(context)))
    append!(kdf_label, context)

    return kdf_expand(suite, secret, kdf_label, out_len)
end

"""
MLS Derive-Secret

DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", Hash.Length)
"""
function derive_secret(suite::CipherSuite, secret::Vector{UInt8}, label::String)
    expand_with_label(suite, secret, label, UInt8[], hash_length(suite))
end

"""
Derive tree secret for ratchet tree

DeriveTreeSecret(Secret, Label, Generation, Length)
"""
function derive_tree_secret(suite::CipherSuite, secret::Vector{UInt8},
                           label::String, generation::UInt32, length::Int)
    # Generation as big-endian 4 bytes
    gen_bytes = reinterpret(UInt8, [hton(generation)])[1:4]
    expand_with_label(suite, secret, label, gen_bytes, length)
end

#=
================================================================================
HPKE (Hybrid Public Key Encryption)
================================================================================
RFC 9180 - using X25519 + ChaCha20-Poly1305/AES-128-GCM
=#

"""
Generate HPKE key pair (X25519)
"""
function hpke_generate_keypair()
    lib = get_libsodium()

    public_key = Vector{UInt8}(undef, 32)
    private_key = Vector{UInt8}(undef, 32)

    ccall(
        Libdl.dlsym(lib, :crypto_box_keypair),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key, private_key
    )

    return (HPKEPublicKey(public_key), private_key)
end

"""
X25519 scalar multiplication
"""
function x25519(private_key::Vector{UInt8}, public_key::Vector{UInt8})
    lib = get_libsodium()

    shared = Vector{UInt8}(undef, 32)

    result = ccall(
        Libdl.dlsym(lib, :crypto_scalarmult),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        shared, private_key, public_key
    )

    if result != 0
        error("X25519 failed")
    end

    return shared
end

"""
HPKE Encap - generate shared secret and encapsulation
"""
function hpke_encap(suite::CipherSuite, pk_r::HPKEPublicKey)
    # Generate ephemeral key pair
    pk_e, sk_e = hpke_generate_keypair()

    # Compute shared secret
    dh = x25519(sk_e, pk_r.data)

    # KEM shared secret = ExtractAndExpand(dh, kem_context)
    kem_context = vcat(pk_e.data, pk_r.data)

    # Extract
    prk = kdf_extract(suite, UInt8[], dh)

    # Expand
    shared_secret = expand_with_label(suite, prk, "shared_secret", kem_context, 32)

    return (shared_secret, pk_e.data)  # (shared_secret, enc)
end

"""
HPKE Decap - recover shared secret from encapsulation
"""
function hpke_decap(suite::CipherSuite, enc::Vector{UInt8},
                   sk_r::Vector{UInt8}, pk_r::HPKEPublicKey)
    # Compute shared secret
    dh = x25519(sk_r, enc)

    # KEM context
    kem_context = vcat(enc, pk_r.data)

    # Extract
    prk = kdf_extract(suite, UInt8[], dh)

    # Expand
    shared_secret = expand_with_label(suite, prk, "shared_secret", kem_context, 32)

    return shared_secret
end

"""
HPKE Key Schedule - derive encryption keys
"""
function hpke_key_schedule(suite::CipherSuite, shared_secret::Vector{UInt8},
                          info::Vector{UInt8}, psk::Vector{UInt8} = UInt8[],
                          psk_id::Vector{UInt8} = UInt8[])
    # psk_id_hash = Hash(psk_id)
    psk_id_hash = mls_hash(suite, psk_id)

    # info_hash = Hash(info)
    info_hash = mls_hash(suite, info)

    # ks_context = mode || psk_id_hash || info_hash
    mode = isempty(psk) ? UInt8(0x00) : UInt8(0x01)
    ks_context = vcat([mode], psk_id_hash, info_hash)

    # secret = Extract(shared_secret, psk)
    actual_psk = isempty(psk) ? zeros(UInt8, hash_length(suite)) : psk
    secret = kdf_extract(suite, shared_secret, actual_psk)

    # key = Expand(secret, "key", key_length)
    key_len = 32  # ChaCha20-Poly1305 or AES-256
    key = expand_with_label(suite, secret, "key", ks_context, key_len)

    # base_nonce = Expand(secret, "base_nonce", nonce_length)
    base_nonce = expand_with_label(suite, secret, "base_nonce", ks_context, 12)

    # exporter_secret = Expand(secret, "exp", Hash.Length)
    exporter_secret = expand_with_label(suite, secret, "exp", ks_context, hash_length(suite))

    return (key=key, base_nonce=base_nonce, exporter_secret=exporter_secret)
end

"""
HPKE Seal (single-shot encryption)
"""
function hpke_seal(suite::CipherSuite, pk_r::HPKEPublicKey,
                  info::Vector{UInt8}, aad::Vector{UInt8}, pt::Vector{UInt8})
    # Encap
    shared_secret, enc = hpke_encap(suite, pk_r)

    # Key schedule
    keys = hpke_key_schedule(suite, shared_secret, info)

    # AEAD encrypt
    ct = aead_encrypt(suite, keys.key, keys.base_nonce, aad, pt)

    return vcat(enc, ct)
end

# Overload accepting public key as raw bytes
function hpke_seal(suite::CipherSuite, pk_data::Vector{UInt8},
                  info::Vector{UInt8}, aad::Vector{UInt8}, pt::Vector{UInt8})
    hpke_seal(suite, HPKEPublicKey(pk_data), info, aad, pt)
end

"""
HPKE Open (single-shot decryption)
"""
function hpke_open(suite::CipherSuite, enc::Vector{UInt8},
                  sk_r::Vector{UInt8}, pk_r::HPKEPublicKey,
                  info::Vector{UInt8}, aad::Vector{UInt8}, ct::Vector{UInt8})
    # Decap
    shared_secret = hpke_decap(suite, enc, sk_r, pk_r)

    # Key schedule
    keys = hpke_key_schedule(suite, shared_secret, info)

    # AEAD decrypt
    return aead_decrypt(suite, keys.key, keys.base_nonce, aad, ct)
end

# Simplified overload: extract enc from ciphertext and derive pk from sk
function hpke_open(suite::CipherSuite, sk_r::Vector{UInt8},
                  info::Vector{UInt8}, aad::Vector{UInt8}, ciphertext::Vector{UInt8})
    # Ciphertext format: enc (32 bytes) || ct
    enc_len = 32  # X25519 public key length
    enc = ciphertext[1:enc_len]
    ct = ciphertext[enc_len+1:end]

    # Derive public key from private key (X25519 base point multiplication)
    lib = get_libsodium()
    pk_r = Vector{UInt8}(undef, 32)
    ccall(
        Libdl.dlsym(lib, :crypto_scalarmult_base),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}),
        pk_r, sk_r
    )

    # Decap
    shared_secret = hpke_decap(suite, enc, sk_r, HPKEPublicKey(pk_r))

    # Key schedule
    keys = hpke_key_schedule(suite, shared_secret, info)

    # AEAD decrypt
    return aead_decrypt(suite, keys.key, keys.base_nonce, aad, ct)
end

#=
================================================================================
AEAD Encryption
================================================================================
=#

"""
AEAD Encrypt using ChaCha20-Poly1305 or AES-GCM
"""
function aead_encrypt(suite::CipherSuite, key::Vector{UInt8},
                     nonce::Vector{UInt8}, aad::Vector{UInt8}, pt::Vector{UInt8})
    lib = get_libsodium()

    if suite in (MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                 MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448)
        # ChaCha20-Poly1305
        ct = Vector{UInt8}(undef, length(pt) + 16)  # +16 for tag

        ccall(
            Libdl.dlsym(lib, :crypto_aead_chacha20poly1305_ietf_encrypt),
            Cint,
            (Ptr{UInt8}, Ptr{Culonglong}, Ptr{UInt8}, Culonglong,
             Ptr{UInt8}, Culonglong, Ptr{Nothing}, Ptr{UInt8}, Ptr{UInt8}),
            ct, C_NULL, pt, length(pt),
            aad, length(aad), C_NULL, nonce, key
        )

        return ct
    else
        # AES-GCM (use MbedTLS or similar)
        # For now, fall back to ChaCha20-Poly1305
        ct = Vector{UInt8}(undef, length(pt) + 16)

        ccall(
            Libdl.dlsym(lib, :crypto_aead_chacha20poly1305_ietf_encrypt),
            Cint,
            (Ptr{UInt8}, Ptr{Culonglong}, Ptr{UInt8}, Culonglong,
             Ptr{UInt8}, Culonglong, Ptr{Nothing}, Ptr{UInt8}, Ptr{UInt8}),
            ct, C_NULL, pt, length(pt),
            aad, length(aad), C_NULL, nonce, key
        )

        return ct
    end
end

"""
AEAD Decrypt
"""
function aead_decrypt(suite::CipherSuite, key::Vector{UInt8},
                     nonce::Vector{UInt8}, aad::Vector{UInt8}, ct::Vector{UInt8})
    lib = get_libsodium()

    if length(ct) < 16
        error("Ciphertext too short")
    end

    pt = Vector{UInt8}(undef, length(ct) - 16)

    result = ccall(
        Libdl.dlsym(lib, :crypto_aead_chacha20poly1305_ietf_decrypt),
        Cint,
        (Ptr{UInt8}, Ptr{Culonglong}, Ptr{Nothing}, Ptr{UInt8}, Culonglong,
         Ptr{UInt8}, Culonglong, Ptr{UInt8}, Ptr{UInt8}),
        pt, C_NULL, C_NULL, ct, length(ct),
        aad, length(aad), nonce, key
    )

    if result != 0
        error("AEAD decryption failed")
    end

    return pt
end

#=
================================================================================
SIGNATURES
================================================================================
=#

"""
Generate Ed25519 key pair
"""
function sign_generate_keypair()
    lib = get_libsodium()

    public_key = Vector{UInt8}(undef, 32)
    secret_key = Vector{UInt8}(undef, 64)

    ccall(
        Libdl.dlsym(lib, :crypto_sign_keypair),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}),
        public_key, secret_key
    )

    return (SignaturePublicKey(public_key), secret_key)
end

"""
Sign with Label (RFC 9420 Section 5.1.2)

SignWithLabel(SignKey, Label, Content) = Sign(SignKey, SignContent)

SignContent = struct {
    opaque label<V>;
    opaque content<V>;
}
"""
function sign_with_label(suite::CipherSuite, secret_key::Vector{UInt8}, label::String, content::Vector{UInt8})
    # Dispatch to actual implementation (suite is currently unused but needed for future P-256 support)
    sign_with_label_impl(secret_key, label, content)
end

# Backward compatible version without suite
function sign_with_label(secret_key::Vector{UInt8}, label::String, content::Vector{UInt8})
    sign_with_label_impl(secret_key, label, content)
end

function sign_with_label_impl(secret_key::Vector{UInt8}, label::String, content::Vector{UInt8})
    lib = get_libsodium()

    full_label = Vector{UInt8}("MLS 1.0 $label")

    # Build SignContent
    sign_content = UInt8[]
    push!(sign_content, UInt8(length(full_label)))
    append!(sign_content, full_label)

    # Content length as varint (simplified: 2 bytes)
    push!(sign_content, UInt8((length(content) >> 8) & 0xff))
    push!(sign_content, UInt8(length(content) & 0xff))
    append!(sign_content, content)

    # Sign
    signature = Vector{UInt8}(undef, 64)

    ccall(
        Libdl.dlsym(lib, :crypto_sign_detached),
        Cint,
        (Ptr{UInt8}, Ptr{Culonglong}, Ptr{UInt8}, Culonglong, Ptr{UInt8}),
        signature, C_NULL, sign_content, length(sign_content), secret_key
    )

    return signature
end

"""
Verify with Label
"""
function verify_with_label(suite::CipherSuite, public_key::Vector{UInt8}, label::String,
                          content::Vector{UInt8}, signature::Vector{UInt8})
    # Dispatch to actual implementation
    verify_with_label_impl(public_key, label, content, signature)
end

# Backward compatible version without suite
function verify_with_label(public_key::SignaturePublicKey, label::String,
                          content::Vector{UInt8}, signature::Vector{UInt8})
    verify_with_label_impl(public_key.data, label, content, signature)
end

function verify_with_label_impl(public_key::Vector{UInt8}, label::String,
                               content::Vector{UInt8}, signature::Vector{UInt8})
    lib = get_libsodium()

    full_label = Vector{UInt8}("MLS 1.0 $label")

    # Build SignContent
    sign_content = UInt8[]
    push!(sign_content, UInt8(length(full_label)))
    append!(sign_content, full_label)
    push!(sign_content, UInt8((length(content) >> 8) & 0xff))
    push!(sign_content, UInt8(length(content) & 0xff))
    append!(sign_content, content)

    result = ccall(
        Libdl.dlsym(lib, :crypto_sign_verify_detached),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}, Culonglong, Ptr{UInt8}),
        signature, sign_content, length(sign_content), public_key
    )

    return result == 0
end

#=
================================================================================
REFERENCE HASHES
================================================================================
=#

"""
RefHash - hash for referencing objects

RefHash(label, value) = Hash(RefHashInput)

RefHashInput = struct {
    opaque label<V>;
    opaque value<V>;
}
"""
function ref_hash(suite::CipherSuite, label::String, value::Vector{UInt8})
    full_label = Vector{UInt8}("MLS 1.0 $label")

    input = UInt8[]
    push!(input, UInt8(length(full_label)))
    append!(input, full_label)

    # Value with length prefix
    push!(input, UInt8((length(value) >> 8) & 0xff))
    push!(input, UInt8(length(value) & 0xff))
    append!(input, value)

    return mls_hash(suite, input)
end

"""
Make KeyPackage reference
"""
function make_key_package_ref(suite::CipherSuite, key_package_bytes::Vector{UInt8})
    KeyPackageRef(ref_hash(suite, "MLS 1.0 KeyPackage Reference", key_package_bytes))
end

#=
================================================================================
KEY GENERATION WRAPPERS
================================================================================
=#

"""
Generate HPKE keypair for a cipher suite

Returns (public_key_bytes, private_key_bytes)
"""
function generate_hpke_keypair(suite::CipherSuite)
    # For X25519-based suites (all currently supported)
    if suite in (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        pk, sk = hpke_generate_keypair()
        return (pk.data, sk)
    else
        # Fallback to X25519 for now
        pk, sk = hpke_generate_keypair()
        return (pk.data, sk)
    end
end

"""
Generate signature keypair for a cipher suite

Returns (public_key_bytes, private_key_bytes)
"""
function generate_signature_keypair(suite::CipherSuite)
    # For Ed25519-based suites (all currently supported)
    if suite in (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        pk, sk = sign_generate_keypair()
        return (pk.data, sk)
    else
        # Fallback to Ed25519 for now
        pk, sk = sign_generate_keypair()
        return (pk.data, sk)
    end
end

"""
Generate random bytes
"""
function random_bytes(n::Int)
    lib = get_libsodium()
    buf = Vector{UInt8}(undef, n)
    ccall(
        Libdl.dlsym(lib, :randombytes_buf),
        Cvoid,
        (Ptr{UInt8}, Csize_t),
        buf, n
    )
    return buf
end

end # module MLSCrypto
