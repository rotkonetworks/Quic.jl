module Crypto

using SHA
using Random
using MbedTLS
using Libdl

# libsodium constants for ChaCha20-Poly1305 IETF
const CHACHA20_POLY1305_KEYBYTES = 32
const CHACHA20_POLY1305_NONCEBYTES = 12
const CHACHA20_POLY1305_TAGBYTES = 16

# Load libsodium once
const _libsodium = Ref{Ptr{Nothing}}(C_NULL)
function get_libsodium()
    if _libsodium[] == C_NULL
        _libsodium[] = dlopen("libsodium")
        ccall(dlsym(_libsodium[], :sodium_init), Cint, ())
    end
    return _libsodium[]
end

# Load mbedtls crypto library for AES-GCM
const _mbedtls_crypto = Ref{Ptr{Nothing}}(C_NULL)
function get_mbedtls_crypto()
    if _mbedtls_crypto[] == C_NULL
        _mbedtls_crypto[] = dlopen("libmbedcrypto")
    end
    return _mbedtls_crypto[]
end

# mbedtls GCM context size (large enough for any platform)
const MBEDTLS_GCM_CONTEXT_SIZE = 512
const MBEDTLS_CIPHER_ID_AES = 2  # From mbedtls cipher.h

# AES-GCM constants
const AES_GCM_TAG_SIZE = 16
const AES_GCM_NONCE_SIZE = 12

# Simple HMAC-SHA256 implementation
function hmac_sha256(key::Vector{UInt8}, data::Vector{UInt8})::Vector{UInt8}
    block_size = 64  # SHA-256 block size

    # If key is longer than block size, hash it
    if length(key) > block_size
        key = SHA.sha256(key)
    end

    # Pad key to block size
    if length(key) < block_size
        key = vcat(key, zeros(UInt8, block_size - length(key)))
    end

    # Compute inner and outer padded keys
    o_key_pad = key .⊻ 0x5c
    i_key_pad = key .⊻ 0x36

    # HMAC = H(o_key_pad || H(i_key_pad || message))
    inner_hash = SHA.sha256(vcat(i_key_pad, data))
    return SHA.sha256(vcat(o_key_pad, inner_hash))
end

# QUIC uses AES-128-GCM or ChaCha20-Poly1305
abstract type CipherSuite end

struct AES128GCM <: CipherSuite
    key_len::Int
    iv_len::Int
    tag_len::Int
    AES128GCM() = new(16, 12, 16)
end

struct AES256GCM <: CipherSuite
    key_len::Int
    iv_len::Int
    tag_len::Int
    AES256GCM() = new(32, 12, 16)
end

struct ChaCha20Poly1305 <: CipherSuite
    key_len::Int
    iv_len::Int
    tag_len::Int
    ChaCha20Poly1305() = new(32, 12, 16)
end

mutable struct CryptoContext
    handshake_complete::Bool
    cipher_suite::CipherSuite

    # keys for each packet space
    initial_secrets::Dict{Symbol, Vector{UInt8}}
    handshake_secrets::Dict{Symbol, Vector{UInt8}}
    application_secrets::Dict{Symbol, Vector{UInt8}}

    # Default to ChaCha20-Poly1305 (well-supported, preferred by Rust QUIC)
    CryptoContext() = new(false, ChaCha20Poly1305(), Dict(), Dict(), Dict())
end

# QUIC v1 initial salt
const INITIAL_SALT = hex2bytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

# derive initial secrets from client's initial destination connection ID
# Note: QUIC Initial packets ALWAYS use AES-128-GCM regardless of negotiated cipher
function derive_initial_secrets!(ctx::CryptoContext, client_dcid::Vector{UInt8})
    # Initial packets use AES-128-GCM
    initial_suite = AES128GCM()

    # extract initial secret
    initial_secret = hkdf_extract(client_dcid, INITIAL_SALT)

    # derive client and server initial secrets
    client_secret = hkdf_expand_label(initial_secret, "client in", UInt8[], 32)
    server_secret = hkdf_expand_label(initial_secret, "server in", UInt8[], 32)

    # derive keys and IVs for each direction (always 16-byte key for Initial)
    ctx.initial_secrets[:client_secret] = client_secret
    ctx.initial_secrets[:server_secret] = server_secret

    ctx.initial_secrets[:client_key] = hkdf_expand_label(client_secret, "quic key", UInt8[], initial_suite.key_len)
    ctx.initial_secrets[:client_iv] = hkdf_expand_label(client_secret, "quic iv", UInt8[], initial_suite.iv_len)
    ctx.initial_secrets[:client_hp] = hkdf_expand_label(client_secret, "quic hp", UInt8[], initial_suite.key_len)

    ctx.initial_secrets[:server_key] = hkdf_expand_label(server_secret, "quic key", UInt8[], initial_suite.key_len)
    ctx.initial_secrets[:server_iv] = hkdf_expand_label(server_secret, "quic iv", UInt8[], initial_suite.iv_len)
    ctx.initial_secrets[:server_hp] = hkdf_expand_label(server_secret, "quic hp", UInt8[], initial_suite.key_len)
end

# HKDF-Extract using SHA256
function hkdf_extract(ikm::Vector{UInt8}, salt::Vector{UInt8})
    if isempty(salt)
        salt = zeros(UInt8, 32)  # SHA256 output length
    end

    # HMAC-SHA256(salt, ikm) - simple implementation
    return hmac_sha256(salt, ikm)
end

# HKDF-Expand using SHA256
function hkdf_expand(prk::Vector{UInt8}, info::Vector{UInt8}, length::Int)
    n = ceil(Int, length / 32)  # SHA256 output length
    okm = UInt8[]
    t = UInt8[]

    for i in 1:n
        # HMAC-SHA256(prk, t || info || i)
        data = vcat(t, info, UInt8[i])
        t = hmac_sha256(prk, data)
        append!(okm, t)
    end

    return okm[1:length]
end

# HKDF-Expand-Label for QUIC/TLS 1.3
function hkdf_expand_label(secret::Vector{UInt8}, label::String, context::Vector{UInt8}, out_length::Int)
    # build info for HKDF-Expand
    # struct {
    #     uint16 length = length;
    #     opaque label<7..255> = "tls13 " + label;
    #     opaque context<0..255> = context;
    # } HkdfLabel;

    full_label = Vector{UInt8}("tls13 $label")

    info = UInt8[]
    # length (2 bytes, big-endian)
    push!(info, UInt8((out_length >> 8) & 0xff))
    push!(info, UInt8(out_length & 0xff))

    # label length and label
    push!(info, UInt8(Base.length(full_label)))
    append!(info, full_label)

    # context length and context
    push!(info, UInt8(Base.length(context)))
    append!(info, context)

    return hkdf_expand(secret, info, out_length)
end

# encrypt payload based on cipher suite
function encrypt_payload(ctx::CryptoContext, payload::Vector{UInt8}, key::Vector{UInt8},
                        iv::Vector{UInt8}, packet_number::UInt64, associated_data::Vector{UInt8})
    if ctx.cipher_suite isa ChaCha20Poly1305
        return encrypt_chacha20_poly1305(payload, key, iv, packet_number, associated_data)
    else
        return encrypt_aes_gcm(payload, key, iv, packet_number, associated_data, ctx.cipher_suite)
    end
end

# backwards compatibility
function encrypt_payload(payload::Vector{UInt8}, key::Vector{UInt8}, iv::Vector{UInt8},
                        packet_number::UInt64, associated_data::Vector{UInt8})
    ctx = CryptoContext()  # defaults to AES128GCM
    return encrypt_payload(ctx, payload, key, iv, packet_number, associated_data)
end

# encrypt with ChaCha20-Poly1305 using libsodium
function encrypt_chacha20_poly1305(payload::Vector{UInt8}, key::Vector{UInt8}, iv::Vector{UInt8},
                                   packet_number::UInt64, associated_data::Vector{UInt8})
    lib = get_libsodium()

    # construct nonce by XORing IV with packet number
    nonce = copy(iv)
    pn_bytes = zeros(UInt8, 12)
    pn_bytes[5:12] = reinterpret(UInt8, [hton(packet_number)])

    for i in 1:12
        nonce[i] ⊻= pn_bytes[i]
    end

    # output buffer: ciphertext + tag
    ciphertext = Vector{UInt8}(undef, length(payload) + CHACHA20_POLY1305_TAGBYTES)
    ciphertext_len = Ref{Culonglong}(0)

    # Call libsodium crypto_aead_chacha20poly1305_ietf_encrypt
    ret = ccall(
        dlsym(lib, :crypto_aead_chacha20poly1305_ietf_encrypt),
        Cint,
        (Ptr{UInt8}, Ptr{Culonglong}, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Culonglong, Ptr{Nothing}, Ptr{UInt8}, Ptr{UInt8}),
        ciphertext, ciphertext_len, payload, length(payload), associated_data, length(associated_data), C_NULL, nonce, key
    )

    if ret != 0
        error("ChaCha20-Poly1305 encryption failed")
    end

    return ciphertext
end

# encrypt payload with AES-GCM using mbedtls FFI
function encrypt_aes_gcm(payload::Vector{UInt8}, key::Vector{UInt8}, iv::Vector{UInt8},
                        packet_number::UInt64, associated_data::Vector{UInt8}, suite::CipherSuite)
    lib = get_mbedtls_crypto()

    # construct nonce by XORing IV with packet number
    nonce = copy(iv)
    pn_bytes = reinterpret(UInt8, [hton(packet_number)])

    # XOR packet number into the last 8 bytes of nonce
    for i in 1:min(8, length(nonce))
        nonce[end - i + 1] ⊻= pn_bytes[end - i + 1]
    end

    # Allocate GCM context
    gcm_ctx = Vector{UInt8}(undef, MBEDTLS_GCM_CONTEXT_SIZE)

    # Initialize GCM context
    ccall(dlsym(lib, :mbedtls_gcm_init), Cvoid, (Ptr{UInt8},), gcm_ctx)

    # Set key (keybits = key length * 8)
    keybits = length(key) * 8
    ret = ccall(dlsym(lib, :mbedtls_gcm_setkey), Cint,
                (Ptr{UInt8}, Cint, Ptr{UInt8}, Cuint),
                gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, keybits)
    if ret != 0
        ccall(dlsym(lib, :mbedtls_gcm_free), Cvoid, (Ptr{UInt8},), gcm_ctx)
        error("Failed to set AES-GCM key: $ret")
    end

    # Allocate output buffers
    ciphertext = Vector{UInt8}(undef, length(payload))
    tag = Vector{UInt8}(undef, AES_GCM_TAG_SIZE)

    # Encrypt and generate tag
    # mbedtls_gcm_crypt_and_tag(ctx, mode, length, iv, iv_len, add, add_len, input, output, tag_len, tag)
    ret = ccall(dlsym(lib, :mbedtls_gcm_crypt_and_tag), Cint,
                (Ptr{UInt8}, Cint, Csize_t, Ptr{UInt8}, Csize_t,
                 Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
                gcm_ctx, 1,  # 1 = MBEDTLS_GCM_ENCRYPT
                length(payload),  # length of input/output
                nonce, length(nonce),
                associated_data, length(associated_data),
                payload, ciphertext,
                AES_GCM_TAG_SIZE, tag)

    # Free context
    ccall(dlsym(lib, :mbedtls_gcm_free), Cvoid, (Ptr{UInt8},), gcm_ctx)

    if ret != 0
        error("AES-GCM encryption failed: $ret")
    end

    # Return ciphertext with tag appended
    return [ciphertext; tag]
end

# decrypt payload based on cipher suite
function decrypt_payload(ctx::CryptoContext, ciphertext_with_tag::Vector{UInt8}, key::Vector{UInt8},
                        iv::Vector{UInt8}, packet_number::UInt64, associated_data::Vector{UInt8})
    if ctx.cipher_suite isa ChaCha20Poly1305
        return decrypt_chacha20_poly1305(ciphertext_with_tag, key, iv, packet_number, associated_data)
    else
        return decrypt_aes_gcm(ciphertext_with_tag, key, iv, packet_number, associated_data, ctx.cipher_suite)
    end
end

# backwards compatibility
function decrypt_payload(ciphertext_with_tag::Vector{UInt8}, key::Vector{UInt8}, iv::Vector{UInt8},
                        packet_number::UInt64, associated_data::Vector{UInt8})
    ctx = CryptoContext()  # defaults to AES128GCM
    return decrypt_payload(ctx, ciphertext_with_tag, key, iv, packet_number, associated_data)
end

# decrypt with ChaCha20-Poly1305 using libsodium
function decrypt_chacha20_poly1305(ciphertext_with_tag::Vector{UInt8}, key::Vector{UInt8}, iv::Vector{UInt8},
                                   packet_number::UInt64, associated_data::Vector{UInt8})
    lib = get_libsodium()

    if length(ciphertext_with_tag) < CHACHA20_POLY1305_TAGBYTES
        error("Ciphertext too short for authentication tag")
    end

    # construct nonce
    nonce = copy(iv)
    pn_bytes = zeros(UInt8, 12)
    pn_bytes[5:12] = reinterpret(UInt8, [hton(packet_number)])

    for i in 1:12
        nonce[i] ⊻= pn_bytes[i]
    end

    # output buffer for plaintext (ciphertext length minus tag)
    plaintext_len = length(ciphertext_with_tag) - CHACHA20_POLY1305_TAGBYTES
    plaintext = Vector{UInt8}(undef, plaintext_len)
    decrypted_len = Ref{Culonglong}(0)

    # Call libsodium crypto_aead_chacha20poly1305_ietf_decrypt
    ret = ccall(
        dlsym(lib, :crypto_aead_chacha20poly1305_ietf_decrypt),
        Cint,
        (Ptr{UInt8}, Ptr{Culonglong}, Ptr{Nothing}, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Ptr{UInt8}),
        plaintext, decrypted_len, C_NULL, ciphertext_with_tag, length(ciphertext_with_tag), associated_data, length(associated_data), nonce, key
    )

    if ret != 0
        error("ChaCha20-Poly1305 decryption/authentication failed")
    end

    return plaintext
end

# decrypt payload with AES-GCM using mbedtls FFI
function decrypt_aes_gcm(ciphertext_with_tag::Vector{UInt8}, key::Vector{UInt8}, iv::Vector{UInt8},
                        packet_number::UInt64, associated_data::Vector{UInt8}, suite::CipherSuite)
    lib = get_mbedtls_crypto()

    if length(ciphertext_with_tag) < AES_GCM_TAG_SIZE
        error("Ciphertext too short for authentication tag")
    end

    # separate ciphertext and tag
    ciphertext = ciphertext_with_tag[1:end-AES_GCM_TAG_SIZE]
    tag = ciphertext_with_tag[end-AES_GCM_TAG_SIZE+1:end]

    # construct nonce
    nonce = copy(iv)
    pn_bytes = reinterpret(UInt8, [hton(packet_number)])

    for i in 1:min(8, length(nonce))
        nonce[end - i + 1] ⊻= pn_bytes[end - i + 1]
    end

    # Allocate GCM context
    gcm_ctx = Vector{UInt8}(undef, MBEDTLS_GCM_CONTEXT_SIZE)

    # Initialize GCM context
    ccall(dlsym(lib, :mbedtls_gcm_init), Cvoid, (Ptr{UInt8},), gcm_ctx)

    # Set key
    keybits = length(key) * 8
    ret = ccall(dlsym(lib, :mbedtls_gcm_setkey), Cint,
                (Ptr{UInt8}, Cint, Ptr{UInt8}, Cuint),
                gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, keybits)
    if ret != 0
        ccall(dlsym(lib, :mbedtls_gcm_free), Cvoid, (Ptr{UInt8},), gcm_ctx)
        error("Failed to set AES-GCM key: $ret")
    end

    # Allocate output buffer
    plaintext = Vector{UInt8}(undef, length(ciphertext))

    # Decrypt and verify tag
    ret = ccall(dlsym(lib, :mbedtls_gcm_auth_decrypt), Cint,
                (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
                 Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
                 Ptr{UInt8}, Ptr{UInt8}),
                gcm_ctx, length(ciphertext), nonce, length(nonce),
                associated_data, length(associated_data), tag, AES_GCM_TAG_SIZE,
                ciphertext, plaintext)

    # Free context
    ccall(dlsym(lib, :mbedtls_gcm_free), Cvoid, (Ptr{UInt8},), gcm_ctx)

    if ret != 0
        error("AES-GCM decryption/authentication failed: $ret")
    end

    return plaintext
end

# header protection (cipher-agnostic)
function protect_header!(ctx::CryptoContext, header::Vector{UInt8}, hp_key::Vector{UInt8},
                        sample::Vector{UInt8}, pn_offset::Int, pn_len::Int)
    if ctx.cipher_suite isa ChaCha20Poly1305
        mask = chacha20_header_protection_mask(hp_key, sample)
    else
        mask = aes_header_protection_mask(hp_key, sample, ctx.cipher_suite)
    end

    # apply mask to packet number and flags
    is_long_header = (header[1] & 0x80) != 0

    if is_long_header
        # long header: 4 bits
        header[1] ⊻= mask[1] & 0x0f
    else
        # short header: 5 bits
        header[1] ⊻= mask[1] & 0x1f
    end

    # XOR packet number bytes
    for i in 1:pn_len
        header[pn_offset + i - 1] ⊻= mask[1 + i]
    end
end

# remove header protection
function unprotect_header!(ctx::CryptoContext, header::Vector{UInt8}, hp_key::Vector{UInt8},
                          sample::Vector{UInt8}, pn_offset::Int, pn_len::Int)
    # same as protect_header! due to XOR
    protect_header!(ctx, header, hp_key, sample, pn_offset, pn_len)
end

# backwards compatibility - accept any AbstractVector for flexibility with views
function protect_header!(header::AbstractVector{UInt8}, hp_key::Vector{UInt8}, sample::Vector{UInt8})
    ctx = CryptoContext()
    pn_offset = 1 + 8  # assuming short header with 8-byte CID
    # Convert to Vector if needed for the internal function
    header_vec = header isa Vector{UInt8} ? header : collect(header)
    protect_header!(ctx, header_vec, hp_key, sample, pn_offset, 2)
    # Copy back if it was a view
    if !(header isa Vector{UInt8})
        header .= header_vec
    end
end

function unprotect_header!(header::AbstractVector{UInt8}, hp_key::Vector{UInt8}, sample::Vector{UInt8})
    ctx = CryptoContext()
    pn_offset = 1 + 8
    header_vec = header isa Vector{UInt8} ? header : collect(header)
    unprotect_header!(ctx, header_vec, hp_key, sample, pn_offset, 2)
    if !(header isa Vector{UInt8})
        header .= header_vec
    end
end

# AES header protection mask
function aes_header_protection_mask(hp_key::Vector{UInt8}, sample::Vector{UInt8}, suite::CipherSuite)
    # use AES-ECB for header protection
    cipher_type = suite isa AES256GCM ? MbedTLS.CIPHER_AES_256_ECB : MbedTLS.CIPHER_AES_128_ECB
    cipher = MbedTLS.Cipher(cipher_type)
    MbedTLS.set_key!(cipher, hp_key, MbedTLS.ENCRYPT)

    mask = Vector{UInt8}(undef, 16)
    MbedTLS.update!(cipher, sample[1:16], mask)

    return mask
end

# ChaCha20 header protection mask using libsodium
function chacha20_header_protection_mask(hp_key::Vector{UInt8}, sample::Vector{UInt8})
    lib = get_libsodium()

    # use first 4 bytes of sample as counter (big-endian per QUIC spec), rest as nonce
    counter = UInt32(sample[1]) << 24 | UInt32(sample[2]) << 16 | UInt32(sample[3]) << 8 | UInt32(sample[4])

    nonce = sample[5:16]

    # generate ChaCha20 keystream by encrypting zeros
    # For header protection we need 5 bytes of keystream
    # libsodium's crypto_stream_chacha20_ietf_xor_ic handles counter internally
    plaintext = zeros(UInt8, 5)
    mask = Vector{UInt8}(undef, 5)

    # Use crypto_stream_chacha20_ietf_xor_ic to encrypt with initial counter
    ret = ccall(
        dlsym(lib, :crypto_stream_chacha20_ietf_xor_ic),
        Cint,
        (Ptr{UInt8}, Ptr{UInt8}, Culonglong, Ptr{UInt8}, UInt32, Ptr{UInt8}),
        mask, plaintext, 5, nonce, counter, hp_key
    )

    if ret != 0
        error("ChaCha20 header protection mask generation failed")
    end

    return mask
end

export CryptoContext, AES128GCM, AES256GCM, ChaCha20Poly1305
export derive_initial_secrets!, encrypt_payload, decrypt_payload
export protect_header!, unprotect_header!
export hkdf_extract, hkdf_expand, hkdf_expand_label
export hmac_sha256
export aes_header_protection_mask, chacha20_header_protection_mask
export encrypt_aes_gcm, decrypt_aes_gcm
export encrypt_chacha20_poly1305, decrypt_chacha20_poly1305

end # module Crypto
