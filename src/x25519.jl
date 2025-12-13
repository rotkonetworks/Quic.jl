module X25519

# X25519 elliptic curve Diffie-Hellman implementation for QUIC/TLS 1.3
# Reference: RFC 7748

const P = BigInt(2)^255 - 19  # Field prime
const A24 = BigInt(121665)    # (A - 2) / 4 where A = 486662

# Clamp private key according to X25519 spec (RFC 7748 section 5)
function clamp_private_key!(key::Vector{UInt8})
    key[1] &= 248      # Clear bottom 3 bits
    key[32] &= 127     # Clear top bit
    key[32] |= 64      # Set second highest bit
    return key
end

# Decode little-endian 32-byte scalar, then clamp
function decode_u_coordinate(bytes::Vector{UInt8})
    # Clear the high bit (bit 255) per RFC 7748
    masked = copy(bytes)
    masked[32] &= 0x7f  # Clear bit 255
    result = BigInt(0)
    for i in 32:-1:1
        result = (result << 8) | masked[i]
    end
    return result
end

# Decode scalar (private key) with clamping
function decode_scalar(bytes::Vector{UInt8})
    clamped = copy(bytes)
    clamp_private_key!(clamped)
    result = BigInt(0)
    for i in 32:-1:1
        result = (result << 8) | clamped[i]
    end
    return result
end

# Convert field element to 32 bytes (little-endian)
function encode_u_coordinate(n::BigInt)
    bytes = zeros(UInt8, 32)
    temp = mod(n, P)
    if temp < 0
        temp += P
    end
    for i in 1:32
        bytes[i] = UInt8(temp & 0xff)
        temp >>= 8
    end
    return bytes
end

# X25519 function per RFC 7748 section 5
# k is the scalar, u is the u-coordinate
function x25519(k::BigInt, u::BigInt)
    x_1 = u
    x_2 = BigInt(1)
    z_2 = BigInt(0)
    x_3 = u
    z_3 = BigInt(1)

    swap = BigInt(0)

    # Montgomery ladder from bit 254 to 0
    for t in 254:-1:0
        k_t = (k >> t) & 1
        swap = swap ⊻ k_t

        # Conditional swap
        if swap != 0
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        end
        swap = k_t

        # Montgomery ladder step
        A = mod(x_2 + z_2, P)
        AA = mod(A * A, P)
        B = mod(x_2 - z_2 + P, P)
        BB = mod(B * B, P)
        E = mod(AA - BB + P, P)
        C = mod(x_3 + z_3, P)
        D = mod(x_3 - z_3 + P, P)
        DA = mod(D * A, P)
        CB = mod(C * B, P)

        x_3 = mod((DA + CB) * (DA + CB), P)
        z_3 = mod(x_1 * mod((DA - CB + P) * (DA - CB + P), P), P)
        x_2 = mod(AA * BB, P)
        z_2 = mod(E * mod(AA + A24 * E, P), P)
    end

    # Final conditional swap
    if swap != 0
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    end

    # Return x_2 * z_2^(p-2) mod p
    return mod(x_2 * powermod(z_2, P - 2, P), P)
end

# Base point for X25519 (u=9)
const BASEPOINT = BigInt(9)

# Generate X25519 key pair
function generate_keypair()
    # Generate random 32-byte private key
    private_key = rand(UInt8, 32)

    # Compute public key: X25519(k, 9)
    k = decode_scalar(private_key)
    public_key_int = x25519(k, BASEPOINT)
    public_key = encode_u_coordinate(public_key_int)

    return private_key, public_key
end

# Scalar multiplication with base point (9)
function scalar_base_mult(scalar::Vector{UInt8})
    k = decode_scalar(scalar)
    result = x25519(k, BASEPOINT)
    return encode_u_coordinate(result)
end

# Compute shared secret: X25519(k, u)
function compute_shared_secret(private_key::Vector{UInt8}, public_key::Vector{UInt8})
    k = decode_scalar(private_key)
    u = decode_u_coordinate(public_key)
    shared = x25519(k, u)
    return encode_u_coordinate(shared)
end

export generate_keypair, scalar_base_mult, compute_shared_secret, clamp_private_key!
export decode_scalar, decode_u_coordinate, encode_u_coordinate

end # module X25519