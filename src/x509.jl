module X509

using ..Ed25519
using Random
using SHA
using Dates

# ASN.1 DER encoding helpers
function der_length(len::Int)
    if len < 128
        return [UInt8(len)]
    elseif len < 256
        return [0x81, UInt8(len)]
    elseif len < 65536
        return [0x82, UInt8(len >> 8), UInt8(len & 0xff)]
    else
        error("Length too large for simple DER encoding")
    end
end

function der_sequence(contents::Vector{UInt8})
    return vcat(0x30, der_length(length(contents)), contents)
end

function der_integer(value::Vector{UInt8})
    # Add leading zero if high bit is set (to ensure positive)
    if length(value) > 0 && value[1] & 0x80 != 0
        value = vcat(0x00, value)
    end
    return vcat(0x02, der_length(length(value)), value)
end

function der_integer(value::Int)
    bytes = UInt8[]
    v = value
    while v > 0
        pushfirst!(bytes, UInt8(v & 0xff))
        v >>= 8
    end
    if isempty(bytes)
        bytes = [0x00]
    end
    return der_integer(bytes)
end

function der_bit_string(bits::Vector{UInt8})
    # First byte is number of unused bits (0 for byte-aligned)
    return vcat(0x03, der_length(length(bits) + 1), 0x00, bits)
end

function der_octet_string(octets::Vector{UInt8})
    return vcat(0x04, der_length(length(octets)), octets)
end

function der_object_identifier(oid::String)
    # Common OIDs
    oids = Dict(
        "1.2.840.10045.4.3.3" => [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03],  # Ed25519
        "1.3.101.112" => [0x06, 0x03, 0x2b, 0x65, 0x70],  # Ed25519 key
        "2.5.4.3" => [0x06, 0x03, 0x55, 0x04, 0x03],  # commonName
        "2.5.4.6" => [0x06, 0x03, 0x55, 0x04, 0x06],  # countryName
        "2.5.4.10" => [0x06, 0x03, 0x55, 0x04, 0x0a],  # organizationName
    )
    return get(oids, oid, [0x06, 0x00])  # Return empty OID if not found
end

function der_utf8_string(str::String)
    bytes = Vector{UInt8}(str)
    return vcat(0x0c, der_length(length(bytes)), bytes)
end

function der_time(timestamp::Float64)
    # Use UTCTime for dates before 2050
    dt = Dates.unix2datetime(timestamp)
    time_str = Dates.format(dt, "yymmddHHMMSS") * "Z"
    bytes = Vector{UInt8}(time_str)
    return vcat(0x17, der_length(length(bytes)), bytes)
end

# Build X.509v3 certificate for Ed25519
function generate_x509_certificate(keypair::Ed25519.KeyPair;
                                  subject_cn::String="QuicNet",
                                  issuer_cn::String="QuicNet",
                                  serial::Int=rand(1:1000000),
                                  validity_days::Int=365)

    # Certificate version (v3 = 2)
    version = der_sequence(vcat(
        0xa0, 0x03,  # Context tag [0]
        der_integer(2)
    ))

    # Serial number
    serial_number = der_integer(serial)

    # Signature algorithm (Ed25519)
    sig_algorithm = der_sequence([
        0x06, 0x03, 0x2b, 0x65, 0x70  # OID for Ed25519
    ])

    # Issuer name
    issuer = der_sequence(
        der_sequence(vcat(
            der_object_identifier("2.5.4.3"),
            der_utf8_string(issuer_cn)
        ))
    )

    # Validity period
    now = time()
    not_before = der_time(now)
    not_after = der_time(now + validity_days * 24 * 60 * 60)
    validity = der_sequence(vcat(not_before, not_after))

    # Subject name
    subject = der_sequence(
        der_sequence(vcat(
            der_object_identifier("2.5.4.3"),
            der_utf8_string(subject_cn)
        ))
    )

    # Subject public key info
    public_key_info = der_sequence(vcat(
        # Algorithm identifier
        der_sequence([0x06, 0x03, 0x2b, 0x65, 0x70]),  # Ed25519 OID
        # Public key
        der_bit_string(keypair.public_key)
    ))

    # Extensions (v3)
    # Basic Constraints: CA:FALSE
    basic_constraints = der_sequence(vcat(
        der_object_identifier("2.5.29.19"),  # OID for basic constraints
        der_octet_string(der_sequence([0x01, 0x01, 0x00]))  # CA:FALSE
    ))

    # Key Usage: Digital Signature, Key Agreement
    key_usage = der_sequence(vcat(
        der_object_identifier("2.5.29.15"),  # OID for key usage
        der_octet_string(der_bit_string([0x88]))  # Digital signature + key agreement
    ))

    extensions = vcat(
        0xa3, der_length(length(der_sequence(vcat(basic_constraints, key_usage)))),
        der_sequence(vcat(basic_constraints, key_usage))
    )

    # Build TBS (To Be Signed) certificate
    tbs_certificate = der_sequence(vcat(
        version,
        serial_number,
        sig_algorithm,
        issuer,
        validity,
        subject,
        public_key_info
        # extensions  # Skip for simplicity
    ))

    # Sign the TBS certificate
    signature = Ed25519.sign(tbs_certificate, keypair)

    # Build complete certificate
    certificate = der_sequence(vcat(
        tbs_certificate,
        sig_algorithm,
        der_bit_string(signature)
    ))

    return certificate
end

# Generate certificate chain (just self-signed for now)
function generate_certificate_chain(keypair::Ed25519.KeyPair; kwargs...)
    cert = generate_x509_certificate(keypair; kwargs...)
    return [cert]  # Single self-signed certificate
end

# Extract public key from certificate (simplified)
function extract_public_key(cert::Vector{UInt8})
    # This is a simplified extraction - real implementation would parse ASN.1
    # Look for Ed25519 public key (32 bytes) after the public key algorithm OID
    ed25519_oid = [0x2b, 0x65, 0x70]

    for i in 1:length(cert)-35
        if cert[i:i+2] == ed25519_oid
            # Public key typically follows within next ~10 bytes
            for j in i+3:min(i+15, length(cert)-32)
                if cert[j] == 0x03 && cert[j+1] == 0x21 && cert[j+2] == 0x00
                    # Found bit string of length 32
                    return cert[j+3:j+34]
                end
            end
        end
    end

    error("Could not extract Ed25519 public key from certificate")
end

export generate_x509_certificate, generate_certificate_chain, extract_public_key

end # module