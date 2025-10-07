module CertGenerator

using ..Ed25519
using Dates
using Base64

# Generate Ed25519 certificate using OpenSSL command line
function generate_ed25519_cert(keypair::Ed25519.KeyPair; cn::String="QuicNet-Julia")
    # Create temp directory for cert generation
    tmpdir = mktempdir()

    try
        # Write private key in PKCS8 PEM format
        privkey_path = joinpath(tmpdir, "private.pem")
        cert_path = joinpath(tmpdir, "cert.pem")

        # Create PKCS8 private key (simplified - would need proper ASN.1 encoding)
        # For now, use openssl to generate a new Ed25519 key and cert

        # Generate Ed25519 key and self-signed cert using OpenSSL
        cmd = `openssl req -new -x509 -key /dev/stdin -sha256 -nodes -days 365 -subj "/CN=$cn" -keyform DER -outform PEM -out $cert_path -keyout $privkey_path -newkey ED25519`

        # Alternative: generate using openssl command line directly
        run(`openssl genpkey -algorithm ED25519 -out $privkey_path`)
        run(`openssl req -new -x509 -key $privkey_path -sha256 -nodes -days 365 -subj "/CN=$cn" -out $cert_path`)

        # Read generated certificate
        cert_pem = read(cert_path, String)
        privkey_pem = read(privkey_path, String)

        return (cert_pem, privkey_pem)
    finally
        rm(tmpdir, recursive=true, force=true)
    end
end

# Generate certificate with existing Ed25519 keypair
function generate_cert_from_keypair(keypair::Ed25519.KeyPair; cn::String="QuicNet-Julia")
    tmpdir = mktempdir()

    try
        # We need to create a PKCS8 DER representation of our Ed25519 key
        # This is complex, so for now we'll use a workaround

        # Create a config file for OpenSSL
        config_path = joinpath(tmpdir, "openssl.cnf")
        open(config_path, "w") do f
            write(f, """
            [ req ]
            default_bits = 2048
            prompt = no
            distinguished_name = req_distinguished_name
            x509_extensions = v3_ca

            [ req_distinguished_name ]
            CN = $cn

            [ v3_ca ]
            basicConstraints = CA:FALSE
            keyUsage = digitalSignature, keyAgreement
            """)
        end

        # For actual implementation, we'd need to properly encode the keypair
        # For now, generate a new key-cert pair
        privkey_path = joinpath(tmpdir, "key.pem")
        cert_path = joinpath(tmpdir, "cert.pem")

        # Generate new Ed25519 key and cert
        run(`openssl genpkey -algorithm ED25519 -out $privkey_path`)
        run(`openssl req -new -x509 -key $privkey_path -days 365 -config $config_path -out $cert_path`)

        cert_pem = read(cert_path, String)
        privkey_pem = read(privkey_path, String)

        return (cert_pem, privkey_pem)
    finally
        rm(tmpdir, recursive=true, force=true)
    end
end

# Parse PEM certificate to extract public key
function extract_pubkey_from_cert(cert_pem::String)
    tmpdir = mktempdir()

    try
        cert_path = joinpath(tmpdir, "cert.pem")
        open(cert_path, "w") do f
            write(f, cert_pem)
        end

        # Extract public key using OpenSSL
        pubkey_pem = read(`openssl x509 -in $cert_path -pubkey -noout`, String)

        # Extract the base64 encoded part
        lines = split(pubkey_pem, '\n')
        pubkey_b64 = join(filter(l -> !startswith(l, "-----"), lines))
        pubkey_der = base64decode(pubkey_b64)

        # Ed25519 public key is the last 32 bytes of the DER structure
        if length(pubkey_der) >= 32
            return pubkey_der[end-31:end]
        else
            error("Invalid public key format")
        end
    finally
        rm(tmpdir, recursive=true, force=true)
    end
end

export generate_ed25519_cert, generate_cert_from_keypair, extract_pubkey_from_cert

end # module