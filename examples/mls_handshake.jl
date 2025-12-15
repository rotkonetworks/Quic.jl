# MLS (Messaging Layer Security) Handshake Example
#
# Demonstrates QUIC-MLS key establishment per draft-tian-quic-quicmls.
# MLS replaces TLS 1.3 for key establishment, providing:
# - Forward secrecy through epoch-based key derivation
# - Post-compromise security via ratchet tree updates
# - Group key management for future multi-party QUIC

using Quic
using Quic.MLS

println("=" ^ 60)
println("QUIC-MLS Handshake Example")
println("=" ^ 60)

# Client identity (could be domain name, public key, etc.)
client_identity = Vector{UInt8}("client@example.com")
server_identity = Vector{UInt8}("server.example.com")

println("\n[1] Initialize client and server")
println("-" ^ 40)

# Create configurations
client_config = QuicMLSConfig(client_identity)
server_config = QuicMLSConfig(server_identity)

# Initialize client - this generates a KeyPackage
client = init_quic_mls_client(client_config)
println("Client initialized (state: KEY_PACKAGE ready)")

# Initialize server
server = init_quic_mls_server(server_config)
println("Server initialized (state: waiting for KeyPackage)")

# Step 2: Client sends KeyPackage to server
println("\n[2] Client → Server: KeyPackage")
println("-" ^ 40)

key_package_data = get_crypto_data_to_send(client)
println("KeyPackage size: $(length(key_package_data)) bytes")

# Server processes KeyPackage and generates Welcome
process_crypto_data(server, key_package_data)
println("Server received KeyPackage, created group")

# Step 3: Server sends Welcome to client
println("\n[3] Server → Client: Welcome")
println("-" ^ 40)

welcome_data = get_crypto_data_to_send(server)
println("Welcome size: $(length(welcome_data)) bytes")

# Client processes Welcome and joins group
process_crypto_data(client, welcome_data)
println("Client joined group")

# Step 4: Verify handshake complete
println("\n[4] Handshake Complete")
println("-" ^ 40)

if is_handshake_complete(client) && is_handshake_complete(server)
    println("Both sides established!")
else
    error("Handshake failed")
end

# Step 5: Get derived QUIC keys
println("\n[5] Derived QUIC Keys")
println("-" ^ 40)

client_keys = get_quic_keys(client)
server_keys = get_quic_keys(server)

println("Client key (hex): ", bytes2hex(client_keys.client_key[1:16]), "...")
println("Client IV (hex):  ", bytes2hex(client_keys.client_iv))
println("Server key (hex): ", bytes2hex(client_keys.server_key[1:16]), "...")
println("Server IV (hex):  ", bytes2hex(client_keys.server_iv))

# Verify both sides derived the same keys
if client_keys.client_key == server_keys.client_key &&
   client_keys.server_key == server_keys.server_key &&
   client_keys.client_iv == server_keys.client_iv &&
   client_keys.server_iv == server_keys.server_iv
    println("\nKeys and IVs match on both sides!")
else
    error("Key/IV mismatch!")
end

# Step 6: Demonstrate export_secret for application use
println("\n[6] Export Application Secret")
println("-" ^ 40)

app_label = "my-app-encryption"
app_context = Vector{UInt8}("session-123")
app_secret = export_secret(client, app_label, app_context, 32)
println("Exported secret (32 bytes): ", bytes2hex(app_secret[1:16]), "...")

println("\n" * "=" ^ 60)
println("MLS provides:")
println("  - Forward secrecy (epoch-based)")
println("  - Post-compromise security (ratchet tree)")
println("  - Group key management (multi-party ready)")
println("=" ^ 60)

# Demonstrate using keys for QUIC packet encryption
println("\n[7] Using Keys for QUIC Encryption")
println("-" ^ 40)

using Quic.Crypto

# Create a sample payload
plaintext = Vector{UInt8}("Hello from MLS-secured QUIC!")
packet_number = UInt64(1)
aad = UInt8[0x00, 0x01, 0x02, 0x03]  # Associated authenticated data (QUIC header)

# Encrypt using client key (client → server)
# The function XORs IV with packet_number internally per RFC 9001
ciphertext = Crypto.encrypt_chacha20_poly1305(
    plaintext,
    client_keys.client_key,
    client_keys.client_iv,
    packet_number,
    aad
)
println("Plaintext:  \"$(String(plaintext))\"")
println("Ciphertext: $(length(ciphertext)) bytes (includes 16-byte auth tag)")

# Decrypt on server side using same key (keys are identical on both sides)
decrypted = Crypto.decrypt_chacha20_poly1305(
    ciphertext,
    client_keys.client_key,  # Server uses client_key to decrypt client messages
    client_keys.client_iv,
    packet_number,
    aad
)
println("Decrypted:  \"$(String(decrypted))\"")

if plaintext == decrypted
    println("\nEncryption/decryption successful!")
end

println("\n" * "=" ^ 60)
println("Example complete - MLS keys successfully used for QUIC encryption")
println("=" ^ 60)
