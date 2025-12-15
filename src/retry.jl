module Retry

using ..Protocol
using ..Packet
using ..Crypto
using SHA
using MbedTLS

# QUIC Retry Integrity Tag key and nonce
const RETRY_KEY_V1 = hex2bytes("be0c690b9f66575a1d766b54e368c84e")
const RETRY_NONCE_V1 = hex2bytes("461599d35d632bf2239825bb")

# Generate a retry token
function generate_retry_token(client_addr::Vector{UInt8}, dcid::ConnectionId)
    # Token contains:
    # - timestamp (8 bytes)
    # - client address (variable)
    # - original destination connection ID

    token = UInt8[]

    # timestamp (microseconds since epoch)
    timestamp = time_ns() ÷ 1000
    append!(token, reinterpret(UInt8, [hton(timestamp)]))

    # client address length and data
    push!(token, UInt8(length(client_addr)))
    append!(token, client_addr)

    # original DCID
    push!(token, UInt8(length(dcid)))
    append!(token, dcid.data)

    # add HMAC for integrity
    hmac = MbedTLS.digest(MbedTLS.MD_SHA256, token, RETRY_KEY_V1)
    append!(token, hmac[1:16])  # truncate to 16 bytes

    return token
end

# Validate a retry token
function validate_retry_token(token::Vector{UInt8}, client_addr::Vector{UInt8}, max_age_seconds::Int=30)
    if length(token) < 25  # minimum: 8 (timestamp) + 1 (addr len) + 16 (HMAC)
        return false, nothing
    end

    # extract HMAC
    data_len = length(token) - 16
    token_data = token[1:data_len]
    token_hmac = token[data_len+1:end]

    # verify HMAC
    expected_hmac = MbedTLS.digest(MbedTLS.MD_SHA256, token_data, RETRY_KEY_V1)
    if token_hmac != expected_hmac[1:16]
        return false, nothing
    end

    # parse token
    pos = 1

    # timestamp
    timestamp_bytes = token_data[pos:pos+7]
    timestamp = ntoh(reinterpret(UInt64, timestamp_bytes)[1])
    pos += 8

    # check age
    current_time = time_ns() ÷ 1000
    if current_time - timestamp > max_age_seconds * 1_000_000
        return false, nothing
    end

    # client address
    addr_len = token_data[pos]
    pos += 1

    if pos + addr_len - 1 > data_len
        return false, nothing
    end

    stored_addr = token_data[pos:pos+addr_len-1]
    pos += addr_len

    # verify address matches
    if stored_addr != client_addr
        return false, nothing
    end

    # original DCID
    dcid_len = token_data[pos]
    pos += 1

    if pos + dcid_len - 1 > data_len
        return false, nothing
    end

    original_dcid = ConnectionId(token_data[pos:pos+dcid_len-1])

    return true, original_dcid
end

# Create a Retry packet
function create_retry_packet(scid::ConnectionId, dcid::ConnectionId,
                            odcid::ConnectionId, token::Vector{UInt8})
    buf = UInt8[]

    # Retry packet header (long header with type 3)
    push!(buf, 0xf0 | (rand(UInt8) & 0x0f))  # long header, type=3, random unused bits

    # version
    append!(buf, reinterpret(UInt8, [hton(QUIC_VERSION_1)]))

    # destination CID (client's source CID)
    push!(buf, UInt8(length(dcid)))
    append!(buf, dcid.data)

    # source CID (server's new CID)
    push!(buf, UInt8(length(scid)))
    append!(buf, scid.data)

    # retry token
    append!(buf, token)

    # compute retry integrity tag
    tag = compute_retry_integrity_tag(buf, odcid)
    append!(buf, tag)

    return buf
end

# Compute Retry Integrity Tag (per RFC 9001)
function compute_retry_integrity_tag(retry_pseudo_packet::Vector{UInt8}, odcid::ConnectionId)
    # Build pseudo packet for tag computation
    pseudo = UInt8[]

    # original destination connection ID length
    push!(pseudo, UInt8(length(odcid)))

    # original destination connection ID
    append!(pseudo, odcid.data)

    # retry packet without tag
    append!(pseudo, retry_pseudo_packet)

    # compute AES-128-GCM tag
    cipher = MbedTLS.Cipher(MbedTLS.CIPHER_AES_128_GCM)
    MbedTLS.set_key!(cipher, RETRY_KEY_V1, MbedTLS.ENCRYPT)
    MbedTLS.set_iv!(cipher, RETRY_NONCE_V1)

    # use pseudo packet as AAD
    MbedTLS.update_ad!(cipher, pseudo)

    # no payload to encrypt
    ciphertext = Vector{UInt8}(undef, 0)
    MbedTLS.update!(cipher, UInt8[], ciphertext)

    # get authentication tag
    tag = Vector{UInt8}(undef, 16)
    MbedTLS.finish!(cipher, tag)

    return tag
end

# Verify Retry packet integrity
function verify_retry_integrity_tag(retry_packet::Vector{UInt8}, odcid::ConnectionId)
    if length(retry_packet) < 16
        return false
    end

    # extract tag from end of packet
    packet_without_tag = retry_packet[1:end-16]
    received_tag = retry_packet[end-15:end]

    # compute expected tag
    expected_tag = compute_retry_integrity_tag(packet_without_tag, odcid)

    return received_tag == expected_tag
end

# Handle retry packet in connection
function handle_retry(conn, retry_packet::Vector{UInt8}, header)
    # verify integrity tag
    if !verify_retry_integrity_tag(retry_packet, conn.initial_dcid)
        println("Retry packet integrity check failed")
        return false
    end

    println(" Retry packet verified")

    # update connection state
    conn.remote_cid = ConnectionId(header.scid)
    conn.retry_token = header.retry_token

    # reset packet numbers
    conn.next_send_pn = PacketNumber()
    conn.next_recv_pn = PacketNumber()

    # clear sent packets
    empty!(conn.sent_packets)

    # restart handshake with token
    return true
end

export generate_retry_token, validate_retry_token
export create_retry_packet, verify_retry_integrity_tag
export handle_retry

end # module Retry