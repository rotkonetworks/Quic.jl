module PacketReceiver

using ..Protocol
using ..Packet
using ..Frame
using ..Stream
using ..Crypto
using ..PacketCodec
using ..VersionNegotiation
using ..Retry
using ..ConnectionModule
using ..LossDetection
using ..X25519
using SHA

# Process incoming QUIC packet
function process_incoming_packet(conn::ConnectionModule.Connection, data::Vector{UInt8}, addr)
    # check for version negotiation
    if VersionNegotiation.is_version_negotiation_packet(data)
        return handle_version_negotiation(conn, data)
    end

    # parse packet header
    header = PacketCodec.parse_packet_header(data, length(conn.local_cid))

    if header === nothing
        println("Failed to parse packet header")
        return nothing
    end

    # handle based on packet type
    if header.type == :retry
        return handle_retry_packet(conn, header, data)
    elseif header.type == :initial
        return handle_initial_packet(conn, header, data)
    elseif header.type == :handshake
        return handle_handshake_packet(conn, header, data)
    elseif header.type == :short
        return handle_short_packet(conn, header, data)
    elseif header.type == :zero_rtt
        return handle_zero_rtt_packet(conn, header, data)
    end
end

# Handle version negotiation packet
function handle_version_negotiation(conn::ConnectionModule.Connection, data::Vector{UInt8})
    vn_data = VersionNegotiation.parse_version_negotiation(data)

    if vn_data === nothing
        return nothing
    end

    println("Received version negotiation with versions: $(vn_data.versions)")

    # choose compatible version
    chosen_version = VersionNegotiation.choose_version(vn_data.versions)

    if chosen_version === nothing
        error("No compatible QUIC version found")
    end

    println("Selected version: 0x$(string(chosen_version, base=16))")

    # would restart connection with new version
    return (:version_negotiation, chosen_version)
end

# Handle retry packet
function handle_retry_packet(conn::ConnectionModule.Connection, header, data::Vector{UInt8})
    println("📦 Processing Retry packet")

    # verify integrity tag
    if !Retry.verify_retry_integrity_tag(data, conn.initial_dcid)
        println("❌ Retry packet integrity check failed")
        return nothing
    end

    println("✅ Retry packet integrity verified")

    # update connection state
    conn.remote_cid = ConnectionId(header.scid)
    conn.retry_token = header.retry_token

    println("   New server CID: $(bytes2hex(conn.remote_cid.data))")
    println("   Retry token length: $(length(conn.retry_token)) bytes")

    # reset packet numbers for new attempt
    conn.next_send_pn = PacketNumber()
    conn.next_recv_pn = PacketNumber()

    # clear sent packets
    empty!(conn.sent_packets)

    # derive new initial keys with new DCID
    derive_initial_secrets!(conn.crypto, conn.remote_cid.data)

    # restart handshake with retry token
    println("🔄 Restarting handshake with retry token...")

    # resend ClientHello with token
    if conn.is_client
        restart_handshake_with_token(conn)
    end

    return (:retry, conn.retry_token)
end

# Restart handshake after retry
function restart_handshake_with_token(conn::ConnectionModule.Connection)
    # update handshake state
    conn.handshake.state = :initial

    # create new Initial packet with token
    crypto_frame = start_client_handshake(conn.handshake, conn.remote_cid, conn.local_cid,
                                         conn.remote_addr.host)

    # send with retry token (needs to be added to packet)
    send_initial_with_token(conn, crypto_frame)
end

# Send Initial packet with retry token
function send_initial_with_token(conn::ConnectionModule.Connection, frame::QuicFrame)
    buf = UInt8[]

    # long header for initial packet
    push!(buf, PACKET_INITIAL | 0xc0)
    append!(buf, reinterpret(UInt8, [hton(QUIC_VERSION_1)]))

    # connection IDs
    push!(buf, UInt8(length(conn.remote_cid)))
    append!(buf, conn.remote_cid.data)
    push!(buf, UInt8(length(conn.local_cid)))
    append!(buf, conn.local_cid.data)

    # retry token
    encode_varint!(buf, VarInt(length(conn.retry_token)))
    append!(buf, conn.retry_token)

    # length placeholder
    length_offset = length(buf) + 1
    encode_varint!(buf, VarInt(0))

    header_len = length(buf)

    # packet number
    pn = next!(conn.next_send_pn)
    pn_offset = length(buf) + 1
    push!(buf, UInt8((pn >> 8) & 0xff), UInt8(pn & 0xff))

    # encode frame
    payload = UInt8[]
    encode_frame!(payload, frame)

    # encrypt payload
    if !isempty(conn.crypto.initial_secrets)
        key = conn.crypto.initial_secrets[:client_key]
        iv = conn.crypto.initial_secrets[:client_iv]
        hp_key = conn.crypto.initial_secrets[:client_hp]

        header_bytes = buf[1:header_len + 2]
        encrypted = encrypt_payload(conn.crypto, payload, key, iv, pn, header_bytes)

        append!(buf, encrypted)

        # update length field
        payload_length = 2 + length(encrypted)
        length_bytes = encode_varint_bytes(VarInt(payload_length))
        buf[length_offset:length_offset + length(length_bytes) - 1] = length_bytes

        # apply header protection
        if length(encrypted) >= 20
            sample_offset = pn_offset + 2 + 4
            sample = buf[sample_offset:sample_offset + 15]
            protect_header!(conn.crypto, @view(buf[1:pn_offset + 1]), hp_key, sample, pn_offset, 2)
        end
    end

    # send packet
    if conn.remote_addr !== nothing
        send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, buf)
        println("📤 Sent Initial packet with retry token ($(length(buf)) bytes)")
    end

    # track sent packet
    conn.sent_packets[pn] = (time=time_ns(), data=copy(buf))
    conn.bytes_in_flight += length(buf)
end

# Handle initial packet
function handle_initial_packet(conn::ConnectionModule.Connection, header, data::Vector{UInt8})
    println("Processing Initial packet")

    # remove header protection if we have keys
    if !isempty(conn.crypto.initial_secrets)
        # determine which keys to use
        if conn.is_client
            hp_key = conn.crypto.initial_secrets[:server_hp]
            key = conn.crypto.initial_secrets[:server_key]
            iv = conn.crypto.initial_secrets[:server_iv]
        else
            hp_key = conn.crypto.initial_secrets[:client_hp]
            key = conn.crypto.initial_secrets[:client_key]
            iv = conn.crypto.initial_secrets[:client_iv]
        end

        # get sample for header protection (4 bytes after assumed packet number)
        sample_offset = header.pn_offset + 4
        if length(data) >= sample_offset + 16
            sample = data[sample_offset:sample_offset + 15]

            # remove header protection
            pn_len = (data[1] & 0x03) + 1
            unprotect_header!(conn.crypto, data, hp_key, sample, header.pn_offset, pn_len)

            # decode packet number
            pn_bytes = data[header.pn_offset:header.pn_offset + pn_len - 1]
            packet_number = PacketCodec.decode_packet_number(
                pn_bytes, pn_len * 8,
                conn.next_recv_pn.value
            )

            # update expected packet number
            if packet_number >= conn.next_recv_pn.value
                conn.next_recv_pn.value = packet_number + 1
            end

            # decrypt payload
            payload_offset = header.pn_offset + pn_len
            encrypted_payload = data[payload_offset:end]

            # build AAD (header including packet number)
            aad = data[1:payload_offset - 1]

            try
                decrypted = decrypt_payload(conn.crypto, encrypted_payload, key, iv, packet_number, aad)

                # parse frames from decrypted payload
                frames = PacketCodec.parse_frames(decrypted)

                println("Decrypted $(length(frames)) frames from Initial packet")

                # process frames
                for frame in frames
                    process_frame(conn, frame, :initial)
                end

                return (:initial, frames)
            catch e
                println("Failed to decrypt Initial packet: $e")
                return nothing
            end
        end
    else
        println("No keys available for Initial packet decryption")
    end

    return nothing
end

# Handle handshake packet
function handle_handshake_packet(conn::ConnectionModule.Connection, header, data::Vector{UInt8})
    println("Processing Handshake packet")

    # need handshake keys
    if !isempty(conn.handshake.handshake_keys)
        # similar to initial packet processing but with handshake keys
        # (implementation needed)
    end

    return (:handshake, nothing)
end

# Handle short header (1-RTT) packet
function handle_short_packet(conn::ConnectionModule.Connection, header, data::Vector{UInt8})
    println("Processing 1-RTT packet")

    # need application keys
    if !isempty(conn.handshake.application_keys)
        # similar processing with application keys
        # (implementation needed)
    end

    return (:short, nothing)
end

# Handle 0-RTT packet
function handle_zero_rtt_packet(conn::ConnectionModule.Connection, header, data::Vector{UInt8})
    println("Processing 0-RTT packet")

    # need 0-RTT keys from session resumption
    # (implementation needed)

    return (:zero_rtt, nothing)
end

# Process individual frame
function process_frame(conn::ConnectionModule.Connection, frame::QuicFrame, packet_type::Symbol)
    if frame isa CryptoFrame
        println("CRYPTO frame at offset $(frame.offset), $(length(frame.data)) bytes")

        # process TLS handshake messages
        if packet_type == :initial && conn.is_client
            # expecting ServerHello or other handshake messages
            process_tls_messages(conn, frame.data)
        end
    elseif frame isa AckFrame
        println("ACK frame, largest: $(frame.largest)")
        # determine packet space based on packet type
        space = if packet_type == :initial
            LDInitial
        elseif packet_type == :handshake
            LDHandshake
        else
            LDApplication
        end
        ConnectionModule.process_ack_frame(conn, frame, space)
    elseif frame isa PaddingFrame
        # ignore padding
    elseif frame isa StreamFrame
        println("STREAM frame, ID: $(frame.stream_id), offset: $(frame.offset), data: $(length(frame.data)) bytes")
        # Handle stream data
        if haskey(conn.streams, frame.stream_id)
            stream_state = conn.streams[frame.stream_id]
            # Add data to receive buffer
            append!(stream_state.recv_buf, frame.data)
            stream_state.recv_offset += length(frame.data)
            if frame.fin
                stream_state.fin_recv = true
            end
        else
            # Create new stream state for incoming stream
            sid = Stream.StreamId(frame.stream_id, :client, :bidi)  # assume client-initiated bidi
            stream_state = Stream.StreamState(sid)
            append!(stream_state.recv_buf, frame.data)
            stream_state.recv_offset += length(frame.data)
            if frame.fin
                stream_state.fin_recv = true
            end
            conn.streams[frame.stream_id] = stream_state
        end

        # Process as HTTP/3 data if HTTP/3 is enabled
        if !isempty(frame.data)
            ConnectionModule.process_http3_data!(conn, frame.stream_id, frame.data)
        end
    elseif frame isa PingFrame
        # should respond with ACK
        println("PING frame received")
    elseif frame isa ConnectionCloseFrame
        println("Connection closed: $(frame.reason)")
        conn.closing = true
    elseif frame isa NewConnectionIdFrame
        println("NEW_CONNECTION_ID frame, seq: $(frame.sequence)")
        ConnectionModule.process_new_connection_id!(conn, frame)
    elseif frame isa RetireConnectionIdFrame
        println("RETIRE_CONNECTION_ID frame, seq: $(frame.sequence)")
        ConnectionModule.process_retire_connection_id!(conn, frame)
    elseif frame isa PathChallengeFrame
        println("PATH_CHALLENGE frame: $(bytes2hex(frame.data))")
        # Respond with PATH_RESPONSE
        response = PathResponseFrame(frame.data)
        ConnectionModule.queue_frame!(conn, response, PacketCoalescing.Application)
        ConnectionModule.flush_packets!(conn)
    elseif frame isa PathResponseFrame
        println("PATH_RESPONSE frame: $(bytes2hex(frame.data))")
        # Validate path challenge response (implementation needed)
    else
        println("Received frame type: $(typeof(frame))")
    end
end

# Process TLS handshake messages
function process_tls_messages(conn::ConnectionModule.Connection, data::Vector{UInt8})
    pos = 1

    while pos <= length(data)
        if pos + 4 > length(data)
            break
        end

        # parse TLS message header
        msg_type = data[pos]
        msg_len = (UInt32(data[pos + 1]) << 16) | (UInt32(data[pos + 2]) << 8) | data[pos + 3]
        pos += 4

        if pos + msg_len - 1 > length(data)
            println("Incomplete TLS message")
            break
        end

        msg_data = data[pos:pos + msg_len - 1]
        pos += msg_len

        # handle based on message type
        if msg_type == 0x02  # ServerHello
            println("Received ServerHello")
            process_server_hello(conn, msg_data)
        elseif msg_type == 0x08  # EncryptedExtensions
            println("Received EncryptedExtensions")
        elseif msg_type == 0x0b  # Certificate
            println("Received Certificate")
        elseif msg_type == 0x0f  # CertificateVerify
            println("Received CertificateVerify")
        elseif msg_type == 0x14  # Finished
            println("Received Finished")
            conn.handshake.state = :completed
            conn.connected = true
        else
            println("Unknown TLS message type: 0x$(string(msg_type, base=16))")
        end
    end
end

# Process ServerHello
function process_server_hello(conn::ConnectionModule.Connection, data::Vector{UInt8})
    if length(data) < 35
        println("ServerHello too short")
        return
    end

    # extract server random
    conn.handshake.server_random = data[3:34]

    # parse rest of ServerHello
    pos = 35

    # session ID
    if pos > length(data)
        return
    end

    sid_len = data[pos]
    pos += 1 + sid_len

    # cipher suite
    if pos + 1 > length(data)
        return
    end

    cipher_suite = (UInt16(data[pos]) << 8) | data[pos + 1]
    pos += 2

    println("Server selected cipher suite: 0x$(string(cipher_suite, base=16))")

    # compression method (should be 0)
    if pos > length(data)
        return
    end
    pos += 1

    # extensions length
    if pos + 1 > length(data)
        return
    end

    ext_len = (UInt16(data[pos]) << 8) | data[pos + 1]
    pos += 2

    # parse extensions
    ext_end = pos + ext_len - 1
    server_key_share = nothing

    while pos < ext_end && pos + 3 < length(data)
        ext_type = (UInt16(data[pos]) << 8) | data[pos + 1]
        ext_data_len = (UInt16(data[pos + 2]) << 8) | data[pos + 3]
        pos += 4

        if ext_type == 0x0033  # key_share
            # parse server key share
            if pos + 3 < length(data)
                group = (UInt16(data[pos]) << 8) | data[pos + 1]
                key_len = (UInt16(data[pos + 2]) << 8) | data[pos + 3]
                pos += 4

                if group == 0x001d && pos + key_len - 1 <= length(data)  # x25519
                    server_key_share = data[pos:pos + key_len - 1]
                    println("Server X25519 public key: $(bytes2hex(server_key_share))")
                end
            end
            pos += ext_data_len - 4
        else
            pos += ext_data_len
        end
    end

    # update cipher suite
    conn.handshake.cipher_suite = cipher_suite

    # compute ECDHE shared secret if we have server's key share
    if server_key_share !== nothing && !isempty(conn.handshake.ecdhe_secret)
        shared_secret = X25519.compute_shared_secret(conn.handshake.ecdhe_secret, server_key_share)
        println("ECDHE shared secret computed: $(bytes2hex(shared_secret[1:16]))...")

        # derive handshake keys with proper TLS 1.3 key schedule
        derive_handshake_keys!(conn, shared_secret)
    else
        println("Missing key share for ECDHE")
    end
end

# Derive handshake keys with ECDHE shared secret
function derive_handshake_keys!(conn::ConnectionModule.Connection, shared_secret::Vector{UInt8})
    hs = conn.handshake

    # TLS 1.3 key schedule
    # 1. Extract early secret (0 for initial handshake)
    early_secret = hkdf_extract(zeros(UInt8, 32), zeros(UInt8, 32))

    # 2. Derive handshake secret from ECDHE
    handshake_secret = hkdf_extract(shared_secret,
                                   hkdf_expand_label(early_secret, "derived", sha256(UInt8[]), 32))

    # 3. Calculate transcript hash up to ServerHello
    transcript = UInt8[]
    if !isempty(hs.messages)
        # ClientHello
        append!(transcript, hs.messages[1])
    end
    # Would add ServerHello here
    transcript_hash = sha256(transcript)

    # 4. Derive traffic secrets
    client_hs_traffic = hkdf_expand_label(handshake_secret, "c hs traffic", transcript_hash, 32)
    server_hs_traffic = hkdf_expand_label(handshake_secret, "s hs traffic", transcript_hash, 32)

    # 5. Select cipher suite parameters
    if hs.cipher_suite == 0x1303  # TLS_CHACHA20_POLY1305_SHA256
        conn.crypto.cipher_suite = ChaCha20Poly1305()
        key_len = 32
    elseif hs.cipher_suite == 0x1302  # TLS_AES_256_GCM_SHA384
        conn.crypto.cipher_suite = AES256GCM()
        key_len = 32
    else  # 0x1301 TLS_AES_128_GCM_SHA256
        conn.crypto.cipher_suite = AES128GCM()
        key_len = 16
    end

    # 6. Derive QUIC keys and IVs
    hs.handshake_keys[:client_key] = hkdf_expand_label(client_hs_traffic, "quic key", UInt8[], key_len)
    hs.handshake_keys[:client_iv] = hkdf_expand_label(client_hs_traffic, "quic iv", UInt8[], 12)
    hs.handshake_keys[:client_hp] = hkdf_expand_label(client_hs_traffic, "quic hp", UInt8[], key_len)

    hs.handshake_keys[:server_key] = hkdf_expand_label(server_hs_traffic, "quic key", UInt8[], key_len)
    hs.handshake_keys[:server_iv] = hkdf_expand_label(server_hs_traffic, "quic iv", UInt8[], 12)
    hs.handshake_keys[:server_hp] = hkdf_expand_label(server_hs_traffic, "quic hp", UInt8[], key_len)

    println("✅ Derived handshake keys for cipher suite 0x$(string(hs.cipher_suite, base=16))")
    println("   Client key: $(bytes2hex(hs.handshake_keys[:client_key][1:16]))...")
    println("   Server key: $(bytes2hex(hs.handshake_keys[:server_key][1:16]))...")

    # Update handshake state
    hs.state = :wait_ee  # waiting for EncryptedExtensions
end

# Process ACK frame
function process_ack(conn::ConnectionModule.Connection, ack::AckFrame)
    # mark packets as acknowledged
    for pn in ack.largest - ack.first_range + 1:ack.largest
        if haskey(conn.sent_packets, pn)
            delete!(conn.sent_packets, pn)
            # update congestion control
            # (implementation needed)
        end
    end

    # process additional ACK ranges
    current = ack.largest - ack.first_range - 1

    for range in ack.ranges
        current -= range.gap + 1
        for pn in current - range.length + 1:current
            if haskey(conn.sent_packets, pn)
                delete!(conn.sent_packets, pn)
            end
        end
        current -= range.length
    end
end

export process_incoming_packet, process_frame

end # module PacketReceiver