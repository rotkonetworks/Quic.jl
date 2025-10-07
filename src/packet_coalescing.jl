module PacketCoalescing

using ..Protocol
using ..Packet
using ..Frame
using ..Crypto
using ..PacketCodec

# Maximum UDP payload size for coalescing
const MAX_UDP_PAYLOAD = 1200

# Packet space types
@enum PacketSpace Initial Handshake Application

# Pending packet to be coalesced
mutable struct PendingPacket
    space::PacketSpace
    frames::Vector{QuicFrame}
    pn::UInt64
    header_data::Vector{UInt8}

    PendingPacket(space::PacketSpace, pn::UInt64) = new(space, QuicFrame[], pn, UInt8[])
end

# Packet coalescer state
mutable struct PacketCoalescer
    pending_packets::Vector{PendingPacket}
    current_size::Int
    max_size::Int

    PacketCoalescer(max_size::Int = MAX_UDP_PAYLOAD) = new(PendingPacket[], 0, max_size)
end

# Add a frame to be sent
function add_frame!(coalescer::PacketCoalescer, space::PacketSpace, frame::QuicFrame, pn::UInt64)
    # find or create packet for this space
    packet = nothing
    for p in coalescer.pending_packets
        if p.space == space && p.pn == pn
            packet = p
            break
        end
    end

    if packet === nothing
        packet = PendingPacket(space, pn)
        push!(coalescer.pending_packets, packet)
    end

    push!(packet.frames, frame)
end

# Estimate size of a packet when serialized
function estimate_packet_size(packet::PendingPacket, crypto_overhead::Int = 16)
    # estimate header size based on packet space
    header_size = if packet.space == Initial
        # long header + version + CIDs + token + length + packet number
        1 + 4 + 2 + 16 + 4 + 2 + 2  # rough estimate
    elseif packet.space == Handshake
        # long header + version + CIDs + length + packet number
        1 + 4 + 2 + 16 + 2 + 2
    else  # Application
        # short header + CID + packet number
        1 + 8 + 2
    end

    # estimate payload size
    payload_size = 0
    for frame in packet.frames
        payload_size += estimate_frame_size(frame)
    end

    return header_size + payload_size + crypto_overhead
end

# Estimate frame size
function estimate_frame_size(frame::QuicFrame)
    if frame isa PaddingFrame
        return 1
    elseif frame isa PingFrame
        return 1
    elseif frame isa AckFrame
        return 8 + length(frame.ranges) * 4  # rough estimate
    elseif frame isa StreamFrame
        return 8 + length(frame.data)  # type + stream_id + offset + length + data
    elseif frame isa CryptoFrame
        return 8 + length(frame.data)  # type + offset + length + data
    elseif frame isa MaxDataFrame
        return 9  # type + varint(max_data)
    elseif frame isa MaxStreamDataFrame
        return 17  # type + varint(stream_id) + varint(max_data)
    elseif frame isa ConnectionCloseFrame
        return 16 + length(frame.reason)
    else
        return 16  # conservative estimate
    end
end

# Check if we can add more frames
function can_add_frame(coalescer::PacketCoalescer, space::PacketSpace, frame::QuicFrame, pn::UInt64)
    # create temporary packet to estimate size
    temp_packet = PendingPacket(space, pn)
    push!(temp_packet.frames, frame)

    frame_size = estimate_packet_size(temp_packet)
    return coalescer.current_size + frame_size <= coalescer.max_size
end

# Build coalesced packet
function build_coalesced_packet(coalescer::PacketCoalescer, conn)
    if isempty(coalescer.pending_packets)
        return UInt8[]
    end

    datagram = UInt8[]

    # sort packets by priority (Initial, Handshake, Application)
    sort!(coalescer.pending_packets, by = p -> Int(p.space))

    for packet in coalescer.pending_packets
        packet_data = build_single_packet(packet, conn)

        # check if this packet fits
        if length(datagram) + length(packet_data) > coalescer.max_size
            # pad previous packet if needed
            if !isempty(datagram) && packet.space != Application
                padding_needed = min(coalescer.max_size - length(datagram), 100)
                if padding_needed > 0
                    append!(datagram, zeros(UInt8, padding_needed))
                end
            end
            break
        end

        append!(datagram, packet_data)
    end

    # clear pending packets
    empty!(coalescer.pending_packets)
    coalescer.current_size = 0

    return datagram
end

# Build a single packet
function build_single_packet(packet::PendingPacket, conn)
    buf = UInt8[]

    # build header based on packet space
    if packet.space == Initial
        build_initial_header!(buf, conn, packet.pn)
    elseif packet.space == Handshake
        build_handshake_header!(buf, conn, packet.pn)
    else  # Application
        build_short_header!(buf, conn, packet.pn)
    end

    header_len = length(buf)

    # encode all frames into payload
    payload = UInt8[]
    for frame in packet.frames
        encode_frame!(payload, frame)
    end

    # add padding if needed for Initial/Handshake packets
    if packet.space == Initial || packet.space == Handshake
        min_payload_size = 128
        while length(payload) < min_payload_size
            push!(payload, FRAME_PADDING)
        end
    end

    # encrypt payload
    encrypted_payload = encrypt_packet_payload(payload, packet.space, conn, packet.pn, buf[1:header_len])
    append!(buf, encrypted_payload)

    # update length field for long headers
    if packet.space == Initial || packet.space == Handshake
        update_length_field!(buf, length(encrypted_payload))
    end

    # apply header protection
    apply_header_protection!(buf, packet.space, conn, header_len)

    return buf
end

# Build Initial packet header
function build_initial_header!(buf::Vector{UInt8}, conn, pn::UInt64)
    # long header with Initial type
    push!(buf, PACKET_INITIAL | 0xc0)

    # version
    append!(buf, reinterpret(UInt8, [hton(QUIC_VERSION_1)]))

    # destination CID
    push!(buf, UInt8(length(conn.remote_cid)))
    append!(buf, conn.remote_cid.data)

    # source CID
    push!(buf, UInt8(length(conn.local_cid)))
    append!(buf, conn.local_cid.data)

    # token (retry token or empty)
    encode_varint!(buf, VarInt(length(conn.retry_token)))
    append!(buf, conn.retry_token)

    # length placeholder (will be updated)
    encode_varint!(buf, VarInt(0))

    # packet number
    append!(buf, encode_packet_number_bytes(pn))
end

# Build Handshake packet header
function build_handshake_header!(buf::Vector{UInt8}, conn, pn::UInt64)
    # long header with Handshake type
    push!(buf, PACKET_HANDSHAKE | 0xc0)

    # version
    append!(buf, reinterpret(UInt8, [hton(QUIC_VERSION_1)]))

    # destination CID
    push!(buf, UInt8(length(conn.remote_cid)))
    append!(buf, conn.remote_cid.data)

    # source CID
    push!(buf, UInt8(length(conn.local_cid)))
    append!(buf, conn.local_cid.data)

    # length placeholder
    encode_varint!(buf, VarInt(0))

    # packet number
    append!(buf, encode_packet_number_bytes(pn))
end

# Build Short (1-RTT) packet header
function build_short_header!(buf::Vector{UInt8}, conn, pn::UInt64)
    # short header with spin bit
    push!(buf, PACKET_SHORT | 0x40)  # fixed bit

    # destination CID
    append!(buf, conn.remote_cid.data)

    # packet number
    append!(buf, encode_packet_number_bytes(pn))
end

# Encode packet number as 2 bytes (simplified)
function encode_packet_number_bytes(pn::UInt64)
    return [UInt8((pn >> 8) & 0xff), UInt8(pn & 0xff)]
end

# Encrypt packet payload based on space
function encrypt_packet_payload(payload::Vector{UInt8}, space::PacketSpace, conn, pn::UInt64, header::Vector{UInt8})
    # select appropriate keys
    keys = if space == Initial
        conn.crypto.initial_secrets
    elseif space == Handshake
        conn.handshake.handshake_keys
    else  # Application
        conn.handshake.application_keys
    end

    if isempty(keys)
        # no encryption available, return as-is (should not happen)
        return payload
    end

    # get encryption keys for this direction
    if conn.is_client
        key = keys[:client_key]
        iv = keys[:client_iv]
    else
        key = keys[:server_key]
        iv = keys[:server_iv]
    end

    return encrypt_payload(conn.crypto, payload, key, iv, pn, header)
end

# Apply header protection
function apply_header_protection!(buf::Vector{UInt8}, space::PacketSpace, conn, header_len::Int)
    # select header protection key
    keys = if space == Initial
        conn.crypto.initial_secrets
    elseif space == Handshake
        conn.handshake.handshake_keys
    else
        conn.handshake.application_keys
    end

    if isempty(keys)
        return
    end

    hp_key = if conn.is_client
        keys[:client_hp]
    else
        keys[:server_hp]
    end

    # get sample from payload (4 bytes after packet number)
    sample_offset = header_len + 2 + 4  # header + pn (2 bytes) + 4 bytes into payload
    if length(buf) >= sample_offset + 16
        sample = buf[sample_offset:sample_offset + 15]
        pn_offset = header_len + 1  # start of packet number
        protect_header!(conn.crypto, buf, hp_key, sample, pn_offset, 2)
    end
end

# Update length field in long header
function update_length_field!(buf::Vector{UInt8}, payload_length::Int)
    # find length field position (after CIDs and token for Initial)
    # this is simplified - real implementation needs proper parsing
    # for now, assume it's at a fixed offset
    length_offset = length(buf) - payload_length - 4  # rough estimate
    if length_offset > 0 && length_offset < length(buf) - 2
        length_bytes = encode_varint_bytes(VarInt(payload_length + 2))  # +2 for packet number
        # would update the length field here
    end
end

# Flush all pending packets
function flush!(coalescer::PacketCoalescer, conn)
    if isempty(coalescer.pending_packets)
        return UInt8[]
    end

    return build_coalesced_packet(coalescer, conn)
end

# Add padding to reach minimum size
function add_padding!(coalescer::PacketCoalescer, space::PacketSpace, pn::UInt64, target_size::Int)
    current_est = sum(estimate_packet_size(p) for p in coalescer.pending_packets)
    padding_needed = max(0, target_size - current_est)

    if padding_needed > 0
        # create padding frames
        while padding_needed > 0
            add_frame!(coalescer, space, PaddingFrame(), pn)
            padding_needed -= 1
        end
    end
end

export PacketCoalescer, PacketSpace, PendingPacket
export add_frame!, can_add_frame, flush!, add_padding!
export Initial, Handshake, Application

end # module PacketCoalescing