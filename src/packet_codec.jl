module PacketCodec

using ..Protocol
using ..Packet
using ..Frame
using ..Crypto

# Packet number encoding - variable length (1-4 bytes)
function encode_packet_number(pn::UInt64, largest_acked::UInt64)
    # determine truncation based on largest acknowledged
    num_unacked = pn - largest_acked

    if num_unacked < (1 << 7)
        # 1 byte encoding
        return UInt8[pn & 0x7f], 1
    elseif num_unacked < (1 << 14)
        # 2 byte encoding
        return UInt8[(pn >> 8) & 0x3f | 0x80, pn & 0xff], 2
    elseif num_unacked < (1 << 30)
        # 4 byte encoding
        return UInt8[
            (pn >> 24) & 0xff | 0xc0,
            (pn >> 16) & 0xff,
            (pn >> 8) & 0xff,
            pn & 0xff
        ], 4
    else
        # 4 byte encoding (max)
        return UInt8[
            (pn >> 24) & 0xff | 0xc0,
            (pn >> 16) & 0xff,
            (pn >> 8) & 0xff,
            pn & 0xff
        ], 4
    end
end

# Decode packet number from truncated representation
function decode_packet_number(truncated::Vector{UInt8}, pn_nbits::Int, expected_pn::UInt64)
    pn_win = UInt64(1) << pn_nbits
    pn_hwin = pn_win >> 1
    pn_mask = pn_win - 1

    # reconstruct packet number
    candidate_pn = (expected_pn & ~pn_mask) | (truncated_to_int(truncated) & pn_mask)

    if candidate_pn <= expected_pn - pn_hwin && candidate_pn < (UInt64(1) << 62) - pn_win
        return candidate_pn + pn_win
    elseif candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win
        return candidate_pn - pn_win
    else
        return candidate_pn
    end
end

function truncated_to_int(bytes::Vector{UInt8})
    result = UInt64(0)
    for b in bytes
        result = (result << 8) | b
    end
    return result
end

# Parse QUIC packet header
function parse_packet_header(data::Vector{UInt8}, dcid_len::Int=8)
    if isempty(data)
        return nothing
    end

    pos = 1
    first_byte = data[pos]
    pos += 1

    is_long_header = (first_byte & 0x80) != 0

    if is_long_header
        return parse_long_header(data, pos, first_byte)
    else
        return parse_short_header(data, pos, first_byte, dcid_len)
    end
end

function parse_long_header(data::Vector{UInt8}, pos::Int, first_byte::UInt8)
    if length(data) < pos + 4
        return nothing
    end

    # packet type from first byte
    packet_type = (first_byte >> 4) & 0x03

    # version (4 bytes)
    version = UInt32(0)
    for i in 0:3
        version = (version << 8) | data[pos + i]
    end
    pos += 4

    # destination connection ID
    dcid_len = data[pos]
    pos += 1

    if length(data) < pos + dcid_len
        return nothing
    end

    dcid = data[pos:pos + dcid_len - 1]
    pos += dcid_len

    # source connection ID
    scid_len = data[pos]
    pos += 1

    if length(data) < pos + scid_len
        return nothing
    end

    scid = data[pos:pos + scid_len - 1]
    pos += scid_len

    # type-specific data
    if packet_type == 0x00  # Initial
        # token length
        token_len, pos = decode_varint(data, pos)
        if token_len === nothing
            return nothing
        end

        token = data[pos:pos + token_len.value - 1]
        pos += token_len.value

        # packet length
        pkt_len, pos = decode_varint(data, pos)
        if pkt_len === nothing
            return nothing
        end

        return (
            type = :initial,
            version = version,
            dcid = dcid,
            scid = scid,
            token = token,
            length = pkt_len.value,
            header_len = pos - 1,
            pn_offset = pos
        )
    elseif packet_type == 0x01  # 0-RTT
        # packet length
        pkt_len, pos = decode_varint(data, pos)

        return (
            type = :zero_rtt,
            version = version,
            dcid = dcid,
            scid = scid,
            length = pkt_len.value,
            header_len = pos - 1,
            pn_offset = pos
        )
    elseif packet_type == 0x02  # Handshake
        # packet length
        pkt_len, pos = decode_varint(data, pos)

        return (
            type = :handshake,
            version = version,
            dcid = dcid,
            scid = scid,
            length = pkt_len.value,
            header_len = pos - 1,
            pn_offset = pos
        )
    elseif packet_type == 0x03  # Retry
        # retry has no packet number or length
        return (
            type = :retry,
            version = version,
            dcid = dcid,
            scid = scid,
            retry_token = data[pos:end-16],  # everything except integrity tag
            integrity_tag = data[end-15:end]
        )
    end

    return nothing
end

function parse_short_header(data::Vector{UInt8}, pos::Int, first_byte::UInt8, dcid_len::Int)
    if length(data) < pos + dcid_len
        return nothing
    end

    # fixed bit must be set
    if (first_byte & 0x40) == 0
        return nothing
    end

    # destination connection ID
    dcid = data[pos:pos + dcid_len - 1]
    pos += dcid_len

    # packet number length from first byte (before header protection removal)
    pn_len = ((first_byte & 0x03) + 1)

    return (
        type = :short,
        dcid = dcid,
        header_len = pos - 1,
        pn_offset = pos,
        pn_len = pn_len,
        key_phase = (first_byte & 0x04) != 0
    )
end

# Parse frames from decrypted packet payload
function parse_frames(data::Vector{UInt8})
    frames = QuicFrame[]
    pos = 1

    while pos <= length(data)
        frame, new_pos = parse_frame(data, pos)

        if frame === nothing
            break
        end

        push!(frames, frame)
        pos = new_pos
    end

    return frames
end

function parse_frame(data::Vector{UInt8}, pos::Int)
    if pos > length(data)
        return nothing, pos
    end

    frame_type = data[pos]
    pos += 1

    if frame_type == FRAME_PADDING
        # padding frames are single bytes
        return PaddingFrame(), pos

    elseif frame_type == FRAME_PING
        return PingFrame(), pos

    elseif frame_type == FRAME_ACK || frame_type == FRAME_ACK_ECN
        largest, pos = decode_varint(data, pos)
        delay, pos = decode_varint(data, pos)
        range_count, pos = decode_varint(data, pos)
        first_range, pos = decode_varint(data, pos)

        ranges = Vector{@NamedTuple{gap::UInt64, length::UInt64}}()
        for i in 1:range_count.value
            gap, pos = decode_varint(data, pos)
            len, pos = decode_varint(data, pos)
            push!(ranges, (gap = gap.value, length = len.value))
        end

        ecn_counts = nothing
        if frame_type == FRAME_ACK_ECN
            ect0, pos = decode_varint(data, pos)
            ect1, pos = decode_varint(data, pos)
            ce, pos = decode_varint(data, pos)
            ecn_counts = (ect0 = ect0.value, ect1 = ect1.value, ce = ce.value)
        end

        return AckFrame(
            largest.value,
            delay.value,
            first_range.value,
            ranges,
            ecn_counts
        ), pos

    elseif (frame_type & 0xf8) == FRAME_STREAM
        stream_id, pos = decode_varint(data, pos)

        offset = UInt64(0)
        if (frame_type & 0x04) != 0
            off, pos = decode_varint(data, pos)
            offset = off.value
        end

        if (frame_type & 0x02) != 0
            # length present
            len, pos = decode_varint(data, pos)
            stream_data = data[pos:pos + len.value - 1]
            pos += len.value
        else
            # extends to end of packet
            stream_data = data[pos:end]
            pos = length(data) + 1
        end

        fin = (frame_type & 0x01) != 0

        return StreamFrame(stream_id.value, offset, stream_data, fin), pos

    elseif frame_type == FRAME_CRYPTO
        offset, pos = decode_varint(data, pos)
        len, pos = decode_varint(data, pos)
        crypto_data = data[pos:pos + len.value - 1]
        pos += len.value

        return CryptoFrame(offset.value, crypto_data), pos

    elseif frame_type == FRAME_MAX_DATA
        max_data, pos = decode_varint(data, pos)
        return MaxDataFrame(max_data.value), pos

    elseif frame_type == FRAME_MAX_STREAM_DATA
        stream_id, pos = decode_varint(data, pos)
        max_data, pos = decode_varint(data, pos)
        return MaxStreamDataFrame(stream_id.value, max_data.value), pos

    elseif frame_type == FRAME_CONNECTION_CLOSE || frame_type == FRAME_APPLICATION_CLOSE
        error_code, pos = decode_varint(data, pos)

        if frame_type == FRAME_CONNECTION_CLOSE
            frame_type_triggered, pos = decode_varint(data, pos)
            reason_len, pos = decode_varint(data, pos)
            reason = String(data[pos:pos + reason_len.value - 1])
            pos += reason_len.value

            return ConnectionCloseFrame(error_code.value, frame_type_triggered.value, reason), pos
        else
            reason_len, pos = decode_varint(data, pos)
            reason = String(data[pos:pos + reason_len.value - 1])
            pos += reason_len.value

            return ApplicationCloseFrame(error_code.value, reason), pos
        end

    else
        # unknown frame type - skip
        return nothing, pos
    end
end

export encode_packet_number, decode_packet_number
export parse_packet_header, parse_frames

end # module PacketCodec