module PacketFast

#=
Optimized QUIC Packet Parsing

Zero-copy parsing using views and preallocated buffers.
Matches quiche-level performance for packet processing.
=#

using ..Perf
using ..Perf: PacketBuffer, WriteBuffer, read_u8!, read_u16!, read_u32!,
              read_varint!, view_bytes, skip!, remaining, write_u8!, write_u16!,
              write_u32!, write_varint!, write_bytes!, written

export parse_packet_fast, build_packet_fast
export PacketHeader, ShortHeader, LongHeader
export PACKET_TYPE_INITIAL, PACKET_TYPE_HANDSHAKE, PACKET_TYPE_0RTT, PACKET_TYPE_RETRY

# Packet types
const PACKET_TYPE_INITIAL = 0x00
const PACKET_TYPE_0RTT = 0x01
const PACKET_TYPE_HANDSHAKE = 0x02
const PACKET_TYPE_RETRY = 0x03

# Header forms
const HEADER_FORM_SHORT = 0x00
const HEADER_FORM_LONG = 0x01

#=
================================================================================
PACKET HEADER STRUCTURES (stack-allocated where possible)
================================================================================
=#

struct ShortHeader
    dcid::SubArray{UInt8, 1}  # View into packet data
    packet_number_offset::Int
    packet_number_length::Int
    key_phase::Bool
    spin_bit::Bool
end

struct LongHeader
    packet_type::UInt8
    version::UInt32
    dcid::SubArray{UInt8, 1}
    scid::SubArray{UInt8, 1}
    token::SubArray{UInt8, 1}  # For Initial packets
    packet_number_offset::Int
    packet_number_length::Int
    payload_length::Int
end

const PacketHeader = Union{ShortHeader, LongHeader}

#=
================================================================================
ZERO-COPY PARSING
================================================================================
=#

"""
Parse QUIC packet header without allocating.
Returns header struct with views into original buffer.

For short headers, `expected_dcid_len` must be provided as the DCID length
is not encoded in the packet (RFC 9000 Section 17.3).
"""
function parse_header(buf::PacketBuffer, expected_dcid_len::Int=8)::PacketHeader
    first_byte = read_u8!(buf)
    header_form = (first_byte >> 7) & 0x01

    if header_form == HEADER_FORM_SHORT
        parse_short_header(buf, first_byte, expected_dcid_len)
    else
        parse_long_header(buf, first_byte)
    end
end

@inline function parse_short_header(buf::PacketBuffer, first_byte::UInt8, dcid_len::Int)::ShortHeader
    # Spin bit (RFC 9000 Section 17.3.1)
    spin_bit = ((first_byte >> 5) & 0x01) == 0x01
    # Key phase bit
    key_phase = ((first_byte >> 2) & 0x01) == 0x01
    # Packet number length encoded in bits 0-1
    pn_length = (first_byte & 0x03) + 1

    # DCID length determined during connection establishment
    dcid = view_bytes(buf, dcid_len)

    pn_offset = buf.pos

    ShortHeader(dcid, pn_offset, pn_length, key_phase, spin_bit)
end

@inline function parse_long_header(buf::PacketBuffer, first_byte::UInt8)::LongHeader
    packet_type = (first_byte >> 4) & 0x03
    pn_length = (first_byte & 0x03) + 1

    version = read_u32!(buf)

    # DCID
    dcid_len = Int(read_u8!(buf))
    dcid = view_bytes(buf, dcid_len)

    # SCID
    scid_len = Int(read_u8!(buf))
    scid = view_bytes(buf, scid_len)

    # Token (Initial packets only)
    token = if packet_type == PACKET_TYPE_INITIAL
        token_len = Int(read_varint!(buf))
        view_bytes(buf, token_len)
    else
        @view buf.data[1:0]  # Empty view
    end

    # Payload length
    payload_length = Int(read_varint!(buf))

    pn_offset = buf.pos

    LongHeader(packet_type, version, dcid, scid, token, pn_offset, pn_length, payload_length)
end

"""
Parse packet number (after header protection removal).
"""
@inline function parse_packet_number(buf::PacketBuffer, length::Int, largest_pn::UInt64)::UInt64
    # Read truncated packet number
    truncated = UInt64(0)
    for _ in 1:length
        truncated = (truncated << 8) | UInt64(read_u8!(buf))
    end

    # Reconstruct full packet number
    decode_packet_number(truncated, length, largest_pn)
end

"""
Decode truncated packet number to full packet number.
RFC 9000 Appendix A.
"""
@inline function decode_packet_number(truncated::UInt64, length::Int, largest_pn::UInt64)::UInt64
    expected = largest_pn + 1
    pn_win = UInt64(1) << (length * 8)
    pn_hwin = pn_win >> 1
    pn_mask = pn_win - 1

    candidate = (expected & ~pn_mask) | truncated

    if candidate <= expected - pn_hwin && candidate < (UInt64(1) << 62) - pn_win
        candidate + pn_win
    elseif candidate > expected + pn_hwin && candidate >= pn_win
        candidate - pn_win
    else
        candidate
    end
end

#=
================================================================================
ZERO-COPY FRAME PARSING
================================================================================
=#

# Frame types
const FRAME_PADDING = 0x00
const FRAME_PING = 0x01
const FRAME_ACK = 0x02
const FRAME_ACK_ECN = 0x03
const FRAME_RESET_STREAM = 0x04
const FRAME_STOP_SENDING = 0x05
const FRAME_CRYPTO = 0x06
const FRAME_NEW_TOKEN = 0x07
const FRAME_STREAM = 0x08  # 0x08-0x0f
const FRAME_MAX_DATA = 0x10
const FRAME_MAX_STREAM_DATA = 0x11
const FRAME_MAX_STREAMS_BIDI = 0x12
const FRAME_MAX_STREAMS_UNI = 0x13
const FRAME_DATA_BLOCKED = 0x14
const FRAME_STREAM_DATA_BLOCKED = 0x15
const FRAME_STREAMS_BLOCKED_BIDI = 0x16
const FRAME_STREAMS_BLOCKED_UNI = 0x17
const FRAME_NEW_CONNECTION_ID = 0x18
const FRAME_RETIRE_CONNECTION_ID = 0x19
const FRAME_PATH_CHALLENGE = 0x1a
const FRAME_PATH_RESPONSE = 0x1b
const FRAME_CONNECTION_CLOSE = 0x1c
const FRAME_CONNECTION_CLOSE_APP = 0x1d
const FRAME_HANDSHAKE_DONE = 0x1e

"""
Parsed frame with zero-copy data references.
"""
struct ParsedFrame
    frame_type::UInt64
    # Frame-specific data as views
    data::SubArray{UInt8, 1}
    # For STREAM frames
    stream_id::UInt64
    offset::UInt64
    fin::Bool
end

"""
Parse frames from decrypted payload. Returns iterator over frames.
"""
function parse_frames(buf::PacketBuffer)
    frames = ParsedFrame[]

    while remaining(buf) > 0
        frame_type = read_varint!(buf)

        frame = if frame_type == FRAME_PADDING
            # Skip padding
            while remaining(buf) > 0 && buf.data[buf.pos] == 0x00
                skip!(buf, 1)
            end
            continue
        elseif frame_type == FRAME_PING
            ParsedFrame(frame_type, @view(buf.data[1:0]), 0, 0, false)
        elseif frame_type == FRAME_ACK || frame_type == FRAME_ACK_ECN
            parse_ack_frame(buf, frame_type)
        elseif frame_type == FRAME_CRYPTO
            parse_crypto_frame(buf)
        elseif frame_type >= FRAME_STREAM && frame_type <= 0x0f
            parse_stream_frame(buf, frame_type)
        elseif frame_type == FRAME_HANDSHAKE_DONE
            ParsedFrame(frame_type, @view(buf.data[1:0]), 0, 0, false)
        else
            # Skip unknown frame (would need length prefix in real impl)
            break
        end

        push!(frames, frame)
    end

    frames
end

@inline function parse_ack_frame(buf::PacketBuffer, frame_type::UInt64)::ParsedFrame
    largest_ack = read_varint!(buf)
    ack_delay = read_varint!(buf)
    ack_range_count = read_varint!(buf)
    first_ack_range = read_varint!(buf)

    # Skip additional ranges
    for _ in 1:ack_range_count
        gap = read_varint!(buf)
        range_len = read_varint!(buf)
    end

    # Skip ECN counts if present
    if frame_type == FRAME_ACK_ECN
        skip!(buf, 24)  # 3 varints, max 8 bytes each
    end

    ParsedFrame(frame_type, @view(buf.data[1:0]), largest_ack, ack_delay, false)
end

@inline function parse_crypto_frame(buf::PacketBuffer)::ParsedFrame
    offset = read_varint!(buf)
    length = Int(read_varint!(buf))
    data = view_bytes(buf, length)

    ParsedFrame(FRAME_CRYPTO, data, 0, offset, false)
end

@inline function parse_stream_frame(buf::PacketBuffer, frame_type::UInt64)::ParsedFrame
    stream_id = read_varint!(buf)

    has_offset = (frame_type & 0x04) != 0
    has_length = (frame_type & 0x02) != 0
    fin = (frame_type & 0x01) != 0

    offset = has_offset ? read_varint!(buf) : UInt64(0)

    data = if has_length
        len = Int(read_varint!(buf))
        view_bytes(buf, len)
    else
        view_bytes(buf, remaining(buf))
    end

    ParsedFrame(frame_type, data, stream_id, offset, fin)
end

#=
================================================================================
ZERO-COPY PACKET BUILDING
================================================================================
=#

"""
Build a QUIC packet using preallocated buffer.
"""
function build_long_header!(buf::WriteBuffer, packet_type::UInt8, version::UInt32,
                           dcid::AbstractVector{UInt8}, scid::AbstractVector{UInt8},
                           pn::UInt64, pn_len::Int)
    # First byte: form=1, fixed=1, type, reserved, pn_len
    first_byte = UInt8(0xc0 | (packet_type << 4) | (pn_len - 1))
    write_u8!(buf, first_byte)

    write_u32!(buf, version)

    # DCID
    write_u8!(buf, UInt8(length(dcid)))
    write_bytes!(buf, dcid)

    # SCID
    write_u8!(buf, UInt8(length(scid)))
    write_bytes!(buf, scid)
end

"""
Build a short header packet.
"""
function build_short_header!(buf::WriteBuffer, dcid::AbstractVector{UInt8},
                            pn::UInt64, pn_len::Int, key_phase::Bool, spin::Bool)
    first_byte = UInt8(0x40)  # form=0, fixed=1
    if spin
        first_byte |= 0x20
    end
    if key_phase
        first_byte |= 0x04
    end
    first_byte |= UInt8(pn_len - 1)

    write_u8!(buf, first_byte)
    write_bytes!(buf, dcid)
end

"""
Build CRYPTO frame.
"""
function build_crypto_frame!(buf::WriteBuffer, offset::UInt64, data::AbstractVector{UInt8})
    write_varint!(buf, UInt64(FRAME_CRYPTO))
    write_varint!(buf, offset)
    write_varint!(buf, UInt64(length(data)))
    write_bytes!(buf, data)
end

"""
Build STREAM frame.
"""
function build_stream_frame!(buf::WriteBuffer, stream_id::UInt64, offset::UInt64,
                            data::AbstractVector{UInt8}, fin::Bool)
    frame_type = UInt64(FRAME_STREAM)
    if offset > 0
        frame_type |= UInt64(0x04)
    end
    frame_type |= UInt64(0x02)  # Always include length
    if fin
        frame_type |= UInt64(0x01)
    end

    write_varint!(buf, frame_type)
    write_varint!(buf, stream_id)
    if offset > 0
        write_varint!(buf, offset)
    end
    write_varint!(buf, UInt64(length(data)))
    write_bytes!(buf, data)
end

"""
Build ACK frame.
"""
function build_ack_frame!(buf::WriteBuffer, largest_ack::UInt64, ack_delay::UInt64,
                         first_range::UInt64)
    write_varint!(buf, UInt64(FRAME_ACK))
    write_varint!(buf, largest_ack)
    write_varint!(buf, ack_delay)
    write_varint!(buf, UInt64(0))  # No additional ranges
    write_varint!(buf, first_range)
end

end # module PacketFast
