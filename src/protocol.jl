module Protocol

using CRC32c

# quic wire format constants
const QUIC_VERSION_1 = 0x00000001
const MAX_PACKET_SIZE = 1200
const MAX_STREAM_DATA_BUFFER = 65536
const INITIAL_RTT_NS = 100_000_000

# packet types
const PACKET_INITIAL = 0x00
const PACKET_0RTT = 0x01
const PACKET_HANDSHAKE = 0x02
const PACKET_RETRY = 0x03
const PACKET_SHORT = 0x40

# frame types
const FRAME_PADDING = 0x00
const FRAME_PING = 0x01
const FRAME_ACK = 0x02
const FRAME_ACK_ECN = 0x03
const FRAME_RESET_STREAM = 0x04
const FRAME_STOP_SENDING = 0x05
const FRAME_CRYPTO = 0x06
const FRAME_NEW_TOKEN = 0x07
const FRAME_STREAM = 0x08  # base, OR with bits for fin(0x01), len(0x02), off(0x04)
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
const FRAME_APPLICATION_CLOSE = 0x1d
const FRAME_HANDSHAKE_DONE = 0x1e
const FRAME_DATAGRAM = 0x30
const FRAME_DATAGRAM_LEN = 0x31

struct VarInt
    value::UInt64
    VarInt(v::Integer) = v < 2^62 ? new(UInt64(v)) : error("VarInt overflow")
end

# encode varint to buffer
function encode_varint!(buf::Vector{UInt8}, v::VarInt)
    val = v.value
    if val < 64
        push!(buf, UInt8(val))
    elseif val < 16384
        push!(buf, UInt8(0x40 | (val >> 8)))
        push!(buf, UInt8(val & 0xff))
    elseif val < 2^30
        push!(buf, UInt8(0x80 | (val >> 24)))
        push!(buf, UInt8((val >> 16) & 0xff))
        push!(buf, UInt8((val >> 8) & 0xff))
        push!(buf, UInt8(val & 0xff))
    else
        push!(buf, UInt8(0xc0 | (val >> 56)))
        for i in 6:-1:0
            push!(buf, UInt8((val >> (i*8)) & 0xff))
        end
    end
end

# decode varint from buffer
function decode_varint(buf::AbstractVector{UInt8}, pos::Int=1)
    isempty(buf) && return nothing, pos
    
    first = buf[pos]
    len = ((first & 0xc0) >> 6)
    
    if len == 0
        return VarInt(first & 0x3f), pos + 1
    elseif len == 1
        pos + 1 > length(buf) && return nothing, pos
        val = ((first & 0x3f) << 8) | buf[pos + 1]
        return VarInt(val), pos + 2
    elseif len == 2
        pos + 3 > length(buf) && return nothing, pos
        val = ((first & 0x3f) << 24) | (buf[pos + 1] << 16) | 
              (buf[pos + 2] << 8) | buf[pos + 3]
        return VarInt(val), pos + 4
    else
        pos + 7 > length(buf) && return nothing, pos
        val = ((first & 0x3f) << 56)
        for i in 1:7
            val |= UInt64(buf[pos + i]) << ((7 - i) * 8)
        end
        return VarInt(val), pos + 8
    end
end

export VarInt, encode_varint!, decode_varint
export QUIC_VERSION_1, MAX_PACKET_SIZE
export PACKET_INITIAL, PACKET_SHORT, PACKET_HANDSHAKE
export FRAME_PADDING, FRAME_PING, FRAME_ACK, FRAME_STREAM, FRAME_CRYPTO

end # module Protocol
