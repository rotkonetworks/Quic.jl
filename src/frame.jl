module Frame

using ..Protocol

abstract type QuicFrame end

# Core frames
struct PaddingFrame <: QuicFrame end

struct PingFrame <: QuicFrame end

struct AckFrame <: QuicFrame
    largest::UInt64
    delay::UInt64
    first_range::UInt64
    ranges::Vector{@NamedTuple{gap::UInt64, length::UInt64}}
    ecn_counts::Union{Nothing, @NamedTuple{ect0::UInt64, ect1::UInt64, ce::UInt64}}
end

# Stream frames
struct StreamFrame <: QuicFrame
    stream_id::UInt64
    offset::UInt64
    data::Vector{UInt8}
    fin::Bool
end

struct ResetStreamFrame <: QuicFrame
    stream_id::UInt64
    error_code::UInt64
    final_size::UInt64
end

struct StopSendingFrame <: QuicFrame
    stream_id::UInt64
    error_code::UInt64
end

struct StreamDataBlockedFrame <: QuicFrame
    stream_id::UInt64
    limit::UInt64
end

# Crypto frame
struct CryptoFrame <: QuicFrame
    offset::UInt64
    data::Vector{UInt8}
end

# Connection management frames
struct ConnectionCloseFrame <: QuicFrame
    error_code::UInt64
    frame_type::UInt8
    reason::String
end

struct ApplicationCloseFrame <: QuicFrame
    error_code::UInt64
    reason::String
end

struct HandshakeDoneFrame <: QuicFrame end

# Flow control frames
struct MaxDataFrame <: QuicFrame
    max_data::UInt64
end

struct MaxStreamDataFrame <: QuicFrame
    stream_id::UInt64
    max_data::UInt64
end

struct MaxStreamsFrame <: QuicFrame
    max_streams::UInt64
    is_bidi::Bool
end

struct DataBlockedFrame <: QuicFrame
    limit::UInt64
end

struct StreamsBlockedFrame <: QuicFrame
    limit::UInt64
    is_bidi::Bool
end

# Connection ID frames
struct NewConnectionIdFrame <: QuicFrame
    sequence::UInt64
    retire_prior_to::UInt64
    connection_id::Vector{UInt8}
    stateless_reset_token::Vector{UInt8}  # 16 bytes
end

struct RetireConnectionIdFrame <: QuicFrame
    sequence::UInt64
end

# Path frames
struct PathChallengeFrame <: QuicFrame
    data::Vector{UInt8}  # 8 bytes
end

struct PathResponseFrame <: QuicFrame
    data::Vector{UInt8}  # 8 bytes
end

# Token frame
struct NewTokenFrame <: QuicFrame
    token::Vector{UInt8}
end

# Datagram frames (RFC 9221)
struct DatagramFrame <: QuicFrame
    data::Vector{UInt8}
    length_present::Bool
end

# encode frame to buffer
function encode_frame!(buf::Vector{UInt8}, frame::QuicFrame)
    if frame isa PaddingFrame
        push!(buf, FRAME_PADDING)

    elseif frame isa PingFrame
        push!(buf, FRAME_PING)

    elseif frame isa AckFrame
        type_byte = frame.ecn_counts !== nothing ? FRAME_ACK_ECN : FRAME_ACK
        push!(buf, type_byte)
        encode_varint!(buf, VarInt(frame.largest))
        encode_varint!(buf, VarInt(frame.delay))
        encode_varint!(buf, VarInt(length(frame.ranges)))
        encode_varint!(buf, VarInt(frame.first_range))

        for range in frame.ranges
            encode_varint!(buf, VarInt(range.gap))
            encode_varint!(buf, VarInt(range.length))
        end

        if frame.ecn_counts !== nothing
            encode_varint!(buf, VarInt(frame.ecn_counts.ect0))
            encode_varint!(buf, VarInt(frame.ecn_counts.ect1))
            encode_varint!(buf, VarInt(frame.ecn_counts.ce))
        end

    elseif frame isa StreamFrame
        type_byte = FRAME_STREAM
        frame.fin && (type_byte |= 0x01)
        true && (type_byte |= 0x02)  # length bit always set
        frame.offset > 0 && (type_byte |= 0x04)

        push!(buf, type_byte)
        encode_varint!(buf, VarInt(frame.stream_id))

        if frame.offset > 0
            encode_varint!(buf, VarInt(frame.offset))
        end

        encode_varint!(buf, VarInt(length(frame.data)))
        append!(buf, frame.data)

    elseif frame isa ResetStreamFrame
        push!(buf, FRAME_RESET_STREAM)
        encode_varint!(buf, VarInt(frame.stream_id))
        encode_varint!(buf, VarInt(frame.error_code))
        encode_varint!(buf, VarInt(frame.final_size))

    elseif frame isa StopSendingFrame
        push!(buf, FRAME_STOP_SENDING)
        encode_varint!(buf, VarInt(frame.stream_id))
        encode_varint!(buf, VarInt(frame.error_code))

    elseif frame isa CryptoFrame
        push!(buf, FRAME_CRYPTO)
        encode_varint!(buf, VarInt(frame.offset))
        encode_varint!(buf, VarInt(length(frame.data)))
        append!(buf, frame.data)

    elseif frame isa NewTokenFrame
        push!(buf, FRAME_NEW_TOKEN)
        encode_varint!(buf, VarInt(length(frame.token)))
        append!(buf, frame.token)

    elseif frame isa MaxDataFrame
        push!(buf, FRAME_MAX_DATA)
        encode_varint!(buf, VarInt(frame.max_data))

    elseif frame isa MaxStreamDataFrame
        push!(buf, FRAME_MAX_STREAM_DATA)
        encode_varint!(buf, VarInt(frame.stream_id))
        encode_varint!(buf, VarInt(frame.max_data))

    elseif frame isa MaxStreamsFrame
        type_byte = frame.is_bidi ? FRAME_MAX_STREAMS_BIDI : FRAME_MAX_STREAMS_UNI
        push!(buf, type_byte)
        encode_varint!(buf, VarInt(frame.max_streams))

    elseif frame isa DataBlockedFrame
        push!(buf, FRAME_DATA_BLOCKED)
        encode_varint!(buf, VarInt(frame.limit))

    elseif frame isa StreamDataBlockedFrame
        push!(buf, FRAME_STREAM_DATA_BLOCKED)
        encode_varint!(buf, VarInt(frame.stream_id))
        encode_varint!(buf, VarInt(frame.limit))

    elseif frame isa StreamsBlockedFrame
        type_byte = frame.is_bidi ? FRAME_STREAMS_BLOCKED_BIDI : FRAME_STREAMS_BLOCKED_UNI
        push!(buf, type_byte)
        encode_varint!(buf, VarInt(frame.limit))

    elseif frame isa NewConnectionIdFrame
        push!(buf, FRAME_NEW_CONNECTION_ID)
        encode_varint!(buf, VarInt(frame.sequence))
        encode_varint!(buf, VarInt(frame.retire_prior_to))
        push!(buf, UInt8(length(frame.connection_id)))
        append!(buf, frame.connection_id)
        append!(buf, frame.stateless_reset_token)

    elseif frame isa RetireConnectionIdFrame
        push!(buf, FRAME_RETIRE_CONNECTION_ID)
        encode_varint!(buf, VarInt(frame.sequence))

    elseif frame isa PathChallengeFrame
        push!(buf, FRAME_PATH_CHALLENGE)
        append!(buf, frame.data[1:8])

    elseif frame isa PathResponseFrame
        push!(buf, FRAME_PATH_RESPONSE)
        append!(buf, frame.data[1:8])

    elseif frame isa ConnectionCloseFrame
        push!(buf, FRAME_CONNECTION_CLOSE)
        encode_varint!(buf, VarInt(frame.error_code))
        encode_varint!(buf, VarInt(frame.frame_type))
        encode_varint!(buf, VarInt(length(frame.reason)))
        append!(buf, Vector{UInt8}(frame.reason))

    elseif frame isa ApplicationCloseFrame
        push!(buf, FRAME_APPLICATION_CLOSE)
        encode_varint!(buf, VarInt(frame.error_code))
        encode_varint!(buf, VarInt(length(frame.reason)))
        append!(buf, Vector{UInt8}(frame.reason))

    elseif frame isa HandshakeDoneFrame
        push!(buf, FRAME_HANDSHAKE_DONE)

    elseif frame isa DatagramFrame
        type_byte = frame.length_present ? FRAME_DATAGRAM_LEN : FRAME_DATAGRAM
        push!(buf, type_byte)
        if frame.length_present
            encode_varint!(buf, VarInt(length(frame.data)))
        end
        append!(buf, frame.data)
    end
end

export QuicFrame, PaddingFrame, PingFrame, AckFrame, StreamFrame, CryptoFrame
export ResetStreamFrame, StopSendingFrame, StreamDataBlockedFrame
export ConnectionCloseFrame, ApplicationCloseFrame, HandshakeDoneFrame
export MaxDataFrame, MaxStreamDataFrame, MaxStreamsFrame
export DataBlockedFrame, StreamsBlockedFrame
export NewConnectionIdFrame, RetireConnectionIdFrame
export PathChallengeFrame, PathResponseFrame
export NewTokenFrame, DatagramFrame
export encode_frame!

end # module Frame
