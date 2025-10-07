module Stream

using ..Protocol

struct StreamId
    value::UInt64
    
    function StreamId(id::Integer, initiator::Symbol, direction::Symbol)
        val = UInt64(id) << 2
        initiator == :server && (val |= 0x01)
        direction == :uni && (val |= 0x02)
        new(val)
    end
end

is_client_initiated(sid::StreamId) = (sid.value & 0x01) == 0
is_bidirectional(sid::StreamId) = (sid.value & 0x02) == 0
stream_index(sid::StreamId) = sid.value >> 2

mutable struct StreamState
    id::StreamId
    send_buf::Vector{UInt8}
    recv_buf::Vector{UInt8}
    send_offset::UInt64
    recv_offset::UInt64
    max_send_offset::UInt64
    max_recv_offset::UInt64
    fin_sent::Bool
    fin_recv::Bool
    reset::Bool
end

function StreamState(id::StreamId)
    StreamState(id, UInt8[], UInt8[], 0, 0, 
                MAX_STREAM_DATA_BUFFER, MAX_STREAM_DATA_BUFFER,
                false, false, false)
end

# write data to stream
function write_stream!(s::StreamState, data::Vector{UInt8}, fin::Bool=false)
    available = s.max_send_offset - s.send_offset
    to_write = min(length(data), available)
    
    if to_write > 0
        append!(s.send_buf, @view data[1:to_write])
        s.send_offset += to_write
    end
    
    if fin && to_write == length(data)
        s.fin_sent = true
    end
    
    return to_write
end

# read data from stream
function read_stream!(s::StreamState, max_bytes::Int)
    to_read = min(length(s.recv_buf), max_bytes)
    if to_read == 0
        return UInt8[], s.fin_recv
    end
    
    data = s.recv_buf[1:to_read]
    s.recv_buf = s.recv_buf[to_read+1:end]
    return data, s.fin_recv && isempty(s.recv_buf)
end

export StreamId, StreamState, write_stream!, read_stream!
export is_client_initiated, is_bidirectional, stream_index

end # module Stream
