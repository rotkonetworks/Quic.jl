module Transport

using ..Protocol
using ..Stream
using ..Frame

mutable struct TransportConfig
    max_idle_timeout_ms::UInt64
    initial_rtt_ms::UInt64
    max_datagram_size::UInt64
    initial_max_data::UInt64
    initial_max_stream_data::UInt64
    max_concurrent_streams_bidi::UInt64
    max_concurrent_streams_uni::UInt64
    ack_delay_exponent::UInt8
    max_ack_delay_ms::UInt64
    disable_active_migration::Bool

    function TransportConfig()
        new(30000, 100, 1200, 10485760, 1048576, 100, 100, 3, 25, false)
    end
end

# Flow control state
mutable struct FlowController
    # connection-level flow control
    max_data::UInt64
    data_sent::UInt64
    data_received::UInt64
    max_data_peer::UInt64

    # stream limits
    max_streams_bidi::UInt64
    max_streams_uni::UInt64
    streams_opened_bidi::UInt64
    streams_opened_uni::UInt64

    # per-stream flow control windows
    stream_windows::Dict{UInt64, @NamedTuple{max_data::UInt64, data_sent::UInt64, data_received::UInt64}}

    FlowController(config::TransportConfig) = new(
        config.initial_max_data, 0, 0, config.initial_max_data,
        config.max_concurrent_streams_bidi, config.max_concurrent_streams_uni, 0, 0,
        Dict()
    )
end

# check if we can send more data
function can_send_data(fc::FlowController, bytes::Integer)
    return fc.data_sent + UInt64(bytes) <= fc.max_data_peer
end

# check if we can open a new stream
function can_open_stream(fc::FlowController, is_bidi::Bool)
    if is_bidi
        return fc.streams_opened_bidi < fc.max_streams_bidi
    else
        return fc.streams_opened_uni < fc.max_streams_uni
    end
end

# update flow control on data sent
function on_data_sent!(fc::FlowController, stream_id::Integer, bytes::Integer)
    b = UInt64(bytes)
    sid = UInt64(stream_id)
    fc.data_sent += b

    if haskey(fc.stream_windows, sid)
        fc.stream_windows[sid] = (
            max_data = fc.stream_windows[sid].max_data,
            data_sent = fc.stream_windows[sid].data_sent + b,
            data_received = fc.stream_windows[sid].data_received
        )
    else
        fc.stream_windows[sid] = (
            max_data = fc.max_data,
            data_sent = b,
            data_received = UInt64(0)
        )
    end
end

# update flow control on data received
function on_data_received!(fc::FlowController, stream_id::UInt64, bytes::UInt64)
    fc.data_received += bytes

    if haskey(fc.stream_windows, stream_id)
        fc.stream_windows[stream_id] = (
            max_data = fc.stream_windows[stream_id].max_data,
            data_sent = fc.stream_windows[stream_id].data_sent,
            data_received = fc.stream_windows[stream_id].data_received + bytes
        )
    else
        fc.stream_windows[stream_id] = (
            max_data = fc.max_data,
            data_sent = 0,
            data_received = bytes
        )
    end

    # check if we need to send MAX_DATA frame
    if fc.data_received > fc.max_data ÷ 2
        # would return a MAX_DATA frame to send
        return true
    end
    return false
end

# process MAX_DATA frame from peer
function process_max_data!(fc::FlowController, new_limit::Integer)
    fc.max_data_peer = max(fc.max_data_peer, UInt64(new_limit))
end

# process MAX_STREAM_DATA frame from peer
function process_max_stream_data!(fc::FlowController, stream_id::Integer, new_limit::Integer)
    sid = UInt64(stream_id)
    nl = UInt64(new_limit)
    if haskey(fc.stream_windows, sid)
        old_window = fc.stream_windows[sid]
        fc.stream_windows[sid] = (
            max_data = max(old_window.max_data, nl),
            data_sent = old_window.data_sent,
            data_received = old_window.data_received
        )
    else
        fc.stream_windows[sid] = (
            max_data = nl,
            data_sent = UInt64(0),
            data_received = UInt64(0)
        )
    end
end

export TransportConfig, FlowController
export can_send_data, can_open_stream, on_data_sent!, on_data_received!
export process_max_data!, process_max_stream_data!

end # module Transport
