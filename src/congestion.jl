module Congestion

using ..Protocol

const MIN_CWND = 2 * 1200  # 2 * max datagram size
const MAX_CWND = 10 * 1024 * 1024  # 10 MB
const INITIAL_CWND = 14720  # ~10 * MSS

# RTT estimation
mutable struct RttEstimator
    min_rtt::UInt64
    smoothed_rtt::UInt64
    rttvar::UInt64
    latest_rtt::UInt64

    RttEstimator() = new(typemax(UInt64), INITIAL_RTT_NS, INITIAL_RTT_NS ÷ 2, 0)
end

function update_rtt!(rtt::RttEstimator, sample::UInt64, ack_delay::UInt64=0)
    rtt.latest_rtt = sample
    rtt.min_rtt = min(rtt.min_rtt, sample)

    adjusted_sample = sample > ack_delay ? sample - ack_delay : sample

    if rtt.smoothed_rtt == INITIAL_RTT_NS
        # first sample
        rtt.smoothed_rtt = adjusted_sample
        rtt.rttvar = adjusted_sample ÷ 2
    else
        # update smoothed RTT and variance
        diff = abs(Int64(rtt.smoothed_rtt) - Int64(adjusted_sample))
        rtt.rttvar = (3 * rtt.rttvar + diff) ÷ 4
        rtt.smoothed_rtt = (7 * rtt.smoothed_rtt + adjusted_sample) ÷ 8
    end
end

function rto(rtt::RttEstimator)
    return rtt.smoothed_rtt + 4 * rtt.rttvar
end

# new reno style congestion control
mutable struct NewReno
    cwnd::UInt64
    ssthresh::UInt64
    bytes_in_flight::UInt64
    recovery_start_time::UInt64

    NewReno() = new(INITIAL_CWND, typemax(UInt64), 0, 0)
end

function on_packet_sent!(cc::NewReno, bytes::UInt64)
    cc.bytes_in_flight += bytes
end

function on_packet_acked!(cc::NewReno, bytes::UInt64)
    cc.bytes_in_flight = max(0, cc.bytes_in_flight - bytes)

    if cc.cwnd < cc.ssthresh
        # slow start
        cc.cwnd = min(cc.cwnd + bytes, MAX_CWND)
    else
        # congestion avoidance
        increment = (bytes * bytes) ÷ cc.cwnd
        cc.cwnd = min(cc.cwnd + increment, MAX_CWND)
    end
end

function on_packet_lost!(cc::NewReno, bytes::UInt64, now::UInt64)
    cc.bytes_in_flight = max(0, cc.bytes_in_flight - bytes)

    # only reduce cwnd once per recovery period
    if now > cc.recovery_start_time + INITIAL_RTT_NS
        cc.recovery_start_time = now
        cc.ssthresh = max(cc.cwnd ÷ 2, MIN_CWND)
        cc.cwnd = cc.ssthresh
    end
end

function can_send(cc::NewReno, bytes::UInt64)
    return cc.bytes_in_flight + bytes <= cc.cwnd
end

# pacing support
mutable struct Pacer
    rate::UInt64  # bytes per second
    last_sent_time::UInt64
    tokens::UInt64  # available tokens in bytes

    Pacer() = new(0, 0, 0)
end

function update_pacing_rate!(pacer::Pacer, cwnd::UInt64, rtt::UInt64)
    # pace at 1.25x the congestion window rate
    pacer.rate = (cwnd * 1_000_000_000 * 5) ÷ (rtt * 4)
end

function can_send_paced(pacer::Pacer, bytes::UInt64, now::UInt64)
    if pacer.last_sent_time == 0
        pacer.last_sent_time = now
        return true
    end

    elapsed = now - pacer.last_sent_time
    pacer.tokens += (pacer.rate * elapsed) ÷ 1_000_000_000

    if pacer.tokens >= bytes
        pacer.tokens -= bytes
        pacer.last_sent_time = now
        return true
    end

    return false
end

export NewReno, RttEstimator, Pacer
export on_packet_sent!, on_packet_acked!, on_packet_lost!, can_send
export update_rtt!, rto, update_pacing_rate!, can_send_paced

end # module Congestion
