module PacketPacing

using ..LossDetection

# Packet pacing state
mutable struct PacingState
    # Pacing parameters
    pacing_rate::Float64        # bytes per second
    burst_size::UInt64          # maximum burst size
    smoothing_factor::Float64   # smoothing for rate calculation

    # Timing state
    last_send_time::UInt64      # nanoseconds
    bucket_tokens::Float64      # token bucket for burst control
    max_tokens::Float64         # maximum tokens in bucket

    # Statistics
    bytes_sent_this_interval::UInt64
    interval_start_time::UInt64
    interval_duration_ns::UInt64

    # Configuration
    min_pacing_rate::Float64    # minimum pacing rate (bytes/sec)
    max_pacing_rate::Float64    # maximum pacing rate (bytes/sec)
    pacing_enabled::Bool

    PacingState() = new(
        0.0,                    # pacing_rate
        14720,                  # burst_size (10 * MSS)
        0.25,                   # smoothing_factor
        0,                      # last_send_time
        14720.0,                # bucket_tokens (start with full burst)
        14720.0,                # max_tokens
        0,                      # bytes_sent_this_interval
        time_ns(),              # interval_start_time
        1_000_000_000,          # interval_duration_ns (1 second)
        1200.0,                 # min_pacing_rate (1 packet/sec)
        100_000_000.0,          # max_pacing_rate (100 MB/sec)
        true                    # pacing_enabled
    )
end

# Calculate pacing rate based on congestion window and RTT
function update_pacing_rate!(pacing::PacingState, cwnd::UInt64, rtt_ns::UInt64)
    if !pacing.pacing_enabled || rtt_ns == 0
        return
    end

    # Basic pacing rate: CWND / RTT
    # Add a small factor to account for variations
    pacing_multiplier = 1.25  # 25% faster than pure CWND/RTT

    # Convert to bytes per second
    rtt_seconds = Float64(rtt_ns) / 1_000_000_000.0
    raw_rate = Float64(cwnd) * pacing_multiplier / rtt_seconds

    # Apply smoothing
    if pacing.pacing_rate > 0
        pacing.pacing_rate = (1.0 - pacing.smoothing_factor) * pacing.pacing_rate +
                            pacing.smoothing_factor * raw_rate
    else
        pacing.pacing_rate = raw_rate
    end

    # Clamp to reasonable bounds
    pacing.pacing_rate = max(pacing.min_pacing_rate,
                           min(pacing.max_pacing_rate, pacing.pacing_rate))

    # Update burst size based on rate (allow 10ms worth of data)
    burst_duration_ns = 10_000_000  # 10ms
    burst_duration_s = Float64(burst_duration_ns) / 1_000_000_000.0
    pacing.burst_size = max(UInt64(1472), UInt64(pacing.pacing_rate * burst_duration_s))
    pacing.max_tokens = Float64(pacing.burst_size)
end

# Update pacing state from loss detection context
function update_from_loss_detection!(pacing::PacingState, ld::LossDetectionContext)
    update_pacing_rate!(pacing, ld.cwnd, ld.smoothed_rtt)
end

# Check if we can send a packet of given size
function can_send_packet(pacing::PacingState, packet_size::UInt64)
    if !pacing.pacing_enabled
        return true
    end

    now = time_ns()

    # Refill token bucket based on elapsed time
    if pacing.last_send_time > 0
        elapsed_ns = now - pacing.last_send_time
        elapsed_s = Float64(elapsed_ns) / 1_000_000_000.0

        # Add tokens based on pacing rate
        tokens_to_add = pacing.pacing_rate * elapsed_s
        pacing.bucket_tokens = min(pacing.max_tokens,
                                 pacing.bucket_tokens + tokens_to_add)
    end

    pacing.last_send_time = now

    # Check if we have enough tokens
    return pacing.bucket_tokens >= Float64(packet_size)
end

# Record a packet send and consume tokens
function on_packet_sent!(pacing::PacingState, packet_size::UInt64)
    if !pacing.pacing_enabled
        return
    end

    now = time_ns()

    # Consume tokens
    pacing.bucket_tokens = max(0.0, pacing.bucket_tokens - Float64(packet_size))
    pacing.last_send_time = now

    # Update statistics
    pacing.bytes_sent_this_interval += packet_size

    # Reset interval statistics if needed
    if now - pacing.interval_start_time >= pacing.interval_duration_ns
        pacing.bytes_sent_this_interval = 0
        pacing.interval_start_time = now
    end
end

# Calculate delay until next packet can be sent
function time_until_send(pacing::PacingState, packet_size::UInt64)
    if !pacing.pacing_enabled || pacing.pacing_rate <= 0
        return 0
    end

    tokens_needed = max(0.0, Float64(packet_size) - pacing.bucket_tokens)
    if tokens_needed <= 0
        return 0
    end

    # Time to accumulate needed tokens
    delay_s = tokens_needed / pacing.pacing_rate
    delay_ns = UInt64(delay_s * 1_000_000_000.0)

    return delay_ns
end

# Get current pacing statistics
function get_pacing_stats(pacing::PacingState)
    now = time_ns()
    interval_elapsed = now - pacing.interval_start_time
    current_rate = if interval_elapsed > 0
        Float64(pacing.bytes_sent_this_interval) * 1_000_000_000.0 / Float64(interval_elapsed)
    else
        0.0
    end

    return (
        pacing_rate = pacing.pacing_rate,
        current_rate = current_rate,
        bucket_tokens = pacing.bucket_tokens,
        burst_size = pacing.burst_size,
        bytes_sent_interval = pacing.bytes_sent_this_interval,
        pacing_enabled = pacing.pacing_enabled
    )
end

# Enable or disable pacing
function set_pacing_enabled!(pacing::PacingState, enabled::Bool)
    pacing.pacing_enabled = enabled
    if enabled && pacing.bucket_tokens <= 0
        # Refill bucket when re-enabling
        pacing.bucket_tokens = pacing.max_tokens
    end
end

# Adjust pacing rate manually (for testing or debugging)
function set_pacing_rate!(pacing::PacingState, rate_bps::Float64)
    pacing.pacing_rate = max(pacing.min_pacing_rate,
                           min(pacing.max_pacing_rate, rate_bps))
end

# Check if pacing would delay transmission significantly
function would_pace_significantly(pacing::PacingState, packet_size::UInt64, threshold_ns::UInt64 = 1_000_000)
    delay = time_until_send(pacing, packet_size)
    return delay > threshold_ns
end

# Calculate optimal burst size for current conditions
function calculate_optimal_burst_size(pacing::PacingState, rtt_ns::UInt64)
    if rtt_ns == 0 || pacing.pacing_rate <= 0
        return pacing.burst_size
    end

    # Allow enough burst for 1/4 of RTT worth of data
    burst_time_ns = rtt_ns ÷ 4
    burst_time_s = Float64(burst_time_ns) / 1_000_000_000.0

    optimal_burst = UInt64(pacing.pacing_rate * burst_time_s)

    # Clamp to reasonable bounds
    min_burst = UInt64(1472)  # At least one packet
    max_burst = UInt64(64000) # Max 64KB burst

    return max(min_burst, min(max_burst, optimal_burst))
end

# Update burst size based on RTT
function update_burst_size!(pacing::PacingState, rtt_ns::UInt64)
    optimal_burst = calculate_optimal_burst_size(pacing, rtt_ns)

    # Smooth the change
    current_burst = Float64(pacing.burst_size)
    target_burst = Float64(optimal_burst)

    new_burst = current_burst * 0.8 + target_burst * 0.2
    pacing.burst_size = UInt64(new_burst)
    pacing.max_tokens = Float64(pacing.burst_size)

    # Ensure we don't exceed new burst size
    pacing.bucket_tokens = min(pacing.bucket_tokens, pacing.max_tokens)
end

# Detect if we're sending too fast (for congestion control feedback)
function is_sending_too_fast(pacing::PacingState, target_rate::Float64)
    stats = get_pacing_stats(pacing)
    return stats.current_rate > target_rate * 1.5  # 50% over target
end

# Reset pacing state (useful for connection restart)
function reset_pacing!(pacing::PacingState)
    pacing.last_send_time = 0
    pacing.bucket_tokens = pacing.max_tokens
    pacing.bytes_sent_this_interval = 0
    pacing.interval_start_time = time_ns()
end

# Pacing scheduler for multiple packets
mutable struct PacingScheduler
    pacing_state::PacingState
    scheduled_packets::Vector{@NamedTuple{send_time::UInt64, packet_size::UInt64, callback::Function}}

    PacingScheduler(pacing_state::PacingState) = new(pacing_state, [])
end

# Schedule a packet for later transmission
function schedule_packet!(scheduler::PacingScheduler, packet_size::UInt64, callback::Function)
    delay = time_until_send(scheduler.pacing_state, packet_size)
    send_time = time_ns() + delay

    push!(scheduler.scheduled_packets, (send_time = send_time, packet_size = packet_size, callback = callback))

    # Sort by send time
    sort!(scheduler.scheduled_packets, by = x -> x.send_time)

    return delay
end

# Process scheduled packets that are ready to send
function process_scheduled_packets!(scheduler::PacingScheduler)
    now = time_ns()
    sent_count = 0

    while !isempty(scheduler.scheduled_packets)
        next_packet = scheduler.scheduled_packets[1]

        if next_packet.send_time <= now
            # Remove from schedule
            popfirst!(scheduler.scheduled_packets)

            # Check if we can still send
            if can_send_packet(scheduler.pacing_state, next_packet.packet_size)
                # Send the packet
                next_packet.callback()
                on_packet_sent!(scheduler.pacing_state, next_packet.packet_size)
                sent_count += 1
            else
                # Reschedule for later
                schedule_packet!(scheduler, next_packet.packet_size, next_packet.callback)
                break
            end
        else
            break
        end
    end

    return sent_count
end

# Get time until next scheduled packet
function time_to_next_packet(scheduler::PacingScheduler)
    if isempty(scheduler.scheduled_packets)
        return nothing
    end

    now = time_ns()
    next_time = scheduler.scheduled_packets[1].send_time

    return max(0, next_time - now)
end

export PacingState, PacingScheduler
export update_pacing_rate!, update_from_loss_detection!
export can_send_packet, on_packet_sent!, time_until_send
export get_pacing_stats, set_pacing_enabled!, set_pacing_rate!
export would_pace_significantly, update_burst_size!, reset_pacing!
export schedule_packet!, process_scheduled_packets!, time_to_next_packet

end # module PacketPacing