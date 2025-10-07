module LossDetection

using ..Protocol
using ..Packet
using ..Frame

# Loss detection parameters (from RFC 9002)
const INITIAL_RTT_NS = 333_000_000  # 333ms in nanoseconds
const MAX_ACK_DELAY_NS = 25_000_000  # 25ms
const GRANULARITY_NS = 1_000_000     # 1ms
const TIME_THRESHOLD = 9/8           # 1.125
const PACKET_THRESHOLD = 3           # packets
const MAX_TIMER_EXPONENT = 16
const PROBE_TIMEOUT_FACTOR = 2.0

# Packet space enumeration for loss detection
@enum LDPacketSpace LDInitial=0 LDHandshake=1 LDApplication=2

# Sent packet information
mutable struct SentPacket
    packet_number::UInt64
    time_sent::UInt64
    ack_eliciting::Bool
    in_flight::Bool
    size::UInt64
    frames::Vector{QuicFrame}
end

# ACK range for efficient range tracking
struct AckRange
    smallest::UInt64
    largest::UInt64
end

# Loss detection state per packet space
mutable struct SpaceState
    largest_acked_packet::Union{UInt64, Nothing}
    loss_time::Union{UInt64, Nothing}
    sent_packets::Dict{UInt64, SentPacket}
    ack_eliciting_outstanding::UInt64
    time_of_last_ack_eliciting_packet::UInt64

    SpaceState() = new(nothing, nothing, Dict{UInt64, SentPacket}(), 0, 0)
end

# Main loss detection context
mutable struct LossDetectionContext
    # RTT tracking
    latest_rtt::UInt64
    smoothed_rtt::UInt64
    rttvar::UInt64
    min_rtt::UInt64
    max_ack_delay::UInt64

    # Timer state
    loss_detection_timer::Union{UInt64, Nothing}
    pto_count::UInt64

    # Space-specific state
    spaces::Vector{SpaceState}  # indexed by LDPacketSpace

    # Congestion control
    cwnd::UInt64
    bytes_in_flight::UInt64

    # Handshake completion
    handshake_confirmed::Bool
    peer_completed_address_validation::Bool

    LossDetectionContext() = new(
        0, INITIAL_RTT_NS, INITIAL_RTT_NS ÷ 2, INITIAL_RTT_NS, 0,
        nothing, 0,
        [SpaceState() for _ in 1:3],
        14720, 0,  # Initial CWND from RFC 9002
        false, false
    )
end

# Record a sent packet for loss detection
function on_packet_sent!(ld::LossDetectionContext, space::LDPacketSpace,
                        packet_number::UInt64, frames::Vector{QuicFrame}, size::UInt64)
    now = time_ns()

    # Determine if packet is ack-eliciting
    ack_eliciting = any(is_ack_eliciting_frame, frames)
    in_flight = ack_eliciting || any(is_in_flight_frame, frames)

    sent_packet = SentPacket(packet_number, now, ack_eliciting, in_flight, size, frames)
    ld.spaces[Int(space) + 1].sent_packets[packet_number] = sent_packet

    if in_flight
        ld.bytes_in_flight += size
        if ack_eliciting
            ld.spaces[Int(space) + 1].ack_eliciting_outstanding += 1
            ld.spaces[Int(space) + 1].time_of_last_ack_eliciting_packet = now
        end
        set_loss_detection_timer!(ld)
    end
end

# Process received ACK frame
function on_ack_received!(ld::LossDetectionContext, space::LDPacketSpace, ack::AckFrame)
    space_state = ld.spaces[Int(space) + 1]

    # Update largest_acked_packet
    if space_state.largest_acked_packet === nothing || ack.largest_acked > space_state.largest_acked_packet
        space_state.largest_acked_packet = ack.largest_acked
    end

    # Find newly acked packets
    newly_acked = UInt64[]

    # Check if largest acked packet is newly acked
    if haskey(space_state.sent_packets, ack.largest_acked)
        push!(newly_acked, ack.largest_acked)
    end

    # Process ACK ranges
    current = ack.largest_acked
    for gap_size in ack.gaps
        current -= gap_size + 1
        for range_length in ack.range_lengths
            for pn in (current - range_length + 1):current
                if haskey(space_state.sent_packets, pn)
                    push!(newly_acked, pn)
                end
            end
            current -= range_length
        end
    end

    # Process newly acked packets
    if !isempty(newly_acked)
        # Update RTT if this ack acknowledges the largest sent packet
        largest_sent = maximum(keys(space_state.sent_packets))
        if ack.largest_acked == largest_sent
            update_rtt!(ld, space_state.sent_packets[ack.largest_acked].time_sent, ack.ack_delay_ns)
        end

        # Remove acked packets from sent_packets
        for pn in newly_acked
            sent_packet = space_state.sent_packets[pn]
            if sent_packet.in_flight
                ld.bytes_in_flight -= sent_packet.size
                if sent_packet.ack_eliciting
                    space_state.ack_eliciting_outstanding -= 1
                end
            end
            delete!(space_state.sent_packets, pn)
        end

        # Reset PTO count
        ld.pto_count = 0

        # Detect and handle lost packets
        detect_and_remove_lost_packets!(ld, space)

        # Set loss detection timer
        set_loss_detection_timer!(ld)
    end
end

# Update RTT measurements
function update_rtt!(ld::LossDetectionContext, sent_time::UInt64, ack_delay_ns::UInt64)
    now = time_ns()
    latest_rtt = now - sent_time

    # Ignore ack delay if it's larger than max_ack_delay
    if ack_delay_ns > ld.max_ack_delay
        ack_delay_ns = 0
    end

    # Adjust for ack delay if this isn't the first RTT measurement
    if ld.latest_rtt > 0
        latest_rtt = max(latest_rtt - ack_delay_ns, latest_rtt ÷ 8)
    end

    ld.latest_rtt = latest_rtt

    # First RTT measurement
    if ld.smoothed_rtt == INITIAL_RTT_NS
        ld.min_rtt = latest_rtt
        ld.smoothed_rtt = latest_rtt
        ld.rttvar = latest_rtt ÷ 2
    else
        ld.min_rtt = min(ld.min_rtt, latest_rtt)
        rttvar_sample = abs(Int64(ld.smoothed_rtt) - Int64(latest_rtt))
        ld.rttvar = (3 * ld.rttvar + rttvar_sample) ÷ 4
        ld.smoothed_rtt = (7 * ld.smoothed_rtt + latest_rtt) ÷ 8
    end
end

# Detect lost packets using time and packet thresholds
function detect_and_remove_lost_packets!(ld::LossDetectionContext, space::LDPacketSpace)
    space_state = ld.spaces[Int(space) + 1]

    if space_state.largest_acked_packet === nothing
        return QuicFrame[]
    end

    lost_packets = QuicFrame[]
    loss_delay = max(UInt64(TIME_THRESHOLD * ld.latest_rtt), GRANULARITY_NS)

    # Packets are lost if they are:
    # 1. Sent before largest_acked - PACKET_THRESHOLD, or
    # 2. Sent more than loss_delay ago

    now = time_ns()
    lost_send_time = now - loss_delay

    for (pn, sent_packet) in space_state.sent_packets
        # Time threshold
        if sent_packet.time_sent <= lost_send_time
            append!(lost_packets, sent_packet.frames)
            if sent_packet.in_flight
                ld.bytes_in_flight -= sent_packet.size
            end
            delete!(space_state.sent_packets, pn)
            continue
        end

        # Packet threshold
        if space_state.largest_acked_packet !== nothing &&
           pn <= space_state.largest_acked_packet - PACKET_THRESHOLD
            append!(lost_packets, sent_packet.frames)
            if sent_packet.in_flight
                ld.bytes_in_flight -= sent_packet.size
            end
            delete!(space_state.sent_packets, pn)
        end
    end

    return lost_packets
end

# Set the loss detection timer
function set_loss_detection_timer!(ld::LossDetectionContext)
    # Get the earliest loss time across all spaces
    earliest_loss_time = nothing
    for space_state in ld.spaces
        if space_state.loss_time !== nothing
            if earliest_loss_time === nothing || space_state.loss_time < earliest_loss_time
                earliest_loss_time = space_state.loss_time
            end
        end
    end

    if earliest_loss_time !== nothing
        ld.loss_detection_timer = earliest_loss_time
        return
    end

    # If no loss time is set, use PTO
    if has_ack_eliciting_in_flight(ld)
        # PTO = smoothed_rtt + max(4*rttvar, GRANULARITY) + max_ack_delay
        pto_timeout = ld.smoothed_rtt + max(4 * ld.rttvar, GRANULARITY_NS) + ld.max_ack_delay
        pto_timeout *= UInt64(PROBE_TIMEOUT_FACTOR) ^ ld.pto_count

        # Find the time of the last ack-eliciting packet
        last_ack_eliciting_time = 0
        for space_state in ld.spaces
            if space_state.time_of_last_ack_eliciting_packet > last_ack_eliciting_time
                last_ack_eliciting_time = space_state.time_of_last_ack_eliciting_packet
            end
        end

        ld.loss_detection_timer = last_ack_eliciting_time + pto_timeout
    else
        ld.loss_detection_timer = nothing
    end
end

# Check if there are ack-eliciting packets in flight
function has_ack_eliciting_in_flight(ld::LossDetectionContext)
    for space_state in ld.spaces
        if space_state.ack_eliciting_outstanding > 0
            return true
        end
    end
    return false
end

# Handle loss detection timer expiry
function on_loss_detection_timeout!(ld::LossDetectionContext)
    # Check for lost packets first
    for (i, space_state) in enumerate(ld.spaces)
        space = LDPacketSpace(i - 1)
        if space_state.loss_time !== nothing && space_state.loss_time <= time_ns()
            lost_packets = detect_and_remove_lost_packets!(ld, space)
            # Handle lost packets (retransmit frames)
            space_state.loss_time = nothing
        end
    end

    # If no packets were declared lost, send probe packets
    if !has_ack_eliciting_in_flight(ld)
        # Send probe packets
        ld.pto_count += 1
        # Application should send probe packets here
    end

    set_loss_detection_timer!(ld)
end

# Frame classification helpers
function is_ack_eliciting_frame(frame::QuicFrame)
    return !(frame isa PaddingFrame || frame isa AckFrame || frame isa ConnectionCloseFrame)
end

function is_in_flight_frame(frame::QuicFrame)
    return !(frame isa AckFrame || frame isa PaddingFrame || frame isa ConnectionCloseFrame)
end

# Get probe timeout (PTO) value
function get_pto_timeout(ld::LossDetectionContext)
    pto = ld.smoothed_rtt + max(4 * ld.rttvar, GRANULARITY_NS) + ld.max_ack_delay
    return pto * UInt64(PROBE_TIMEOUT_FACTOR) ^ ld.pto_count
end

# Check if we should send probe packets
function should_send_probe_packets(ld::LossDetectionContext)
    return ld.loss_detection_timer !== nothing && time_ns() >= ld.loss_detection_timer
end

export LossDetectionContext, LDPacketSpace, SentPacket, AckRange
export on_packet_sent!, on_ack_received!, on_loss_detection_timeout!
export set_loss_detection_timer!, should_send_probe_packets, get_pto_timeout
export LDInitial, LDHandshake, LDApplication

end # module LossDetection