module ConnectionIdManager

using ..Protocol
using ..Packet: ConnectionId
using ..Frame
using Random

# Connection ID with associated data
mutable struct ConnectionIdData
    cid::ConnectionId
    sequence_number::UInt64
    retire_prior_to::UInt64
    stateless_reset_token::Vector{UInt8}
    issued_time::UInt64
    active::Bool

    function ConnectionIdData(cid::ConnectionId, seq::UInt64, retire_prior::UInt64,
                              token::Vector{UInt8} = UInt8[])
        new(cid, seq, retire_prior, token, time_ns(), true)
    end
end

# Connection ID Manager for handling rotation
mutable struct ConnectionIdManagerState
    # Local connection IDs (that we issue to peer)
    local_cids::Vector{ConnectionIdData}
    next_local_sequence::UInt64
    local_cid_limit::UInt64

    # Remote connection IDs (that peer issues to us)
    remote_cids::Vector{ConnectionIdData}
    current_remote_cid::Union{ConnectionIdData, Nothing}
    remote_cid_limit::UInt64

    # Retirement tracking
    retired_local_cids::Set{UInt64}  # sequence numbers
    retired_remote_cids::Set{UInt64}

    # Configuration
    max_active_connection_ids::UInt64
    connection_id_length::UInt8

    ConnectionIdManagerState(initial_local_cid::ConnectionId, initial_remote_cid::ConnectionId) = new(
        [ConnectionIdData(initial_local_cid, UInt64(0), UInt64(0))],
        1,
        2,  # default limit
        [ConnectionIdData(initial_remote_cid, UInt64(0), UInt64(0))],
        ConnectionIdData(initial_remote_cid, UInt64(0), UInt64(0)),
        2,  # default limit
        Set{UInt64}(),
        Set{UInt64}(),
        8,  # max active CIDs
        8   # CID length
    )
end

# Generate a new connection ID
function generate_connection_id(length::Integer = 8)
    data = rand(UInt8, Int(length))
    return ConnectionId(data)
end

# Generate stateless reset token for a CID
function generate_stateless_reset_token(cid::ConnectionId)
    # In practice, this should be derived from a secret key
    # For now, use a simple hash of the CID
    return rand(UInt8, 16)  # 128-bit token
end

# Issue a new local connection ID
function issue_new_local_cid!(manager::ConnectionIdManagerState)
    if length(manager.local_cids) >= manager.max_active_connection_ids
        return nothing
    end

    new_cid = generate_connection_id(manager.connection_id_length)
    reset_token = generate_stateless_reset_token(new_cid)

    cid_data = ConnectionIdData(
        new_cid,
        manager.next_local_sequence,
        UInt64(0),  # retire_prior_to
        reset_token
    )

    push!(manager.local_cids, cid_data)
    manager.next_local_sequence += 1

    return cid_data
end

# Add a remote connection ID from NEW_CONNECTION_ID frame
function add_remote_cid!(manager::ConnectionIdManagerState, seq::UInt64, retire_prior::UInt64,
                        cid::ConnectionId, reset_token::Vector{UInt8})
    # Check if we already have this sequence number
    for existing in manager.remote_cids
        if existing.sequence_number == seq
            # Update existing
            existing.cid = cid
            existing.retire_prior_to = retire_prior
            existing.stateless_reset_token = reset_token
            existing.issued_time = time_ns()
            return true
        end
    end

    # Retire older CIDs as required
    for existing in manager.remote_cids
        if existing.sequence_number < retire_prior
            retire_remote_cid!(manager, existing.sequence_number)
        end
    end

    # Add new CID
    if length(manager.remote_cids) < manager.max_active_connection_ids
        cid_data = ConnectionIdData(cid, seq, retire_prior, reset_token)
        push!(manager.remote_cids, cid_data)
        return true
    end

    return false
end

# Retire a local connection ID
function retire_local_cid!(manager::ConnectionIdManagerState, sequence::UInt64)
    for (i, cid_data) in enumerate(manager.local_cids)
        if cid_data.sequence_number == sequence && cid_data.active
            cid_data.active = false
            push!(manager.retired_local_cids, sequence)
            # Remove from active list after a delay
            deleteat!(manager.local_cids, i)
            return true
        end
    end
    return false
end

# Retire a remote connection ID
function retire_remote_cid!(manager::ConnectionIdManagerState, sequence::UInt64)
    for (i, cid_data) in enumerate(manager.remote_cids)
        if cid_data.sequence_number == sequence && cid_data.active
            cid_data.active = false
            push!(manager.retired_remote_cids, sequence)

            # If this was our current CID, switch to another
            if manager.current_remote_cid !== nothing &&
               manager.current_remote_cid.sequence_number == sequence
                switch_to_next_remote_cid!(manager)
            end

            # Remove from active list
            deleteat!(manager.remote_cids, i)
            return true
        end
    end
    return false
end

# Switch to next available remote CID
function switch_to_next_remote_cid!(manager::ConnectionIdManagerState)
    for cid_data in manager.remote_cids
        if cid_data.active && cid_data != manager.current_remote_cid
            manager.current_remote_cid = cid_data
            return cid_data
        end
    end
    return nothing
end

# Get current remote CID for sending packets
function get_current_remote_cid(manager::ConnectionIdManagerState)
    if manager.current_remote_cid !== nothing && manager.current_remote_cid.active
        return manager.current_remote_cid.cid
    end

    # Fallback to first active CID
    for cid_data in manager.remote_cids
        if cid_data.active
            manager.current_remote_cid = cid_data
            return cid_data.cid
        end
    end

    return nothing
end

# Create NEW_CONNECTION_ID frame for a local CID
function create_new_connection_id_frame(cid_data::ConnectionIdData)
    return NewConnectionIdFrame(
        cid_data.sequence_number,
        cid_data.retire_prior_to,
        cid_data.cid.data,
        cid_data.stateless_reset_token
    )
end

# Create RETIRE_CONNECTION_ID frame
function create_retire_connection_id_frame(sequence::UInt64)
    return RetireConnectionIdFrame(sequence)
end

# Proactively issue new CIDs if needed
function maintain_connection_ids!(manager::ConnectionIdManagerState)
    active_count = count(cid -> cid.active, manager.local_cids)

    # Ensure we have at least 2 active local CIDs
    frames = QuicFrame[]

    while active_count < 2 && length(manager.local_cids) < manager.max_active_connection_ids
        new_cid = issue_new_local_cid!(manager)
        if new_cid !== nothing
            frame = create_new_connection_id_frame(new_cid)
            push!(frames, frame)
            active_count += 1
        else
            break
        end
    end

    return frames
end

# Process received NEW_CONNECTION_ID frame
function process_new_connection_id_frame!(manager::ConnectionIdManagerState, frame::NewConnectionIdFrame)
    success = add_remote_cid!(
        manager,
        frame.sequence_number,
        frame.retire_prior_to,
        ConnectionId(frame.connection_id),
        frame.stateless_reset_token
    )

    # Return RETIRE_CONNECTION_ID frames for any CIDs we need to retire
    retirement_frames = QuicFrame[]

    if success
        # Check if we need to retire any CIDs due to retire_prior_to
        for cid_data in manager.remote_cids
            if cid_data.sequence_number < frame.retire_prior_to && cid_data.active
                push!(retirement_frames, create_retire_connection_id_frame(cid_data.sequence_number))
                retire_remote_cid!(manager, cid_data.sequence_number)
            end
        end
    end

    return retirement_frames
end

# Process received RETIRE_CONNECTION_ID frame
function process_retire_connection_id_frame!(manager::ConnectionIdManagerState, frame::RetireConnectionIdFrame)
    retire_local_cid!(manager, frame.sequence_number)

    # Issue a new CID to replace the retired one
    new_frames = maintain_connection_ids!(manager)
    return new_frames
end

# Handle path migration by switching CID
function initiate_path_migration!(manager::ConnectionIdManagerState)
    new_cid = switch_to_next_remote_cid!(manager)
    if new_cid !== nothing
        return new_cid.cid
    end
    return nothing
end

# Check if we have enough connection IDs
function needs_new_connection_ids(manager::ConnectionIdManagerState)
    active_local = count(cid -> cid.active, manager.local_cids)
    return active_local < 2
end

# Get all active local CIDs
function get_active_local_cids(manager::ConnectionIdManagerState)
    return [cid.cid for cid in manager.local_cids if cid.active]
end

# Get all active remote CIDs
function get_active_remote_cids(manager::ConnectionIdManagerState)
    return [cid.cid for cid in manager.remote_cids if cid.active]
end

# Validate CID against known CIDs
function is_valid_destination_cid(manager::ConnectionIdManagerState, cid::ConnectionId)
    for cid_data in manager.local_cids
        if cid_data.active && cid_data.cid == cid
            return true
        end
    end
    return false
end

# Get stateless reset token for a local CID
function get_stateless_reset_token(manager::ConnectionIdManagerState, cid::ConnectionId)
    for cid_data in manager.local_cids
        if cid_data.active && cid_data.cid == cid
            return cid_data.stateless_reset_token
        end
    end
    return nothing
end

# Statistics and debugging
function get_cid_stats(manager::ConnectionIdManagerState)
    active_local = count(cid -> cid.active, manager.local_cids)
    active_remote = count(cid -> cid.active, manager.remote_cids)

    return (
        active_local_cids = active_local,
        active_remote_cids = active_remote,
        total_local_issued = manager.next_local_sequence - 1,
        retired_local = length(manager.retired_local_cids),
        retired_remote = length(manager.retired_remote_cids),
        current_remote_seq = manager.current_remote_cid !== nothing ?
                           manager.current_remote_cid.sequence_number : nothing
    )
end

export ConnectionIdManager, ConnectionIdData
export generate_connection_id, issue_new_local_cid!, add_remote_cid!
export retire_local_cid!, retire_remote_cid!, get_current_remote_cid
export create_new_connection_id_frame, create_retire_connection_id_frame
export maintain_connection_ids!, process_new_connection_id_frame!
export process_retire_connection_id_frame!, initiate_path_migration!
export needs_new_connection_ids, is_valid_destination_cid
export get_stateless_reset_token, get_cid_stats

end # module ConnectionIdManager