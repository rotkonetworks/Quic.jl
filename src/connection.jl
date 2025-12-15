module ConnectionModule

using ..Protocol
using ..Protocol: MAX_STREAM_DATA_BUFFER, INITIAL_RTT_NS
using ..Packet
using ..Packet: ConnectionId, PacketNumber
using ..Frame
using ..Stream
using ..Crypto
using ..Crypto: CryptoContext
using ..Handshake
using ..Handshake: HandshakeState
using ..PacketCoalescing
using ..PacketCoalescing: PacketCoalescer
using ..LossDetection
using ..LossDetection: LossDetectionContext
using ..PacketPacing
using ..ConnectionIdManager
using ..HTTP3
using ..GFWMitigation
using ..GFWMitigation: GFWMitigationConfig
using ..MLS
using ..MLS: QuicMLSConnection, QuicMLSConfig
using Sockets

mutable struct Connection
    local_cid::ConnectionId
    remote_cid::ConnectionId
    initial_dcid::ConnectionId  # original DCID for retry validation
    retry_token::Vector{UInt8}  # token from retry packet
    socket::UDPSocket
    remote_addr::Union{Sockets.InetAddr, Nothing}
    is_client::Bool
    
    # packet tracking
    next_send_pn::PacketNumber
    next_recv_pn::PacketNumber
    acked_packets::Set{UInt64}
    sent_packets::Dict{UInt64, @NamedTuple{time::UInt64, data::Vector{UInt8}}}
    
    # streams
    streams::Dict{UInt64, StreamState}
    next_stream_id::UInt64
    
    # crypto and handshake
    crypto::CryptoContext
    handshake::HandshakeState
    
    # flow control
    max_data::UInt64
    data_sent::UInt64
    data_recv::UInt64
    
    # congestion control
    cwnd::UInt64
    ssthresh::UInt64
    bytes_in_flight::UInt64
    rtt_ns::UInt64
    
    # state
    connected::Bool
    closing::Bool
    error_code::Union{Nothing, UInt64}

    # packet coalescing
    coalescer::PacketCoalescer

    # loss detection
    loss_detection::LossDetectionContext

    # connection ID management
    cid_manager::ConnectionIdManager.ConnectionIdManagerState

    # packet pacing
    pacing_state::PacketPacing.PacingState

    # HTTP/3 support
    http3::Union{HTTP3.HTTP3Connection, Nothing}

    # 0-RTT support
    zero_rtt_enabled::Bool
    early_data_accepted::Bool
    max_early_data::UInt32

    # GFW censorship mitigation
    gfw_config::GFWMitigationConfig

    # MLS (QUIC-MLS) support
    use_mls::Bool
    mls_conn::Union{QuicMLSConnection, Nothing}
end

function Connection(socket::UDPSocket, is_client::Bool;
                    gfw_config::GFWMitigationConfig = GFWMitigation.default_config(),
                    use_mls::Bool = false,
                    mls_identity::Vector{UInt8} = UInt8[])
    remote_cid = ConnectionId()

    # Initialize MLS if enabled
    mls_conn = if use_mls && !isempty(mls_identity)
        config = QuicMLSConfig(mls_identity)
        if is_client
            MLS.init_quic_mls_client(config)
        else
            MLS.init_quic_mls_server(config)
        end
    else
        nothing
    end

    Connection(
        ConnectionId(), remote_cid, remote_cid, UInt8[],
        socket, nothing, is_client,
        PacketNumber(), PacketNumber(),
        Set{UInt64}(), Dict{UInt64, @NamedTuple{time::UInt64, data::Vector{UInt8}}}(),
        Dict{UInt64, StreamState}(), is_client ? 0 : 1,
        CryptoContext(),
        HandshakeState(is_client ? :client : :server),
        MAX_STREAM_DATA_BUFFER * 10, 0, 0,
        14720, typemax(UInt64), 0, INITIAL_RTT_NS,
        false, false, nothing,
        PacketCoalescer(),
        LossDetectionContext(),
        ConnectionIdManager.ConnectionIdManagerState(ConnectionId(), remote_cid),
        PacketPacing.PacingState(),
        nothing,  # HTTP/3 connection (initialized on demand)
        false,    # zero_rtt_enabled
        false,    # early_data_accepted
        0,        # max_early_data
        gfw_config,  # GFW mitigation config
        use_mls,  # MLS mode flag
        mls_conn  # MLS connection state
    )
end

# open new stream
function open_stream(conn::Connection, bidirectional::Bool=true)
    initiator = conn.is_client ? :client : :server
    direction = bidirectional ? :bidi : :uni
    
    sid = StreamId(conn.next_stream_id, initiator, direction)
    conn.next_stream_id += 1
    
    stream = StreamState(sid)
    conn.streams[sid.value] = stream
    
    return sid
end

# send data on stream
function send_stream(conn::Connection, stream_id::StreamId, data::Vector{UInt8}, fin::Bool=false)
    haskey(conn.streams, stream_id.value) || error("Stream not found")
    
    stream = conn.streams[stream_id.value]
    written = write_stream!(stream, data, fin)
    
    # create stream frame
    frame = StreamFrame(stream_id.value, stream.send_offset - written, 
                       data[1:written], fin && written == length(data))
    
    send_frame(conn, frame)
    return written
end

# send frame in packet with proper encryption
function send_frame(conn::Connection, frame::QuicFrame)
    buf = UInt8[]
    header_len = 0

    # determine packet type and keys
    is_initial = !conn.connected && conn.handshake.state != :completed

    # build packet header
    if is_initial
        # long header for initial packet
        push!(buf, PACKET_INITIAL | 0xc0)  # long header with 2-byte pn
        append!(buf, reinterpret(UInt8, [hton(QUIC_VERSION_1)]))

        # connection IDs
        push!(buf, UInt8(length(conn.remote_cid)))
        append!(buf, conn.remote_cid.data)
        push!(buf, UInt8(length(conn.local_cid)))
        append!(buf, conn.local_cid.data)

        # token (empty for client)
        encode_varint!(buf, VarInt(0))

        # length placeholder (2 bytes varint)
        length_offset = length(buf) + 1
        encode_varint!(buf, VarInt(0))  # will be updated

        header_len = length(buf)
    else
        # short header for 1-RTT packets
        push!(buf, PACKET_SHORT | 0x40)  # fixed bit set
        append!(buf, conn.remote_cid.data)
        header_len = length(buf)
    end

    # packet number (2 bytes for now)
    pn = next!(conn.next_send_pn)
    pn_offset = length(buf) + 1
    push!(buf, UInt8((pn >> 8) & 0xff), UInt8(pn & 0xff))

    # build payload
    payload = UInt8[]
    encode_frame!(payload, frame)

    # apply encryption if keys are available
    if !isempty(conn.crypto.initial_secrets)
        # select appropriate keys
        if conn.is_client
            key = conn.crypto.initial_secrets[:client_key]
            iv = conn.crypto.initial_secrets[:client_iv]
            hp_key = conn.crypto.initial_secrets[:client_hp]
        else
            key = conn.crypto.initial_secrets[:server_key]
            iv = conn.crypto.initial_secrets[:server_iv]
            hp_key = conn.crypto.initial_secrets[:server_hp]
        end

        # encrypt payload
        header_bytes = buf[1:header_len + 2]  # including packet number
        encrypted = encrypt_payload(payload, key, iv, pn, header_bytes)

        # append encrypted payload
        append!(buf, encrypted)

        # update length field for long header
        if is_initial
            # packet number (2) + encrypted payload length
            payload_length = 2 + length(encrypted)
            length_bytes = encode_varint_bytes(VarInt(payload_length))
            buf[length_offset:length_offset + length(length_bytes) - 1] = length_bytes
        end

        # apply header protection
        if length(encrypted) >= 20
            sample_offset = pn_offset + 2 + 4  # skip pn and 4 bytes into payload
            sample = buf[sample_offset:sample_offset + 15]
            # Apply header protection in-place
            header_slice = buf[1:pn_offset + 1]
            protect_header!(header_slice, hp_key, sample)
            buf[1:pn_offset + 1] = header_slice
        end
    else
        # no encryption (shouldn't happen in production)
        append!(buf, payload)
    end

    # check pacing before sending
    packet_size = UInt64(length(buf))

    if !PacketPacing.can_send_packet(conn.pacing_state, packet_size)
        # Would be paced - schedule for later or wait
        delay_ns = PacketPacing.time_until_send(conn.pacing_state, packet_size)
        if delay_ns > 0 && delay_ns < 1_000_000  # less than 1ms, just wait
            sleep(delay_ns / 1_000_000_000.0)
        end
    end

    # send packet
    if conn.remote_addr !== nothing
        send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, buf)
        # Record send for pacing
        PacketPacing.on_packet_sent!(conn.pacing_state, packet_size)
    end

    # track sent packet
    conn.sent_packets[pn] = (time=time_ns(), data=copy(buf))

    # track with loss detection
    space = is_initial ? LDInitial : LDApplication
    on_packet_sent!(conn.loss_detection, space, pn, [frame], UInt64(length(buf)))

    conn.bytes_in_flight += length(buf)
end

# helper to encode varint and return bytes
function encode_varint_bytes(v::VarInt)
    buf = UInt8[]
    encode_varint!(buf, v)
    return buf
end

# initiate QUIC handshake with GFW mitigation support
function initiate_handshake(conn::Connection, server_name::Union{String, Nothing}=nothing)
    # derive initial keys using proper crypto context
    derive_initial_secrets!(conn.crypto, conn.remote_cid.data)

    if conn.is_client
        # start client handshake with server name for SNI
        crypto_frame = start_client_handshake(conn.handshake, conn.remote_cid, conn.local_cid, server_name)

        # Apply SNI fragmentation if enabled
        if GFWMitigation.should_fragment_sni(conn.gfw_config)
            # Fragment the ClientHello to split SNI across frames
            fragments = GFWMitigation.fragment_around_sni(crypto_frame.data, conn.gfw_config)

            if length(fragments) > 1
                # Send multiple CRYPTO frames with fragmented data
                for (offset, data) in fragments
                    fragment_frame = CryptoFrame(offset, data)
                    send_frame(conn, fragment_frame)
                end
            else
                # No fragmentation needed, send as-is
                send_frame(conn, crypto_frame)
            end
        else
            send_frame(conn, crypto_frame)
        end
    end
end

# process received handshake data
function process_handshake_data(conn::Connection, data::Vector{UInt8})
    # Check if using MLS mode
    if conn.use_mls && conn.mls_conn !== nothing
        process_mls_crypto_data(conn, data)
        return
    end

    if conn.handshake.state == :handshake && !conn.is_client
        # server processing client hello
        # (simplified - real implementation needs full TLS processing)
        conn.handshake.client_hello = data

        # send server hello and other handshake messages
        # ...
    elseif conn.handshake.state == :handshake && conn.is_client
        # client processing server hello
        process_server_hello(conn.handshake, data)

        # check if handshake is complete
        if length(data) > 100  # simplified check
            complete_handshake(conn.handshake)
            conn.connected = true
        end
    end
end

#=
================================================================================
MLS (QUIC-MLS) HANDSHAKE SUPPORT
================================================================================
=#

"""
Initiate MLS handshake (for QUIC-MLS mode)

Client sends KeyPackage, server waits for it.
"""
function initiate_mls_handshake(conn::Connection)
    if !conn.use_mls || conn.mls_conn === nothing
        error("MLS mode not enabled")
    end

    # Derive initial keys (still needed for Initial packets)
    derive_initial_secrets!(conn.crypto, conn.remote_cid.data)

    if conn.is_client
        # Get KeyPackage to send
        crypto_data = MLS.get_crypto_data_to_send(conn.mls_conn)

        if !isempty(crypto_data)
            # Send in CRYPTO frame
            crypto_frame = CryptoFrame(UInt64(0), crypto_data)
            send_frame(conn, crypto_frame)
        end
    end
    # Server just waits for client's KeyPackage
end

"""
Process MLS CRYPTO frame data
"""
function process_mls_crypto_data(conn::Connection, data::Vector{UInt8})
    if !conn.use_mls || conn.mls_conn === nothing
        return
    end

    # Process the MLS message
    success = MLS.process_crypto_data(conn.mls_conn, data)

    if !success
        println(" MLS handshake error: $(conn.mls_conn.error_message)")
        conn.error_code = UInt64(0x0100)  # CRYPTO_ERROR
        return
    end

    # Check if we have a response to send
    response = MLS.get_crypto_data_to_send(conn.mls_conn)
    if !isempty(response)
        crypto_frame = CryptoFrame(UInt64(0), response)
        send_frame(conn, crypto_frame)
    end

    # Check if handshake is complete
    if MLS.is_handshake_complete(conn.mls_conn)
        complete_mls_handshake!(conn)
    end
end

"""
Complete MLS handshake and derive QUIC keys
"""
function complete_mls_handshake!(conn::Connection)
    if !conn.use_mls || conn.mls_conn === nothing
        return
    end

    # Get derived keys
    keys = MLS.get_quic_keys(conn.mls_conn)

    # Install keys into crypto context
    # Client keys
    conn.crypto.handshake_secrets[:client_key] = keys.client_key
    conn.crypto.handshake_secrets[:client_iv] = keys.client_iv
    conn.crypto.handshake_secrets[:client_hp] = keys.client_hp

    # Server keys
    conn.crypto.handshake_secrets[:server_key] = keys.server_key
    conn.crypto.handshake_secrets[:server_iv] = keys.server_iv
    conn.crypto.handshake_secrets[:server_hp] = keys.server_hp

    # Also set as application keys (1-RTT)
    conn.crypto.application_secrets[:client_key] = keys.client_key
    conn.crypto.application_secrets[:client_iv] = keys.client_iv
    conn.crypto.application_secrets[:client_hp] = keys.client_hp
    conn.crypto.application_secrets[:server_key] = keys.server_key
    conn.crypto.application_secrets[:server_iv] = keys.server_iv
    conn.crypto.application_secrets[:server_hp] = keys.server_hp

    # Mark handshake as complete
    complete_handshake(conn.handshake)
    conn.connected = true

    epoch = MLS.get_epoch(conn.mls_conn)
    println(" MLS handshake complete (epoch $epoch)")
end

"""
Check if MLS handshake is complete
"""
function is_mls_handshake_complete(conn::Connection)
    if !conn.use_mls || conn.mls_conn === nothing
        return false
    end
    return MLS.is_handshake_complete(conn.mls_conn)
end

"""
Get current MLS epoch
"""
function get_mls_epoch(conn::Connection)
    if !conn.use_mls || conn.mls_conn === nothing
        return UInt64(0)
    end
    return MLS.get_epoch(conn.mls_conn)
end

"""
Export a secret from MLS for application use
"""
function mls_export_secret(conn::Connection, label::String,
                          context::Vector{UInt8}, length::Int)
    if !conn.use_mls || conn.mls_conn === nothing
        error("MLS mode not enabled")
    end
    return MLS.export_secret(conn.mls_conn, label, context, length)
end

# queue frame for coalescing
function queue_frame!(conn::Connection, frame::QuicFrame, space::PacketSpace = Initial)
    pn = current(conn.next_send_pn) + 1
    add_frame!(conn.coalescer, space, frame, pn)
end

# flush coalesced packets
function flush_packets!(conn::Connection)
    if conn.remote_addr === nothing
        return 0
    end

    datagram = flush!(conn.coalescer, conn)
    if !isempty(datagram)
        # track packet numbers that were sent
        pn = next!(conn.next_send_pn)
        conn.sent_packets[pn] = (time=time_ns(), data=copy(datagram))

        # send the coalesced datagram
        sent_bytes = send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, datagram)
        conn.bytes_in_flight += length(datagram)

        println(" Sent coalesced datagram: $(length(datagram)) bytes")
        return sent_bytes
    end

    return 0
end

# send frame immediately (non-coalesced)
function send_frame_immediate(conn::Connection, frame::QuicFrame)
    # use the existing send_frame implementation for immediate sending
    send_frame(conn, frame)
end

# auto-flush when coalescer is full
function auto_flush_if_needed!(conn::Connection)
    if length(conn.coalescer.pending_packets) >= 3  # arbitrary threshold
        flush_packets!(conn)
    end
end

# process received ACK frame and update loss detection
function process_ack_frame(conn::Connection, ack::AckFrame, packet_space::LDPacketSpace)
    # update loss detection with received ACK
    on_ack_received!(conn.loss_detection, packet_space, ack)

    # update connection RTT from loss detection
    conn.rtt_ns = conn.loss_detection.smoothed_rtt
end

# handle loss detection timeout
function handle_loss_detection_timeout(conn::Connection)
    if should_send_probe_packets(conn.loss_detection)
        # handle timeout and possibly send probe packets
        on_loss_detection_timeout!(conn.loss_detection)

        # send probe packets if needed
        # for Initial space, send CRYPTO frames
        # for Handshake space, send CRYPTO frames
        # for Application space, send PING frames

        # send a PING frame as probe
        ping_frame = PingFrame()
        queue_frame!(conn, ping_frame, Application)
        flush_packets!(conn)
    end
end

# check and handle timers periodically
function process_timers(conn::Connection)
    if conn.loss_detection.loss_detection_timer !== nothing
        now = time_ns()
        if now >= conn.loss_detection.loss_detection_timer
            handle_loss_detection_timeout(conn)
        end
    end

    # Update pacing state from loss detection
    PacketPacing.update_from_loss_detection!(conn.pacing_state, conn.loss_detection)
end

# Rotate to a new connection ID for path migration
function rotate_connection_id!(conn::Connection)
    new_cid = ConnectionIdManager.initiate_path_migration!(conn.cid_manager)
    if new_cid !== nothing
        conn.remote_cid = new_cid
        println(" Rotated to new connection ID: $(bytes2hex(new_cid.data))")
        return true
    end
    return false
end

# Process received NEW_CONNECTION_ID frame
function process_new_connection_id!(conn::Connection, frame::NewConnectionIdFrame)
    retirement_frames = ConnectionIdManager.process_new_connection_id_frame!(conn.cid_manager, frame)

    # Queue any retirement frames that need to be sent
    for retire_frame in retirement_frames
        queue_frame!(conn, retire_frame, Application)
    end

    println("➕ Processed NEW_CONNECTION_ID frame, seq: $(frame.sequence)")
    return length(retirement_frames)
end

# Process received RETIRE_CONNECTION_ID frame
function process_retire_connection_id!(conn::Connection, frame::RetireConnectionIdFrame)
    new_frames = ConnectionIdManager.process_retire_connection_id_frame!(conn.cid_manager, frame)

    # Queue new connection ID frames to replace retired ones
    for new_frame in new_frames
        queue_frame!(conn, new_frame, Application)
    end

    println("🗑️ Processed RETIRE_CONNECTION_ID frame, seq: $(frame.sequence)")
    return length(new_frames)
end

# Maintain connection IDs by issuing new ones as needed
function maintain_connection_ids!(conn::Connection)
    if ConnectionIdManager.needs_new_connection_ids(conn.cid_manager)
        new_frames = ConnectionIdManager.maintain_connection_ids!(conn.cid_manager)

        # Queue the new connection ID frames
        for frame in new_frames
            queue_frame!(conn, frame, Application)
        end

        if !isempty(new_frames)
            println(" Issued $(length(new_frames)) new connection IDs")
            flush_packets!(conn)
        end

        return length(new_frames)
    end
    return 0
end

# Get current destination connection ID for outgoing packets
function get_destination_cid(conn::Connection)
    current_cid = ConnectionIdManager.get_current_remote_cid(conn.cid_manager)
    return current_cid !== nothing ? current_cid : conn.remote_cid
end

# Validate incoming packet's destination CID
function validate_destination_cid(conn::Connection, cid::ConnectionId)
    return ConnectionIdManager.is_valid_destination_cid(conn.cid_manager, cid)
end

# Get connection ID statistics for debugging
function get_cid_statistics(conn::Connection)
    return ConnectionIdManager.get_cid_stats(conn.cid_manager)
end

# Get packet pacing statistics
function get_pacing_statistics(conn::Connection)
    return PacketPacing.get_pacing_stats(conn.pacing_state)
end

# Enable or disable packet pacing
function set_pacing_enabled!(conn::Connection, enabled::Bool)
    PacketPacing.set_pacing_enabled!(conn.pacing_state, enabled)
    println(" Packet pacing $(enabled ? "enabled" : "disabled")")
end

# Update pacing parameters based on network conditions
function update_pacing_parameters!(conn::Connection)
    # Update pacing rate based on current congestion control state
    PacketPacing.update_pacing_rate!(conn.pacing_state, conn.cwnd, conn.rtt_ns)

    # Update burst size based on RTT
    PacketPacing.update_burst_size!(conn.pacing_state, conn.rtt_ns)

    # Log current pacing state
    stats = get_pacing_statistics(conn)
    println(" Updated pacing: rate=$(Int(stats.pacing_rate)) B/s, burst=$(stats.burst_size) bytes")
end

# Check if pacing would significantly delay transmission
function would_pacing_delay(conn::Connection, packet_size::UInt64)
    return PacketPacing.would_pace_significantly(conn.pacing_state, packet_size)
end

# Force immediate send (bypass pacing - use carefully)
function send_immediate_bypassing_pacing(conn::Connection, data::Vector{UInt8})
    if conn.remote_addr !== nothing
        send(conn.socket, conn.remote_addr.host, conn.remote_addr.port, data)
        println(" Sent $(length(data)) bytes bypassing pacing")
    end
end

# Enable HTTP/3 support on connection
function enable_http3!(conn::Connection)
    if conn.http3 === nothing
        conn.http3 = HTTP3.HTTP3Connection()
        HTTP3.initialize_http3_connection!(conn.http3, conn.is_client)

        # Send initial SETTINGS frame on control stream
        control_stream = open_stream(conn, false)  # unidirectional for control
        conn.http3.control_stream_id = control_stream.value

        # Mark stream as HTTP/3 control stream
        control_stream_type = UInt8[]
        encode_varint!(control_stream_type, VarInt(HTTP3.HTTP3_STREAM_CONTROL))

        # Send stream type
        send_stream(conn, control_stream, control_stream_type, false)

        # Send SETTINGS frame
        settings_frame = HTTP3.create_settings_frame(conn.http3)
        settings_data = UInt8[]
        HTTP3.encode_http3_frame!(settings_data, settings_frame)
        send_stream(conn, control_stream, settings_data, false)

        println(" HTTP/3 enabled on connection")
        println("   Control stream: $(control_stream.value)")
        return true
    end

    return false
end

# Send HTTP/3 request
function send_http_request!(conn::Connection, method::String, path::String,
                           headers::Dict{String, String} = Dict{String, String}(),
                           body::Union{Vector{UInt8}, String} = UInt8[])
    if conn.http3 === nothing
        enable_http3!(conn)
    end

    # Open new bidirectional stream for request
    request_stream = open_stream(conn, true)

    # Create and send HEADERS frame
    headers_frame = HTTP3.create_http_request(method, path, headers)
    headers_data = UInt8[]
    HTTP3.encode_http3_frame!(headers_data, headers_frame)

    send_stream(conn, request_stream, headers_data, false)

    # Send body if present
    if !isempty(body)
        body_data = body isa String ? Vector{UInt8}(body) : body
        data_frame = HTTP3.HTTP3DataFrame(body_data)
        frame_data = UInt8[]
        HTTP3.encode_http3_frame!(frame_data, data_frame)
        send_stream(conn, request_stream, frame_data, true)  # FIN with body
    else
        # Send empty DATA frame with FIN to close request
        data_frame = HTTP3.HTTP3DataFrame(UInt8[])
        frame_data = UInt8[]
        HTTP3.encode_http3_frame!(frame_data, data_frame)
        send_stream(conn, request_stream, frame_data, true)
    end

    println(" HTTP/3 $method request sent to $path")
    println("   Stream: $(request_stream.value)")
    println("   Headers: $headers")

    return request_stream
end

# Send HTTP/3 response
function send_http_response!(conn::Connection, stream_id::StreamId, status::Int,
                            headers::Dict{String, String} = Dict{String, String}(),
                            body::Union{Vector{UInt8}, String} = UInt8[])
    if conn.http3 === nothing
        println(" HTTP/3 not enabled on connection")
        return false
    end

    # Create and send HEADERS frame
    headers_frame = HTTP3.create_http_response(status, headers)
    headers_data = UInt8[]
    HTTP3.encode_http3_frame!(headers_data, headers_frame)

    send_stream(conn, stream_id, headers_data, false)

    # Send body if present
    if !isempty(body)
        body_data = body isa String ? Vector{UInt8}(body) : body
        data_frame = HTTP3.HTTP3DataFrame(body_data)
        frame_data = UInt8[]
        HTTP3.encode_http3_frame!(frame_data, data_frame)
        send_stream(conn, stream_id, frame_data, true)  # FIN with body
    else
        # Send empty DATA frame with FIN to close response
        data_frame = HTTP3.HTTP3DataFrame(UInt8[])
        frame_data = UInt8[]
        HTTP3.encode_http3_frame!(frame_data, data_frame)
        send_stream(conn, stream_id, frame_data, true)
    end

    println(" HTTP/3 response sent: $status")
    println("   Stream: $(stream_id.value)")
    println("   Headers: $headers")

    return true
end

# Process HTTP/3 data received on a stream
function process_http3_data!(conn::Connection, stream_id::UInt64, data::Vector{UInt8})
    if conn.http3 === nothing
        # Not an HTTP/3 connection
        return nothing
    end

    # Check if this is the control stream
    if conn.http3.control_stream_id == stream_id || conn.http3.peer_control_stream_id == stream_id
        return process_http3_control_stream!(conn, stream_id, data)
    end

    # Process as HTTP/3 frames
    pos = 1
    frames = HTTP3.HTTP3Frame[]

    while pos <= length(data)
        frame, new_pos = HTTP3.decode_http3_frame(data[pos:end])
        if frame === nothing
            break
        end

        push!(frames, frame)
        pos += new_pos - 1
    end

    for frame in frames
        process_http3_frame!(conn, stream_id, frame)
    end

    return frames
end

# Process HTTP/3 control stream
function process_http3_control_stream!(conn::Connection, stream_id::UInt64, data::Vector{UInt8})
    if conn.http3.peer_control_stream_id === nothing
        # First data on peer control stream - check stream type
        if !isempty(data) && data[1] == HTTP3.HTTP3_STREAM_CONTROL
            conn.http3.peer_control_stream_id = stream_id
            println(" Peer HTTP/3 control stream identified: $stream_id")
            # Process remaining data
            if length(data) > 1
                return process_http3_data!(conn, stream_id, data[2:end])
            end
        end
        return nothing
    end

    # Process control stream frames
    return process_http3_data!(conn, stream_id, data)
end

# Process individual HTTP/3 frame
function process_http3_frame!(conn::Connection, stream_id::UInt64, frame::HTTP3.HTTP3Frame)
    if frame isa HTTP3.HTTP3SettingsFrame
        println(" Received HTTP/3 SETTINGS frame")
        HTTP3.process_settings_frame!(conn.http3, frame)

        for (id, value) in frame.settings
            setting_name = if id == HTTP3.HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY
                "QPACK_MAX_TABLE_CAPACITY"
            elseif id == HTTP3.HTTP3_SETTING_MAX_FIELD_SECTION_SIZE
                "MAX_FIELD_SECTION_SIZE"
            elseif id == HTTP3.HTTP3_SETTING_QPACK_BLOCKED_STREAMS
                "QPACK_BLOCKED_STREAMS"
            else
                "Unknown($id)"
            end
            println("   $setting_name = $value")
        end

    elseif frame isa HTTP3.HTTP3HeadersFrame
        println(" Received HTTP/3 HEADERS frame on stream $stream_id")
        headers = HTTP3.decode_headers_qpack(frame.encoded_headers)

        # Check if this is a request or response
        if haskey(headers, ":method")
            # This is a request
            request_state = HTTP3.process_http3_request!(conn.http3, stream_id, frame)
            println("   Request: $(request_state.method) $(request_state.path)")

            for (name, value) in headers
                if !startswith(name, ":")
                    println("   $name: $value")
                end
            end
        else
            # This is a response
            status = get(headers, ":status", "")
            println("   Response: $status")

            for (name, value) in headers
                if !startswith(name, ":")
                    println("   $name: $value")
                end
            end
        end

    elseif frame isa HTTP3.HTTP3DataFrame
        println(" Received HTTP/3 DATA frame on stream $stream_id: $(length(frame.data)) bytes")
        if haskey(conn.http3.request_streams, stream_id)
            HTTP3.add_request_data!(conn.http3, stream_id, frame.data, false)
        end

        # Print data if it looks like text
        if length(frame.data) < 200 && all(c -> c >= 32 || c in [9, 10, 13], frame.data)
            println("   Data: \"$(String(frame.data))\"")
        end

    elseif frame isa HTTP3.HTTP3GoAwayFrame
        println(" Received HTTP/3 GOAWAY frame: stream $(frame.stream_id)")
        conn.http3.goaway_received = true

    else
        println(" Received HTTP/3 frame: $(typeof(frame))")
    end
end

export Connection, open_stream, send_stream, send_frame
export initiate_handshake, process_handshake_data
export queue_frame!, flush_packets!, send_frame_immediate
export process_ack_frame, handle_loss_detection_timeout, process_timers
export rotate_connection_id!, process_new_connection_id!, process_retire_connection_id!
export maintain_connection_ids!
export get_pacing_statistics, set_pacing_enabled!, update_pacing_parameters!
export enable_http3!, send_http_request!, send_http_response!, process_http3_data!

# MLS exports
export initiate_mls_handshake, process_mls_crypto_data, complete_mls_handshake!
export is_mls_handshake_complete, get_mls_epoch, mls_export_secret

end # module ConnectionModule
