module QuicheFFI

using Sockets

# Path to libquiche - adjust as needed
const LIBQUICHE = get(ENV, "LIBQUICHE_PATH",
    joinpath(homedir(), "rotko/quiche-ffi/target/release/libquiche.so"))

# QUIC protocol version
const PROTOCOL_VERSION = 0x00000001
const MAX_CONN_ID_LEN = 20
const MIN_CLIENT_INITIAL_LEN = 1200

# Error codes
@enum QuicheError begin
    QUICHE_ERR_DONE = -1
    QUICHE_ERR_BUFFER_TOO_SHORT = -2
    QUICHE_ERR_UNKNOWN_VERSION = -3
    QUICHE_ERR_INVALID_FRAME = -4
    QUICHE_ERR_INVALID_PACKET = -5
    QUICHE_ERR_INVALID_STATE = -6
    QUICHE_ERR_INVALID_STREAM_STATE = -7
    QUICHE_ERR_INVALID_TRANSPORT_PARAM = -8
    QUICHE_ERR_CRYPTO_FAIL = -9
    QUICHE_ERR_TLS_FAIL = -10
    QUICHE_ERR_FLOW_CONTROL = -11
    QUICHE_ERR_STREAM_LIMIT = -12
    QUICHE_ERR_FINAL_SIZE = -13
    QUICHE_ERR_CONGESTION_CONTROL = -14
    QUICHE_ERR_STREAM_STOPPED = -15
    QUICHE_ERR_STREAM_RESET = -16
    QUICHE_ERR_ID_LIMIT = -17
    QUICHE_ERR_OUT_OF_IDENTIFIERS = -18
    QUICHE_ERR_KEY_UPDATE = -19
    QUICHE_ERR_CRYPTO_BUFFER_EXCEEDED = -20
end

# Congestion control algorithms
@enum CongestionControl begin
    CC_RENO = 0
    CC_CUBIC = 1
    CC_BBR = 2
    CC_BBR2 = 3
end

# Opaque pointer types
const QuicheConfig = Ptr{Cvoid}
const QuicheConn = Ptr{Cvoid}

# Recv info struct
struct RecvInfo
    from::Ptr{Cvoid}      # sockaddr pointer
    from_len::Csize_t
    to::Ptr{Cvoid}        # sockaddr pointer
    to_len::Csize_t
end

# Send info struct
struct SendInfo
    to::NTuple{128, UInt8}  # sockaddr_storage
    to_len::Csize_t
    from::NTuple{128, UInt8}
    from_len::Csize_t
    at::Int64  # timespec
end

#= Configuration Functions =#

function quiche_version()
    str = ccall((:quiche_version, LIBQUICHE), Cstring, ())
    return unsafe_string(str)
end

function config_new(version::UInt32 = PROTOCOL_VERSION)
    ccall((:quiche_config_new, LIBQUICHE), QuicheConfig, (UInt32,), version)
end

function config_free(config::QuicheConfig)
    ccall((:quiche_config_free, LIBQUICHE), Cvoid, (QuicheConfig,), config)
end

function config_load_cert_chain(config::QuicheConfig, path::String)
    ret = ccall((:quiche_config_load_cert_chain_from_pem_file, LIBQUICHE),
                Cint, (QuicheConfig, Cstring), config, path)
    return ret == 0
end

function config_load_priv_key(config::QuicheConfig, path::String)
    ret = ccall((:quiche_config_load_priv_key_from_pem_file, LIBQUICHE),
                Cint, (QuicheConfig, Cstring), config, path)
    return ret == 0
end

function config_verify_peer(config::QuicheConfig, verify::Bool)
    ccall((:quiche_config_verify_peer, LIBQUICHE),
          Cvoid, (QuicheConfig, Bool), config, verify)
end

function config_set_application_protos(config::QuicheConfig, protos::Vector{String})
    # Wire format: length-prefixed strings concatenated
    buf = UInt8[]
    for proto in protos
        push!(buf, UInt8(length(proto)))
        append!(buf, Vector{UInt8}(proto))
    end
    ret = ccall((:quiche_config_set_application_protos, LIBQUICHE),
                Cint, (QuicheConfig, Ptr{UInt8}, Csize_t),
                config, buf, length(buf))
    return ret == 0
end

function config_set_max_idle_timeout(config::QuicheConfig, timeout_ms::UInt64)
    ccall((:quiche_config_set_max_idle_timeout, LIBQUICHE),
          Cvoid, (QuicheConfig, UInt64), config, timeout_ms)
end

function config_set_initial_max_data(config::QuicheConfig, v::UInt64)
    ccall((:quiche_config_set_initial_max_data, LIBQUICHE),
          Cvoid, (QuicheConfig, UInt64), config, v)
end

function config_set_initial_max_stream_data_bidi_local(config::QuicheConfig, v::UInt64)
    ccall((:quiche_config_set_initial_max_stream_data_bidi_local, LIBQUICHE),
          Cvoid, (QuicheConfig, UInt64), config, v)
end

function config_set_initial_max_stream_data_bidi_remote(config::QuicheConfig, v::UInt64)
    ccall((:quiche_config_set_initial_max_stream_data_bidi_remote, LIBQUICHE),
          Cvoid, (QuicheConfig, UInt64), config, v)
end

function config_set_initial_max_streams_bidi(config::QuicheConfig, v::UInt64)
    ccall((:quiche_config_set_initial_max_streams_bidi, LIBQUICHE),
          Cvoid, (QuicheConfig, UInt64), config, v)
end

function config_set_initial_max_streams_uni(config::QuicheConfig, v::UInt64)
    ccall((:quiche_config_set_initial_max_streams_uni, LIBQUICHE),
          Cvoid, (QuicheConfig, UInt64), config, v)
end

function config_set_cc_algorithm(config::QuicheConfig, algo::CongestionControl)
    ccall((:quiche_config_set_cc_algorithm, LIBQUICHE),
          Cvoid, (QuicheConfig, Cint), config, Int(algo))
end

#= Connection Functions =#

function connect(server_name::String, scid::Vector{UInt8},
                 local_addr::IPAddr, local_port::UInt16,
                 peer_addr::IPAddr, peer_port::UInt16,
                 config::QuicheConfig)
    # Build sockaddr structures
    local_sa = make_sockaddr(local_addr, local_port)
    peer_sa = make_sockaddr(peer_addr, peer_port)

    conn = ccall((:quiche_connect, LIBQUICHE), QuicheConn,
                 (Cstring, Ptr{UInt8}, Csize_t,
                  Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, QuicheConfig),
                 server_name, scid, length(scid),
                 local_sa, sizeof(local_sa), peer_sa, sizeof(peer_sa), config)
    return conn
end

function accept(scid::Vector{UInt8}, odcid::Union{Vector{UInt8}, Nothing},
                local_addr::IPAddr, local_port::UInt16,
                peer_addr::IPAddr, peer_port::UInt16,
                config::QuicheConfig)
    local_sa = make_sockaddr(local_addr, local_port)
    peer_sa = make_sockaddr(peer_addr, peer_port)

    odcid_ptr = odcid === nothing ? C_NULL : pointer(odcid)
    odcid_len = odcid === nothing ? 0 : length(odcid)

    conn = ccall((:quiche_accept, LIBQUICHE), QuicheConn,
                 (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
                  Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, QuicheConfig),
                 scid, length(scid), odcid_ptr, odcid_len,
                 local_sa, sizeof(local_sa), peer_sa, sizeof(peer_sa), config)
    return conn
end

function conn_recv(conn::QuicheConn, buf::Vector{UInt8}, info::RecvInfo)
    ret = ccall((:quiche_conn_recv, LIBQUICHE), Cssize_t,
                (QuicheConn, Ptr{UInt8}, Csize_t, Ref{RecvInfo}),
                conn, buf, length(buf), info)
    return ret
end

function conn_send(conn::QuicheConn, buf::Vector{UInt8})
    info = Ref{SendInfo}()
    ret = ccall((:quiche_conn_send, LIBQUICHE), Cssize_t,
                (QuicheConn, Ptr{UInt8}, Csize_t, Ref{SendInfo}),
                conn, buf, length(buf), info)
    return ret, info[]
end

function conn_free(conn::QuicheConn)
    ccall((:quiche_conn_free, LIBQUICHE), Cvoid, (QuicheConn,), conn)
end

#= Stream Functions =#

function stream_recv(conn::QuicheConn, stream_id::UInt64, buf::Vector{UInt8})
    fin = Ref{Bool}(false)
    ret = ccall((:quiche_conn_stream_recv, LIBQUICHE), Cssize_t,
                (QuicheConn, UInt64, Ptr{UInt8}, Csize_t, Ref{Bool}),
                conn, stream_id, buf, length(buf), fin)
    return ret, fin[]
end

function stream_send(conn::QuicheConn, stream_id::UInt64, buf::Vector{UInt8}, fin::Bool)
    ret = ccall((:quiche_conn_stream_send, LIBQUICHE), Cssize_t,
                (QuicheConn, UInt64, Ptr{UInt8}, Csize_t, Bool),
                conn, stream_id, buf, length(buf), fin)
    return ret
end

function stream_shutdown(conn::QuicheConn, stream_id::UInt64, direction::Int, err::UInt64)
    ret = ccall((:quiche_conn_stream_shutdown, LIBQUICHE), Cint,
                (QuicheConn, UInt64, Cint, UInt64),
                conn, stream_id, direction, err)
    return ret == 0
end

#= Connection State Functions =#

function is_established(conn::QuicheConn)
    ccall((:quiche_conn_is_established, LIBQUICHE), Bool, (QuicheConn,), conn)
end

function is_closed(conn::QuicheConn)
    ccall((:quiche_conn_is_closed, LIBQUICHE), Bool, (QuicheConn,), conn)
end

function is_in_early_data(conn::QuicheConn)
    ccall((:quiche_conn_is_in_early_data, LIBQUICHE), Bool, (QuicheConn,), conn)
end

function timeout_as_nanos(conn::QuicheConn)
    ccall((:quiche_conn_timeout_as_nanos, LIBQUICHE), UInt64, (QuicheConn,), conn)
end

function on_timeout(conn::QuicheConn)
    ccall((:quiche_conn_on_timeout, LIBQUICHE), Cvoid, (QuicheConn,), conn)
end

function close(conn::QuicheConn, app::Bool, err::UInt64, reason::String)
    reason_bytes = Vector{UInt8}(reason)
    ret = ccall((:quiche_conn_close, LIBQUICHE), Cint,
                (QuicheConn, Bool, UInt64, Ptr{UInt8}, Csize_t),
                conn, app, err, reason_bytes, length(reason_bytes))
    return ret == 0
end

#= Iterator Functions =#

function readable(conn::QuicheConn)
    iter = ccall((:quiche_conn_readable, LIBQUICHE), Ptr{Cvoid}, (QuicheConn,), conn)
    streams = UInt64[]
    stream_id = Ref{UInt64}(0)
    while ccall((:quiche_stream_iter_next, LIBQUICHE), Bool,
                (Ptr{Cvoid}, Ref{UInt64}), iter, stream_id)
        push!(streams, stream_id[])
    end
    ccall((:quiche_stream_iter_free, LIBQUICHE), Cvoid, (Ptr{Cvoid},), iter)
    return streams
end

function writable(conn::QuicheConn)
    iter = ccall((:quiche_conn_writable, LIBQUICHE), Ptr{Cvoid}, (QuicheConn,), conn)
    streams = UInt64[]
    stream_id = Ref{UInt64}(0)
    while ccall((:quiche_stream_iter_next, LIBQUICHE), Bool,
                (Ptr{Cvoid}, Ref{UInt64}), iter, stream_id)
        push!(streams, stream_id[])
    end
    ccall((:quiche_stream_iter_free, LIBQUICHE), Cvoid, (Ptr{Cvoid},), iter)
    return streams
end

#= Helper Functions =#

function make_sockaddr(addr::IPv4, port::UInt16)
    # sockaddr_in structure (16 bytes)
    sa = zeros(UInt8, 16)
    sa[1] = 0x02  # AF_INET (family) - little endian on x86
    sa[2] = 0x00
    sa[3] = UInt8((port >> 8) & 0xff)  # port in network byte order
    sa[4] = UInt8(port & 0xff)
    # IPv4 address
    ip_bytes = reinterpret(UInt8, [addr.host])
    sa[5:8] = ip_bytes
    return sa
end

function make_sockaddr(addr::IPv6, port::UInt16)
    # sockaddr_in6 structure (28 bytes)
    sa = zeros(UInt8, 28)
    sa[1] = 0x0a  # AF_INET6 (family)
    sa[2] = 0x00
    sa[3] = UInt8((port >> 8) & 0xff)
    sa[4] = UInt8(port & 0xff)
    # flowinfo (4 bytes) - zeros
    # IPv6 address (16 bytes)
    sa[9:24] = reinterpret(UInt8, [addr.host])
    # scope_id (4 bytes) - zeros
    return sa
end

#= High-Level Wrapper =#

mutable struct Connection
    ptr::QuicheConn
    config::QuicheConfig

    function Connection(ptr::QuicheConn, config::QuicheConfig)
        conn = new(ptr, config)
        finalizer(conn) do c
            if c.ptr != C_NULL
                conn_free(c.ptr)
                c.ptr = C_NULL
            end
        end
        return conn
    end
end

mutable struct Config
    ptr::QuicheConfig

    function Config(version::UInt32 = PROTOCOL_VERSION)
        ptr = config_new(version)
        cfg = new(ptr)
        finalizer(cfg) do c
            if c.ptr != C_NULL
                config_free(c.ptr)
                c.ptr = C_NULL
            end
        end
        return cfg
    end
end

# JAMNP-S specific configuration
function jamnps_config(genesis_hash::Vector{UInt8}; verify_peer::Bool=true)
    cfg = Config()

    # JAMNP-S ALPN: jamnp-s/0/<first 8 hex chars of genesis hash>
    genesis_prefix = bytes2hex(genesis_hash[1:4])
    alpn = "jamnp-s/0/$genesis_prefix"
    config_set_application_protos(cfg.ptr, [alpn])

    # TLS settings
    config_verify_peer(cfg.ptr, verify_peer)

    # Transport parameters
    config_set_max_idle_timeout(cfg.ptr, UInt64(30000))  # 30 seconds
    config_set_initial_max_data(cfg.ptr, UInt64(10485760))  # 10 MB
    config_set_initial_max_stream_data_bidi_local(cfg.ptr, UInt64(1048576))
    config_set_initial_max_stream_data_bidi_remote(cfg.ptr, UInt64(1048576))
    config_set_initial_max_streams_bidi(cfg.ptr, UInt64(100))
    config_set_initial_max_streams_uni(cfg.ptr, UInt64(100))

    # BBR2 congestion control
    config_set_cc_algorithm(cfg.ptr, CC_BBR2)

    return cfg
end

export Config, Connection, QuicheError, CongestionControl
export config_new, config_free, config_load_cert_chain, config_load_priv_key
export config_verify_peer, config_set_application_protos
export connect, accept, conn_recv, conn_send, conn_free
export stream_recv, stream_send, stream_shutdown
export is_established, is_closed, timeout_as_nanos, on_timeout
export readable, writable, close
export jamnps_config, quiche_version

end # module QuicheFFI
