module EndpointModule

using ..Protocol
using ..Packet
using ..ConnectionModule
using Sockets

mutable struct EndpointConfig
    server_name::Union{String, Nothing}
    alpn_protocols::Vector{String}
    max_idle_timeout_ms::UInt64
    
    EndpointConfig() = new(nothing, String[], 30000)
end

mutable struct Endpoint
    socket::UDPSocket
    config::EndpointConfig
    connections::Dict{ConnectionId, Connection}
    is_server::Bool
    
    function Endpoint(addr::Sockets.InetAddr, config::EndpointConfig, is_server::Bool)
        sock = UDPSocket()
        is_server && bind(sock, addr.host, addr.port)
        new(sock, config, Dict{ConnectionId, Connection}(), is_server)
    end
end

# client connect
function connect(endpoint::Endpoint, addr::Sockets.InetAddr)
    conn = Connection(endpoint.socket, true)
    conn.remote_addr = addr

    # save initial DCID for retry validation
    conn.initial_dcid = conn.remote_cid

    endpoint.connections[conn.local_cid] = conn
    return conn
end

# server accept
function accept(endpoint::Endpoint)
    # simplified accept - real impl needs proper handshake
    data, addr = recvfrom(endpoint.socket)
    
    # parse initial packet to get client cid
    # simplified - assumes cid at fixed offset
    client_cid = ConnectionId(data[7:14])
    
    conn = Connection(endpoint.socket, false)
    conn.remote_cid = client_cid
    conn.remote_addr = addr
    
    endpoint.connections[conn.local_cid] = conn
    return conn
end

export Endpoint, EndpointConfig, connect, accept

end # module EndpointModule
