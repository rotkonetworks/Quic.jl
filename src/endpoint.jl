module EndpointModule

using ..Protocol
using ..Packet
using ..ConnectionModule
using ..GFWMitigation
using Sockets

mutable struct EndpointConfig
    server_name::Union{String, Nothing}
    alpn_protocols::Vector{String}
    max_idle_timeout_ms::UInt64

    # GFW censorship mitigation
    gfw_mitigation::GFWMitigationConfig

    function EndpointConfig(;
        server_name::Union{String, Nothing} = nothing,
        alpn_protocols::Vector{String} = String[],
        max_idle_timeout_ms::UInt64 = UInt64(30000),
        gfw_mitigation::GFWMitigationConfig = GFWMitigation.default_config()
    )
        new(server_name, alpn_protocols, max_idle_timeout_ms, gfw_mitigation)
    end
end

# Convenience constructor for China-optimized endpoint
function ChinaEndpointConfig(;
    server_name::Union{String, Nothing} = nothing,
    alpn_protocols::Vector{String} = String[]
)
    EndpointConfig(
        server_name = server_name,
        alpn_protocols = alpn_protocols,
        gfw_mitigation = GFWMitigation.china_config()
    )
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

# client connect with GFW mitigation support
function connect(endpoint::Endpoint, addr::Sockets.InetAddr)
    config = endpoint.config.gfw_mitigation

    # Apply port selection strategy if enabled
    actual_addr = addr
    if GFWMitigation.should_select_port(config)
        recommended_port = GFWMitigation.get_recommended_dest_port(config)
        if addr.port != recommended_port
            # Log recommendation but use original port
            # (server must be configured to listen on high port)
        end
    end

    conn = Connection(endpoint.socket, true; gfw_config=config)
    conn.remote_addr = actual_addr

    # save initial DCID for retry validation
    conn.initial_dcid = conn.remote_cid

    # Apply GFW mitigations before handshake
    if config.enabled
        # Send dummy packet to prime the flow (GFW will track this as first packet)
        if GFWMitigation.should_send_dummy(config)
            dummy = GFWMitigation.generate_dummy_packet(config)
            send(endpoint.socket, actual_addr.host, actual_addr.port, dummy)

            # Optional delay after dummy packet
            if config.dummy_packet_delay_ms > 0
                sleep(config.dummy_packet_delay_ms / 1000.0)
            end
        end

        # Send version negotiation probe if configured
        if GFWMitigation.should_version_negotiate(config)
            probe = GFWMitigation.create_version_probe_packet(
                conn.remote_cid.data,
                conn.local_cid.data
            )
            send(endpoint.socket, actual_addr.host, actual_addr.port, probe)
        end
    end

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

export Endpoint, EndpointConfig, ChinaEndpointConfig, connect, accept

end # module EndpointModule
