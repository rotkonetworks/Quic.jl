module Packet

using ..Protocol
using Random

struct ConnectionId
    data::Vector{UInt8}
    
    ConnectionId(data::Vector{UInt8}) = new(data)
    ConnectionId(len::Int=8) = new(rand(UInt8, len))
end

Base.length(cid::ConnectionId) = length(cid.data)
Base.:(==)(a::ConnectionId, b::ConnectionId) = a.data == b.data

mutable struct PacketNumber
    value::UInt64
    PacketNumber() = new(0)
    PacketNumber(value::Integer) = new(UInt64(value))
end

next!(pn::PacketNumber) = (pn.value += 1; pn.value - 1)
current(pn::PacketNumber) = pn.value

abstract type PacketHeader end

struct LongHeader <: PacketHeader
    packet_type::UInt8
    version::UInt32
    dest_cid::ConnectionId
    src_cid::ConnectionId
    token::Vector{UInt8}
    packet_number::UInt64
    payload_length::UInt64
end

struct ShortHeader <: PacketHeader
    dest_cid::ConnectionId
    packet_number::UInt64
end

struct PacketData
    header::PacketHeader
    frames::Vector{Any}  # will be typed as Frame later
    raw::Vector{UInt8}
end

export ConnectionId, PacketNumber, LongHeader, ShortHeader, PacketData
export next!, current

end # module Packet
