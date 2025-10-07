# QUIC Bidirectional Examples

This directory contains examples demonstrating bidirectional QUIC communication between client and server.

## 🚀 Current Implementation Status

**✅ READY FOR BIDIRECTIONAL COMMUNICATION!**

Our Julia QUIC implementation includes:
- ✅ Complete TLS 1.3 handshake with X25519 ECDHE
- ✅ ChaCha20-Poly1305 and AES-GCM encryption
- ✅ Proper ACK processing and loss detection
- ✅ Packet pacing and congestion control
- ✅ Connection ID rotation and path migration
- ✅ Bidirectional stream support
- ✅ Packet coalescing and optimization

## 📁 Example Files

### Core Examples
- `quic_server.jl` - Full QUIC server implementation
- `quic_bidirectional_client.jl` - Complete bidirectional client
- `test_bidirectional.jl` - Test harness and documentation

### Quinn Compatibility
- `quinn_client.jl` - Basic Quinn interoperability client
- `quinn_client_with_loss_detection.jl` - Advanced loss detection demo
- `quinn_client_with_cid_rotation.jl` - Connection ID rotation demo
- `quinn_client_with_pacing.jl` - Packet pacing demonstration

## 🖥️ Running the Examples

### 1. Start QUIC Server
```bash
julia examples/quic_server.jl
```

### 2. Run Bidirectional Client
```bash
# In another terminal
julia examples/quic_bidirectional_client.jl
```

### 3. Test with Quinn (Rust QUIC)
```bash
# Start Quinn server
cargo run --example server

# Run Julia client
julia examples/quinn_client_with_pacing.jl
```

## 🔄 Bidirectional Communication Features

### Multiple Stream Types
- **Control streams**: Connection management, flow control
- **Data streams**: Application data transfer
- **Request-response**: Client queries with server responses
- **Push streams**: Server-initiated data delivery

### Demonstrated Patterns
1. **Simple Echo**: Client sends, server echoes back
2. **Multiple Streams**: Concurrent bidirectional communication
3. **Large Transfers**: Bulk data with pacing and flow control
4. **Burst Messaging**: Rapid fire message exchange

### Performance Features
- **Packet Pacing**: Prevents network congestion
- **Loss Detection**: Automatic retransmission of lost packets
- **Congestion Control**: Adaptive bandwidth utilization
- **Stream Multiplexing**: Multiple conversations per connection

## 📊 Example Output

### Server
```
🚀 QUIC Server starting on port 4433...
🤝 New connection attempt from 127.0.0.1:xxxxx
🎉 Handshake completed with 127.0.0.1:xxxxx
📤 Sent welcome message on stream 1
📥 Received on stream 2: "Hello from Julia QUIC client! 👋"
📤 Sent response: "Server processed: "Hello from Julia QUIC client! 👋" ✅"
```

### Client
```
🔗 Connecting to QUIC server at 127.0.0.1:4433...
🎉 Handshake completed in 45.67 ms!
📥 Received on stream 1: "Hello from Julia QUIC Server! 🚀"
📤 Sent 32 bytes on stream 2: "Hello from Julia QUIC client! 👋"
📥 Response: "Server processed: "Hello from Julia QUIC client! 👋" ✅"
```

## 🔧 Technical Implementation

### Stream Management
```julia
# Open bidirectional stream
stream_id = open_stream(connection, true)

# Send data with flow control
bytes_sent = send_stream(connection, stream_id, data, fin=false)

# Receive data
data, fin_received = read_stream!(stream_state, max_bytes)
```

### Connection Management
```julia
# Monitor connection health
rtt_ms = connection.loss_detection.smoothed_rtt ÷ 1_000_000
cwnd_bytes = connection.cwnd

# Handle connection events
process_timers(connection)
maintain_connection_ids!(connection)
```

## 🎯 Ready for Production Testing!

The QUIC implementation is now complete with full bidirectional communication support!