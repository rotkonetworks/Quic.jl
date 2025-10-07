# Quic.jl

A Julia implementation of the QUIC transport protocol with QuicNet compatibility
aspirations. This is experimental software that prioritizes correctness over
performance abstractions that compromise security.

## Status

This implementation is incomplete and should not be used in production. The TLS
1.3 implementation lacks proper mutual authentication, making it fundamentally
insecure for QuicNet's threat model. Don't use this for anything that matters.

## Architecture

Unlike most QUIC implementations that properly leverage existing TLS libraries,
this project attempted to implement the cryptographic components from scratch.
This was a mistake. Security-critical code requires extensive auditing and
battle-testing that this codebase lacks.

### What Works

- Basic QUIC v1 packet structure
- Initial handshake packets
- Ed25519 cryptography via libsodium bindings
- X.509 certificate generation (poorly)
- 0-RTT session resumption (untested in adversarial conditions)

### What Doesn't

- TLS 1.3 client certificate authentication
- Proper certificate validation
- Connection migration
- Most congestion control algorithms
- Actual QuicNet protocol compatibility

## Security Considerations

This implementation has numerous security flaws:

1. **No proper TLS implementation**: We don't send Certificate/CertificateVerify
   messages, making mutual authentication impossible
2. **Unvalidated crypto**: Hand-rolled cryptographic protocols are always broken
3. **No constant-time operations**: Timing side-channels everywhere
4. **Memory unsafe patterns**: Julia's GC doesn't zero secrets
5. **No protocol downgrade protection**: Vulnerable to version rollback

## Dependencies

The project uses several external libraries, each with their own attack surface:

- `Sodium.jl` - libsodium bindings (the only properly implemented crypto)
- `MbedTLS.jl` - Incomplete TLS wrapper we barely use
- `SHA.jl` - Pure Julia SHA implementation (why?)
- `ChaChaCiphers.jl` - Another crypto dependency to increase attack surface

## Why This Approach Failed

The Rust QuicNet implementation correctly uses:
- `quinn` for QUIC (40,000+ lines of battle-tested code)
- `rustls` for TLS (proper certificate handling)
- `rcgen` for certificate generation (does ASN.1 correctly)

We tried to implement all of this ourselves in a few thousand lines. This is hubris.

## Correct Approach

```julia
# Don't implement QUIC yourself
# Use FFI to proven implementations
const libquicnet = "path/to/tested/quic/library.so"
ccall((:quic_connect, libquicnet), ...)
```

## Building

Don't. But if you insist:

```julia
using Pkg
Pkg.add(path=".")
```

## Testing

The test suite is inadequate. It doesn't test:
- Malformed packets
- State machine violations
- Cryptographic edge cases
- Timing attacks
- Memory corruption

## QuicNet Compatibility

QuicNet requires Ed25519-based TLS client certificates in the handshake. We
generate the certificates but never send them because our TLS implementation is
incomplete. The server correctly rejects our connections with "authentication
failed".

This is the correct behavior. An incomplete security protocol is worse than no
protocol.

## Performance

Performance is irrelevant when the implementation is incorrect. Fix the security
issues first, optimize never (because you should use a real implementation
instead).

## Contributing

Don't contribute to this. Contribute to proper QUIC implementations like quinn,
quiche, or picoquic instead. They have actual security reviews and thousands of
hours of testing.

If you must work on Julia QUIC, create FFI bindings to existing implementations
rather than rolling your own crypto.

## License

MIT, but using this code would be negligent.

## Conclusion

This project demonstrates why you shouldn't implement security-critical network
protocols from scratch. Use existing, audited implementations. The hybrid
approach (FFI to proven libraries) is the only responsible path forward.

The code might look like it works, but it's fundamentally broken in ways that
enable active attackers. In security, "mostly working" means "completely
broken".
