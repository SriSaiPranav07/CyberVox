# One-Way Enclave Security Model & Airgap Assurance

## Threat Model & Enclave Guarantees

In modern intelligence and defense environments, threat detection systems connected to sensitive core networks must guarantee that compromise of the monitoring tool cannot compromise monitored production assets.

### 1. Zero Outgoing Network Socket Creation
- The enclave software is prevented by architecture and code validation from establishing outbound TCP handshakes or sending UDP/ICMP datagrams.
- Monitored assets cannot be probed or scanned.

### 2. Untrusted Input Handling
- Ingested IP packets and flow metadata are treated as strictly untrusted user input.
- All fields (IPs, ports, headers, DNS strings, TLS ClientHello bytes) undergo regex validation and bounds checking (`ReadOnlyIngestValidator`).

### 3. Payload Privacy & Decryption Immunity
- TLS 1.2, TLS 1.3, and QUIC encrypted payloads are never decrypted.
- Session classification relies exclusively on ClientHello metadata (JA3/JA4, cipher suites, SNI) and side-channel packet length distributions.
