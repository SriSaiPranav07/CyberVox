# Independent Threat Detection Engines

The platform implements 6 specialized detection modules corresponding to core network threat vectors.

---

## 1. Volumetric & Protocol DDoS (`DdosDetector`)
- **Target Threat Classes**: `DDoS_SYN_FLOOD`, `DDoS_UDP_FLOOD`, `DDoS_AMPLIFICATION`, `DDoS_SPOOFED_SOURCE`
- **Detection Methodology**:
  - Sliding time window (1s & 5s) rate tracking: SYN packets/sec, UDP packets/sec, total bytes/sec.
  - Source IP Shannon Entropy: $H_{src} > 0.85$ bits indicates distributed spoofed origins or massive botnet reflection.
  - Destination Concentration Index: Ratio of traffic targeted at a single host vs. entire subnet ($> 0.80$).
  - Amplification Ratio: Response-to-request byte volume ratio for UDP services (DNS port 53, NTP port 123, SSDP port 1900, Memcached port 11211).

---

## 2. Botnet C2 Beaconing (`C2BeaconDetector`)
- **Target Threat Classes**: `C2_BEACONING`, `C2_PERIODIC_HEARTBEAT`
- **Detection Methodology**:
  - Passive tracking of connection timestamps for distinct `(Source IP, Destination IP, Port)` tuples.
  - Inter-Arrival Time (IAT) statistics: Mean $\mu_{iat}$, Standard Deviation $\sigma_{iat}$.
  - Jitter Coefficient of Variation: $CV = \frac{\sigma_{iat}}{\mu_{iat}}$. A $CV < 0.15$ indicates robotic programmatic beaconing rather than human browsing.
  - Autocorrelation & Fast Fourier Transform (FFT) regularity peak scoring.

---

## 3. DGA Domains & DNS Tunnelling (`DnsThreatDetector`)
- **Target Threat Classes**: `DGA_DOMAIN`, `DNS_TUNNELLING`, `SUSPICIOUS_DNS`
- **Detection Methodology** (Strictly Read-Only Metadata — No Active Resolution):
  - Label Shannon Entropy: $H_{label} \ge 3.65$ bits detects randomized DGA names.
  - Structural Character Analysis: Vowel-to-consonant ratios, consecutive consonant runs ($\ge 5$), digit ratios.
  - DNS Tunnelling Encapsulation: Subdomain nesting depth ($> 4$), query length ($> 35$ characters), hex/base32 payload chunk pattern recognition, and TXT/NULL record metadata analysis.

---

## 4. Encrypted Traffic Analysis (`EncryptedTrafficDetector`)
- **Target Threat Classes**: `TLS_METADATA_ANOMALY`, `SUSPICIOUS_JA3_FINGERPRINT`, `ENCRYPTED_BURST_PATTERN`
- **Detection Methodology** (Strictly Zero Payload Decryption):
  - Passive ClientHello extraction: JA3 MD5 hashes and JA4 fingerprints.
  - Signatures matched against known C2 frameworks (Cobalt Strike, TrickBot, Metasploit, AsyncRAT).
  - Packet length burst sequence dispersion: Constant MTU packet bursts with near-zero standard deviation ($\sigma_{pkt} < 15$ bytes) indicating automated tunnel encapsulation.

---

## 5. Reconnaissance & Port Scanning (`ReconnaissanceDetector`)
- **Target Threat Classes**: `PORT_SCAN`, `HOST_SCAN`, `HORIZONTAL_SCAN`, `VERTICAL_SCAN`
- **Detection Methodology**:
  - Fan-out analysis: Unique destination ports swept per source IP ($> 15$ ports indicates vertical scan).
  - Subnet sweep: Unique destination hosts contacted on identical ports ($> 15$ hosts indicates horizontal discovery).
  - Velocity tracking: Scan attempt frequency (probes/sec).

---

## 6. Potential Data Exfiltration (`DataExfiltrationDetector`)
- **Target Threat Classes**: `POTENTIAL_DATA_EXFILTRATION`, `DATA_EXFILTRATION`
- **Detection Methodology**:
  - Asymmetric byte transfer ratio: $\frac{\text{Outbound Bytes}}{\text{Inbound Bytes}} > 8.0$.
  - Sustained egress volume: Outbound transfer payload exceeding baseline ($> 500\text{ KB}$ single flow or continuous stream).
  - Labeled carefully as **Potential Data Exfiltration** per cybersecurity intelligence standards.
