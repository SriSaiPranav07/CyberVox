# Feature Engineering Pipeline

## Mathematical Formulations

### 1. Shannon Entropy
Used to detect randomized DGA domains, spoofed IP distributions, and encoded exfiltration chunks:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

### 2. Inter-Arrival Time (IAT) Jitter & Periodicity
Measures regularity in periodic Botnet C2 beaconing heartbeats:
$$\mu_{iat} = \frac{1}{N-1} \sum_{i=2}^N (t_i - t_{i-1})$$
$$\sigma_{iat} = \sqrt{\frac{1}{N-1} \sum_{i=2}^N ((t_i - t_{i-1}) - \mu_{iat})^2}$$
$$\text{Jitter CV} = \frac{\sigma_{iat}}{\mu_{iat}}$$

### 3. Destination Concentration Ratio
$$\text{Concentration} = \frac{\max(\text{Count}(DstIP))}{\sum \text{Total Flows in Window}}$$

### 4. Asymmetric Byte Ratio
$$\text{Byte Ratio} = \frac{\text{Bytes}_{outbound}}{\max(1, \text{Bytes}_{inbound})}$$

---

## Feature Vector Composition for ML

| Index | Feature Name | Description | Units |
|---|---|---|---|
| 0 | `duration_sec` | Total flow active duration | seconds |
| 1 | `packet_count` | Total packets in flow | integer |
| 2 | `byte_count` | Total bytes in flow | bytes |
| 3 | `bytes_per_sec` | Bitrate throughput | bits/sec |
| 4 | `packets_per_sec` | Packet arrival velocity | pkts/sec |
| 5 | `avg_packet_size` | Mean packet payload size | bytes |
| 6 | `syn_ratio` | Ratio of SYN flags to total packets | $[0.0, 1.0]$ |
| 7 | `udp_ratio` | Binary protocol flag (1 for UDP, 0 for TCP) | $\{0, 1\}$ |
| 8 | `dns_query_len` | Character length of DNS query string | chars |
| 9 | `dns_entropy` | Shannon entropy of domain label | bits |
