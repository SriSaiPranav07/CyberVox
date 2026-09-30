"""
High-performance deterministic feature extraction engine for passive network traffic analysis.
Computes sliding-window network metrics, Shannon entropy, IAT periodicity, DNS metadata, and TLS fingerprints.
"""

import math
import hashlib
from collections import Counter
from typing import List, Dict, Any, Optional
import numpy as np
from app.models.schemas import RawFlowRecord

def calculate_shannon_entropy(data_seq) -> float:
    """
    Computes Shannon Entropy: H(X) = - sum(p(x) * log2(p(x)))
    Returns normalized or raw entropy in bits.
    """
    if not data_seq:
        return 0.0
    length = len(data_seq)
    if length <= 1:
        return 0.0
    
    counts = Counter(data_seq)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def calculate_dns_features(domain: str) -> Dict[str, Any]:
    """
    Extracts structural, character-level, and entropy features from DNS query strings without resolution.
    """
    if not domain:
        return {
            "domain_length": 0,
            "shannon_entropy": 0.0,
            "digit_ratio": 0.0,
            "vowel_ratio": 0.0,
            "subdomain_count": 0,
            "consecutive_consonants_max": 0,
            "has_hex_pattern": False,
        }
    
    clean_domain = domain.lower().strip(".")
    parts = clean_domain.split(".")
    main_label = parts[0] if parts else clean_domain
    
    length = len(clean_domain)
    main_len = len(main_label)
    
    # Entropy of the primary subdomain/label
    entropy = calculate_shannon_entropy(main_label)
    
    # Character ratios
    digits = sum(c.isdigit() for c in clean_domain)
    vowels = sum(c in "aeiou" for c in clean_domain)
    letters = sum(c.isalpha() for c in clean_domain)
    
    digit_ratio = round(digits / length, 4) if length > 0 else 0.0
    vowel_ratio = round(vowels / letters, 4) if letters > 0 else 0.0
    
    # Consecutive consonants count (common in random DGA)
    max_consonants = 0
    curr_consonants = 0
    for c in main_label:
        if c.isalpha() and c not in "aeiou":
            curr_consonants += 1
            if curr_consonants > max_consonants:
                max_consonants = curr_consonants
        else:
            curr_consonants = 0
            
    # Hex pattern check (e.g. DNS tunnelling chunks like '4a7f9b2c')
    has_hex = False
    if main_len >= 8:
        hex_chars = sum(c in "0123456789abcdef" for c in main_label)
        if hex_chars / main_len > 0.85:
            has_hex = True
            
    return {
        "domain_length": length,
        "main_label_length": main_len,
        "shannon_entropy": entropy,
        "digit_ratio": digit_ratio,
        "vowel_ratio": vowel_ratio,
        "subdomain_count": len(parts),
        "consecutive_consonants_max": max_consonants,
        "has_hex_pattern": has_hex,
    }

def calculate_time_series_periodicity(timestamps: List[float]) -> Dict[str, Any]:
    """
    Calculates Inter-Arrival Time (IAT) statistics, Jitter, Coefficient of Variation,
    and autocorrelation periodicity peak for Botnet C2 beacon detection.
    """
    if len(timestamps) < 3:
        return {
            "mean_iat_sec": 0.0,
            "std_iat_sec": 0.0,
            "jitter_cv": 1.0,
            "is_periodic": False,
            "periodicity_score": 0.0,
            "sample_count": len(timestamps)
        }
    
    # Sort timestamps
    sorted_ts = sorted(timestamps)
    iats = [sorted_ts[i] - sorted_ts[i-1] for i in range(1, len(sorted_ts))]
    
    # Filter out near-zero simultaneous packets
    valid_iats = [iat for iat in iats if iat > 0.0001]
    if len(valid_iats) < 2:
        return {
            "mean_iat_sec": 0.0,
            "std_iat_sec": 0.0,
            "jitter_cv": 1.0,
            "is_periodic": False,
            "periodicity_score": 0.0,
            "sample_count": len(timestamps)
        }
        
    mean_iat = float(np.mean(valid_iats))
    std_iat = float(np.std(valid_iats))
    
    # Coefficient of Variation: CV = std / mean
    # A true C2 beacon has very low CV (e.g. CV < 0.10 or CV < 0.20 with light jitter)
    cv = (std_iat / mean_iat) if mean_iat > 0 else 1.0
    
    # Periodicity score (0.0 to 1.0)
    # High score indicates strict periodicity
    periodicity_score = max(0.0, min(1.0, 1.0 - (cv / 0.5))) if cv < 0.5 else 0.0
    is_periodic = (cv < 0.20) and (len(timestamps) >= 4) and (mean_iat >= 0.5)
    
    return {
        "mean_iat_sec": round(mean_iat, 3),
        "std_iat_sec": round(std_iat, 4),
        "jitter_cv": round(cv, 4),
        "is_periodic": is_periodic,
        "periodicity_score": round(periodicity_score, 4),
        "sample_count": len(timestamps)
    }

def calculate_window_features(flows: List[RawFlowRecord]) -> Dict[str, Any]:
    """
    Computes aggregated statistical features over a window of flows.
    """
    if not flows:
        return {}
        
    total_packets = sum(f.packet_count for f in flows)
    total_bytes = sum(f.byte_count for f in flows)
    
    src_ips = [f.source_ip for f in flows]
    dst_ips = [f.destination_ip for f in flows]
    dst_ports = [f.destination_port for f in flows]
    src_ports = [f.source_port for f in flows]
    
    unique_sources = len(set(src_ips))
    unique_dests = len(set(dst_ips))
    unique_dst_ports = len(set(dst_ports))
    unique_src_ports = len(set(src_ports))
    
    src_entropy = calculate_shannon_entropy(src_ips)
    dst_entropy = calculate_shannon_entropy(dst_ips)
    port_entropy = calculate_shannon_entropy(dst_ports)
    
    # Destination concentration: top destination count / total flows
    dst_counts = Counter(dst_ips)
    top_dst_count = dst_counts.most_common(1)[0][1] if dst_counts else 0
    dst_concentration = round(top_dst_count / len(flows), 4) if flows else 0.0
    
    # SYN and UDP counts
    syn_count = sum(f.syn_count or 0 for f in flows)
    udp_count = sum(f.packet_count for f in flows if f.protocol.upper() == "UDP")
    
    # Packet size distribution
    packet_sizes = []
    for f in flows:
        if f.packet_sizes:
            packet_sizes.extend(f.packet_sizes)
        else:
            avg_pkt = f.byte_count / max(1, f.packet_count)
            packet_sizes.append(avg_pkt)
            
    avg_pkt_size = float(np.mean(packet_sizes)) if packet_sizes else 0.0
    std_pkt_size = float(np.std(packet_sizes)) if packet_sizes else 0.0
    
    return {
        "flow_count": len(flows),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "unique_sources": unique_sources,
        "unique_destinations": unique_dests,
        "unique_destination_ports": unique_dst_ports,
        "unique_source_ports": unique_src_ports,
        "source_entropy": src_entropy,
        "destination_entropy": dst_entropy,
        "destination_port_entropy": port_entropy,
        "destination_concentration": dst_concentration,
        "syn_count": syn_count,
        "udp_count": udp_count,
        "avg_packet_size": round(avg_pkt_size, 2),
        "std_packet_size": round(std_pkt_size, 2),
    }

def generate_ja3_fingerprint(tls_version: str, ciphers: List[int], extensions: List[int], elliptic_curves: List[int], ec_point_formats: List[int]) -> str:
    """
    Computes standard JA3 MD5 client fingerprint string from TLS ClientHello parameters.
    Format: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    """
    ciphers_str = "-".join(map(str, ciphers)) if ciphers else ""
    exts_str = "-".join(map(str, extensions)) if extensions else ""
    curves_str = "-".join(map(str, elliptic_curves)) if elliptic_curves else ""
    points_str = "-".join(map(str, ec_point_formats)) if ec_point_formats else ""
    
    ja3_string = f"{tls_version},{ciphers_str},{exts_str},{curves_str},{points_str}"
    return hashlib.md5(ja3_string.encode('utf-8')).hexdigest()
