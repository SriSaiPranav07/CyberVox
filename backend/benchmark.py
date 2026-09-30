"""
Command-Line Interface Benchmark Runner for SIH 2026.
Usage:
    python benchmark.py --flows 10000 --rate 2000 --ratio 0.15
"""

import argparse
import json
import os
import sys

# Ensure backend directory is in python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.models.schemas import BenchmarkRequest
from app.benchmark.runner import run_benchmark_test

def main():
    parser = argparse.ArgumentParser(description="SIH 2026 Passive Network Threat Detection Throughput Benchmark")
    parser.add_argument("--flows", type=int, default=10000, help="Total number of network flows to process")
    parser.add_argument("--rate", type=int, default=2000, help="Target processing rate (flows/sec)")
    parser.add_argument("--ratio", type=float, default=0.15, help="Threat scenario injection ratio (0.0 - 1.0)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    args = parser.parse_args()

    req = BenchmarkRequest(
        total_flows=args.flows,
        target_rate=args.rate,
        threat_ratio=args.ratio
    )

    print("======================================================================")
    print(" SIH 2026: PASSIVE NETWORK THREAT DETECTION - THROUGHPUT BENCHMARK")
    print("======================================================================")
    print(f"[*] Configuration: {args.flows} Flows | Target Rate: {args.rate} FPS | Threat Ratio: {args.ratio * 100}%")
    print("[*] Enclave Security Mode: Strictly Read-Only Ingest (Zero Return Path)")
    print("[*] Executing high-speed pipeline stream...")

    result = run_benchmark_test(req)

    if args.json:
        print(json.dumps(result.model_dump(), indent=2))
        return

    print("\n------------------------- BENCHMARK RESULTS -------------------------")
    print(f"  Test Run ID                  : {result.test_id}")
    print(f"  Total Processed Flows        : {result.total_flows_processed:,} flows")
    print(f"  Total Test Duration          : {result.duration_sec:.3f} seconds")
    print(f"  Actual Throughput            : {result.actual_flows_per_sec:,.1f} flows/sec")
    print(f"  Packet Rate                  : {result.actual_packets_per_sec:,.1f} packets/sec")
    print(f"  Effective Bandwidth          : {result.actual_mbps:,.2f} Mbps")
    print("----------------------------------------------------------------------")
    print(f"  Average Processing Latency   : {result.avg_latency_ms:.4f} ms")
    print(f"  P50 Median Latency           : {result.p50_latency_ms:.4f} ms")
    print(f"  P95 Latency                  : {result.p95_latency_ms:.4f} ms")
    print(f"  P99 Latency                  : {result.p99_latency_ms:.4f} ms")
    print(f"  Feature Extraction Time      : {result.feature_extraction_time_total_ms:.2f} ms total")
    print(f"  ML Inference Time            : {result.ml_inference_time_total_ms:.2f} ms total")
    print("----------------------------------------------------------------------")
    print(f"  Alerts Generated             : {result.alerts_generated:,} alerts")
    print(f"  Memory Footprint             : {result.memory_usage_mb:.1f} MB")
    print(f"  One-Way Enclave Integrity    : {'PASS (100% Read-Only / Zero Egress)' if result.enclave_integrity_verified else 'FAIL'}")
    print("======================================================================")

if __name__ == "__main__":
    main()
