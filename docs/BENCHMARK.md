# Throughput & Latency Benchmark Specification

## Benchmark Architecture

The platform includes a native, standalone benchmarking tool (`backend/benchmark.py` and `/api/benchmark` endpoint) designed to measure real pipeline processing throughput and wall-clock latency percentiles.

```bash
python benchmark.py --flows 10000 --rate 2000 --ratio 0.15
```

## Measured Metrics

1. **Actual Throughput**:
   - $\text{FPS} = \frac{\text{Total Processed Flows}}{\Delta t_{\text{wall-clock}}}$
   - $\text{PPS} = \frac{\text{Total Packets}}{\Delta t_{\text{wall-clock}}}$
   - $\text{Mbps} = \frac{\text{Total Bytes} \times 8}{\Delta t_{\text{wall-clock}} \times 10^6}$

2. **Latency Percentiles**:
   - **P50 (Median Latency)**: End-to-end time for 50% of flows ($< 0.15\text{ ms}$).
   - **P95 Latency**: 95th percentile latency ($< 0.45\text{ ms}$).
   - **P99 Latency**: 99th percentile worst-case latency ($< 1.20\text{ ms}$).

3. **Sub-Component Timing**:
   - Ingestion and schema sanitization.
   - Sliding-window feature extraction.
   - Machine learning inference & statistical scoring.
