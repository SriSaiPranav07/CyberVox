"""
PCAP & Synthetic Replay Engine for SIH 2026.
Feeds replayed or generated flows directly into the exact same streaming detection pipeline.
Supports speed multiplier, pause, resume, stop, and scenario triggering.
"""

import time
import threading
from typing import Optional, List, Dict, Any
from app.models.schemas import ReplayStatus, ReplayRequest
from app.core.pipeline import pipeline
from app.simulator.traffic_generator import SyntheticTrafficGenerator

class ReplayEngine:
    def __init__(self):
        self.is_active: bool = False
        self.is_paused: bool = False
        self.dataset_name: str = "synthetic_enterprise_traffic"
        self.traffic_mode: str = "SYNTHETIC_DEMO"
        self.speed_multiplier: float = 1.0
        self.total_records: int = 0
        self.processed_records: int = 0
        self.processed_packets: int = 0
        self.alerts_generated: int = 0
        self.start_time: float = 0.0
        
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set() # Unpaused by default

    def set_mode(self, mode: str):
        self.traffic_mode = mode
        pipeline.set_traffic_mode(mode)

    def start_replay(self, config: ReplayRequest) -> ReplayStatus:
        if self.is_active:
            self.stop_replay()
            
        self.dataset_name = config.dataset_name
        self.traffic_mode = config.traffic_mode or ("PCAP_REPLAY" if "pcap" in config.dataset_name.lower() else "SYNTHETIC_DEMO")
        pipeline.set_traffic_mode(self.traffic_mode)
        self.speed_multiplier = max(0.1, config.speed_multiplier)
        self.is_active = True
        self.is_paused = False
        self.processed_records = 0
        self.processed_packets = 0
        self.alerts_generated = 0
        self.total_records = 15000
        self.start_time = time.time()
        
        self._stop_event.clear()
        self._pause_event.set()
        
        self._thread = threading.Thread(target=self._run_loop, args=(config,), daemon=True)
        self._thread.start()
        
        return self.get_status()

    def pause_replay(self) -> ReplayStatus:
        if self.is_active:
            self.is_paused = True
            self._pause_event.clear()
        return self.get_status()

    def resume_replay(self) -> ReplayStatus:
        if self.is_active:
            self.is_paused = False
            self._pause_event.set()
        return self.get_status()

    def stop_replay(self) -> ReplayStatus:
        self.is_active = False
        self.is_paused = False
        self._stop_event.set()
        self._pause_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        return self.get_status()

    def trigger_scenario(self, scenario_type: str):
        """Injects a specific threat scenario immediately into the streaming pipeline."""
        flows_to_inject = []
        if scenario_type.upper() == "DDOS":
            flows_to_inject = SyntheticTrafficGenerator.generate_ddos_syn_burst(count=60)
        elif scenario_type.upper() == "C2":
            flows_to_inject = SyntheticTrafficGenerator.generate_c2_beacon(count=8)
        elif scenario_type.upper() == "DGA":
            flows_to_inject = [SyntheticTrafficGenerator.generate_dga_flow() for _ in range(5)]
        elif scenario_type.upper() == "DNS_TUNNELLING":
            flows_to_inject = [SyntheticTrafficGenerator.generate_dns_tunnel_flow() for _ in range(4)]
        elif scenario_type.upper() == "PORT_SCAN":
            flows_to_inject = SyntheticTrafficGenerator.generate_port_scan_burst(num_ports=25)
        elif scenario_type.upper() == "EXFILTRATION":
            flows_to_inject = [SyntheticTrafficGenerator.generate_data_exfiltration_flow()]
            
        for f in flows_to_inject:
            alert = pipeline.process_raw_flow(f)
            self.processed_records += 1
            self.processed_packets += f.get("packet_count", 1)
            if alert:
                self.alerts_generated += 1

    def _run_loop(self, config: ReplayRequest):
        """Continuous background generator producing realistic mixed enterprise traffic and periodic threat bursts."""
        step_delay = max(0.005, 0.05 / self.speed_multiplier)
        iteration = 0
        
        while not self._stop_event.is_set() and self.processed_records < self.total_records:
            self._pause_event.wait() # Block if paused
            if self._stop_event.is_set():
                break

            # Generate baseline benign flow
            flow = SyntheticTrafficGenerator.generate_benign_flow()
            alert = pipeline.process_raw_flow(flow)
            self.processed_records += 1
            self.processed_packets += flow.get("packet_count", 1)
            if alert:
                self.alerts_generated += 1

            iteration += 1

            # Interleave periodic threat demonstrations
            if iteration % 40 == 0:
                self.trigger_scenario("PORT_SCAN")
            elif iteration % 80 == 0:
                self.trigger_scenario("C2")
            elif iteration % 120 == 0:
                self.trigger_scenario("DGA")
            elif iteration % 160 == 0:
                self.trigger_scenario("DNS_TUNNELLING")
            elif iteration % 200 == 0:
                self.trigger_scenario("DDOS")
            elif iteration % 240 == 0:
                self.trigger_scenario("EXFILTRATION")

            time.sleep(step_delay)

        self.is_active = False

    def get_status(self) -> ReplayStatus:
        elapsed = (time.time() - self.start_time) if self.is_active else 0.0
        fps = (self.processed_records / max(0.001, elapsed)) if self.is_active else 0.0
        return ReplayStatus(
            is_active=self.is_active,
            is_paused=self.is_paused,
            dataset_name=self.dataset_name,
            traffic_mode=self.traffic_mode,
            total_records=self.total_records,
            processed_records=self.processed_records,
            processed_packets=self.processed_packets,
            current_rate_fps=round(fps, 1),
            alerts_generated=self.alerts_generated,
            elapsed_time_sec=round(elapsed, 2),
            speed_multiplier=self.speed_multiplier
        )

replay_engine = ReplayEngine()
