"""
Flow Aggregator with Sliding & Tumbling Time Windows for SIH 2026.
Maintains streaming state over configurable windows (1s, 5s, 30s, 60s) for temporal and volumetric correlation.
"""

from collections import deque, defaultdict
from typing import List, Dict, Any, Optional
from app.models.schemas import RawFlowRecord
from app.config import settings

class SlidingWindowFlowAggregator:
    """
    Maintains ring-buffered sliding time windows of flows with O(1) IP indexing.
    """
    def __init__(self, max_window_sec: float = 60.0, max_items: int = 5000):
        self.max_window_sec = max_window_sec
        self.max_items = max_items
        self.flows: deque[RawFlowRecord] = deque(maxlen=max_items)
        self.dst_index: Dict[str, deque[RawFlowRecord]] = defaultdict(lambda: deque(maxlen=500))
        self.src_index: Dict[str, deque[RawFlowRecord]] = defaultdict(lambda: deque(maxlen=500))
        
    def add_flow(self, flow: RawFlowRecord):
        """Appends flow and updates indices."""
        self.flows.append(flow)
        self.dst_index[flow.destination_ip].append(flow)
        self.src_index[flow.source_ip].append(flow)
        self._evict_expired(flow.timestamp)

    def _evict_expired(self, current_time: float):
        min_allowed_time = current_time - self.max_window_sec
        while self.flows and self.flows[0].timestamp < min_allowed_time:
            self.flows.popleft()

    def get_window_flows(self, window_sec: float = 5.0) -> List[RawFlowRecord]:
        """Returns flows that occurred within the last window_sec seconds."""
        if not self.flows:
            return []
        current_time = self.flows[-1].timestamp
        cutoff = current_time - window_sec
        # Scan from recent backwards for efficiency
        res = []
        for f in reversed(self.flows):
            if f.timestamp < cutoff:
                break
            res.append(f)
        return res

    def get_dst_flows(self, dst_ip: str, window_sec: float = 5.0) -> List[RawFlowRecord]:
        """Returns flows for a specific destination IP in O(k) time."""
        queue = self.dst_index.get(dst_ip)
        if not queue:
            return []
        current_time = self.flows[-1].timestamp if self.flows else queue[-1].timestamp
        cutoff = current_time - window_sec
        return [f for f in queue if f.timestamp >= cutoff]

    def get_src_flows(self, src_ip: str, window_sec: float = 5.0) -> List[RawFlowRecord]:
        """Returns flows for a specific source IP in O(k) time."""
        queue = self.src_index.get(src_ip)
        if not queue:
            return []
        current_time = self.flows[-1].timestamp if self.flows else queue[-1].timestamp
        cutoff = current_time - window_sec
        return [f for f in queue if f.timestamp >= cutoff]

    def clear(self):
        self.flows.clear()
        self.dst_index.clear()
        self.src_index.clear()

    @property
    def size(self) -> int:
        return len(self.flows)
