"""
Abstract Base Detector interface for SIH 2026 passive detection modules.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from app.models.schemas import RawFlowRecord, Alert

class BaseThreatDetector(ABC):
    """
    Base class for independent threat detection modules.
    Enforces passive intelligence execution without returning packets or active probing.
    """
    
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def analyze_flow(self, flow: RawFlowRecord, context_window: List[RawFlowRecord]) -> Optional[Alert]:
        """
        Analyzes an individual flow within the current time window.
        Returns a structured Alert if an anomaly or threat is detected, else None.
        """
        pass
