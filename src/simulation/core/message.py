from dataclasses import dataclass
from typing import Dict, Any
from datetime import datetime

@dataclass
class Message:
    """Base class for all messages in the simulation"""
    id: str
    type: str
    source_node: str
    target_node: str
    data: Dict[str, Any]
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().timestamp()

@dataclass
class Alarm(Message):
    """Alarm message for reporting suspicious behavior"""
    def __init__(self, source_node: str, target_node: str, data: Dict[str, Any]):
        super().__init__(
            id=f"alarm_{datetime.now().timestamp()}",
            type="alarm",
            source_node=source_node,
            target_node=target_node,
            data=data
        )

@dataclass
class Challenge(Message):
    """Challenge message for trust verification"""
    def __init__(self, source_node: str, target_node: str, data: Dict[str, Any]):
        super().__init__(
            id=f"challenge_{datetime.now().timestamp()}",
            type="challenge", 
            source_node=source_node,
            target_node=target_node,
            data=data
        ) 