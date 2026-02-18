"""Collaboration exports for Evaluation-2 runtime.

Canonical implementation lives in `module.py` (`CollaborationModule`).
Legacy `collab_manager.py` has been removed.
"""

from .gossip_protocol import GossipProtocol
from .module import CollaborationModule

__all__ = ["GossipProtocol", "CollaborationModule"]
