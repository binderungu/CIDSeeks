from .message import Message, Alarm, Challenge, TrustRequest, TrustResponse

__all__ = [
    'Message',
    'Alarm',
    'Challenge',
    'TrustRequest',
    'TrustResponse',
    'Node',
    'SimulationEngine',
    'Network'
]


def __getattr__(name):
    if name == 'Node':
        from .node import Node
        return Node
    if name == 'SimulationEngine':
        from .simulation_engine import SimulationEngine
        return SimulationEngine
    if name == 'Network':
        from .network import Network
        return Network
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
