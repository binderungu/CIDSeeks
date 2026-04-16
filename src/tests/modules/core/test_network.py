from __future__ import annotations

from dataclasses import dataclass, field
import math
import random

import networkx as nx

from simulation.core.network import Network


@dataclass
class DummyNode:
    id: int
    neighbors: list["DummyNode"] = field(default_factory=list)


def _reachable_count(network: Network, start: int = 0) -> int:
    visited: set[int] = set()
    stack = [start]
    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        stack.extend(network.adjacency_list.get(current, set()) - visited)
    return len(visited)


def _neighbor_ids(nodes: list[DummyNode], index: int) -> list[int]:
    return sorted(node.id for node in nodes[index].neighbors)


def test_initialize_from_graph_exposes_consistent_metrics() -> None:
    nodes = [DummyNode(i) for i in range(4)]
    network = Network(nodes, rng=random.Random(11))

    network.initialize_from_graph(nx.path_graph(4))

    assert network.get_degree(0) == 1
    assert network.get_degree(1) == 2
    assert network.get_neighbors(1) == [0, 2]
    assert _neighbor_ids(nodes, 2) == [1, 3]
    assert math.isclose(network.get_average_degree(), 1.5, rel_tol=0, abs_tol=1e-9)
    assert math.isclose(network.get_clustering_coefficient(), 0.0, rel_tol=0, abs_tol=1e-9)
    assert math.isclose(network.get_average_path_length(), 10 / 6, rel_tol=0, abs_tol=1e-9)

    metrics = network.get_network_metrics()
    assert metrics["is_connected"] is True
    assert math.isclose(metrics["density"], 0.5, rel_tol=0, abs_tol=1e-9)
    assert metrics["diameter"] == 3
    assert math.isclose(metrics["avg_path_length"], 10 / 6, rel_tol=0, abs_tol=1e-9)


def test_initialize_from_graph_repairs_disconnected_components() -> None:
    nodes = [DummyNode(i) for i in range(4)]
    network = Network(nodes, rng=random.Random(7))
    graph = nx.Graph()
    graph.add_nodes_from(range(4))
    graph.add_edges_from([(0, 1), (2, 3)])

    network.initialize_from_graph(graph)

    assert _reachable_count(network) == 4
    for i in range(4):
        assert sorted(network.adjacency_list[i]) == _neighbor_ids(nodes, i)

    metrics = network.get_network_metrics()
    assert metrics["is_connected"] is True
    assert math.isfinite(float(metrics["avg_path_length"]))


def test_initialize_connections_keeps_neighbors_in_sync_with_adjacency() -> None:
    nodes = [DummyNode(i) for i in range(5)]
    network = Network(nodes, rng=random.Random(3))

    network.initialize_connections(connectivity=0.0)

    assert _reachable_count(network) == len(nodes)
    for i in range(len(nodes)):
        assert sorted(network.adjacency_list[i]) == _neighbor_ids(nodes, i)
        assert i not in network.adjacency_list[i]
