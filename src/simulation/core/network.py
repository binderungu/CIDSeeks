import logging
import random
from typing import Optional
from typing import List, Dict, Any
import networkx as nx
from .node import Node

class Network:
    """Kelas untuk mengelola jaringan node CIDS"""
    
    def __init__(self, nodes: List[Node], avg_degree=8, rng: Optional[random.Random] = None):
        """
        Inisialisasi jaringan
        
        Args:
            nodes (List[Node]): Daftar node dalam jaringan
            avg_degree (int): Rata-rata jumlah tetangga per node
        """
        self.nodes = nodes
        self.avg_degree = avg_degree
        self.logger = logging.getLogger(__name__)
        self.adjacency_list: dict[int, set[int]] = {}
        self.rng = rng or random.Random(0)

    def _to_nx_graph(self) -> nx.Graph:
        """Build a NetworkX graph view from the internal adjacency list."""
        graph = nx.Graph()
        graph.add_nodes_from(range(len(self.nodes)))
        for source, neighbors in self.adjacency_list.items():
            for target in neighbors:
                if source != target:
                    graph.add_edge(source, target)
        return graph
        
    def initialize_connections(self, connectivity=0.3):
        """
        Inisialisasi koneksi antar nodes
        
        Args:
            connectivity (float): Persentase connectivity (0-1)
        """
        self.logger.info(f"Initializing network connections with connectivity {connectivity}")
        
        # Get total number of nodes
        n = len(self.nodes)
        
        # Initialize empty adjacency list
        self.adjacency_list = {i: set() for i in range(n)}
        
        # For each node, determine its neighbors
        for i in range(n):
            # Reset node's neighbors list
            self.nodes[i].neighbors = []
            
            # Connect to other nodes with probability based on connectivity
            for j in range(n):
                if i != j and self.rng.random() < connectivity:
                    self.adjacency_list[i].add(j)
                    # Add node reference to neighbors list
                    self.nodes[i].neighbors.append(self.nodes[j])
        
        # Ensure network is connected
        self._ensure_connected()
        
        # Log connection information
        self.logger.info(f"Network initialized with {sum(len(neighbors) for neighbors in self.adjacency_list.values())} connections")
        
        # Log per-node connectivity
        for i, node in enumerate(self.nodes):
            connections = len(self.adjacency_list[i])
            self.logger.debug(f"Node {i} has {connections} connections and {len(node.neighbors)} neighbors")
            
            # Verify neighbor references are correctly set
            if connections != len(node.neighbors):
                self.logger.warning(f"Node {i} connections mismatch: Adjacency list has {connections} but neighbors list has {len(node.neighbors)}")
                # Fix the mismatch by updating neighbors list
                node.neighbors = [self.nodes[j] for j in self.adjacency_list[i]]
                self.logger.debug(f"Fixed: Node {i} now has {len(node.neighbors)} neighbors")
        
    def get_neighbors(self, node_id):
        """Get list of neighbor IDs for a node"""
        return list(self.adjacency_list.get(node_id, set()))
        
    def get_degree(self, node_id):
        """Get degree (number of neighbors) for a node"""
        return len(self.adjacency_list.get(node_id, set()))
        
    def get_average_degree(self):
        """Calculate average degree across network"""
        total_degree = sum(len(neighbors) for neighbors in self.adjacency_list.values())
        return total_degree / len(self.nodes)
        
    def get_clustering_coefficient(self):
        """Calculate global clustering coefficient"""
        total_coef = 0
        for node_id in self.adjacency_list:
            neighbors = self.adjacency_list[node_id]
            if len(neighbors) < 2:
                continue
                
            # Count connections between neighbors
            connections = 0
            for n1 in neighbors:
                for n2 in neighbors:
                    if n1 < n2 and n2 in self.adjacency_list[n1]:
                        connections += 1
                        
            # Calculate local clustering coefficient
            possible_connections = (len(neighbors) * (len(neighbors) - 1)) / 2
            if possible_connections > 0:
                total_coef += connections / possible_connections
                
        return total_coef / len(self.nodes)
        
    def get_average_path_length(self):
        """Calculate average shortest path length"""
        total_length = 0
        total_paths = 0
        
        for start in self.adjacency_list:
            # Use BFS to find shortest paths
            distances = self._bfs_distances(start)
            
            # Add up all finite distances
            for end, dist in distances.items():
                if dist != float('inf') and start != end:
                    total_length += dist
                    total_paths += 1
                    
        return total_length / total_paths if total_paths > 0 else float('inf')
        
    def _bfs_distances(self, start):
        """Helper method for BFS to calculate distances"""
        distances = {node_id: float('inf') for node_id in self.adjacency_list}
        distances[start] = 0
        queue = [start]
        
        while queue:
            current = queue.pop(0)
            for neighbor in self.adjacency_list[current]:
                if distances[neighbor] == float('inf'):
                    distances[neighbor] = distances[current] + 1
                    queue.append(neighbor)
                    
        return distances
        
    def _log_network_stats(self):
        """Log network statistics"""
        avg_degree = self.get_average_degree()
        degrees = [self.get_degree(n.id) for n in self.nodes]
        clustering = self.get_clustering_coefficient()
        avg_path = self.get_average_path_length()
        
        self.logger.info(f"Jaringan diinisialisasi: {len(self.nodes)} nodes, "
                      f"rata-rata {self.avg_degree} neighbors per node")
        self.logger.info("Statistik Jaringan:")
        self.logger.info(f"- Rata-rata degree: {avg_degree:.2f}")
        self.logger.info(f"- Max degree: {max(degrees)}")
        self.logger.info(f"- Min degree: {min(degrees)}")
        self.logger.info(f"- Clustering coefficient: {clustering:.3f}")
        self.logger.info(f"- Average path length: {avg_path:.2f}")
        
    def get_network_metrics(self) -> Dict[str, Any]:
        """
        Hitung metrik jaringan
        
        Returns:
            Dict[str, Any]: Metrik jaringan (degree distribution, clustering, dll)
        """
        try:
            graph = self._to_nx_graph()
            is_connected = graph.number_of_nodes() <= 1 or nx.is_connected(graph)
            metrics = {
                'avg_degree': self.get_average_degree(),
                'max_degree': max(self.get_degree(n.id) for n in self.nodes),
                'min_degree': min(self.get_degree(n.id) for n in self.nodes),
                'clustering': self.get_clustering_coefficient(),
                'density': nx.density(graph),
                'is_connected': is_connected,
            }
            
            if metrics['is_connected']:
                metrics['avg_path_length'] = self.get_average_path_length()
                metrics['diameter'] = nx.diameter(graph)
            else:
                metrics['avg_path_length'] = float('inf')
                metrics['diameter'] = float('inf')
                
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error menghitung metrik jaringan: {str(e)}")
            return {}

    def _ensure_connected(self):
        """Memastikan jaringan terhubung (semua node dapat berkomunikasi)"""
        # Depth-first search to check connectivity
        def dfs(node, visited):
            visited[node] = True
            for neighbor in self.adjacency_list[node]:
                if not visited[neighbor]:
                    dfs(neighbor, visited)
        
        # Check if all nodes are reachable from node 0
        n = len(self.nodes)
        visited = [False] * n
        
        # Start DFS from first node
        if n > 0:
            dfs(0, visited)
        
        # If any node is not visited, add connections to make the graph connected
        for i in range(n):
            if not visited[i]:
                # Connect to a random visited node
                connected_node = self.rng.choice([j for j in range(n) if visited[j]])
                
                # Add bidirectional connection
                self.adjacency_list[i].add(connected_node)
                self.adjacency_list[connected_node].add(i)
                
                # Add to neighbors list
                self.nodes[i].neighbors.append(self.nodes[connected_node])
                self.nodes[connected_node].neighbors.append(self.nodes[i])
                
                # Mark as visited and continue DFS
                visited[i] = True
                dfs(i, visited)
                
        self.logger.info("Network connectivity check completed - all nodes are reachable")

    def initialize_from_graph(self, graph: nx.Graph):
        """Initialize adjacency list and neighbors from a NetworkX graph."""
        n = len(self.nodes)
        self.adjacency_list = {i: set() for i in range(n)}
        for u, v in graph.edges():
            if u == v:
                continue
            self.adjacency_list[u].add(v)
            self.adjacency_list[v].add(u)

        for i in range(n):
            self.nodes[i].neighbors = [self.nodes[j] for j in self.adjacency_list[i]]

        # Ensure connectivity by linking components if needed
        self._ensure_connected()
