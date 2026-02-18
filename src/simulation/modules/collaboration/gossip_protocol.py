from typing import List, Set, Dict, Optional
import random
import logging

class GossipProtocol:
    """Implementasi protokol gossip untuk penyebaran pesan"""
    
    def __init__(self, fanout: int = 3, rng: Optional[random.Random] = None):
        """
        Initialize protokol gossip
        
        Args:
            fanout: Jumlah node yang akan menerima pesan dalam satu kali gossip
        """
        self.fanout = fanout
        self.max_hops = 5  # Maksimum hop untuk setiap pesan
        self.message_cache = {}  # Untuk mencegah pesan duplikat
        self.logger = logging.getLogger(__name__)
        self.rng = rng or random.Random(0)

    def select_targets(self, nodes: List[str], sender: str, 
                      exclude: Set[str] = None) -> List[str]:
        """
        Pilih node target untuk meneruskan pesan
        
        Args:
            nodes: List semua node ID yang tersedia
            sender: ID node pengirim
            exclude: Set node ID yang harus diexclude (optional)
            
        Returns:
            List node ID yang terpilih sebagai target
        """
        available_nodes = [n for n in nodes if n != sender]
        if exclude:
            available_nodes = [n for n in available_nodes if n not in exclude]
            
        num_targets = min(self.fanout, len(available_nodes))
        return self.rng.sample(available_nodes, num_targets)

    def process_message(self, message: Dict, nodes: Dict[str, object]) -> List[str]:
        """
        Proses pesan dan tentukan target penyebaran berikutnya
        
        Args:
            message: Pesan yang akan disebarkan
            nodes: Dictionary dari node objects
            
        Returns:
            List node ID yang akan menerima pesan
        """
        try:
            # Check if message has been seen before
            msg_id = message.get('id')
            if msg_id in self.message_cache:
                return []

            # Add to cache
            self.message_cache[msg_id] = {
                'hops': 0,
                'seen_by': set([message['source_node']])
            }

            # Select targets for gossip
            available_nodes = list(nodes.keys())
            targets = self.select_targets(
                available_nodes,
                message['source_node'],
                self.message_cache[msg_id]['seen_by']
            )

            # Update cache
            self.message_cache[msg_id]['seen_by'].update(targets)
            self.message_cache[msg_id]['hops'] += 1

            return targets

        except Exception as e:
            self.logger.error(f"Error processing message: {str(e)}")
            return []

    def should_forward(self, message_id: str) -> bool:
        """
        Tentukan apakah pesan masih perlu diteruskan
        
        Args:
            message_id: ID pesan yang dicek
            
        Returns:
            Boolean indicating if message should be forwarded
        """
        if message_id not in self.message_cache:
            return True
            
        return self.message_cache[message_id]['hops'] < self.max_hops

    def cleanup_cache(self):
        """Bersihkan cache pesan lama"""
        # Implementasi pembersihan cache bisa ditambahkan di sini
        self.message_cache.clear() 
