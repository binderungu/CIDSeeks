from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    from ..core.node import Node
    from ..core.message import Message

class BaseMethod(ABC):
    """
    Abstract base class untuk semua metode trust dan privacy dalam CIDS.
    
    Menerapkan aturan: Setiap metode harus mengimplementasikan interface yang sama
    untuk memungkinkan perbandingan yang fair di dalam simulator.
    """
    
    def __init__(self, method_name: str, config: Dict[str, Any]):
        self.method_name = method_name
        self.config = config
        self.logger = logging.getLogger(f"Method-{method_name}")
        
        # Metrics dasar + metrik tambahan (Rule: Evaluation & Testing – Cost/Overhead)
        self.metrics = {
            # Core metrics
            'trust_calculations': 0,
            'alarms_processed': 0,
            'challenges_handled': 0,
            'execution_time': 0.0,

            # Blockchain Overhead (Kategori V)
            'consensus_delay': 0.0,           # Total delay (s)
            'ledger_storage': 0,              # Total ledger size (bytes)
            'blockchain_transactions': 0,     # Jumlah transaksi

            # Privacy & Resource Cost (Kategori VI)
            'enc_time': 0.0,                  # Total waktu enkripsi (s)
            'dec_time': 0.0,                  # Total waktu dekripsi (s)
            'ciphertext_size': 0,             # Total ukuran ciphertext (bytes)
            'cpu_util_percent': 0.0           # Agregat utilisasi CPU (persen*iterasi)
        }
    
    @abstractmethod
    def calculate_trust(self, source_node: 'Node', target_node: 'Node', **kwargs) -> float:
        """
        Menghitung trust score antara source_node dan target_node.
        
        Args:
            source_node: Node yang melakukan evaluasi
            target_node: Node yang dievaluasi
            **kwargs: Parameter tambahan spesifik metode
            
        Returns:
            float: Trust score dalam range [0, 1]
        """
        raise NotImplementedError
    
    @abstractmethod
    def process_alarm(self, alarm: Dict[str, Any], node: 'Node', **kwargs) -> List[Dict[str, Any]]:
        """
        Memproses alarm untuk privacy dan obfuscation.
        
        Args:
            alarm: Alarm data yang akan diproses
            node: Node yang memproses alarm
            **kwargs: Parameter tambahan spesifik metode
            
        Returns:
            List[Dict]: List alarm yang sudah diproses (bisa 1 atau lebih variasi)
        """
        raise NotImplementedError
    
    @abstractmethod
    def handle_challenge(self, challenge: 'Message', node: 'Node', **kwargs) -> Optional[Dict[str, Any]]:
        """
        Menangani challenge message.
        
        Args:
            challenge: Challenge message yang diterima
            node: Node yang menangani challenge
            **kwargs: Parameter tambahan spesifik metode
            
        Returns:
            Optional[Dict]: Response data atau None jika tidak ada response
        """
        raise NotImplementedError
    
    def initialize_node(self, node: 'Node') -> None:
        """
        Inisialisasi node dengan parameter metode ini.
        Override jika metode memerlukan inisialisasi khusus.
        
        Args:
            node: Node yang akan diinisialisasi
        """
        # Default implementation - bisa di-override
        node.trust_method_name = self.method_name
        self.logger.debug(f"Initialized node {node.id} with method {self.method_name}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Mendapatkan metrics performa metode.
        
        Returns:
            Dict: Metrics data
        """
        return self.metrics.copy()
    
    def reset_metrics(self) -> None:
        """Reset metrics counter."""
        for key in self.metrics:
            if isinstance(self.metrics[key], (int, float)):
                self.metrics[key] = 0
                
    def update_metric(self, metric_name: str, value: Any) -> None:
        """
        Update specific metric.
        
        Args:
            metric_name: Nama metric
            value: Nilai baru (untuk counter akan ditambahkan)
        """
        if metric_name in self.metrics:
            current_val = self.metrics[metric_name]

            # Jika numeric → jumlahkan; jika dict → update per-key
            if isinstance(current_val, (int, float)) and isinstance(value, (int, float)):
                self.metrics[metric_name] += value
            elif isinstance(current_val, dict) and isinstance(value, dict):
                for k, v in value.items():
                    if k in current_val and isinstance(current_val[k], (int, float)) and isinstance(v, (int, float)):
                        current_val[k] += v
                    else:
                        current_val[k] = v
            else:
                # Override untuk tipe lain
                self.metrics[metric_name] = value
    
    def validate_config(self) -> bool:
        """
        Validasi konfigurasi metode.
        Override untuk validasi spesifik metode.
        
        Returns:
            bool: True jika konfigurasi valid
        """
        required_keys = ['name']  # Minimal requirement
        for key in required_keys:
            if key not in self.config:
                self.logger.error(f"Missing required config key: {key}")
                return False
        return True
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}(method_name='{self.method_name}')"
    
    def __repr__(self) -> str:
        return self.__str__() 
