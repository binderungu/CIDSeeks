import logging
import random
from collections import defaultdict
from typing import List, Dict, Any, Optional
import simpy

# Import Modul-modul
from ..modules.database.node_database import NodeDatabase
from ..modules.trust import TrustCalculator, TrustManager
from ..modules.authentication import AuthenticationModule
from ..modules.privacy import PrivacyModule
from ..modules.ids import IdsModule
from ..modules.collaboration import CollaborationModule
from ..modules.attacks.behavior_policy import BehaviorPolicy

class Node:
    """Represents a node in the CIDS network, delegating functionalities to specialized modules."""
    
    def __init__(self, id: int, env: simpy.Environment, is_malicious: bool = False, 
                 attack_type: Optional[str] = None, db: Optional[NodeDatabase] = None, 
                 trust_config: Optional[Dict[str, Any]] = None, feature_config: Optional[Dict[str, Any]] = None, 
                 trust_method_instance=None,
                 metrics_recorder=None,
                 attack_config: Optional[Dict] = None,
                 auth_config: Optional[Dict] = None,
                 rng: Optional[random.Random] = None,
                 pmfa_cache=None):
        """
        Initialize a Node.

        Args:
            id (int): Unique node identifier.
            env (simpy.Environment): SimPy environment instance.
            is_malicious (bool): True if the node is malicious.
            attack_type (Optional[str]): Type of attack if malicious.
            db (Optional[NodeDatabase]): Database manager instance.
            trust_config (Dict): Configuration dictionary for the trust model.
            feature_config (Dict): Configuration dictionary for features like gossip.
            trust_method_instance: Instance of BaseMethod for trust calculation (optional).
            auth_config (Optional[Dict]): Authentication simulation configuration.
        """
        self.id = id
        self.env = env
        self.is_malicious = is_malicious
        self.attack_type = attack_type
        self.db = db
        self.logger = logging.getLogger(f"Node-{id}")
        self.trust_config = dict(trust_config or {})
        self.feature_config = dict(feature_config or {})
        self.trust_method_instance = trust_method_instance
        self.metrics_recorder = metrics_recorder
        self.attack_config = attack_config or {}
        self.auth_config = auth_config or {}
        self.rng = rng or random.Random(int(self.id))
        
        # Core Node State
        self.neighbors: List['Node'] = [] 
        self.current_iteration = 0
        self.alarm_counter = 0
        self.current_request_alarm_set_id: Optional[str] = None
        # Initialize trust_scores from config if available, else empty dict
        self.trust_scores: Dict[int, float] = {} 
        # Per-target trust components (basic/advanced/final)
        self.trust_components: Dict[int, Dict[str, float]] = {}
        # Per-target behavior history for biometric-style scoring
        self.behavior_history = defaultdict(list)
        # Per-target contribution counts (accepted alarms)
        self.contribution_counts = defaultdict(int)
        # Quarantine set for low-trust peers
        self.quarantined_nodes: set[int] = set()
        self.alarms: List[Dict[str, Any]] = []
        self.false_alarms: List[Dict[str, Any]] = [] 
        self.suspicious_nodes: set[int] = set()
        
        # Status counters
        self.auth_success = 0
        self.auth_failed = 0

        # --- Trust Method Selection & Auth Flag ---
        self.trust_method: str = self._normalize_trust_method(self.trust_config.get('method', '3-level-challenge'))
        # Alias for backward-compatibility (some modules still reference trust_method_name)
        self.trust_method_name: str = self.trust_method

        auth_mode = str(self.auth_config.get('mode', 'required')).strip().lower()
        self.require_auth: bool = auth_mode not in {'off', 'disabled', 'none', 'noauth'}

        # --- Extract Trust Model Weights from Config --- 
        # Use defaults if not found in config
        self.learning_rate = self.trust_config.get('learning_rate', 0.3)
        weights_advanced = self.trust_config.get('weights_advanced', {})
        weights_final = self.trust_config.get('weights_final', {})
        weights_biometric = self.trust_config.get('weights_biometric', {})
        # Combine all weights into a single dict for easier access by modules
        self.weights = {
            'alpha': weights_advanced.get('alpha', 0.4),
            'beta': weights_advanced.get('beta', 0.3),
            'gamma': weights_advanced.get('gamma', 0.2),
            'delta': weights_advanced.get('delta', 0.1),
            'theta': weights_final.get('theta', 0.4),
            'epsilon': weights_final.get('epsilon', 0.3),
            'zeta': weights_final.get('zeta', 0.3),
            'mu': weights_biometric.get('mu', 0.3),
            'nu': weights_biometric.get('nu', 0.4),
            'xi': weights_biometric.get('xi', 0.3)
        }
        # Total trust weights are used by SimulationEngine, not directly by Node
        # --- End Extract Weights --- 

        # --- Initialize Modules --- 
        self.authentication_module = AuthenticationModule(self)
        self.trust_calculator = TrustCalculator() 
        # Pass node (for state access) and calculator to TrustManager
        self.trust_manager = TrustManager(self, self.trust_calculator, metrics_recorder=metrics_recorder)
        self.privacy_module = PrivacyModule(self)
        self.ids_module = IdsModule(self)
        # Pass feature_config to CollaborationModule for gossip params
        self.collaboration_module = CollaborationModule(
            self, 
            feature_config=self.feature_config, 
            trust_method_name=self.trust_method_name
        )
        self.behavior_policy = BehaviorPolicy(
            node=self,
            attack_config=self.attack_config,
            rng=self.rng,
            pmfa_cache=pmfa_cache,
        )
        # --- End Initialize Modules --- 

        # Store initial node info in DB
        if self.db:
            try:
                self.db.store_node(self.id, 'malicious' if self.is_malicious else 'normal', self.is_malicious)
            except Exception as e:
                 self.logger.error(f"Failed to store initial node info in DB: {e}")

        self.logger.info(f"Node {self.id} created. Malicious: {self.is_malicious}, Attack: {self.attack_type}, Trust Method: {self.trust_method_name}")

    # --- Core Node Actions (Delegated to Modules) ---

    def detect_attack(self) -> Optional[Dict[str, Any]]:
        """Delegate attack detection to the IDS module."""
        return self.ids_module.detect_attack()

    def spread_alarm(self, alarm: Dict[str, Any]):
        """Delegate alarm spreading to the Collaboration module."""
        self.collaboration_module.spread_alarm(alarm)
        
    def receive_alarm(self, alarm: Dict[str, Any], sender: 'Node'):
        """Delegate alarm receiving to the Collaboration module."""
        # Called by the sender's CollaborationModule
        # No need for explicit call here, handled by neighbor interaction
        # self.collaboration_module.receive_alarm(alarm, sender) 
        # Correction: The CollaborationModule of the *receiving* node needs to handle this.
        # Let's assume the SimulationEngine or the sender's CollaborationModule calls
        # the *target* node's `collaboration_module.receive_alarm`. 
        # We'll keep this method as a potential entry point if needed later.
        self.logger.warning("Node.receive_alarm called directly, should be handled by CollaborationModule? Check logic.")
        # For safety, delegate if called directly for some reason
        # self.collaboration_module.receive_alarm(alarm, sender)

    def authenticate(self, target_node: 'Node') -> bool:
        """Authenticate the target node using the CIDSeeks challenge flow."""
        if not self.require_auth:
            return True
        return self.authentication_module.authenticate_target(target_node)

    def evaluate_trust(self, target_node: 'Node') -> float:
        """Delegate trust evaluation to the Trust manager."""
        return self.trust_manager.evaluate(target_node)
        
    # --- Methods Providing State/Data (Potentially used by Modules) ---

    def get_trust_score(self, node_id: int) -> float:
        """Get the current calculated trust score for a specific target node."""
        # Returns the score this node holds for the target node
        return self.trust_scores.get(node_id, 0.5) # Default to neutral

    def calculate_biometric(self, target_node: 'Node') -> float:
        """Calculate biometric score using observed behavior history (no ground truth)."""
        w = self.weights
        history = self.behavior_history.get(target_node.id, [])
        if not history:
            return 0.5

        mean_val = sum(history) / len(history)
        if len(history) > 1:
            variance = sum((x - mean_val) ** 2 for x in history) / len(history)
            std = variance ** 0.5
        else:
            std = 0.0

        last_val = history[-1]
        anomaly = min(1.0, abs(last_val - mean_val))
        pattern = max(0.0, min(1.0, mean_val))
        stability = max(0.0, min(1.0, 1.0 - std))

        biometric_score = (
            w['mu'] * (1 - anomaly) +
            w['nu'] * pattern +
            w['xi'] * stability
        )
        return max(0.0, min(1.0, biometric_score))

    # --- Helper methods removed as logic moved to modules ---
    # HAPUS: _obfuscate_alarm, _vary_alarm, _calculate_*_challenge_score 
    # HAPUS: _generate_key_pair, _sign_message, _verify_signature (pindah ke AuthModule)
    # HAPUS: attack (generik), store_trust_score (dilakukan oleh TrustManager)
    # HAPUS: update_trust_score (dilakukan oleh TrustManager)
    # HAPUS: receive_alarm (dipindah ke CollaborationModule, perlu penyesuaian caller)
    
    # Metode get_* (get_feedback, get_reputation, dll) mungkin tidak diperlukan lagi
    # jika TrustManager bisa akses DB atau Node state lain yang relevan secara langsung.
    # Kita biarkan dulu untuk kompatibilitas, tapi bisa dibersihkan nanti.

    def get_feedback(self, node_id: int) -> float:
        """Helper to get basic malicious status feedback (can be removed later)."""
        node = next((n for n in self.neighbors if n.id == node_id), None)
        if not node: return 0.5
        return 0.0 if node.is_malicious else 1.0
    
    @staticmethod
    def _normalize_trust_method(method_name: str) -> str:
        aliases = {
            'default_3_level': '3-level-challenge',
            '3_level_challenge': '3-level-challenge',
            'CIDSeeks': '3-level-challenge',
        }
        return aliases.get(method_name, '3-level-challenge')
        
    # --- TAMBAHKAN METODE LOGIKA PER ITERASI --- 
    def run_iteration_logic(self, iteration: int):
        """Generator process SimPy untuk menjalankan logika node dalam satu iterasi."""
        self.current_iteration = iteration
        # self.logger.debug(f"Running iteration {iteration} logic...")

        try:
            # 1. Deteksi alarm (IDS) untuk semua node
            self.logger.debug(f"Iter {iteration}: Running IDS detection...")
            potential_alarm = self.ids_module.detect_attack()
            if potential_alarm:
                self.logger.info(f"Iter {iteration}: Detected potential alarm! Spreading...")
                self.collaboration_module.spread_alarm(potential_alarm)
            else:
                self.logger.debug(f"Iter {iteration}: No alarm detected by IDS.")

            # 2. Update Trust (SEKARANG DI DALAM BLOK TRY UTAMA)
            self.logger.debug(f"Iter {iteration}: Evaluating trust for all neighbors ({len(self.neighbors)})...") # <-- Pastikan kurung benar
            evaluated_count = 0
            for neighbor_node in self.neighbors:
                try:
                    # Panggil evaluate untuk setiap tetangga
                    self.trust_manager.evaluate(neighbor_node)
                    evaluated_count += 1
                except Exception as eval_err:
                    # Log error spesifik per tetangga tapi lanjutkan ke tetangga berikutnya
                    self.logger.error(f"Iter {iteration}: Error evaluating trust for neighbor {neighbor_node.id}: {eval_err}")
            self.logger.debug(f"Iter {iteration}: Finished evaluating trust for {evaluated_count}/{len(self.neighbors)} neighbors.")

            # ---> SIMULASI WAKTU (TETAP DI DALAM TRY UTAMA) <---
            processing_time = 0.1
            yield self.env.timeout(processing_time)

        except Exception as e:
            self.logger.error(f"Error during node {self.id} iteration {iteration}: {str(e)}")
            yield self.env.timeout(0.01)
            
    # --- Metode repr untuk representasi string ---
    def __repr__(self):
        status = "Malicious" if self.is_malicious else "Normal"
        return f"Node(id={self.id}, status={status}, attack={self.attack_type or 'N/A'})"
