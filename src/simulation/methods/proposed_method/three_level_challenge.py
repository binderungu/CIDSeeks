from typing import Dict, Any, List, Optional, TYPE_CHECKING
import logging
from ..base_method import BaseMethod

if TYPE_CHECKING:
    from ...core.node import Node
    from ...core.message import Message

class ThreeLevelChallengeMethod(BaseMethod):
    """
    Wrapper untuk metode 3-level challenge yang sudah ada.
    
    Mengintegrasikan metode trust hierarkis 3-tingkat dengan dynamic message 
    pattern obfuscation ke dalam framework perbandingan metode.
    """
    
    def __init__(self, method_name: str = "3-level-challenge", config: Dict[str, Any] = None):
        if config is None:
            config = {}
        super().__init__(method_name, config)
        
        self.logger.info("Initialized 3-Level Challenge method")
    
    def calculate_trust(self, source_node: 'Node', target_node: 'Node', **kwargs) -> float:
        """
        Menghitung trust menggunakan 3-level challenge mechanism.
        
        Delegasi ke existing TrustManager di source_node.
        """
        try:
            self.update_metric('trust_calculations', 1)
            
            # Gunakan existing trust evaluation dari node
            if hasattr(source_node, 'trust_manager'):
                trust_score = source_node.trust_manager.evaluate(target_node)
            else:
                # Fallback jika trust_manager tidak ada
                trust_score = source_node.get_trust_score(target_node.id)
            
            return trust_score
            
        except Exception as e:
            self.logger.error(f"Error calculating trust: {e}")
            return 0.5  # Default neutral trust
    
    def process_alarm(self, alarm: Dict[str, Any], node: 'Node', **kwargs) -> List[Dict[str, Any]]:
        """
        Memproses alarm dengan dynamic message pattern obfuscation.
        
        Delegasi ke existing PrivacyModule di node.
        """
        try:
            self.update_metric('alarms_processed', 1)
            
            # Gunakan existing privacy module untuk obfuscation
            if hasattr(node, 'privacy_module') and hasattr(node.privacy_module, 'generate_alarm_variations'):
                # Generate variations using privacy module
                alarm_variations = node.privacy_module.generate_alarm_variations(alarm)
                return alarm_variations
            else:
                # Fallback: return original alarm
                return [alarm]
                
        except Exception as e:
            self.logger.error(f"Error processing alarm: {e}")
            return [alarm]  # Return original alarm on error
    
    def handle_challenge(self, challenge: 'Message', node: 'Node', **kwargs) -> Optional[Dict[str, Any]]:
        """
        Menangani challenge menggunakan 3-level challenge system.
        
        Delegasi ke existing ChallengeManager di node.
        """
        try:
            self.update_metric('challenges_handled', 1)
            
            # Gunakan existing challenge manager
            if hasattr(node, 'challenge_manager'):
                # Extract challenge data
                challenge_data = challenge if isinstance(challenge, dict) else challenge.__dict__
                
                # Process challenge using existing manager
                response = node.challenge_manager.handle_challenge(challenge_data)
                return response
            else:
                # Fallback: basic response
                return {
                    'type': 'challenge_response',
                    'sender_id': node.id,
                    'trust_score': node.get_trust_score(challenge.get('sender_id', 0))
                }
                
        except Exception as e:
            self.logger.error(f"Error handling challenge: {e}")
            return None
    
    def initialize_node(self, node: 'Node') -> None:
        """
        Inisialisasi node untuk metode 3-level challenge.
        """
        super().initialize_node(node)
        
        # Set trust method name untuk collaboration module
        if hasattr(node, 'collaboration_module'):
            node.collaboration_module.trust_method_name = self.method_name
        
        self.logger.debug(f"Node {node.id} initialized with 3-level challenge method")
    
    def validate_config(self) -> bool:
        """
        Validasi konfigurasi untuk 3-level challenge method.
        """
        # Basic validation - bisa diperluas sesuai kebutuhan
        required_sections = ['weights_advanced', 'weights_final', 'weights_biometric', 'weights_total_trust']
        
        for section in required_sections:
            if section not in self.config:
                self.logger.warning(f"Config section '{section}' not found, using defaults")
        
        return True  # Always valid, will use defaults if needed
    
    def get_method_info(self) -> Dict[str, Any]:
        """
        Mendapatkan informasi detail tentang metode 3-level challenge.
        """
        return {
            'name': self.method_name,
            'description': 'Hierarchical 3-level trust mechanism with dynamic message pattern obfuscation',
            'features': [
                'Basic Challenge (λ learning rate)',
                'Advanced Challenge (reputation, contribution, penalty)',
                'Final Challenge (authentication, biometric)',
                'Dynamic Message Obfuscation',
                'Gossip-based Collaboration'
            ],
            'parameters': {
                'learning_rate': self.config.get('learning_rate', 0.3),
                'trust_threshold': self.config.get('trust_threshold', 0.5),
                'initial_trust': self.config.get('initial_trust', 0.5)
            }
        } 