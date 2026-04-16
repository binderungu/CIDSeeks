# src/simulation/modules/trust/calculator.py

from typing import TYPE_CHECKING

# Hindari circular import
if TYPE_CHECKING:
    from ...core.node import Node 

class TrustCalculator:
    """Handles the pure calculation logic for the 3-level challenge trust model."""

    def calculate_basic_challenge_score(
        self,
        feedback: float,
        prev_trust: float,
        learning_rate: float,
    ) -> float:
        """Calculate basic challenge score: Tij(t) = (1-λ)×Tij(t-1) + λ×Fij(t)."""
        lambda_val = learning_rate
        basic_trust = (1 - lambda_val) * prev_trust + lambda_val * feedback
        return max(0.0, min(1.0, basic_trust))

    def calculate_advanced_challenge_score(
        self,
        target_node_is_malicious: bool,
        iteration: int,
        prev_trust: float,
        reputation: float,
        contribution: float,
        penalty: float,
        weights: dict,
        advanced_terms: dict | None = None,
    ) -> float:
        """Calculate advanced score with explicit attribution penalty.

        Runtime form:
        α×Tij(t-1) + β×Rj(t) + γ×Cj(t) - δ×(Pj(t) + P_apmfa(t))
        """
        alpha = weights['alpha']
        beta = weights['beta']
        gamma = weights['gamma']
        delta = weights['delta']
            
        fibd = 0.0
        split_fail = 0.0
        coalcorr = 0.0
        apmfa_penalty = 0.0
        if advanced_terms:
            fibd = max(0.0, min(1.0, float(advanced_terms.get('fibd', 0.0))))
            split_fail = max(0.0, min(1.0, float(advanced_terms.get('split_fail', 0.0))))
            coalcorr = max(0.0, min(1.0, float(advanced_terms.get('coalcorr', 0.0))))
            apmfa_penalty = max(0.0, min(1.0, float(advanced_terms.get('apmfa_penalty', 0.0))))
        attribution_penalty = apmfa_penalty or ((fibd + split_fail + coalcorr) / 3.0)
        advanced_trust = (alpha * prev_trust + beta * reputation + gamma * contribution - delta * (penalty + attribution_penalty))
        return max(0.0, min(1.0, advanced_trust))

    def calculate_final_challenge_score(
        self, 
        prev_trust: float, 
        auth_status: float, # Use float (1.0 or 0.0) for easier calculation 
        biometric_score: float, 
        weights: dict,
        attribution_penalty: float = 0.0,
    ) -> float:
        """Calculate final score with verifier-reconstruction penalty.

        Runtime form:
        θ×Tij(t-1) + ϵ×Aj(t) + ζ×Bj(t) - P_split(t)
        """
        theta = weights['theta']
        epsilon = weights['epsilon']
        zeta = weights['zeta']

        penalty = max(0.0, min(1.0, float(attribution_penalty)))
        final_trust = (theta * prev_trust + epsilon * auth_status + zeta * biometric_score - penalty)
        return max(0.0, min(1.0, final_trust))

    def calculate_total_trust(
        self,
        basic_trust: float,
        advanced_trust: float,
        final_trust: float,
        total_trust_weights: dict # e.g., {'w1': 0.3, 'w2': 0.3, 'w3': 0.4}
    ) -> float:
        """Combine the three challenge scores into a total trust score."""
        w1 = total_trust_weights['w1']
        w2 = total_trust_weights['w2']
        w3 = total_trust_weights['w3']
        
        total_trust = w1 * basic_trust + w2 * advanced_trust + w3 * final_trust
        return max(0.0, min(1.0, total_trust)) # Ensure final score is in [0,1] 
