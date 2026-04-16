# src/tests/modules/trust/test_trust_calculator.py

import pytest
from simulation.modules.trust.calculator import TrustCalculator
from config import settings  # Untuk bobot default jika diperlukan

@pytest.fixture
def calculator():
    return TrustCalculator()

# --- Test Basic Challenge --- 
def test_basic_challenge_normal_target(calculator):
    "Test basic score when target is normal (feedback=1)."""
    score = calculator.calculate_basic_challenge_score(
        feedback=1.0, prev_trust=0.5, learning_rate=0.3
    )
    assert score > 0.5 # Should increase from neutral

def test_basic_challenge_malicious_target(calculator):
    "Test basic score when target is malicious (feedback=0)."""
    score = calculator.calculate_basic_challenge_score(
        feedback=0.0, prev_trust=0.5, learning_rate=0.3
    )
    assert score < 0.5 # Should decrease from neutral

# --- Test Advanced Challenge --- 
@pytest.fixture
def adv_weights():
    return {
        'alpha': settings.TRUST_WEIGHT_ALPHA,
        'beta': settings.TRUST_WEIGHT_BETA,
        'gamma': settings.TRUST_WEIGHT_GAMMA,
        'delta': settings.TRUST_WEIGHT_DELTA
    }

def test_advanced_challenge_good_inputs(calculator, adv_weights):
    "Test advanced score with good reputation, contribution, low penalty."""
    score = calculator.calculate_advanced_challenge_score(
        target_node_is_malicious=False, iteration=5, prev_trust=0.6,
        reputation=0.7, contribution=0.8, penalty=0.1, weights=adv_weights
    )
    # Based on weights 0.4*0.6 + 0.3*0.7 + 0.2*0.8 - 0.1*0.1 = 0.24 + 0.21 + 0.16 - 0.01 = 0.6
    assert abs(score - 0.6) < 1e-6
    
def test_advanced_challenge_bad_inputs(calculator, adv_weights):
    "Test advanced score with bad reputation, contribution, high penalty."""
    score = calculator.calculate_advanced_challenge_score(
        target_node_is_malicious=True, iteration=5, prev_trust=0.4,
        reputation=0.3, contribution=0.2, penalty=0.9, weights=adv_weights
    )
     # Based on weights 0.4*0.4 + 0.3*0.3 + 0.2*0.2 - 0.1*0.9 = 0.16 + 0.09 + 0.04 - 0.09 = 0.2
    assert abs(score - 0.2) < 1e-6


def test_advanced_challenge_uses_explicit_apmfa_penalty(calculator, adv_weights):
    score = calculator.calculate_advanced_challenge_score(
        target_node_is_malicious=True,
        iteration=5,
        prev_trust=0.5,
        reputation=0.5,
        contribution=0.5,
        penalty=0.2,
        weights=adv_weights,
        advanced_terms={"fibd": 0.1, "split_fail": 0.1, "coalcorr": 0.1, "apmfa_penalty": 0.6},
    )
    expected = 0.4 * 0.5 + 0.3 * 0.5 + 0.2 * 0.5 - 0.1 * (0.2 + 0.6)
    assert abs(score - expected) < 1e-6

# --- Test Final Challenge --- 
@pytest.fixture
def final_weights():
     return {
        'theta': settings.TRUST_WEIGHT_THETA,
        'epsilon': settings.TRUST_WEIGHT_EPSILON,
        'zeta': settings.TRUST_WEIGHT_ZETA
    }

def test_final_challenge_good_inputs(calculator, final_weights):
    "Test final score with successful auth and good biometric."""
    score = calculator.calculate_final_challenge_score(
        prev_trust=0.6, auth_status=1.0, biometric_score=0.8, weights=final_weights
    )
    # 0.4*0.6 + 0.3*1.0 + 0.3*0.8 = 0.24 + 0.3 + 0.24 = 0.78
    assert abs(score - 0.78) < 1e-6

def test_final_challenge_bad_inputs(calculator, final_weights):
    "Test final score with failed auth and bad biometric."""
    score = calculator.calculate_final_challenge_score(
        prev_trust=0.4, auth_status=0.0, biometric_score=0.2, weights=final_weights
    )
    # 0.4*0.4 + 0.3*0.0 + 0.3*0.2 = 0.16 + 0.0 + 0.06 = 0.22
    assert abs(score - 0.22) < 1e-6


def test_final_challenge_supports_split_fail_penalty(calculator, final_weights):
    score = calculator.calculate_final_challenge_score(
        prev_trust=0.6,
        auth_status=1.0,
        biometric_score=0.8,
        weights=final_weights,
        attribution_penalty=0.15,
    )
    assert abs(score - 0.63) < 1e-6

# --- Test Total Trust --- 
def test_total_trust(calculator):
    "Test combining scores."""
    total_weights = {
        'w1': settings.TOTAL_TRUST_WEIGHT_W1,
        'w2': settings.TOTAL_TRUST_WEIGHT_W2,
        'w3': settings.TOTAL_TRUST_WEIGHT_W3
    }
    score = calculator.calculate_total_trust(
        basic_trust=0.6, advanced_trust=0.7, final_trust=0.8, total_trust_weights=total_weights
    )
    # 0.3*0.6 + 0.3*0.7 + 0.4*0.8 = 0.18 + 0.21 + 0.32 = 0.71
    assert abs(score - 0.71) < 1e-6 
