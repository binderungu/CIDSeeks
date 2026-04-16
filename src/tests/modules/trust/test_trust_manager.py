# src/tests/modules/trust/test_trust_manager.py

import pytest
import simpy
import random
from collections import defaultdict
from unittest.mock import MagicMock  # Gunakan MagicMock dari unittest.mock

# Modul yang diuji
from simulation.core.message import TrustResponse
from simulation.modules.privacy.module import PrivacyModule
from simulation.modules.trust.manager import TrustManager
from simulation.modules.trust.calculator import TrustCalculator
from simulation.utils.perf import metric_logger

# Kelas yang perlu di-mock
from simulation.core.node import Node
from simulation.modules.database.node_database import NodeDatabase

# Setup Environment dan Node Mock
@pytest.fixture
def test_env():
    return simpy.Environment()

@pytest.fixture
def mock_db():
    """Fixture untuk mock database yang tidak melakukan apa-apa."""
    db = MagicMock(spec=NodeDatabase)
    db.store_trust_score.return_value = None
    return db

@pytest.fixture
def mock_calculator():
    """Fixture untuk mock TrustCalculator."""
    calc = MagicMock(spec=TrustCalculator)
    # Set default return values untuk metode kalkulasi
    calc.calculate_basic_challenge_score.return_value = 0.6
    calc.calculate_advanced_challenge_score.return_value = 0.7
    calc.calculate_final_challenge_score.return_value = 0.8
    calc.calculate_total_trust.return_value = 0.75 # Skor total default
    return calc

@pytest.fixture
def evaluating_node(test_env, mock_db, mock_calculator): # Menggunakan mock calculator
    """Fixture untuk node yang melakukan evaluasi (mocked)."""
    node = MagicMock(spec=Node)
    node.id = 1
    node.env = test_env
    node.current_iteration = 5
    node.is_malicious = False
    node.attack_type = None
    node.trust_config = {
        "challenge_rate": 1.0,
        "challenge_rate_tiers": {"basic": 1.0, "advanced": 1.0, "final": 1.0},
        "challenge_min_interval_tiers": {"basic": 0, "advanced": 0, "final": 0},
        "trust_threshold": 0.5,
        "trust_fall_threshold": 0.2,
        "trust_rise_threshold": 0.3,
        "initial_trust": 0.5,
        "weights_total_trust": {"w1": 0.3, "w2": 0.3, "w3": 0.4},
        "collusion_penalty": {"enabled": False},
    }
    node.rng = random.Random(0)
    node.feature_config = {
        "dmpo_pmfa_guard": True,
        "variants_per_alarm": 3,
        "min_alarm_send_delay": 0.1,
        "max_alarm_send_delay": 0.5,
        "privacy_salt": "cidseeks-test",
        "attribution": {
            "weights_apmfa": {"fibd": 0.34, "split_fail": 0.33, "coalcorr": 0.33},
            "final_split_fail_weight": 0.25,
        },
    }
    node.current_request_alarm_set_id = "req_test"
    node.trust_scores = {2: 0.5} # Skor awal untuk target node 2
    node.trust_components = {}
    node.behavior_history = defaultdict(list)
    node.contribution_counts = defaultdict(int)
    node.quarantined_nodes = set()
    node.neighbors = []
    node.trust_method = "3-level-challenge"
    node.db = mock_db
    node.learning_rate = 0.3 # Contoh
    node.weights = { # Contoh bobot
            'alpha': 0.4, 'beta': 0.3, 'gamma': 0.2, 'delta': 0.1,
            'theta': 0.4, 'epsilon': 0.3, 'zeta': 0.3,
            'mu': 0.3, 'nu': 0.4, 'xi': 0.3
    }
    # Mock metode yang dipanggil oleh TrustManager
    node.authenticate.return_value = True # Asumsi auth berhasil
    node.calculate_biometric.return_value = 0.85 # Contoh skor biometrik
    return node

@pytest.fixture
def target_node(test_env):
    """Fixture untuk node yang dievaluasi (mocked)."""
    node = MagicMock(spec=Node)
    node.id = 2
    node.env = test_env
    node.is_malicious = False # Target normal
    node.attack_type = None
    node.neighbors = []
    node.trust_scores = {}
    node.behavior_policy = MagicMock()
    node.behavior_policy.respond.return_value = (0.8, {})
    return node

@pytest.fixture
def malicious_target_node(test_env):
     """Fixture untuk node target yang malicious (mocked)."""
     node = MagicMock(spec=Node)
     node.id = 3
     node.env = test_env
     node.is_malicious = True # Target malicious
     node.attack_type = "PMFA"
     node.neighbors = []
     node.trust_scores = {}
     node.behavior_policy = MagicMock()
     node.behavior_policy.respond.return_value = (0.2, {})
     return node

@pytest.fixture
def trust_manager(evaluating_node, mock_calculator):
    """Fixture untuk instance TrustManager yang diuji."""
    # Perhatikan: Kita inject mock_calculator ke TrustManager
    return TrustManager(node=evaluating_node, calculator=mock_calculator)

# --- Test Cases --- 

def test_trust_manager_initialization(trust_manager, evaluating_node, mock_calculator):
    """Test inisialisasi TrustManager."""
    assert trust_manager.node == evaluating_node
    assert trust_manager.calculator == mock_calculator
    assert trust_manager.logger is not None

def test_evaluate_normal_target(trust_manager, evaluating_node, target_node, mock_calculator, mock_db):
    """Test evaluasi trust terhadap node normal yang tepercaya."""
    # Setup mock return values spesifik jika perlu (opsional, sudah ada default)
    evaluating_node.authenticate.return_value = True
    evaluating_node.calculate_biometric.return_value = 0.9
    mock_calculator.calculate_total_trust.return_value = 0.88 # Skor tinggi yang diharapkan
    
    # Jalankan metode yang diuji
    final_score = trust_manager.evaluate(target_node)
    
    # Assertions
    assert final_score == 0.88 # Cek skor kembali
    # Verifikasi bahwa metode kalkulator dipanggil
    mock_calculator.calculate_basic_challenge_score.assert_called_once()
    mock_calculator.calculate_advanced_challenge_score.assert_called_once()
    mock_calculator.calculate_final_challenge_score.assert_called_once()
    mock_calculator.calculate_total_trust.assert_called_once()
    # Verifikasi bahwa metode node dipanggil
    evaluating_node.authenticate.assert_called_once_with(target_node)
    evaluating_node.calculate_biometric.assert_called_once_with(target_node)
    # Verifikasi skor disimpan di node dan DB
    assert evaluating_node.trust_scores[target_node.id] == 0.88
    mock_db.store_trust_score.assert_called_once_with(
        node_id=evaluating_node.id, 
        target_node_id=target_node.id, 
        score=0.88, 
        iteration=evaluating_node.current_iteration
    )

def test_evaluate_malicious_target_low_score(trust_manager, evaluating_node, malicious_target_node, mock_calculator, mock_db):
    """Test evaluasi trust terhadap node malicious, hasilkan skor rendah."""
    # Setup mock return values untuk skenario malicious
    evaluating_node.authenticate.return_value = True # Mungkin auth masih lolos?
    evaluating_node.calculate_biometric.return_value = 0.2 # Biometrik buruk
    # Biarkan kalkulator mengembalikan skor default-nya, tapi set total trust rendah
    mock_calculator.calculate_total_trust.return_value = 0.25 

    final_score = trust_manager.evaluate(malicious_target_node)
    
    assert final_score == 0.25
    # Cek pemanggilan basic challenge sinkron dengan state awal.
    kwargs = mock_calculator.calculate_basic_challenge_score.call_args.kwargs
    assert kwargs["prev_trust"] == 0.5
    assert kwargs["learning_rate"] == evaluating_node.learning_rate
    assert 0.0 <= kwargs["feedback"] <= 1.0
    assert evaluating_node.trust_scores[malicious_target_node.id] == 0.25
    mock_db.store_trust_score.assert_called()

def test_evaluate_authentication_failure(trust_manager, evaluating_node, target_node, mock_calculator, mock_db):
    """Test kasus ketika otentikasi gagal."""
    evaluating_node.authenticate.return_value = False # Otentikasi GAGAL
    # Skor akhir tidak boleh hanya bergantung pada auth, final challenge akan rendah
    mock_calculator.calculate_final_challenge_score.return_value = 0.1 # Skor final rendah
    mock_calculator.calculate_total_trust.return_value = 0.3 # Skor total rendah

    final_score = trust_manager.evaluate(target_node)
    
    assert final_score == 0.3
    # Pastikan final challenge dipanggil dengan auth_status=0.0
    final_kwargs = mock_calculator.calculate_final_challenge_score.call_args.kwargs
    assert final_kwargs["auth_status"] == 0.0
    assert final_kwargs["weights"] == evaluating_node.weights
    # Verifikasi skor disimpan
    assert evaluating_node.trust_scores[target_node.id] == 0.3
    mock_db.store_trust_score.assert_called()


def test_evaluate_records_pmfa_privacy_event(trust_manager, target_node):
    metric_logger.reset()
    try:
        trust_manager.evaluate(target_node)
        snapshot = metric_logger.snapshot()
        assert len(snapshot["privacy_pmfa_logs"]) == 1
        event = snapshot["privacy_pmfa_logs"][0]
        assert event["event_scope"] == "internal"
        assert event["privacy_strategy"] == "dmpo_legacy"
        assert event["is_challenge"] in {True, False}
        assert isinstance(event["privacy_policy"], dict)
    finally:
        metric_logger.reset()


def test_evaluate_records_dmpox_alias_and_policy_trace_on_internal_privacy_event(
    trust_manager,
    evaluating_node,
    target_node,
):
    evaluating_node.feature_config.update(
        {
            "privacy_strategy": "dmpo_x",
            "total_nodes": 8,
            "privacy": {
                "strategy": "dmpo_x",
                "alias_epoch_rounds": 4,
                "controller": {
                    "enabled": True,
                    "candidate_policies": [
                        {"policy_id": "px", "K_t": 4, "f_t": 2, "ell_t": "medium", "d_t": "exp_mid", "r_t": 0.2},
                    ],
                },
            },
        }
    )
    evaluating_node.privacy_module = PrivacyModule(evaluating_node)
    evaluating_node.neighbors = [target_node]
    metric_logger.reset()
    try:
        trust_manager.evaluate(target_node)
        snapshot = metric_logger.snapshot()
        assert len(snapshot["privacy_pmfa_logs"]) == 1
        event = snapshot["privacy_pmfa_logs"][0]
        assert event["privacy_strategy"] == "dmpo_x"
        assert event["privacy_alias_scope"] == "recipient_epoch"
        assert event["privacy_alias_epoch"] == 1
        assert event["privacy_alias_epoch_rounds"] == 4
        assert event["privacy_policy_decision"]["selected_policy_id"] == event["privacy_policy"]["policy_id"]
        assert event["privacy_policy_decision"]["selection_mode"] == "objective_minimization"
    finally:
        metric_logger.reset()


def test_evaluate_records_protocol_metadata_on_events(trust_manager, evaluating_node, target_node, mock_db):
    evaluating_node.send_protocol_message.return_value = TrustResponse(
        source_node=str(target_node.id),
        target_node=str(evaluating_node.id),
        msg_kind="CHALLENGE",
        response_value=0.9,
        flags={
            "challenge_proof_valid": True,
            "challenge_proof_type": "final_attestation_proof",
        },
        data={"alarm_set_id": "chal_1_2_5_final", "challenge_tier": "final"},
        message_id="response_2_1_5",
        iteration=evaluating_node.current_iteration,
        correlation_id="challenge_1_2_5",
    )

    trust_manager.evaluate(target_node)

    evaluating_node.send_protocol_message.assert_called_once()
    observation_events = [
        call.kwargs
        for call in mock_db.store_event.call_args_list
        if call.kwargs.get("event_type") == "observation"
    ]
    assert len(observation_events) == 1
    observation_details = observation_events[0]["details"]
    assert observation_details["protocol_request_id"] == "challenge_1_2_5"
    assert observation_details["protocol_request_type"] == "challenge"
    assert observation_details["protocol_request_correlation_id"] == "chal_1_2_5_final"
    assert observation_details["protocol_response_id"] == "response_2_1_5"
    assert observation_details["protocol_response_type"] == "challenge_response"
    assert observation_details["protocol_response_correlation_id"] == "challenge_1_2_5"

    outcome_events = [
        call.kwargs
        for call in mock_db.store_event.call_args_list
        if call.kwargs.get("event_type") == "challenge_outcome"
    ]
    assert len(outcome_events) == 1
    outcome_details = outcome_events[0]["details"]
    assert outcome_details["protocol_request_id"] == "challenge_1_2_5"
    assert outcome_details["protocol_response_id"] == "response_2_1_5"
    trace = trust_manager.get_last_evaluation_trace(target_node.id)
    assert trace["alarm_set_id"] == "chal_1_2_5_final"
    assert trace["protocol_request_id"] == "challenge_1_2_5"
    assert trace["protocol_response_id"] == "response_2_1_5"


def test_evaluate_emits_explicit_attribution_penalty_and_final_split_fail_penalty(
    trust_manager,
    evaluating_node,
    malicious_target_node,
    mock_calculator,
    mock_db,
):
    malicious_target_node.behavior_policy.respond.return_value = (
        0.2,
        {
            "challenge_proof_valid": False,
            "challenge_proof_type": "final_attestation_bundle",
            "pmfa_predicted_kind": "REQUEST",
            "pmfa_response": "malicious",
        },
    )

    trust_manager.evaluate(malicious_target_node)

    advanced_terms = mock_calculator.calculate_advanced_challenge_score.call_args.kwargs["advanced_terms"]
    assert advanced_terms["split_fail"] == pytest.approx(1.0)
    assert advanced_terms["apmfa_penalty"] > 0.0

    final_kwargs = mock_calculator.calculate_final_challenge_score.call_args.kwargs
    assert final_kwargs["attribution_penalty"] > 0.0

    outcome_events = [
        call.kwargs
        for call in mock_db.store_event.call_args_list
        if call.kwargs.get("event_type") == "challenge_outcome"
    ]
    assert len(outcome_events) == 1
    details = outcome_events[0]["details"]
    assert details["apmfa_penalty"] > 0.0
    assert details["final_split_fail_penalty"] > 0.0
    assert details["attribution_signal_count"] == 3

    trace = trust_manager.get_last_evaluation_trace(malicious_target_node.id)
    assert trace["apmfa_penalty"] > 0.0
    assert trace["final_split_fail_penalty"] > 0.0


def test_evaluate_respects_attribution_ablations(
    evaluating_node,
    malicious_target_node,
    mock_calculator,
):
    evaluating_node.feature_config["ablations"] = {
        "fibd": False,
        "split_fail": False,
        "coalcorr": False,
    }
    trust_manager = TrustManager(node=evaluating_node, calculator=mock_calculator)
    malicious_target_node.behavior_policy.respond.return_value = (
        0.2,
        {
            "challenge_proof_valid": False,
            "challenge_proof_type": "final_attestation_bundle",
            "pmfa_predicted_kind": "REQUEST",
            "pmfa_response": "malicious",
        },
    )

    trust_manager.evaluate(malicious_target_node)

    advanced_terms = mock_calculator.calculate_advanced_challenge_score.call_args.kwargs["advanced_terms"]
    assert advanced_terms["fibd"] == 0.0
    assert advanced_terms["split_fail"] == 0.0
    assert advanced_terms["coalcorr"] == 0.0
    assert advanced_terms["apmfa_penalty"] == 0.0

    final_kwargs = mock_calculator.calculate_final_challenge_score.call_args.kwargs
    assert final_kwargs["attribution_penalty"] == 0.0

# TODO: Tambahkan test case lain:
# - Test helper methods (_get_target_reputation, _get_target_contribution, _get_target_penalty) 
#   jika logikanya kompleks atau diambil dari DB (perlu mock DB lebih canggih).
# - Test penanganan error (misalnya jika db.store_trust_score gagal).
# - Test dengan berbagai kombinasi input ke kalkulator. 
