import pytest
import simpy
from unittest.mock import patch

from simulation.core.node import Node
from simulation.core.message import TrustRequest
from simulation.modules.authentication import AuthenticationModule
from simulation.modules.trust.observation import Observation
from simulation.modules.trust import TrustManager, TrustCalculator

# Setup fixture jika diperlukan (misal, mock database, env)
@pytest.fixture
def mock_db():
    return None # Tidak pakai DB untuk test unit dasar Node

@pytest.fixture
def test_env():
    return simpy.Environment()

@pytest.fixture
def normal_node(test_env, mock_db):
    """Fixture untuk node normal"""
    return Node(id=1, env=test_env, is_malicious=False, db=mock_db)

@pytest.fixture
def malicious_node(test_env, mock_db):
    """Fixture untuk node malicious"""
    # Berikan attack type spesifik untuk test yang lebih jelas
    return Node(id=2, env=test_env, is_malicious=True, attack_type="PMFA", db=mock_db)

# --- Test Inisialisasi Node dan Modul --- 
def test_node_initialization(normal_node):
    """Test inisialisasi dasar node dan modul-modulnya."""
    assert normal_node.id == 1
    assert not normal_node.is_malicious
    assert isinstance(normal_node.authentication_module, AuthenticationModule)
    assert isinstance(normal_node.trust_manager, TrustManager)
    assert isinstance(normal_node.trust_calculator, TrustCalculator)
    assert normal_node.trust_manager.node == normal_node # Pastikan referensi node benar
    assert normal_node.authentication_module.node == normal_node
    # ... test inisialisasi modul lain jika perlu ...

# --- Test Pendelegasian Metode Node ke Modul --- 
def test_node_authenticate_delegation(normal_node, malicious_node):
    """Test bahwa Node.authenticate mendelegasikan ke AuthenticationModule."""
    with patch.object(
        normal_node.authentication_module,
        "authenticate_target",
        wraps=normal_node.authentication_module.authenticate_target,
    ) as mock_auth_target:
        normal_node.authenticate(malicious_node)  # Panggil metode Node
        mock_auth_target.assert_called_once_with(malicious_node)  # Verifikasi pendelegasian

def test_node_evaluate_trust_delegation(normal_node, malicious_node):
    """Test bahwa Node.evaluate_trust mendelegasikan ke TrustManager."""
    with patch.object(
        normal_node.trust_manager,
        "evaluate",
        wraps=normal_node.trust_manager.evaluate,
    ) as mock_evaluate:
        normal_node.evaluate_trust(malicious_node)
        mock_evaluate.assert_called_once_with(malicious_node)

def test_node_send_protocol_message_records_request_and_response(normal_node, malicious_node):
    """Trust protocol messages must traverse node inbox/outbox, not bypass the node."""
    observation = Observation(
        round_id=3,
        src_id=normal_node.id,
        dst_id=malicious_node.id,
        msg_kind="REQUEST",
        alarm_set_id="req_1_3",
        flags={"pmfa_surface_id": "surface-1"},
    )
    request = TrustRequest(
        source_node=str(normal_node.id),
        target_node=str(malicious_node.id),
        alarm_set_id=observation.alarm_set_id,
        data={"challenge_tier": None},
        message_id="request_1_2_3",
        iteration=observation.round_id,
        correlation_id=observation.alarm_set_id,
    )

    with patch.object(
        malicious_node.behavior_policy,
        "respond",
        return_value=(0.25, {"pmfa_response": "malicious"}),
    ) as mock_respond:
        response = normal_node.send_protocol_message(malicious_node, request, observation)

    assert response is not None
    assert response.type == "request_response"
    assert response.data["response_value"] == 0.25
    assert response.data["flags"]["pmfa_response"] == "malicious"
    assert response.correlation_id == request.id
    assert normal_node.protocol_outbox[-1] is request
    assert normal_node.protocol_inbox[-1] is response
    assert malicious_node.protocol_inbox[-1] is request
    assert malicious_node.protocol_outbox[-1] is response
    mock_respond.assert_called_once_with(observation, source_is_malicious=normal_node.is_malicious)

def test_node_send_alarm_message_records_wire_artifact(normal_node, malicious_node):
    payload = {
        "message_id": "alarm-node-1",
        "original_alarm_hash": "family-node-1",
        "classification_text": "suspicious_activity",
    }

    wire_message = normal_node.send_alarm_message(malicious_node, payload)

    assert wire_message.type == "alarm"
    assert wire_message.id == "alarm-node-1"
    assert wire_message.correlation_id == "family-node-1"
    assert normal_node.protocol_outbox[-1] is wire_message
    assert malicious_node.protocol_inbox[-1] is wire_message

# --- Test Fungsi Node yang Tersisa --- 
def test_calculate_biometric_deterministic(normal_node, malicious_node):
    """Test calculate_biometric yang sudah deterministik."""
    normal_node.behavior_history[normal_node.id] = [0.8, 0.82, 0.79, 0.81]
    normal_node.behavior_history[malicious_node.id] = [0.2, 0.15, 0.3, 0.1]

    biometric_normal = normal_node.calculate_biometric(normal_node)
    biometric_malicious = normal_node.calculate_biometric(malicious_node)
    
    assert 0.0 <= biometric_normal <= 1.0
    assert 0.0 <= biometric_malicious <= 1.0
    # Ekspektasi umum: skor untuk node normal > skor untuk node jahat
    assert biometric_normal > biometric_malicious 

# --- Test yang Perlu Dihapus/Disesuaikan --- 
# Hapus test untuk metode helper trust yang sudah tidak ada di Node
# def test_calculate_basic_challenge_score(...): pass 
# def test_calculate_advanced_challenge_score(...): pass
# def test_calculate_final_challenge_score(...): pass

# Hapus/sesuaikan test authenticate lama
# def test_authenticate_placeholder_ca(...): pass
# def test_authenticate_dummy_signature(...): pass

# Test evaluate_trust lama perlu dihapus
# def test_evaluate_trust_basic(...): pass
# def test_evaluate_trust_collusion(...): pass

# TODO: Buat file test terpisah untuk:
# - TrustManager (menguji orkestrasi dan helper get reputasi/contrib/penalty)
# - AuthenticationModule (menguji logika _sign, _verify secara lebih detail)
# - PrivacyModule
# - IdsModule
# - CollaborationModule
# - Malicious behaviors (perform_*_attack) 
