import pytest
import simpy
from unittest.mock import patch

from simulation.core.node import Node
from simulation.modules.authentication import AuthenticationModule
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
