from simulation.modules.trust.fibd import FIBDTracker
from simulation.modules.trust.split_verifier import SplitVerifierTracker
from simulation.modules.trust.coalcorr import CoalitionCorrelationTracker


def test_fibd_tracker_nonzero_when_family_behaviors_diverge():
    tracker = FIBDTracker()
    for _ in range(5):
        tracker.observe(peer_id=2, context_bin="REQUEST::request", family_id="f1", response_value=0.9, supportive_action=True)
        tracker.observe(peer_id=2, context_bin="REQUEST::request", family_id="f2", response_value=0.1, supportive_action=False)
    assert tracker.score(2, "REQUEST::request") > 0.0


def test_split_verifier_fail_rate():
    tracker = SplitVerifierTracker()
    tracker.observe(peer_id=3, reconstruction_ok=True)
    tracker.observe(peer_id=3, reconstruction_ok=False, tier="final")
    assert tracker.fail_rate(3) == 0.5
    assert tracker.fail_rate(3, tier="final") == 1.0


def test_coalcorr_score_positive_for_outlier_peer():
    tracker = CoalitionCorrelationTracker()
    for _ in range(4):
        tracker.observe(peer_id=1, context_bin="CHALLENGE::advanced", suspicious_score=1.0)
        tracker.observe(peer_id=2, context_bin="CHALLENGE::advanced", suspicious_score=0.0)
    assert tracker.score(1, "CHALLENGE::advanced") > 0.0
