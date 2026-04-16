from simulation.modules.privacy.module import PrivacyModule


class _DummyNode:
    def __init__(
        self,
        strategy: str,
        *,
        current_iteration: int = 3,
        alias_epoch_rounds: int = 5,
        privacy_overrides: dict | None = None,
    ):
        self.id = 1
        self.rng = None
        self.current_iteration = current_iteration
        self.neighbors = []
        self.attack_config = {"pmfa_detect_prob": 0.8, "pmfa_dmpo_resistance": 0.2}
        privacy_cfg = {"strategy": strategy, "alias_epoch_rounds": alias_epoch_rounds}
        if privacy_overrides:
            for key, value in privacy_overrides.items():
                if isinstance(value, dict) and isinstance(privacy_cfg.get(key), dict):
                    privacy_cfg[key] = {**privacy_cfg[key], **value}
                else:
                    privacy_cfg[key] = value
        self.feature_config = {
            "privacy_strategy": strategy,
            "privacy": privacy_cfg,
            "variants_per_alarm": 2,
            "total_nodes": 8,
            "dmpo_pmfa_guard": True,
        }


def _alarm():
    return {
        "message_id": "m1",
        "original_destination_ip": "10.0.0.1",
        "original_destination_port": 443,
        "original_message_body": "alert-body",
    }


def test_legacy_strategy_default_fields():
    mod = PrivacyModule(_DummyNode("dmpo_legacy"))
    vars_ = mod.generate_alarm_variations(_alarm())
    assert vars_
    assert all(v.get("privacy_strategy") == "dmpo_legacy" for v in vars_)
    assert any("variation_sequence_number" in v for v in vars_)


def test_dmpox_strategy_policy_and_stealth_meta():
    mod = PrivacyModule(_DummyNode("dmpo_x"))
    vars_ = mod.generate_alarm_variations(_alarm())
    assert vars_
    non_cover = [v for v in vars_ if not v.get("is_cover")]
    assert non_cover
    assert all(v.get("privacy_strategy") == "dmpo_x" for v in vars_)
    assert all("privacy_policy" in v for v in vars_)
    assert all("privacy_policy_decision" in v for v in vars_)
    assert all("stealth_header" in v for v in non_cover)
    assert all(isinstance(v["stealth_header"], str) and v["stealth_header"].startswith("sh1:") for v in non_cover)
    assert all(v["privacy_alias_scope"] == "recipient_epoch" for v in vars_)
    assert all(v["privacy_alias_epoch"] == 0 for v in vars_)
    assert all(v["privacy_alias_epoch_rounds"] == 5 for v in vars_)
    assert all(v["privacy_policy_decision"]["selected_policy_id"] == v["privacy_policy"]["policy_id"] for v in vars_)
    assert all(v["privacy_policy_decision"]["selection_mode"] in {"objective_minimization", "disabled_default"} for v in vars_)
    assert all("_stealth_meta" not in v for v in non_cover)
    assert all("[f" not in str(v.get("current_msg", "")) for v in non_cover)


def test_dmpox_strategy_recipient_scopes_aliases_and_headers():
    mod = PrivacyModule(_DummyNode("dmpo_x"))
    policy = mod.select_dissemination_policy(_alarm(), trust_scores=[0.7, 0.8], neighbor_count=3)

    recipient_a = mod.generate_alarm_variations(_alarm(), recipient_id=7, policy=policy, include_cover=False)
    recipient_b = mod.generate_alarm_variations(_alarm(), recipient_id=8, policy=policy, include_cover=False)

    first_a = recipient_a[0]
    first_b = recipient_b[0]

    assert first_a["privacy_policy"] == first_b["privacy_policy"]
    assert first_a["message_id"] != first_b["message_id"]
    assert first_a["stealth_header"] != first_b["stealth_header"]


def test_dmpox_strategy_alias_epoch_is_stable_within_epoch_and_rotates_on_boundary():
    node_same_epoch_a = _DummyNode("dmpo_x", current_iteration=3, alias_epoch_rounds=4)
    node_same_epoch_b = _DummyNode("dmpo_x", current_iteration=2, alias_epoch_rounds=4)
    node_next_epoch = _DummyNode("dmpo_x", current_iteration=4, alias_epoch_rounds=4)

    mod_same_epoch_a = PrivacyModule(node_same_epoch_a)
    mod_same_epoch_b = PrivacyModule(node_same_epoch_b)
    mod_next_epoch = PrivacyModule(node_next_epoch)
    policy = mod_same_epoch_a.select_dissemination_policy(_alarm(), trust_scores=[0.8], neighbor_count=2)

    first_same_epoch_a = mod_same_epoch_a.generate_alarm_variations(
        _alarm(),
        recipient_id=7,
        policy=policy,
        include_cover=False,
    )[0]
    first_same_epoch_b = mod_same_epoch_b.generate_alarm_variations(
        _alarm(),
        recipient_id=7,
        policy=policy,
        include_cover=False,
    )[0]
    first_next_epoch = mod_next_epoch.generate_alarm_variations(
        _alarm(),
        recipient_id=7,
        policy=policy,
        include_cover=False,
    )[0]

    assert first_same_epoch_a["privacy_alias_epoch"] == 0
    assert first_same_epoch_b["privacy_alias_epoch"] == 0
    assert first_next_epoch["privacy_alias_epoch"] == 1
    assert first_same_epoch_a["message_id"] == first_same_epoch_b["message_id"]
    assert first_same_epoch_a["stealth_header"] == first_same_epoch_b["stealth_header"]
    assert first_same_epoch_a["message_id"] != first_next_epoch["message_id"]
    assert first_same_epoch_a["stealth_header"] != first_next_epoch["stealth_header"]


def test_dmpox_strategy_emits_cover_variations_when_policy_has_nonzero_r_t():
    mod = PrivacyModule(
        _DummyNode(
            "dmpo_x",
            privacy_overrides={
                "controller": {
                    "enabled": True,
                    "candidate_policies": [
                        {"policy_id": "covery", "K_t": 2, "f_t": 3, "ell_t": "medium", "d_t": "exp_mid", "r_t": 0.6},
                    ],
                },
            },
        )
    )
    policy = mod.select_dissemination_policy(_alarm(), trust_scores=[0.8], neighbor_count=3)
    vars_ = mod.generate_alarm_variations(_alarm(), recipient_id=7, policy=policy, include_cover=True)

    covers = [v for v in vars_ if v.get("is_cover")]
    non_cover = [v for v in vars_ if not v.get("is_cover")]

    assert covers
    assert non_cover
    assert all(v["privacy_policy"]["r_t"] == 0.6 for v in vars_)
    assert all(v["privacy_policy_decision"]["selected_r_t"] == 0.6 for v in vars_)
    assert all(v["privacy_policy_decision"]["candidate_count"] == 1 for v in vars_)
    assert all(isinstance(v["stealth_header"], str) and v["stealth_header"].startswith("sh1:") for v in covers)


def test_generate_alarm_variations_regenerates_without_cover_when_strategy_returns_cover_only(monkeypatch):
    mod = PrivacyModule(_DummyNode("dmpo_x"))
    policy = mod.select_dissemination_policy(_alarm(), trust_scores=[0.8], neighbor_count=2)
    calls: list[bool] = []

    def _fake_generate(original_alarm, *, recipient_id=None, policy=None, include_cover=True):
        calls.append(bool(include_cover))
        if include_cover:
            return [{"message_id": "cover-1", "is_cover": True, "privacy_strategy": "dmpo_x"}]
        return [{"message_id": "primary-1", "privacy_strategy": "dmpo_x"}]

    monkeypatch.setattr(mod.strategy, "generate_alarm_variations", _fake_generate)

    vars_ = mod.generate_alarm_variations(_alarm(), recipient_id=7, policy=policy, include_cover=True)

    assert calls == [True, False]
    assert vars_ == [{"message_id": "primary-1", "privacy_strategy": "dmpo_x"}]


def test_primary_variations_clear_inherited_cover_flag():
    mod = PrivacyModule(_DummyNode("dmpo_x"))
    policy = mod.select_dissemination_policy(_alarm(), trust_scores=[0.8], neighbor_count=2)
    alarm = _alarm()
    alarm["is_cover"] = True

    vars_ = mod.generate_alarm_variations(alarm, recipient_id=7, policy=policy, include_cover=False)

    assert vars_
    assert all(v.get("is_cover") is False for v in vars_)
