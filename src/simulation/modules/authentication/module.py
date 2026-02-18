import hashlib
import logging
import random
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from ...core.node import Node


class AuthenticationModule:
    """
    Simulated PKI authentication for protocol-level evaluation.

    This module intentionally abstracts away full X.509/crypto operations while
    preserving key control knobs used in experiments:
    - certificate validity window
    - revocation model
    - controlled false accept / false reject rates
    """

    def __init__(self, node: "Node"):
        self.node = node
        self.logger = logging.getLogger(f"AuthModule-Node{self.node.id}")
        node_rng = getattr(node, "rng", None)
        self.rng = node_rng if node_rng is not None else random.Random(int(getattr(node, "id", 0) or 0))
        self.config = self._build_config()
        self._generate_key_pair()
        self._generate_certificate()

    def _build_config(self) -> Dict[str, Any]:
        auth_cfg = getattr(self.node, "auth_config", {}) or {}
        seed_raw = auth_cfg.get("seed", 0)
        try:
            seed = int(seed_raw)
        except (TypeError, ValueError):
            seed = 0

        def _as_float(name: str, default: float) -> float:
            value = auth_cfg.get(name, default)
            try:
                parsed = float(value)
            except (TypeError, ValueError):
                parsed = default
            return max(0.0, min(1.0, parsed))

        def _as_int(name: str, default: int, minimum: int = 0) -> int:
            value = auth_cfg.get(name, default)
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                parsed = default
            return max(minimum, parsed)

        mode = str(auth_cfg.get("mode", "required")).strip().lower()
        ca_name = str(auth_cfg.get("ca_name", "CIDSeeks-SimCA")).strip() or "CIDSeeks-SimCA"
        revoked_serials = {str(v) for v in (auth_cfg.get("revoked_serials") or [])}

        return {
            "mode": mode,
            "seed": seed,
            "ca_name": ca_name,
            "certificate_ttl_rounds": _as_int("certificate_ttl_rounds", 0),
            "transport_failure_rate": _as_float("transport_failure_rate", 0.0),
            "verification_false_accept_rate": _as_float("verification_false_accept_rate", 0.0),
            "verification_false_reject_rate": _as_float("verification_false_reject_rate", 0.0),
            "revocation_enabled": bool(auth_cfg.get("revocation_enabled", True)),
            "revocation_delay_rounds": _as_int("revocation_delay_rounds", 2),
            "revocation_epoch_rounds": _as_int("revocation_epoch_rounds", 5, minimum=1),
            "revocation_rate_malicious": _as_float("revocation_rate_malicious", 0.8),
            "revocation_rate_honest": _as_float("revocation_rate_honest", 0.0),
            "revoked_serials": revoked_serials,
        }

    @staticmethod
    def _hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _current_iteration(self) -> int:
        try:
            return int(getattr(self.node, "current_iteration", 0) or 0)
        except (TypeError, ValueError):
            return 0

    def _generate_key_pair(self) -> None:
        nonce = self.rng.randint(1000, 999999)
        priv_seed = f"{self.config['seed']}|{self.node.id}|{nonce}|priv"
        self.private_key = self._hash_text(priv_seed)
        self.public_key = self._hash_text(f"{self.private_key}|pub")
        self.logger.debug("Generated simulated key pair.")

    def _generate_certificate(self) -> None:
        issued_round = self._current_iteration()
        ttl = int(self.config["certificate_ttl_rounds"])
        not_after = (issued_round + ttl) if ttl > 0 else None

        serial = self._hash_text(f"{self.config['ca_name']}|{self.node.id}|{self.public_key}")[:16]
        signing_token = self._hash_text(f"{self.public_key}|{self.config['ca_name']}|sign")

        cert = {
            "issuer": self.config["ca_name"],
            "subject": f"Node_{self.node.id}",
            "public_key": self.public_key,
            "serial": serial,
            "issued_round": issued_round,
            "not_after_round": not_after,
            "valid": True,
            # chain_ok is an explicit hook for simulation ablation.
            "chain_ok": True,
            # Token is public in this simulation and enables deterministic
            # signature verification without real asymmetric crypto.
            "signing_token": signing_token,
        }
        self.certificate = cert
        self.logger.debug("Generated simulated certificate serial=%s", serial)

    def _sign_message(self, message: str) -> str:
        token = self.certificate.get("signing_token", "")
        serial = self.certificate.get("serial", "")
        return self._hash_text(f"{message}|{token}|{serial}")

    def _verify_signature(self, message: str, signature: str, cert: Dict[str, Any]) -> bool:
        token = cert.get("signing_token")
        serial = cert.get("serial")
        if not token or not serial:
            return False
        expected = self._hash_text(f"{message}|{token}|{serial}")
        return signature == expected

    def _deterministic_probability(self, *parts: Any) -> float:
        payload = "|".join(str(part) for part in parts)
        digest = hashlib.sha256(payload.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") / float(2**64)

    def _is_revoked(self, target_node: "Node", cert: Dict[str, Any]) -> bool:
        serial = str(cert.get("serial", ""))
        if serial in self.config["revoked_serials"]:
            return True
        if not self.config["revocation_enabled"]:
            return False

        current_iter = self._current_iteration()
        issued_round = int(cert.get("issued_round", 0) or 0)
        if current_iter < issued_round + self.config["revocation_delay_rounds"]:
            return False

        if bool(getattr(target_node, "is_malicious", False)) or bool(cert.get("spoofed", False)):
            rate = self.config["revocation_rate_malicious"]
        else:
            rate = self.config["revocation_rate_honest"]
        if rate <= 0.0:
            return False

        epoch_rounds = self.config["revocation_epoch_rounds"]
        epoch = current_iter // epoch_rounds
        score = self._deterministic_probability(self.config["seed"], serial, epoch, "revocation")
        return score < rate

    def _validate_certificate(self, target_node: "Node", cert: Dict[str, Any]) -> bool:
        if not cert or not isinstance(cert, dict):
            return False
        if not cert.get("valid", False):
            return False
        if cert.get("issuer") != self.config["ca_name"]:
            return False
        if not cert.get("public_key"):
            return False
        if not cert.get("chain_ok", False):
            return False

        current_iter = self._current_iteration()
        not_after = cert.get("not_after_round")
        if not_after is not None:
            try:
                if current_iter > int(not_after):
                    return False
            except (TypeError, ValueError):
                return False

        if self._is_revoked(target_node, cert):
            return False

        return True

    def _record_auth(self, target_node: "Node", success: bool, reason: str) -> None:
        if success:
            self.node.auth_success += 1
        else:
            self.node.auth_failed += 1

        if self.node.db:
            try:
                self.node.db.store_auth_result(
                    self.node.id,
                    target_node.id,
                    bool(success),
                    self.node.current_iteration,
                )
            except Exception:
                self.logger.debug("Failed to store auth result", exc_info=True)
            try:
                self.node.db.store_event(
                    timestamp=float(getattr(self.node.env, "now", 0)),
                    iteration=self.node.current_iteration,
                    node_id=self.node.id,
                    event_type="auth_success" if success else "auth_failed",
                    details={
                        "target": target_node.id,
                        "require_auth": bool(getattr(self.node, "require_auth", True)),
                        "method": getattr(self.node, "trust_method_name", "unknown"),
                        "reason": reason,
                    },
                    related_node_id=target_node.id,
                )
            except Exception:
                self.logger.debug("Failed to store auth event", exc_info=True)

    def authenticate_target(self, target_node: "Node") -> bool:
        """Authenticate target using simulated PKI validation and challenge-response."""
        if not bool(getattr(self.node, "require_auth", True)):
            return True

        try:
            target_auth_module = getattr(target_node, "authentication_module", None)
            if not target_auth_module:
                self._record_auth(target_node, False, "missing_auth_module")
                return False

            target_cert = getattr(target_auth_module, "certificate", None)
            if not self._validate_certificate(target_node, target_cert):
                self._record_auth(target_node, False, "invalid_certificate")
                return False

            if self.rng.random() < self.config["transport_failure_rate"]:
                self._record_auth(target_node, False, "transport_failure")
                return False

            current_iter = self._current_iteration()
            challenge_nonce = self.rng.randint(10000, 99999)
            challenge = f"auth_challenge|src={self.node.id}|dst={target_node.id}|it={current_iter}|nonce={challenge_nonce}"
            signature = target_auth_module._sign_message(challenge)
            verified = self._verify_signature(challenge, signature, target_cert)

            if verified and self.rng.random() < self.config["verification_false_reject_rate"]:
                verified = False
            elif (not verified) and self.rng.random() < self.config["verification_false_accept_rate"]:
                verified = True

            self._record_auth(target_node, bool(verified), "ok" if verified else "signature_or_noise")
            return bool(verified)

        except Exception as exc:
            self.logger.error("Error during simulated authentication to node %s: %s", target_node.id, exc)
            self._record_auth(target_node, False, "exception")
            return False
