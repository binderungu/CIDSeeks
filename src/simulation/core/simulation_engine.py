import json
import math
import numpy as np
import logging
import time
import random
import os
import hashlib
import platform
import subprocess
import shutil
import uuid
import simpy
import sys
import yaml  # Tambahkan import yaml
import traceback  # <-- Tambahkan import traceback
import psutil
import pandas as pd
import networkx as nx
from typing import Dict, List, Any, Optional
from pathlib import Path
from importlib import metadata as importlib_metadata
from ..modules.database.node_database import NodeDatabase
from .network import Network
from .node import Node
from evaluation.metrics import EnhancedMetrics
from ..utils.perf import metric_logger
from evaluation.metrics.enhanced_metrics import compute_metrics_for_iteration, compute_tti_summary
from ..utils.rng import make_random, make_numpy_rng, derive_seed
from ..modules.attacks.behavior_policy import PMFAMatchCache

class SimulationError(Exception):
    """Custom error untuk simulasi CIDS."""

class _ProgressAwareStreamHandler(logging.StreamHandler):
    """StreamHandler yang menjaga progress bar tetap di bawah saat log masuk."""

    def __init__(self, engine: "SimulationEngine", stream=None):
        super().__init__(stream)
        self._engine = engine

    def emit(self, record):
        try:
            self._engine._clear_progress_line()
        except Exception:
            self._engine._progress_active = False
        super().emit(record)
        try:
            self._engine._repaint_progress_line()
        except Exception:
            self._engine._progress_active = False

class SimulationEngine:
    """Manages the setup, execution, and result collection of a CIDS simulation.

    Reads configuration from a YAML file, initializes the network of Nodes,
    runs the simulation using SimPy discrete-event scheduling, calculates 
    performance metrics, and optionally generates output plots and logs.

    Attributes:
        config (Dict): Loaded simulation configuration from YAML.
        env (simpy.Environment): SimPy environment instance.
        logger (logging.Logger): Logger instance for the engine.
        total_nodes (int): Total number of nodes.
        malicious_nodes (int): Number of malicious nodes.
        attack_type (Optional[str]): Type of attack being simulated.
        total_iterations (int): Total number of iterations (SimPy time units).
        trust_threshold (float): Threshold for accepting alarms based on sender trust.
        initial_trust (float): Initial trust value assigned between nodes.
        detection_event_probability (float): Probability a normal node generates an alarm per iteration.
        gossip_fanout (int): Number of neighbors to gossip to.
        gossip_max_hops (int): Maximum hops for gossip propagation.
        plot_enabled (bool): Whether to generate plots at the end.
        output_dir (str): Directory for saving outputs (DB, plots, logs).
        nodes (Dict[int, Node]): Dictionary mapping node IDs to Node objects.
        network (Network): Network instance managing node connectivity.
        db_manager (NodeDatabase): Instance for database interactions.
        node_trust_scores (Dict[int, List[Dict]]): Stores history of trust scores given BY nodes.
        is_running (bool): Flag indicating if the simulation is currently running.
        is_completed (bool): Flag indicating if the simulation finished successfully.
        current_iteration (int): The current simulation iteration number.
        start_time (float): Real-world start time of the simulation run.
        simulation_process (Optional[simpy.Process]): Process for running the main simulation loop.
    """

    def __init__(self, config_path: str = "config.yaml", db_manager: Optional[NodeDatabase] = None, ui_params: Optional[Dict] = None):
        """
        Initialize the simulation engine from a configuration file, optionally overriding with UI parameters.

        Args:
            config_path (str): Path to the YAML configuration file.
            db_manager (NodeDatabase, optional): External database manager instance.
            ui_params (Dict, optional): Dictionary containing parameters from the UI to override config file values.
        """
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        log_config = self.config.get('logging', {}) or {}
        self.progress_bar = bool(log_config.get('progress_bar', False))
        self._progress_stream = sys.stderr
        self._progress_active = False
        self._progress_render = ""
        self._setup_logging()
        self.config.setdefault('simulation', {})

        # Deterministic RNG setup
        self.seed = self._resolve_seed()
        self.config['simulation']['seed'] = self.seed
        self.config['seed'] = self.seed
        self.rng = make_random(self.seed, "engine")
        self.np_rng = make_numpy_rng(self.seed, "engine")
        # Fallback global seeding (covers legacy random usage)
        random.seed(self.seed)
        np.random.seed(self.seed)

        attack_cfg = self.config.get('attack', {}) or {}
        self.pmfa_cache = PMFAMatchCache() if attack_cfg.get('pmfa_collusion_enabled') else None

        # --- Load parameters from config --- 
        sim_config = self.config.get('simulation', {})
        net_config = self.config.get('network', {})
        trust_config = self.config.get('trust_model', {})
        attack_config = self.config.get('attack', {})
        auth_config = self.config.get('auth', {})
        output_config = self.config.get('output', {})
        feature_config = self.config.get('features', {})

        # Defaults for trust thresholds (rise/fall) if not specified
        base_tau = float(trust_config.get('trust_threshold', 0.5))
        trust_config.setdefault('trust_fall_threshold', base_tau)
        trust_config.setdefault('trust_rise_threshold', min(1.0, base_tau + 0.1))
        self.config['trust_model'] = trust_config

        # Defaults for privacy obfuscation
        feature_config.setdefault('privacy_salt', f"cidseeks-{self.seed}")
        feature_config.setdefault('privacy_prefix_bits', 24)
        feature_config.setdefault('privacy_k_anonymity', 16)
        self.config['features'] = feature_config
        auth_config.setdefault('mode', 'required')
        auth_config.setdefault('seed', self.seed)
        self.config['auth'] = auth_config
        
        self.total_nodes = sim_config.get('total_nodes', 20)
        malicious_ratio = sim_config.get('malicious_ratio', 0.2)
        self.malicious_nodes = int(self.total_nodes * malicious_ratio)
        self.attack_type = attack_config.get('type', "PMFA")
        self.total_iterations = sim_config.get('iterations', 50)
        self.trust_threshold = trust_config.get('trust_threshold', 0.5)
        self.initial_trust = trust_config.get('initial_trust', 0.5)
        self.detection_event_probability = feature_config.get('detection_event_probability', 0.05)
        self.gossip_fanout = feature_config.get('gossip_fanout', 3)
        self.gossip_max_hops = feature_config.get('gossip_max_hops', 5)
        self.min_alarm_send_delay = feature_config.get('min_alarm_send_delay', 0.1)
        self.max_alarm_send_delay = feature_config.get('max_alarm_send_delay', 0.5)
        self.feature_config = dict(feature_config)
        self.feature_config.setdefault('total_nodes', self.total_nodes)
        self.config.setdefault('features', {})['total_nodes'] = self.total_nodes
        self.plot_enabled = output_config.get('plot_enabled', True)
        # Output layout (canonical)
        self.suite = sim_config.get('suite', self.config.get('suite', 'ad_hoc'))
        raw_experiment_id = sim_config.get('experiment_id')
        legacy_run_id = sim_config.get('run_id')
        if not raw_experiment_id:
            if legacy_run_id:
                raw_experiment_id = legacy_run_id
            else:
                scenario_token = self._sanitize_run_token(sim_config.get('name', 'run'))
                raw_experiment_id = f"{scenario_token}_seed{self.seed}"
        self.experiment_id = str(raw_experiment_id)
        self.run_uid = str(sim_config.get('run_uid') or self._generate_run_uid())
        self.run_id = f"{self.experiment_id}__{self.run_uid}"
        self.config['simulation']['experiment_id'] = self.experiment_id
        self.config['simulation']['run_uid'] = self.run_uid
        self.config['simulation']['run_id'] = self.run_id
        self.config['simulation']['suite'] = self.suite

        output_root = output_config.get('root_dir') or output_config.get('directory') or "results"
        self.output_root = Path(output_root)
        self.output_overwrite = bool(output_config.get('overwrite', False))
        manifest_keep_last = output_config.get('manifest_keep_last', 200)
        try:
            self.manifest_keep_last: Optional[int] = int(manifest_keep_last)
        except Exception:
            self.manifest_keep_last = 200
        self.output_path = self.output_root / self.suite / self.run_id
        self._prepare_output_path(overwrite=self.output_overwrite)
        self.output_dir = str(self.output_path)
        # --- End Load parameters --- 

        # --- Override with UI parameters if provided ---
        if ui_params:
            self.logger.info(f"Mengganti parameter config dengan nilai dari UI: {ui_params}")
            original_total_nodes = self.total_nodes
            self.total_nodes = ui_params.get('total_nodes', self.total_nodes)
            # Hitung ulang malicious_nodes HANYA jika total_nodes dari UI berbeda ATAU malicious_nodes ada di UI
            if self.total_nodes != original_total_nodes or 'malicious_nodes' in ui_params:
                # Prioritaskan malicious_nodes dari UI jika ada
                if 'malicious_nodes' in ui_params:
                    self.malicious_nodes = ui_params['malicious_nodes']
                else:
                    # Jika tidak, hitung ulang berdasarkan total_nodes baru dan ratio dari config
                    self.malicious_nodes = int(self.total_nodes * malicious_ratio) 
            self.attack_type = ui_params.get('attack_type', self.attack_type)
            self.total_iterations = ui_params.get('iterations', self.total_iterations)
            
            # Override trust method if provided from UI
            if 'trust_method' in ui_params:
                # Update trust_model config section
                if 'trust_model' not in self.config:
                    self.config['trust_model'] = {}
                self.config['trust_model']['method'] = ui_params['trust_method']
                trust_config = self.config['trust_model']  # Update reference
                self.logger.info(f"Trust method overridden from UI: {ui_params['trust_method']}")
            
            # Log nilai akhir setelah override
            selected_method = self.config.get('trust_model', {}).get('method', '3-level-challenge')
            # Normalize and validate attack type after overrides
            try:
                from config.settings import normalize_attack, VALID_ATTACK_TYPES
                normalized = normalize_attack(self.attack_type)
                if normalized and normalized in VALID_ATTACK_TYPES:
                    self.attack_type = normalized
                elif normalized not in VALID_ATTACK_TYPES:
                    self.logger.warning(f"Unknown attack type '{self.attack_type}', fallback to PMFA")
                    self.attack_type = 'PMFA'
            except Exception as e:
                self.logger.debug(f"Attack type normalization skipped: {e}")

            self.logger.info(f"Effective AttackType: {self.attack_type}")
            self.logger.info(f"Parameter final: Nodes={self.total_nodes}, Malicious={self.malicious_nodes}, Attack={self.attack_type}, Iterations={self.total_iterations}, Method={selected_method}")
        # --- End Override ---

        # Validasi parameter (sekarang menggunakan parameter yang mungkin sudah di-override)
        self._validate_params(self.total_nodes, self.malicious_nodes, self.attack_type)

        # Inisialisasi SimPy Environment
        self.env = simpy.Environment()

        # Status simulasi
        self.is_running = False
        self.is_completed = False
        self.current_iteration = 0

        # Struktur data (tetap sama)
        self.nodes: Dict[int, Node] = {}
        self.node_trust_scores: Dict[int, List[Dict]] = {}
        # self.metrics = {} # Tidak digunakan secara aktif? Bisa dihapus jika tidak perlu

        # --- Tambahkan atribut untuk process SimPy --- 
        self.simulation_process: Optional[simpy.Process] = None

        # Preflight permission checks before DB setup
        self._preflight_output_paths(output_config)

        # Setup Database Manager
        self.db_manager = self._setup_database(db_manager, output_config)
        
        # Setup Trust Method
        self.trust_method_instance = self._setup_trust_method(trust_config)
        
        # Setup Enhanced Metrics System
        self.enhanced_metrics = EnhancedMetrics(seed=self.seed)

        # Runtime/performance bookkeeping for each run
        self._perf_monitor: Optional[Dict[str, Any]] = None
        self.last_run_summary: Optional[Dict[str, Any]] = None

        # Inisialisasi nodes dan network (menggunakan parameter dari config)
        self._initialize_simulation(net_config)

        self.logger.info(f"Engine simulasi diinisialisasi dari {config_path}")
        self.logger.info(f"Parameter: {self.total_nodes} node, {self.malicious_nodes} malicious ({malicious_ratio*100:.1f}%), attack: {self.attack_type}")

    def _load_config(self, config_path: str) -> Dict:
        """Load simulation configuration from a YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                if not config: raise ValueError("Config file is empty")
                self.logger.info(f"Konfigurasi berhasil dimuat dari: {config_path}")
                return config
        except FileNotFoundError:
            self.logger.error(f"Config file tidak ditemukan di: {config_path}")
            raise
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing config file {config_path}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error loading config file {config_path}: {e}")
            raise

    def _resolve_seed(self) -> int:
        seed = self.config.get('seed')
        if seed is None:
            seed = self.config.get('simulation', {}).get('seed')
        if seed is None:
            self.logger.warning("No seed provided in config; defaulting to 0.")
            seed = 0
        try:
            return int(seed)
        except Exception:
            self.logger.warning("Invalid seed value %s; defaulting to 0.", seed)
            return 0

    @staticmethod
    def _sanitize_run_token(value: Any) -> str:
        token = str(value or "run").strip().lower()
        safe = []
        for char in token:
            if char.isalnum() or char in ("-", "_"):
                safe.append(char)
            else:
                safe.append("-")
        collapsed = "".join(safe).strip("-_")
        return collapsed or "run"

    def _generate_run_uid(self) -> str:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        nonce = uuid.uuid4().hex[:8]
        return f"{timestamp}_{nonce}_seed{self.seed}"

    def _prepare_output_path(self, overwrite: bool) -> None:
        if self.output_path.exists():
            if overwrite:
                if self.output_path.is_dir():
                    shutil.rmtree(self.output_path)
                else:
                    self.output_path.unlink()
            else:
                raise FileExistsError(
                    f"Output path already exists: {self.output_path}. "
                    "Set output.overwrite=true or pass --overwrite to replace it."
                )
        self.output_path.mkdir(parents=True, exist_ok=False)

    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[3]

    def _get_git_hash(self) -> Optional[str]:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(self._repo_root()),
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except Exception:
            return None

    def _get_git_dirty(self) -> Optional[bool]:
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(self._repo_root()),
                capture_output=True,
                text=True,
                check=True,
            )
            return bool(result.stdout.strip())
        except Exception:
            return None

    @staticmethod
    def _sha256_bytes(payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    def _sha256_file(self, path: Path) -> Optional[str]:
        try:
            if not path.exists() or not path.is_file():
                return None
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except Exception:
            return None

    def _config_sha256(self) -> Optional[str]:
        try:
            canonical = yaml.safe_dump(self.config, sort_keys=True).encode("utf-8")
            return self._sha256_bytes(canonical)
        except Exception:
            return None

    def _dependency_versions(self) -> Dict[str, Optional[str]]:
        package_names = {
            "simpy": "simpy",
            "numpy": "numpy",
            "pandas": "pandas",
            "scipy": "scipy",
            "scikit-learn": "scikit-learn",
            "networkx": "networkx",
            "matplotlib": "matplotlib",
            "PyYAML": "PyYAML",
            "psutil": "psutil",
        }
        versions: Dict[str, Optional[str]] = {}
        for label, package in package_names.items():
            try:
                versions[label] = importlib_metadata.version(package)
            except importlib_metadata.PackageNotFoundError:
                versions[label] = None
            except Exception:
                versions[label] = None
        return versions

    @staticmethod
    def _epoch_to_iso8601(epoch_seconds: Optional[float]) -> Optional[str]:
        if epoch_seconds is None:
            return None
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(epoch_seconds)))
        except Exception:
            return None

    def _write_config_snapshot(self) -> None:
        try:
            self.output_path.mkdir(parents=True, exist_ok=True)
            config_path = self.output_path / "config_resolved.yaml"
            with config_path.open("w", encoding="utf-8") as handle:
                yaml.safe_dump(self.config, handle, sort_keys=False)
        except Exception as exc:
            self.logger.debug(f"Failed to write config snapshot: {exc}")

    def _write_metadata(self, end_time: float, error: Optional[str] = None) -> None:
        try:
            repo_root = self._repo_root()
            uv_lock_path = repo_root / "uv.lock"
            command_line = (
                self.config.get("provenance", {}).get("cli_command")
                or " ".join(sys.argv)
            )
            meta = {
                "suite": self.suite,
                "experiment_id": self.experiment_id,
                "run_uid": self.run_uid,
                "run_id": self.run_id,
                "seed": self.seed,
                "seeds": [self.seed],
                "start_time": self.start_time,
                "start_time_utc": self._epoch_to_iso8601(self.start_time),
                "end_time": end_time,
                "end_time_utc": self._epoch_to_iso8601(end_time),
                "duration_s": max(0.0, end_time - self.start_time) if self.start_time else None,
                "python_version": platform.python_version(),
                "git_hash": self._get_git_hash(),
                "git_dirty": self._get_git_dirty(),
                "attack_type": self.attack_type,
                "output_overwrite": self.output_overwrite,
                "manifest_keep_last": self.manifest_keep_last,
                "command": command_line,
                "experiments_config": self.config.get("provenance", {}).get("experiments_config"),
                "config_sha256": self._config_sha256(),
                "uv_lock_sha256": self._sha256_file(uv_lock_path),
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "machine": platform.machine(),
                    "python_implementation": platform.python_implementation(),
                },
                "dependency_versions": self._dependency_versions(),
            }
            if error:
                meta["error"] = error
            meta_path = self.output_path / "metadata.json"
            meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        except Exception as exc:
            self.logger.debug(f"Failed to write metadata: {exc}")

    def _make_alarm_set_id(self, iteration: int) -> str:
        return f"alarmset_{iteration}_{derive_seed(self.seed, 'alarmset', iteration)}"

    def _render_progress_bar(self, current: int, total: int) -> None:
        if total <= 0:
            return
        if not self._progress_is_enabled():
            return
        bar_width = 30
        ratio = min(max(current / total, 0.0), 1.0)
        filled = int(bar_width * ratio)
        bar = "#" * filled + "-" * (bar_width - filled)
        pct = int(ratio * 100)
        self._progress_render = f"\rProgress [{bar}] {pct}% ({current}/{total})"
        self._progress_active = current < total
        stream = self._progress_stream or sys.stderr
        stream.write(self._progress_render)
        stream.flush()
        if current >= total:
            stream.write("\n")
            stream.flush()
            self._progress_active = False
            self._progress_render = ""
            
    def _progress_is_enabled(self) -> bool:
        if not self.progress_bar:
            return False
        stream = self._progress_stream or sys.stderr
        return hasattr(stream, "isatty") and stream.isatty()

    def _clear_progress_line(self) -> None:
        if not self._progress_active or not self._progress_is_enabled():
            return
        stream = self._progress_stream or sys.stderr
        stream.write("\r")
        stream.write("\x1b[2K")
        stream.flush()

    def _repaint_progress_line(self) -> None:
        if not self._progress_active or not self._progress_is_enabled():
            return
        stream = self._progress_stream or sys.stderr
        stream.write(self._progress_render)
        stream.flush()

    def _setup_logging(self):
        """Setup logging based on configuration."""
        log_config = self.config.get('logging', {})
        log_level_str = log_config.get('level', 'INFO').upper()
        log_file = log_config.get('file')
        
        log_level = getattr(logging, log_level_str, logging.INFO)
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        console_stream = sys.stderr
        self._progress_stream = console_stream
        if self.progress_bar:
            console_handler = _ProgressAwareStreamHandler(self, stream=console_stream)
        else:
            console_handler = logging.StreamHandler(stream=console_stream)
        handlers = [console_handler] # Selalu log ke console
        if log_file:
             # Pastikan direktori log ada
            log_dir = os.path.dirname(log_file)
            if log_dir:
                 os.makedirs(log_dir, exist_ok=True)
            handlers.append(logging.FileHandler(log_file, mode='w'))
        
        # Hapus handler default jika ada, lalu tambahkan yang baru
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                self.logger.debug("Failed to close existing log handler cleanly.", exc_info=True)
        logging.basicConfig(level=log_level, format=log_format, handlers=handlers)
        self.logger.info(f"Logging di-setup ke level {log_level_str}" + (f" dan file {log_file}" if log_file else ""))

    def _setup_database(self, db_manager: Optional[NodeDatabase], output_config: Dict) -> NodeDatabase:
        """Initialize or use existing database manager based on config."""
        if db_manager:
            self.logger.info("Menggunakan instance database manager eksternal.")
            return db_manager
        else:
            db_filename = output_config.get('database_file', "simulation_data.db")
            # Buat path absolut atau relatif terhadap output directory
            if os.path.isabs(db_filename):
                db_path = db_filename
            else:
                output_base = self.output_path if hasattr(self, "output_path") else Path(self.output_dir)
                output_base.mkdir(parents=True, exist_ok=True)
                db_path = str(output_base / db_filename)
                
            self.logger.info(f"Menginisialisasi database baru di: {db_path}")
            return NodeDatabase(db_path=db_path)

    def _preflight_output_paths(self, output_config: Dict) -> None:
        """Check output/log/db paths are writable before simulation starts."""
        errors = []
        output_dir = Path(self.output_dir)
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            errors.append(f"output_dir create failed: {output_dir} ({exc})")

        if not os.access(output_dir, os.W_OK):
            errors.append(f"output_dir not writable: {output_dir}")

        test_path = output_dir / ".write_test"
        try:
            test_path.write_text("ok", encoding="utf-8")
            test_path.unlink(missing_ok=True)
        except Exception as exc:
            errors.append(f"output_dir write test failed: {output_dir} ({exc})")

        db_filename = output_config.get('database_file', "simulation_data.db")
        db_path = Path(db_filename)
        if not db_path.is_absolute():
            db_path = output_dir / db_filename
        if db_path.exists() and db_path.is_dir():
            errors.append(f"db_path is a directory: {db_path}")
        db_dir = db_path.parent
        if not os.access(db_dir, os.W_OK):
            errors.append(f"db_dir not writable: {db_dir}")

        log_file = (self.config.get('logging', {}) or {}).get('file')
        if log_file:
            log_dir = Path(log_file).expanduser().resolve().parent
            if not os.access(log_dir, os.W_OK):
                errors.append(f"log_dir not writable: {log_dir}")

        if errors:
            message = "Preflight check failed:\n- " + "\n- ".join(errors)
            self.logger.error(message)
            raise PermissionError(message)
        self.logger.info("Preflight check OK: output_dir=%s db_path=%s", output_dir, db_path)

    def _log_run_config_summary(self) -> None:
        sim_cfg = self.config.get('simulation', {}) or {}
        net_cfg = self.config.get('network', {}) or {}
        trust_cfg = self.config.get('trust_model', {}) or {}
        attack_cfg = self.config.get('attack', {}) or {}
        auth_cfg = self.config.get('auth', {}) or {}
        feat_cfg = self.config.get('features', {}) or {}
        log_cfg = self.config.get('logging', {}) or {}
        summary_lines = [
            f"suite={self.suite}",
            f"experiment_id={self.experiment_id}",
            f"run_uid={self.run_uid}",
            f"run_id={self.run_id}",
            f"seed={self.seed}",
            f"total_nodes={self.total_nodes}",
            f"malicious_ratio={sim_cfg.get('malicious_ratio', None)}",
            f"malicious_nodes={self.malicious_nodes}",
            f"iterations={self.total_iterations}",
            f"attack_type={self.attack_type}",
            f"trust_method={trust_cfg.get('method', None)}",
            f"trust_threshold={self.trust_threshold}",
            f"initial_trust={self.initial_trust}",
            f"challenge_rate={trust_cfg.get('challenge_rate', None)}",
            f"challenge_rate_tiers={trust_cfg.get('challenge_rate_tiers', None)}",
            f"challenge_min_interval_tiers={trust_cfg.get('challenge_min_interval_tiers', None)}",
            f"forgetting_factor={trust_cfg.get('forgetting_factor', None)}",
            f"auth_mode={auth_cfg.get('mode', None)}",
            f"auth_revocation_enabled={auth_cfg.get('revocation_enabled', None)}",
            f"auth_revocation_rate_malicious={auth_cfg.get('revocation_rate_malicious', None)}",
            f"network_type={net_cfg.get('type', None)}",
            f"connection_probability={net_cfg.get('connection_probability', None)}",
            f"hybrid_backbone={net_cfg.get('hybrid_backbone', None)}",
            f"hybrid_core_ratio={net_cfg.get('hybrid_core_ratio', None)}",
            f"hybrid_bridge_probability={net_cfg.get('hybrid_bridge_probability', None)}",
            f"gossip_fanout={feat_cfg.get('gossip_fanout', None)}",
            f"gossip_max_hops={feat_cfg.get('gossip_max_hops', None)}",
            f"min_alarm_send_delay={feat_cfg.get('min_alarm_send_delay', None)}",
            f"max_alarm_send_delay={feat_cfg.get('max_alarm_send_delay', None)}",
            f"variants_per_alarm={feat_cfg.get('variants_per_alarm', None)}",
            f"output_dir={self.output_dir}",
            f"output_overwrite={self.output_overwrite}",
            f"manifest_keep_last={self.manifest_keep_last}",
            f"db_path={getattr(self.db_manager, 'db_path', None)}",
            f"plot_enabled={self.plot_enabled}",
            f"log_level={log_cfg.get('level', None)}",
            f"log_file={log_cfg.get('file', None)}",
        ]
        self.logger.info("Simulation config recap:\n- " + "\n- ".join(summary_lines))
    
    def _setup_trust_method(self, trust_config: Dict):
        """Initialize trust method using method factory."""
        try:
            # Import method factory
            from simulation.methods.method_factory import MethodFactory
            
            # Get method name from config
            method_name = trust_config.get('method', '3-level-challenge')
            self.logger.info(f"Setting up trust method: {method_name}")
            
            # Check if method is available
            if not MethodFactory.is_method_available(method_name):
                available_methods = MethodFactory.get_available_methods()
                self.logger.warning(f"Method '{method_name}' not available. Available methods: {available_methods}")
                
                # Fallback to 3-level-challenge if available, otherwise first available
                if MethodFactory.is_method_available('3-level-challenge'):
                    method_name = '3-level-challenge'
                elif available_methods:
                    method_name = available_methods[0]
                else:
                    self.logger.error("No trust methods available!")
                    return None
                    
                self.logger.info(f"Using fallback method: {method_name}")
            
            # Create method instance
            method_instance = MethodFactory.create_method(method_name, trust_config)
            
            if method_instance:
                self.logger.info(f"Trust method '{method_name}' initialized successfully")
                return method_instance
            else:
                self.logger.error(f"Failed to create trust method instance for '{method_name}'")
                return None
                
        except ImportError as e:
            self.logger.warning(f"Method factory not available: {e}")
            self.logger.info("Using default trust mechanism (3-level challenge modules)")
            return None
        except Exception as e:
            self.logger.error(f"Error setting up trust method: {e}")
            return None

    def _validate_params(self, total_nodes, malicious_nodes, attack_type):
        """Validate simulation parameters"""
        if not isinstance(total_nodes, int) or total_nodes <= 0:
            raise ValueError("Config error: simulation.total_nodes must be a positive integer")
        if not isinstance(malicious_nodes, int) or malicious_nodes < 0:
            raise ValueError("Config error: Calculated malicious_nodes must be non-negative")
        if malicious_nodes > total_nodes:
            raise ValueError("Config error: malicious_nodes cannot exceed total_nodes")
        if not isinstance(attack_type, str) or not attack_type:
             # Tambahkan check untuk 'None' type
            if attack_type is not None:
                raise ValueError("Config error: attack.type must be a non-empty string or None")
        # Consider validating attack_type against a list of known types
        valid_attacks = ["PMFA", "Collusion", "Sybil", "Betrayal", None, "None"]
        if attack_type not in valid_attacks:
            self.logger.warning(f"Config warning: attack.type '{attack_type}' is not in the recognized list: {valid_attacks[:-1]}")
            # raise ValueError(f"Invalid attack type: {attack_type}. Must be one of {valid_attacks}")
        self.logger.debug("Parameter simulasi berhasil divalidasi")

    def _initialize_simulation(self, net_config: Dict):
        """Inisialisasi nodes dan network berdasarkan config."""
        self.logger.info("Menginisialisasi nodes dan network...")
        
        self.nodes = {}
        # Regenerate malicious indices based on loaded parameters
        malicious_indices = self.rng.sample(range(self.total_nodes), self.malicious_nodes)
        self.logger.debug(f"Node berbahaya akan dibuat pada indeks: {malicious_indices}")
        
        for i in range(self.total_nodes):
            is_malicious = i in malicious_indices
            node = Node(
                id=i,
                env=self.env,
                is_malicious=is_malicious,
                # Gunakan attack_type dari config jika node malicious
                attack_type=self.attack_type if is_malicious else None, 
                db=self.db_manager,
                # Teruskan konfigurasi trust model ke Node
                trust_config=self.config.get('trust_model', {}), 
                # Teruskan konfigurasi feature (gossip) ke Node (melalui collab module)
                feature_config=self.feature_config,
                # Teruskan trust method instance jika ada
                trust_method_instance=self.trust_method_instance,
                metrics_recorder=self.enhanced_metrics,
                attack_config=self.config.get('attack', {}),
                auth_config=self.config.get('auth', {}),
                rng=make_random(self.seed, "node", i),
                pmfa_cache=self.pmfa_cache,
            )
            self.nodes[i] = node
            
        # Inisialisasi network berdasarkan tipe dari config
        network_type = str(net_config.get('type', 'random')).strip().lower()
        self.network = Network(list(self.nodes.values()), rng=self.rng) 
        if network_type == 'random':
             connection_probability = net_config.get('connection_probability', 0.3)
             self.network.initialize_connections(connectivity=connection_probability)
        elif network_type == 'small_world':
             neighbors_per_node = int(net_config.get('neighbors_per_node', 4))
             rewiring_probability = float(net_config.get('rewiring_probability', 0.1))
             graph = nx.watts_strogatz_graph(self.total_nodes, neighbors_per_node, rewiring_probability, seed=self.seed)
             self.network.initialize_from_graph(graph)
        elif network_type == 'scale_free':
             neighbors_to_attach = int(net_config.get('neighbors_to_attach', 2))
             graph = nx.barabasi_albert_graph(self.total_nodes, neighbors_to_attach, seed=self.seed)
             self.network.initialize_from_graph(graph)
        elif network_type == 'mesh':
             graph = nx.complete_graph(self.total_nodes)
             self.network.initialize_from_graph(graph)
        elif network_type == 'hybrid':
             graph = self._build_hybrid_graph(net_config)
             self.network.initialize_from_graph(graph)
        else:
             self.logger.warning(f"Tipe network '{network_type}' belum diimplementasikan. Menggunakan default random.")
             self.network.initialize_connections() # Gunakan default connectivity
             
        # Inisialisasi trust (menggunakan nilai dari config)
        self.node_trust_scores = {node_id: [] for node_id in self.nodes}
        self._init_trust_values(self.initial_trust)

        self.logger.info(f"Inisialisasi node dan network selesai.")

    def _build_hybrid_graph(self, net_config: Dict) -> nx.Graph:
        """Build a hybrid graph: stochastic backbone + meshed core overlay."""
        n = self.total_nodes
        graph = nx.Graph()
        graph.add_nodes_from(range(n))
        if n <= 1:
            return graph
        if n <= 2:
            return nx.complete_graph(n)

        backbone = str(net_config.get('hybrid_backbone', 'small_world')).strip().lower()
        if backbone == 'random':
            p = float(net_config.get('connection_probability', 0.3))
            graph = nx.erdos_renyi_graph(n, p, seed=self.seed)
        elif backbone == 'scale_free':
            m = int(net_config.get('neighbors_to_attach', 2))
            m = max(1, min(m, max(1, n - 1)))
            graph = nx.barabasi_albert_graph(n, m, seed=self.seed)
        else:
            # Default backbone is small_world
            k = int(net_config.get('neighbors_per_node', 4))
            k = min(max(2, k), max(2, n - 1))
            if k % 2 == 1:
                k = max(2, k - 1)
            k = min(k, n - 1)
            p = float(net_config.get('rewiring_probability', 0.1))
            graph = nx.watts_strogatz_graph(n, k, p, seed=self.seed)

        core_ratio = float(net_config.get('hybrid_core_ratio', 0.2))
        core_ratio = max(0.0, min(1.0, core_ratio))
        core_size = max(2, min(n, int(round(n * core_ratio))))
        core_nodes = sorted(self.rng.sample(range(n), core_size))

        # Mesh overlay on core nodes.
        for idx, u in enumerate(core_nodes):
            for v in core_nodes[idx + 1:]:
                graph.add_edge(u, v)

        bridge_prob = float(net_config.get('hybrid_bridge_probability', net_config.get('connection_probability', 0.3)))
        bridge_prob = max(0.0, min(1.0, bridge_prob))
        core_set = set(core_nodes)
        for node_id in range(n):
            if node_id in core_set:
                continue
            # Ensure at least one core link per non-core node.
            if not any(graph.has_edge(node_id, core_id) for core_id in core_nodes):
                graph.add_edge(node_id, self.rng.choice(core_nodes))
            for core_id in core_nodes:
                if graph.has_edge(node_id, core_id):
                    continue
                if self.rng.random() < bridge_prob:
                    graph.add_edge(node_id, core_id)

        return graph

    def _init_trust_values(self, initial_value: float):
        """Initialize trust values between nodes using the configured initial value."""
        self.logger.info(f"Menginisialisasi nilai trust awal ke: {initial_value}")

        for node in self.nodes.values():
            # Set trust score awal di dalam objek Node
            node.trust_scores = {}
            node.trust_components = {}
            db_rows = []
            for target_node in self.nodes.values():
                if node.id != target_node.id:
                     node.trust_scores[target_node.id] = initial_value
                     node.trust_components[target_node.id] = {
                         'basic': initial_value,
                         'advanced': initial_value,
                         'final': initial_value,
                     }
                     # Simpan ke DB (iterasi 0)
                     if self.db_manager:
                         db_rows.append((node.id, target_node.id, initial_value, 0))
            if self.db_manager and db_rows:
                self.db_manager.store_trust_scores_bulk(db_rows)
            # Update struktur data lokal engine (meskipun mungkin redundan jika DB utama)
            # self.node_trust_scores[node.id] = [{...}] # Struktur lama mungkin tidak perlu lagi
            # Kosongkan saja, akan diisi oleh update_trust_scores saat run

        self.logger.info(f"Inisialisasi nilai trust di semua node selesai.")

    def run(self, iterations=None):
        """
        Jalankan loop simulasi utama, memeriksa flag berhenti.
        """
        run_error: Optional[str] = None
        if self.is_running:
            self.logger.warning("Simulasi sudah berjalan.")
            return
        if iterations is None:
            iterations = self.total_iterations
        else:
            # Pastikan total_iterations engine diupdate jika dari UI
            self.total_iterations = iterations
        self._log_run_config_summary()
        self.is_running = True
        self.is_completed = False
        self.current_iteration = 0 # Reset iterasi saat mulai
        self.start_time = time.time()
        self.last_run_summary = None
        self._write_config_snapshot()

        # Reset run-level logger to avoid cross-run leakage
        try:
            from evaluation.engine import Engine as EvalEngine
            EvalEngine.reset()
            EvalEngine.log('experiment_id', self.experiment_id)
            EvalEngine.log('run_uid', self.run_uid)
            EvalEngine.log('run_id', self.run_id)
            EvalEngine.log('attack_type', self.attack_type)
            EvalEngine.log('results_path', str(self.output_path))
            EvalEngine.log('seed', self.seed)
            EvalEngine.log('trust_threshold', self.trust_threshold)
        except Exception as reset_exc:
            self.logger.debug(f"EvalEngine reset skipped: {reset_exc}")

        # Reset enhanced metrics collectors for fresh run
        try:
            if hasattr(self, 'enhanced_metrics') and self.enhanced_metrics:
                self.enhanced_metrics.reset()
                self.enhanced_metrics.update_runtime_stats(tau=self.trust_threshold)
        except Exception as reset_exc:
            self.logger.debug(f"Enhanced metrics reset skipped: {reset_exc}")

        # Reset global perf logger (latencies, privacy logs, etc.)
        try:
            metric_logger.reset()
        except Exception as perf_reset_exc:
            self.logger.debug(f"Metric logger reset skipped: {perf_reset_exc}")

        # Prepare runtime performance monitor (CPU/memory/latency)
        try:
            process = psutil.Process(os.getpid())
        except Exception:
            process = None
        self._perf_monitor = {
            'process': process,
            'mem_peak_bytes': 0,
            'cpu_start': time.process_time(),
            'wall_start': time.perf_counter(),
        }

        self.logger.info(f"Memulai eksekusi simulasi hingga iterasi {iterations}...")
        
        try:
            # --- HAPUS BAGIAN INI --- 
            # # Store initial node data if db manager exists
            # if self.db_manager:
            #     self._store_initial_nodes() # <-- Pemanggilan yang redundan
            # else:
            #     self.logger.warning("DB Manager tidak ada, node awal tidak disimpan.")
            # --- AKHIR HAPUS BAGIAN INI --- 

            # --- PERUBAHAN: Jalankan simulasi menggunakan process SimPy --- 
            self.logger.info("Memulai process loop simulasi SimPy...")
            # Simpan process utama untuk kemungkinan interupsi
            self.simulation_process = self.env.process(self._simulation_loop(iterations))
            
            # Jalankan SimPy environment sampai process utama selesai atau diinterupsi
            self.env.run(until=self.simulation_process)
            # --- AKHIR PERUBAHAN --- 

            # Cek apakah simulasi berhenti karena diinterupsi atau selesai normal
            # Jika env.run selesai karena process diinterupsi, self.is_running sudah False
            if not self.is_running:
                self.logger.info("Simulasi dihentikan oleh pengguna (terinterupsi).")
                self.is_completed = False # Tidak selesai normal
            else:
                # Jika process selesai tanpa interupsi
                self.logger.info("Loop simulasi SimPy selesai secara normal.")
                self.is_completed = True

        except simpy.Interrupt as interrupt: # Tangkap interupsi dari stop()
             self.logger.info(f"Simulasi diinterupsi: {interrupt.cause}")
             self.is_completed = False
             run_error = str(interrupt.cause)
        except Exception as e:
            self.logger.error(f"Simulasi error: {e}")
            traceback.print_exc()
            self.is_completed = False # Tandai tidak selesai
            run_error = str(e)
        finally:
            self.is_running = False # Selalu set false di akhir
            end_time = time.time()
            run_duration = end_time - self.start_time
            self.logger.info(f"Eksekusi simulasi selesai dalam {run_duration:.2f} detik.")
            # Update runtime stats (cpu/mem/duration)
            try:
                cpu_ms = None
                mem_peak_mb = None
                if self._perf_monitor:
                    cpu_ms = (time.process_time() - self._perf_monitor.get('cpu_start', time.process_time())) * 1000.0
                    peak_bytes = self._perf_monitor.get('mem_peak_bytes', 0) or 0
                    mem_peak_mb = peak_bytes / (1024 ** 2)
                if hasattr(self, 'enhanced_metrics') and self.enhanced_metrics:
                    self.enhanced_metrics.update_runtime_stats(
                        cpu_time_ms=cpu_ms,
                        mem_peak_mb=mem_peak_mb,
                        run_duration_s=run_duration,
                    )
            except Exception as perf_exc:
                self.logger.debug(f"Runtime stats update skipped: {perf_exc}")
            self._write_metadata(end_time=end_time, error=run_error)
            # Simpan hasil akhir jika db manager ada
            if self.db_manager:
                try:
                    # Simpan ringkasan akhir dengan status is_completed
                    final_results = self.get_results()
                    sim_info = final_results.get('simulation_info', {})
                    metrics = final_results.get('metrics', {})
                    
                    self.logger.info(f"Basic metrics snapshot (end-of-run): {metrics}")
                    
                    # --- Log metrics to evaluation.Engine for UI JSON visibility ---
                    try:
                        from evaluation.engine import Engine as EvalEngine
                        method_prefix = self.trust_method_instance.method_name if self.trust_method_instance else "CIDSeeks"
                        for k, v in metrics.items():
                            # Skip confusion matrix (dict), handled separately
                            if isinstance(v, (int, float)):
                                EvalEngine.log(f"{method_prefix}/{k}", v)
                        # confusion matrix store as individual keys
                        cm = metrics.get("confusion_matrix", {})
                        for cm_key, cm_val in cm.items():
                            EvalEngine.log(f"{method_prefix}/cm_{cm_key.lower()}", cm_val)

                        # Detection latency distribution (if collected)
                        try:
                            from simulation.utils.perf import metric_logger
                            if metric_logger.latencies:
                                import numpy as np
                                lat_arr = np.array(metric_logger.latencies)
                                EvalEngine.log(f"{method_prefix}/mean_latency", float(lat_arr.mean()))
                                EvalEngine.log(f"{method_prefix}/95p_latency", float(np.percentile(lat_arr, 95)))
                        except Exception:
                            self.logger.debug("Latency logging skipped", exc_info=True)

                    except Exception as log_exc:
                        self.logger.debug(f"EvalEngine logging skipped: {log_exc}")

                    # Store enhanced metrics summary to database
                    enhanced_metrics_data = self.enhanced_metrics.get_comprehensive_metrics()
                    self.logger.info(f"Enhanced metrics data: {enhanced_metrics_data}")
                    
                    # Use new enhanced summary storage method
                    self.db_manager.store_enhanced_summary(
                        metrics=enhanced_metrics_data,
                        method="three_level_challenge",
                        total_nodes=sim_info.get('total_nodes'),
                        malicious_nodes=sim_info.get('malicious_nodes'),
                        attack_type=sim_info.get('attack_type'),
                        total_iterations=sim_info.get('total_iterations'),
                        completed_iterations=sim_info.get('completed_iterations'),
                        duration=sim_info.get('duration'),
                        is_completed=sim_info.get('is_completed'),
                        error=sim_info.get('error')
                    )
                    self.logger.info("Enhanced metrics summary stored to database.")
                    # Optimasi DB setelah selesai
                    self.db_manager.optimize_database()
                except Exception as db_err:
                    self.logger.error(f"Gagal menyimpan hasil akhir atau optimasi DB: {db_err}")

            # ----------------------------------------------
            # Academic evaluation pipeline (summary, events, plots)
            # ----------------------------------------------
            try:
                scenario_id = self.config.get('simulation', {}).get('name', 'default')
                variant_label = self.config.get('simulation', {}).get('variant')
                if not variant_label:
                    variant_label = self._derive_variant_label()
                run_id = str(self.config.get('simulation', {}).get('run_id') or self.run_id)
                self.config.setdefault('simulation', {})['run_id'] = run_id

                runtime_snapshot = metric_logger.snapshot()
                latency_rounds = runtime_snapshot.get('latencies', [])
                if latency_rounds:
                    try:
                        interval = float(self.config.get('simulation', {}).get('update_interval', 0.1))
                        latency_ms_samples = [float(v) * interval * 1000.0 for v in latency_rounds]
                        self.enhanced_metrics.update_runtime_stats(latency_ms_samples=latency_ms_samples)
                    except Exception as latency_exc:
                        self.logger.debug(f"Failed to record latency samples: {latency_exc}")

                # Include collaboration latency samples if present
                try:
                    collab_latency = runtime_snapshot.get('collab_latency', {}) or {}
                    collab_samples = [float(v) for vals in collab_latency.values() for v in (vals or [])]
                    if collab_samples:
                        self.enhanced_metrics.update_runtime_stats(latency_ms_samples=collab_samples)
                except Exception as latency_exc:
                    self.logger.debug(f"Failed to record collab latency samples: {latency_exc}")

                total_messages_snapshot = runtime_snapshot.get('message_events')
                if total_messages_snapshot is not None:
                    try:
                        per_round_counts = {}
                        for ev in total_messages_snapshot:
                            rnd = int(ev.get('iteration', 0))
                            per_round_counts[rnd] = per_round_counts.get(rnd, 0) + 1
                        if per_round_counts:
                            counts = list(per_round_counts.values())
                            mean_msgs = float(sum(counts) / len(counts))
                            p95_msgs = float(np.percentile(np.array(counts, dtype=float), 95))
                        else:
                            mean_msgs = float('nan')
                            p95_msgs = float('nan')
                        self.enhanced_metrics.update_runtime_stats(
                            total_messages=len(total_messages_snapshot),
                            msgs_per_round_total=len(total_messages_snapshot),
                            msgs_per_round_mean=mean_msgs,
                            msgs_per_round_p95=p95_msgs,
                        )
                    except Exception as msg_exc:
                        self.logger.debug(f"Failed to record message totals: {msg_exc}")
                fraction_colluders = self.config.get('attack', {}).get('collusion_ratio')
                if fraction_colluders is None:
                    fraction_colluders = self.config.get('simulation', {}).get('malicious_ratio')
                fraction_sybils = self.config.get('attack', {}).get('sybil_ratio')
                topology = self.config.get('network', {}).get('type', 'random')

                from evaluation.pipeline.run_evaluator import RunEvaluator, RunEvaluationInputs

                output_dir = Path(self.output_dir or 'results')
                inputs = RunEvaluationInputs(
                    run_id=run_id,
                    scenario_id=scenario_id,
                    variant_label=variant_label,
                    method=self.config.get('trust_model', {}).get('method', 'unknown'),
                    attack_type=self.attack_type or 'generic',
                    topology=topology,
                    n_nodes=self.total_nodes,
                    fraction_colluders=float(fraction_colluders or 0.0),
                    fraction_sybils=float(fraction_sybils or 0.0),
                    seed=int(self.config.get('simulation', {}).get('seed') or 0),
                    malicious_ratio=float(self.config.get('simulation', {}).get('malicious_ratio') or 0.0),
                    trust_threshold=self.trust_threshold,
                    config=self.config,
                    enhanced_metrics=self.enhanced_metrics,
                    runtime_snapshot=runtime_snapshot,
                    db_path=Path(self.db_manager.db_path),
                    output_dir=output_dir,
                )
                run_result = RunEvaluator(inputs).evaluate()
                self.last_run_summary = {
                    'summary': run_result.summary_row,
                    'per_round': run_result.per_round_metrics,
                    'overhead': run_result.overhead_per_round,
                    'stability': run_result.stability_per_round,
                    'pmfa': run_result.pmfa_stats,
                    'figures': run_result.figures,
                    'output_dir': str(output_dir),
                }

                self._refresh_suite_aggregates()

                try:
                    from evaluation.engine import Engine as EvalEngine
                    EvalEngine.log('results_path', str(output_dir))
                    EvalEngine.log('attack_type', self.attack_type)
                except Exception as log_exc:
                    self.logger.debug(f"EvalEngine logging skipped: {log_exc}")
            except Exception as eval_exc:
                self.logger.error(f"Run evaluation failed: {eval_exc}", exc_info=True)

            # Flush run metrics once after all logging is complete
            try:
                from evaluation.engine import Engine as EvalEngine
                EvalEngine.flush(
                    self.output_root / "_manifests",
                    keep_last=self.manifest_keep_last,
                )
            except Exception as flush_exc:
                self.logger.debug(f"EvalEngine flush skipped: {flush_exc}")

        return self.get_results()

    def simulation_process(self, iterations):
        """
        Contoh loop simulasi manual (JIKA TIDAK PAKAI SimPy env.run/step).
        PENTING: Metode ini perlu memeriksa self.is_running.
        """
        self.logger.warning("Metode simulation_process dipanggil - pastikan ini yang diinginkan.")
        for i in range(iterations):
            # --- Pemeriksaan flag berhenti --- 
            if not self.is_running:
                self.logger.info(f"Simulasi dihentikan pada iterasi {i}")
                break
            # --- Akhir pemeriksaan --- 

            self.current_iteration = i
            self.logger.info(f"=================== ITERASI {i+1}/{iterations} ===================")

            # 1. Node Actions (Deteksi, Serangan jika malicious)
            for node in self.nodes.values():
                node.perform_iteration_actions()
            
            # 2. Update Trust Scores (berdasarkan interaksi di iterasi ini)
            # Logika ini mungkin perlu dipindahkan ke dalam Node atau Modul Trust
            # self.update_all_trust_scores(i)
            
            # Hindari sleep blocking dalam core simulation; waktu simulasi diatur oleh SimPy.
            
        # Set status selesai jika loop selesai tanpa break
        if self.is_running: # Jika tidak di-break
            self.is_completed = True 

    def stop(self):
        """Hentikan simulasi dengan menginterupsi process SimPy."""
        if not self.is_running:
             self.logger.warning("Perintah stop diterima, tapi simulasi tidak sedang berjalan.")
             return 

        self.is_running = False # Set flag utama dulu
        self.is_completed = False
        self.logger.info("Mengirim sinyal berhenti ke simulasi...")
        
        # Interupsi process SimPy utama jika sedang berjalan
        if self.simulation_process and self.simulation_process.is_alive:
            try:
                 self.simulation_process.interrupt("Simulation stopped by user")
                 self.logger.info("Process simulasi SimPy berhasil diinterupsi.")
            except RuntimeError as e:
                 # Tangkap error jika process sudah selesai tapi belum 'cleaned up'
                 self.logger.warning(f"Gagal menginterupsi process (mungkin sudah selesai): {e}")
        else:
             self.logger.warning("Tidak ada process simulasi SimPy yang aktif untuk diinterupsi.")

    def _refresh_suite_aggregates(self) -> None:
        """Regenerate suite-level statistics tables (experiments, stats, aggregates)."""
        try:
            from evaluation.export.experiment_aggregator import ExperimentAggregator
        except Exception as exc:
            self.logger.debug(f"ExperimentAggregator not available: {exc}")
            return

        try:
            suite_root = self.output_root / self.suite
            if not suite_root.exists():
                return

            rows: List[Dict[str, Any]] = []
            for summary_path in suite_root.glob('*/summary.csv'):
                try:
                    df = pd.read_csv(summary_path)
                except Exception as read_exc:
                    self.logger.debug(f"Skip summary at {summary_path}: {read_exc}")
                    continue
                if df.empty:
                    continue
                run_dir = summary_path.parent
                row = df.iloc[0].to_dict()
                row['run_dir'] = str(run_dir)

                overhead = self._estimate_overhead_from_events(run_dir)
                if overhead is not None:
                    updated = False
                    for col, key in (
                        ('msgs_per_round_mean', 'msgs_mean'),
                        ('bytes_per_round_mean', 'bytes_mean'),
                        ('latency_per_round_mean', 'latency_mean'),
                    ):
                        if col not in df.columns or pd.isna(df.at[0, col]) or float(df.at[0, col] or 0.0) == 0.0:
                            df.loc[0, col] = overhead[key]
                            row[col] = overhead[key]
                            updated = True
                    if overhead.get('per_round') is not None:
                        per_round_df = overhead['per_round']
                        if not per_round_df.empty:
                            per_round_df.to_csv(run_dir / 'overhead_per_round.csv', index=False)
                    if updated:
                        df.to_csv(summary_path, index=False)

                rows.append(row)

            if not rows:
                return

            aggregator = ExperimentAggregator(output_dir=suite_root, bootstrap_samples=2000, seed=self.seed)
            try:
                aggregator.run_log_path.unlink(missing_ok=True)  # reset run log for deterministic outputs
            except AttributeError:
                self.logger.debug("Run log reset skipped for aggregator")
            aggregator.records = rows
            aggregator.finalize()

            attack_metrics = ['AUROC_final', 'TTD_median', 'bypass_rate', 'msgs_per_round_mean',
                              'bytes_per_round_mean', 'latency_per_round_mean', 'trust_gap_final',
                              'stability_kendall_tau']
            df_all = pd.DataFrame(rows)
            if not df_all.empty:
                attack_summary = df_all.groupby('attack')[attack_metrics].describe().reset_index()
                attack_summary.columns = ['_'.join(col).rstrip('_') for col in attack_summary.columns.to_flat_index()]
                attack_summary.to_csv(suite_root / 'attack_summary.csv', index=False)
        except Exception as agg_exc:
            self.logger.warning(f"Failed to refresh scenario aggregates: {agg_exc}")

    def _estimate_overhead_from_events(self, run_dir: Path) -> Optional[Dict[str, Any]]:
        events_path = run_dir / 'events.jsonl'
        if not events_path.exists():
            return None

        default_latency_ms = float(self.config.get('simulation', {}).get('update_interval', 0.1) * 1000.0)
        per_round: Dict[int, Dict[str, Any]] = {}

        try:
            with events_path.open('r', encoding='utf-8') as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    if event.get('event_type') != 'challenge_outcome':
                        continue
                    round_idx = int(event.get('iteration', 0))
                    stats = self._compute_event_payload_bytes(event, default_latency_ms)
                    bucket = per_round.setdefault(round_idx, {'msgs': 0.0, 'bytes': 0.0, 'latency': []})
                    bucket['msgs'] += stats['messages']
                    bucket['bytes'] += stats['bytes']
                    if stats['latency_ms'] is not None:
                        bucket['latency'].append(stats['latency_ms'])
        except Exception as read_exc:
            self.logger.debug(f"Failed parsing events for overhead: {read_exc}")
            return None

        if not per_round:
            return None

        rows = []
        for round_idx, metrics in per_round.items():
            lat_samples = metrics['latency'] or [default_latency_ms]
            rows.append({
                'round': float(round_idx),
                'msgs': float(metrics['msgs']),
                'bytes': float(metrics['bytes']),
                'latency_ms_mean': float(np.mean(lat_samples)),
            })

        per_round_df = pd.DataFrame(rows).sort_values('round').reset_index(drop=True)
        return {
            'per_round': per_round_df,
            'msgs_mean': float(per_round_df['msgs'].mean()),
            'bytes_mean': float(per_round_df['bytes'].mean()),
            'latency_mean': float(per_round_df['latency_ms_mean'].mean()),
        }

    @staticmethod
    def _compute_event_payload_bytes(event: Dict[str, Any], default_latency_ms: float) -> Dict[str, float]:
        details = event.get('details', {}) or {}
        base_payload = {
            'source': int(event.get('node_id', -1)),
            'target': int(event.get('related_node_id', -1)),
            'round': int(event.get('iteration', 0)),
            'trust_before': SimulationEngine._safe_float(details.get('prev_trust')),
            'trust_after': SimulationEngine._safe_float(details.get('total_trust')),
            'threshold': SimulationEngine._safe_float(details.get('detection_threshold')),
            'target_is_malicious': bool(details.get('target_is_malicious', False)),
        }

        payload_lens: List[float] = []

        def _payload_size(message: Dict[str, Any]) -> float:
            sanitized = {k: SimulationEngine._sanitize_payload_value(v) for k, v in message.items()}
            try:
                return float(len(json.dumps(sanitized, separators=(',', ':')).encode('utf-8')))
            except Exception:
                return float(len(str(sanitized).encode('utf-8')))

        stages = (
            ('basic', SimulationEngine._safe_float(details.get('basic'))),
            ('advanced', SimulationEngine._safe_float(details.get('advanced'))),
            ('final', SimulationEngine._safe_float(details.get('final'))),
        )

        for stage, score in stages:
            if score is None:
                continue
            request = dict(base_payload)
            request.update({'stage': stage, 'direction': 'request', 'score': score})
            if stage == 'advanced':
                request.update({
                    'reputation': SimulationEngine._safe_float(details.get('reputation')),
                    'contribution': SimulationEngine._safe_float(details.get('contribution')),
                    'penalty': SimulationEngine._safe_float(details.get('penalty')),
                })
            if stage == 'final':
                request.update({
                    'auth_status': SimulationEngine._safe_float(details.get('auth')),
                    'biometric': SimulationEngine._safe_float(details.get('biometric_score', details.get('final'))),
                })

            response = dict(base_payload)
            response.update({'stage': stage, 'direction': 'response', 'score': score})

            payload_lens.append(_payload_size(request))
            payload_lens.append(_payload_size(response))

        messages = len(payload_lens)
        bytes_total = float(sum(payload_lens)) if payload_lens else 0.0

        return {
            'messages': float(messages),
            'bytes': bytes_total,
            'latency_ms': default_latency_ms,
        }

    @staticmethod
    def _safe_float(value: Any) -> Optional[float]:
        try:
            val = float(value)
            if math.isnan(val) or math.isinf(val):
                return None
            return val
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _sanitize_payload_value(value: Any) -> Any:
        if isinstance(value, (int, str, bool)) or value is None:
            return value
        try:
            val = float(value)
            if math.isnan(val) or math.isinf(val):
                return None
            return round(val, 6)
        except (TypeError, ValueError):
            return str(value)

    def _derive_variant_label(self) -> str:
        trust_method = self.config.get('trust_model', {}).get('method', 'default')
        attack = (self.attack_type or 'generic').lower()
        coll = self.config.get('attack', {}).get('collusion_ratio')
        syb = self.config.get('attack', {}).get('sybil_ratio')
        forgetting = self.config.get('trust_model', {}).get('forgetting_factor') or self.config.get('trust_model', {}).get('lambda')
        parts = [trust_method, f'attack-{attack}', f'N{self.total_nodes}']
        if coll is not None:
            parts.append(f'coll{float(coll):.2f}')
        if syb is not None:
            parts.append(f'syb{float(syb):.2f}')
        if forgetting is not None:
            parts.append(f'lambda{float(forgetting):.2f}')
        return "_".join(parts)

    def update_trust_scores(self, node_id: int, target_node_id: int, score: float, iteration: int):
        """Update trust scores di database DAN di memori engine."""
        try:
            # 1. Simpan ke database
            self.db_manager.store_trust_score(
                node_id=node_id,
                target_node_id=target_node_id,
                score=score,
                iteration=iteration
            )
            
            # --- TAMBAHAN: Update state lokal di memori engine --- 
            if node_id not in self.node_trust_scores:
                self.node_trust_scores[node_id] = []
            
            # Cari apakah skor untuk target ini di iterasi ini sudah ada
            found = False
            for score_data in self.node_trust_scores[node_id]:
                if score_data['target_node_id'] == target_node_id and score_data['iteration'] == iteration:
                    score_data['score'] = score # Update skor yang ada
                    found = True
                    break
            
            # Jika belum ada, tambahkan entri baru
            if not found:
                self.node_trust_scores[node_id].append({
                    'target_node_id': target_node_id, 
                    'score': score, 
                    'iteration': iteration
                })
            # --- AKHIR TAMBAHAN --- 
            
        except Exception as e:
            self.logger.error(f"Error updating trust score (iter {iteration}, {node_id}->{target_node_id}): {str(e)}")
            # Mungkin tidak perlu raise agar simulasi lanjut? Tergantung kebutuhan.
            # raise # Re-raise jika ingin simulasi berhenti saat gagal update trust

    def _store_metrics(self, iteration: int, node_metrics: dict):
        """Store metrics for current iteration"""
        try:
            # Store node states
            for node_id, metrics in node_metrics.items():
                self.db_manager.store_node_state(
                    iteration=iteration,
                    node_id=node_id,
                    state=metrics.get('state', 'normal'),
                    trust_score=metrics.get('trust_score', 0.5)
                )
                
                # Store trust relationships
                for target_id, trust in metrics.get('trust_scores', {}).items():
                    self.db_manager.store_trust_score(
                        iteration=iteration,
                        node_id=node_id,
                        target_node_id=target_id,
                        score=trust
                    )
                    
        except Exception as e:
            self.logger.error(f"Error storing metrics: {str(e)}")
            raise

    def calculate_accuracy(self):
        """Calculate accuracy metric"""
        try:
            total = len(self.nodes)
            if total == 0:
                return 0.0
            threshold = float(getattr(self, 'trust_threshold', 0.5) or 0.5)
            correct = sum(1 for n in self.nodes.values() 
                         if (n.is_malicious and self.get_node_trust(n.id) < threshold) or
                            (not n.is_malicious and self.get_node_trust(n.id) >= threshold))
                        
            return correct / total
        
        except Exception as e:
            self.logger.error(f"Error calculating accuracy: {str(e)}")
            return 0.0

    def calculate_precision(self):
        """Calculate precision metric"""
        try:
            threshold = float(getattr(self, 'trust_threshold', 0.5) or 0.5)
            detected = sum(1 for n in self.nodes.values() if self.get_node_trust(n.id) < threshold)
            if detected == 0:
                return 0.0
            
            true_positives = sum(1 for n in self.nodes.values() 
                                if n.is_malicious and self.get_node_trust(n.id) < threshold)
                                
            return true_positives / detected
        
        except Exception as e:
            self.logger.error(f"Error calculating precision: {str(e)}")
            return 0.0

    def calculate_recall(self):
        """Calculate recall metric"""
        try:
            malicious = sum(1 for n in self.nodes.values() if n.is_malicious)
            if malicious == 0:
                return 0.0
            threshold = float(getattr(self, 'trust_threshold', 0.5) or 0.5)
            detected = sum(1 for n in self.nodes.values() 
                          if n.is_malicious and self.get_node_trust(n.id) < threshold)
                          
            return detected / malicious
        
        except Exception as e:
            self.logger.error(f"Error calculating recall: {str(e)}")
            return 0.0

    def calculate_f1_score(self):
        """Calculate F1 score"""
        try:
            precision = self.calculate_precision()
            recall = self.calculate_recall()
            
            if precision + recall == 0:
                return 0.0
            
            return 2 * (precision * recall) / (precision + recall)
        
        except Exception as e:
            self.logger.error(f"Error calculating F1 score: {str(e)}")
            return 0.0

    def calculate_detection_rate(self):
        """Calculate detection rate"""
        try:
            malicious = sum(1 for n in self.nodes.values() if n.is_malicious)
            if malicious == 0:
                return 0.0
            threshold = float(getattr(self, 'trust_threshold', 0.5) or 0.5)
            detected = sum(1 for n in self.nodes.values() 
                          if n.is_malicious and self.get_node_trust(n.id) < threshold)
                          
            return detected / malicious
        
        except Exception as e:
            self.logger.error(f"Error calculating detection rate: {str(e)}")
            return 0.0

    def calculate_false_positive_rate(self):
        """Calculate false positive rate"""
        try:
            normal = sum(1 for n in self.nodes.values() if not n.is_malicious)
            if normal == 0:
                return 0.0
            threshold = float(getattr(self, 'trust_threshold', 0.5) or 0.5)
            false_positives = sum(1 for n in self.nodes.values() 
                                 if not n.is_malicious and self.get_node_trust(n.id) < threshold)
                                 
            return false_positives / normal
        
        except Exception as e:
            self.logger.error(f"Error calculating false positive rate: {str(e)}")
            return 0.0

    def calculate_time_to_detect(self):
        """
        Menghitung Time-to-Detect: Berapa iterasi hingga node jahat terdeteksi
        Return: Rata-rata iterasi untuk mendeteksi node jahat
        """
        try:
            self.logger.debug("Calculating Time-to-Detect...") # <-- Log awal
            if self.current_iteration == 0:
                self.logger.debug("Time-to-Detect: Iteration 0, returning 0.0")
                return 0.0
            
            detection_times = {}
            malicious_node_ids = [n.id for n in self.nodes.values() if n.is_malicious]
            self.logger.debug(f"Malicious nodes for TTD: {malicious_node_ids}")
            threshold = float(getattr(self, 'trust_threshold', 0.5) or 0.5)
            
            for node_id in malicious_node_ids:
                detected_at = -1 # Inisialisasi
                for i in range(self.current_iteration + 1):
                    trust_score = self.get_node_trust(node_id, i)
                    self.logger.debug(f"  TTD Check: Node {node_id}, Iter {i}, Trust = {trust_score}") # <-- Log skor trust
                    if trust_score < threshold:  # Trust threshold
                        self.logger.debug(f"    Node {node_id} detected at iteration {i}")
                        detection_times[node_id] = i
                        detected_at = i
                        break
                
                # Jika tidak terdeteksi
                if detected_at == -1:
                    self.logger.debug(f"    Node {node_id} never detected, using final iteration {self.current_iteration}")
                    detection_times[node_id] = self.current_iteration
            
            # Hitung rata-rata
            if not detection_times:
                # Cek jika tidak ada node jahat sama sekali
                if not malicious_node_ids:
                    self.logger.debug("Time-to-Detect: No malicious nodes, returning 0.0")
                    return 0.0
                else:
                    self.logger.debug(f"Time-to-Detect: No detection times recorded (unexpected!), returning {self.current_iteration}")
                    return float(self.current_iteration)
                
            avg_detection_time = sum(detection_times.values()) / len(detection_times)
            self.logger.debug(f"Time-to-Detect: Calculated avg = {avg_detection_time}") # <-- Log hasil
            return avg_detection_time
        except Exception as e:
            self.logger.error(f"Error calculating time to detect: {str(e)}")
            return None # Return None agar jelas N/A
            
    def calculate_trust_degradation(self):
        """
        Menghitung Speed of Trust Degradation: Laju penurunan trust node jahat
        Return: Rata-rata kecepatan penurunan trust untuk node jahat
        """
        try:
            self.logger.debug("Calculating Trust Degradation...") # <-- Log awal
            if self.current_iteration < 1: # Cukup 1 iterasi untuk degradasi dari iter 0
                self.logger.debug("Trust Degradation: Not enough iterations (<1), returning 0.0")
                return 0.0
                
            degradation_rates = []
            malicious_node_ids = [n.id for n in self.nodes.values() if n.is_malicious]
            self.logger.debug(f"Malicious nodes for Trust Degradation: {malicious_node_ids}")

            for node_id in malicious_node_ids:
                initial_trust = self.get_node_trust(node_id, 0)
                current_trust = self.get_node_trust(node_id) # Iterasi terakhir
                self.logger.debug(f"  TD Check: Node {node_id}, Initial Trust={initial_trust}, Current Trust={current_trust}") # <-- Log skor
                
                # Hitung degradasi per iterasi
                if self.current_iteration > 0:
                    # Degradasi adalah penurunan, jadi initial - current
                    degradation = (initial_trust - current_trust) / self.current_iteration
                    degradation_rates.append(max(0, degradation)) # Hanya nilai positif (penurunan)
                    self.logger.debug(f"    Node {node_id} degradation rate: {degradation}")
            
            if not degradation_rates:
                self.logger.debug("Trust Degradation: No degradation rates calculated, returning 0.0")
                return 0.0
                
            avg_degradation = sum(degradation_rates) / len(degradation_rates)
            self.logger.debug(f"Trust Degradation: Calculated avg = {avg_degradation}") # <-- Log hasil
            return avg_degradation
        except Exception as e:
            self.logger.error(f"Error calculating trust degradation: {str(e)}")
            return None # Return None agar jelas N/A
            
    def calculate_undetected_malicious(self):
        """
        Menghitung Fraction of Malicious Nodes Undetected: 
        Persentase node jahat yang masih dipercaya di atas ambang tertentu
        """
        try:
            self.logger.debug("Calculating Undetected Malicious...") # <-- Log awal
            malicious_nodes = [n for n in self.nodes.values() if n.is_malicious]
            total_malicious = len(malicious_nodes)
            self.logger.debug(f"Total malicious nodes: {total_malicious}")
            threshold = float(getattr(self, 'trust_threshold', 0.5) or 0.5)

            if total_malicious == 0:
                self.logger.debug("Undetected Malicious: No malicious nodes, returning 0.0")
                return 0.0
                
            # Hitung jumlah node jahat yang trust score-nya >= 0.5
            undetected_count = 0
            for node in malicious_nodes:
                current_trust = self.get_node_trust(node.id)
                self.logger.debug(f"  UM Check: Node {node.id}, Current Trust={current_trust}") # <-- Log skor
                if current_trust >= threshold:
                    undetected_count += 1
            
            self.logger.debug(f"Undetected Malicious Count: {undetected_count}")
            ratio = undetected_count / total_malicious
            self.logger.debug(f"Undetected Malicious: Calculated ratio = {ratio}") # <-- Log hasil
            return ratio
        except Exception as e:
            self.logger.error(f"Error calculating undetected malicious: {str(e)}")
            return None # Return None agar jelas N/A
            
    def calculate_misalignment(self):
        """
        Menghitung Misalignment: Sejauh mana kepercayaan menyimpang dari status sebenarnya
        Return: Rata-rata selisih antara status sebenarnya dan trust score
        """
        try:
            self.logger.debug("Calculating Misalignment...") # <-- Log awal
            misalignments = []
            self.logger.debug(f"Calculating misalignment for {len(self.nodes)} nodes.")
            
            for node in self.nodes.values():
                # Expected trust score: 1 jika normal, 0 jika jahat
                expected = 0 if node.is_malicious else 1
                actual = self.get_node_trust(node.id)
                self.logger.debug(f"  MA Check: Node {node.id}, Expected={expected}, Actual Trust={actual}") # <-- Log skor
                
                # Hitung selisih absolut
                misalignment = abs(expected - actual)
                misalignments.append(misalignment)
                self.logger.debug(f"    Node {node.id} misalignment: {misalignment}")
                
            if not misalignments:
                self.logger.debug("Misalignment: No nodes found, returning 0.0")
                return 0.0
                
            avg_misalignment = sum(misalignments) / len(misalignments)
            self.logger.debug(f"Misalignment: Calculated avg = {avg_misalignment}") # <-- Log hasil
            return avg_misalignment
        except Exception as e:
            self.logger.error(f"Error calculating misalignment: {str(e)}")
            return None # Return None agar jelas N/A
            
    def get_confusion_matrix_counts(self):
        """Menghitung jumlah True Positives, False Negatives, False Positives, True Negatives."""
        tp = 0 # Malicious, terdeteksi (<0.5)
        fn = 0 # Malicious, tidak terdeteksi (>=0.5)
        fp = 0 # Normal, terdeteksi (<0.5)
        tn = 0 # Normal, tidak terdeteksi (>=0.5)
        try:
            threshold = float(getattr(self, 'trust_threshold', 0.5) or 0.5)
            for node in self.nodes.values():
                is_detected_malicious = self.get_node_trust(node.id) < threshold
                if node.is_malicious:
                    if is_detected_malicious:
                        tp += 1
                    else:
                        fn += 1
                else: # Node is normal
                    if is_detected_malicious:
                        fp += 1
                    else:
                        tn += 1
            self.logger.debug(f"Confusion Matrix Counts: TP={tp}, FN={fn}, FP={fp}, TN={tn}")
            return {'TP': tp, 'FN': fn, 'FP': fp, 'TN': tn}
        except Exception as e:
            self.logger.error(f"Error calculating confusion matrix counts: {e}")
            return {'TP': 0, 'FN': 0, 'FP': 0, 'TN': 0} # Return default on error

    def get_node_trust(self, node_id, iteration=None):
        """
        Dapatkan rata-rata trust score untuk node tertentu
        """
        try:
            target_iteration = int(self.env.now) - 1 if iteration is None else int(iteration)
            if target_iteration < 0:
                return 0.5

            # Prefer DB as source of truth
            if self.db_manager:
                try:
                    row = self.db_manager.execute_query(
                        "SELECT AVG(score) AS avg_trust FROM trust_scores WHERE target_node_id = ? AND iteration = ?",
                        (node_id, target_iteration),
                    ).fetchone()
                    if row is not None:
                        try:
                            avg_val = row[0]
                        except Exception:
                            avg_val = row["avg_trust"] if hasattr(row, 'keys') and "avg_trust" in row.keys() else None
                        if avg_val is not None:
                            return float(avg_val)

                    # Fallback to last known <= target_iteration
                    row = self.db_manager.execute_query(
                        (
                            """
                            SELECT AVG(score) AS avg_trust
                            FROM trust_scores
                            WHERE target_node_id = ?
                              AND iteration = (
                                SELECT MAX(iteration)
                                FROM trust_scores
                                WHERE target_node_id = ?
                                  AND iteration <= ?
                              )
                            """
                        ),
                        (node_id, node_id, target_iteration),
                    ).fetchone()
                    if row is not None:
                        try:
                            avg_val = row[0]
                        except Exception:
                            avg_val = row["avg_trust"] if hasattr(row, 'keys') and "avg_trust" in row.keys() else None
                        if avg_val is not None:
                            return float(avg_val)
                except Exception as db_exc:
                    self.logger.debug(f"DB fallback get_node_trust failed: {db_exc}")

            # Memory cache fallback
            relevant_scores = []
            for scores_list in self.node_trust_scores.values():
                for score_data in scores_list:
                    if score_data['target_node_id'] == node_id and score_data['iteration'] == target_iteration:
                        relevant_scores.append(score_data['score'])

            if not relevant_scores:
                # New fallback: compute from live node states if DB/cache miss
                try:
                    vals = []
                    for src in self.nodes.values():
                        if src.id == node_id:
                            continue
                        if node_id in src.trust_scores:
                            vals.append(float(src.trust_scores[node_id]))
                    if vals:
                        return sum(vals) / len(vals)
                except Exception:
                    self.logger.debug("Live trust fallback skipped", exc_info=True)

                for prev_iter in range(target_iteration - 1, -1, -1):
                    prev_scores = []
                    for scores_list in self.node_trust_scores.values():
                        for score_data in scores_list:
                            if score_data['target_node_id'] == node_id and score_data['iteration'] == prev_iter:
                                prev_scores.append(score_data['score'])
                    if prev_scores:
                        return sum(prev_scores) / len(prev_scores)
                return 0.5
            else:
                return sum(relevant_scores) / len(relevant_scores)

        except Exception as e:
            self.logger.error(f"Error getting node trust for node {node_id} at iteration {iteration}: {str(e)}")
            return 0.5

    def get_results(self):
        """
        Mendapatkan hasil simulasi untuk ditampilkan di UI
        
        Returns:
            Dict: Hasil simulasi dalam bentuk dictionary
        """
        try:
            # Tentukan iterasi yang selesai berdasarkan status
            completed_iter = 0
            current_sim_time = int(self.env.now) # Waktu SimPy saat ini
            if hasattr(self, 'is_completed') and self.is_completed:
                 # Jika selesai normal, iterasi selesai adalah total iterasi
                 completed_iter = self.total_iterations 
            elif hasattr(self, 'current_iteration'):
                 # Jika berhenti di tengah atau error, gunakan iterasi terakhir yang dimulai
                 # SimPy time maju sebelum iterasi berikutnya, jadi env.now cocok
                 completed_iter = current_sim_time
                 
            # Pastikan completed_iter tidak melebihi total_iterations
            completed_iter = min(completed_iter, getattr(self, 'total_iterations', completed_iter))
                 
            run_duration = time.time() - self.start_time if hasattr(self, 'start_time') and self.start_time else 0
            
            # Update enhanced metrics with final data
            if hasattr(self, 'enhanced_metrics'):
                # Set ground truth for trust estimates
                for node in self.nodes.values():
                    node_key = str(node.id)
                    self.enhanced_metrics.trust_ground_truth[node_key] = bool(node.is_malicious)

                    # Record final trust estimates
                    final_trust = self.get_node_trust(node.id)
                    self.enhanced_metrics.trust_estimates[node_key].append((completed_iter, final_trust))

                    # Record demotion times for malicious nodes
                    if node.is_malicious and final_trust < float(getattr(self, 'trust_threshold', 0.5) or 0.5):
                        # Demotion times are tracked in record_trust_evolution
                        self.logger.debug("Malicious node %s demoted at end of run", node.id)
                
                # Generate enhanced report
                enhanced_report = self.enhanced_metrics.get_comprehensive_metrics()
            else:
                enhanced_report = {}

            # Kompilasi hasil simulasi (Basic + Enhanced)
            results = {
                'simulation_info': {
                    'total_nodes': self.total_nodes,
                    'malicious_nodes': self.malicious_nodes,
                    'attack_type': self.attack_type,
                    'completed_iterations': completed_iter, # Gunakan nilai yang sudah dihitung
                    'total_iterations': getattr(self, 'total_iterations', 0),
                    'duration': run_duration, # Gunakan durasi yang dihitung di sini
                    'is_completed': getattr(self, 'is_completed', False)
                },
                'metrics': {
                    # Basic metrics (backward compatibility)
                    'accuracy': self.calculate_accuracy(),
                    'precision': self.calculate_precision(),
                    'recall': self.calculate_recall(),
                    'f1_score': self.calculate_f1_score(),
                    'detection_rate': self.calculate_detection_rate(),
                    'false_positive_rate': self.calculate_false_positive_rate(),
                    'time_to_detect': self.calculate_time_to_detect(),
                    'trust_degradation': self.calculate_trust_degradation(),
                    'undetected_malicious': self.calculate_undetected_malicious(),
                    'misalignment': self.calculate_misalignment(),
                    'confusion_matrix': self.get_confusion_matrix_counts()
                },
                'enhanced_metrics': enhanced_report,  # New comprehensive metrics
                'trust_scores': getattr(self, 'node_trust_scores', {}),
                'nodes': [
                    {
                        'id': node.id,
                        'is_malicious': node.is_malicious,
                        'attack_type': node.attack_type,
                        'final_trust': self.get_node_trust(node.id)
                    } for node in self.nodes.values()
                ] if hasattr(self, 'nodes') else []
            }
            
            trust_scores_count = len(results['trust_scores']) if isinstance(results['trust_scores'], dict) else 0
            self.logger.info(f"Hasil simulasi berhasil dikompilasi: {len(results['nodes'])} node, {trust_scores_count} trust scores")
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting simulation results: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            # Kembalikan hasil minimal yang tidak akan menyebabkan error di UI
            return {
                'simulation_info': {
                    'total_nodes': getattr(self, 'total_nodes', 0),
                    'malicious_nodes': getattr(self, 'malicious_nodes', 0),
                    'attack_type': getattr(self, 'attack_type', 'Unknown'),
                    'completed_iterations': 0,
                    'total_iterations': 0,
                    'duration': 0,
                    'is_completed': False,
                    'error': str(e)
                },
                'metrics': {},
                'trust_scores': {},
                'nodes': []
            }

    def _simulation_loop(self, iterations: int):
        """Process SimPy yang menjalankan loop iterasi utama."""
        self.logger.info(f"Memasuki _simulation_loop untuk {iterations} iterasi.")
        progress_every = max(1, iterations // 10)
        try:
            for i in range(iterations):
                # --- Pemeriksaan flag berhenti di awal setiap iterasi --- 
                if not self.is_running:
                    self.logger.info(f"Flag is_running False pada iterasi {i}, menghentikan loop.")
                    # Tidak perlu raise Interrupt di sini, cukup break/return
                    # Karena env.run akan selesai jika process ini berakhir
                    return 
                
                self.current_iteration = i
                # Update simpy time juga untuk sinkronisasi
                if i == 0 or i + 1 == iterations or (i + 1) % progress_every == 0:
                    progress_pct = (i + 1) / max(1, iterations) * 100
                    self.logger.info(
                        "Progress %d/%d (%.0f%%) - SimPy time: %s",
                        i + 1,
                        iterations,
                        progress_pct,
                        self.env.now,
                    )
                    if self.progress_bar:
                        self._render_progress_bar(i + 1, iterations)
                else:
                    self.logger.debug(f">>> ITERASI {i+1}/{iterations} (SimPy time: {self.env.now}) <<< ")

                # Shared alarm_set_id for REQUEST messages in this round
                current_alarm_set_id = self._make_alarm_set_id(i)
                for node in self.nodes.values():
                    node.current_request_alarm_set_id = current_alarm_set_id
                
                # --- Logika Per Iterasi --- 
                # 1. Node Actions (Deteksi, Serangan jika malicious, dll.)
                #    Ini mungkin perlu dijadwalkan sebagai event SimPy terpisah per node
                #    agar lebih sesuai dengan model discrete-event.
                #    Untuk sekarang, kita panggil langsung, tapi ini bisa jadi bottleneck.
                active_node_processes = []
                for node in self.nodes.values():
                    # Daripada memanggil langsung, jadwalkan process untuk node
                    # Ini memungkinkan node berjalan secara konkuren dalam simulasi
                    # Pastikan Node memiliki metode perform_iteration_actions(iteration)
                    proc = self.env.process(node.run_iteration_logic(i))
                    active_node_processes.append(proc)
                
                # Tunggu semua node selesai logic iterasinya sebelum lanjut
                if active_node_processes:
                     yield simpy.AllOf(self.env, active_node_processes)
                
                # 2. Update Trust Scores (setelah semua node bertindak)
                #    Ini juga idealnya event/process terpisah.
                # self.update_all_trust_scores(i) # Contoh fungsi hypothetical
                # self.logger.debug(f"Selesai Aksi dan Update Iterasi {i+1}")

                # Majukan waktu simulasi SimPy sebesar 1 unit
                # Ini PENTING agar SimPy bisa memproses event terjadwal lainnya
                yield self.env.timeout(1)
                # --- Akhir Logika Per Iterasi --- 
                
                # --- Panggil Penyimpanan Metrik Historis --- 
                self._calculate_and_store_iteration_metrics(i)
                # --- Akhir Pemanggilan --- 
                
            # Jika loop selesai normal
            self.logger.info(f"Loop simulasi menyelesaikan semua {iterations} iterasi.")

            # Jika loop selesai tanpa interupsi
            self.logger.info("Loop simulasi SimPy selesai secara normal.")
            # Set is_completed HANYA jika loop selesai normal
            if int(self.env.now) >= iterations:
                self.is_completed = True
            else:
                # Jika loop berakhir sebelum waktunya tanpa interrupt (jarang terjadi)
                self.logger.warning(f"Loop simulasi berakhir pada waktu {self.env.now} sebelum target {iterations}")
                self.is_completed = False

        except simpy.Interrupt as interrupt:
            # Jika process ini diinterupsi oleh stop()
            self.logger.info(f"Process _simulation_loop diinterupsi: {interrupt.cause}")
            # Tidak perlu melakukan apa-apa lagi, env.run akan berhenti.
            # Pastikan is_running sudah False (diatur oleh stop())
        except Exception as e:
             self.logger.error(f"Error tak terduga dalam _simulation_loop: {e}", exc_info=True)
             self.is_running = False # Hentikan simulasi jika ada error tak terduga
             self.is_completed = False
             # Mungkin raise lagi agar ditangkap oleh blok except utama di run()
             raise 
    
    @property 
    def current_iteration_safe(self):
        """Thread-safe getter untuk current iteration."""
        # Gunakan SimPy time sebagai source of truth untuk iterasi
        if hasattr(self, 'env') and self.env:
            return min(int(self.env.now), self.total_iterations)
        return getattr(self, 'current_iteration', 0)

    # --- Fungsi Helper Baru --- 
    def _calculate_and_store_iteration_metrics(self, iteration: int):
        """Record metrics for current iteration using EnhancedMetrics system."""
        self.logger.debug(f"Recording enhanced metrics for iteration {iteration}...")
        try:
            # Record trust evolution for all nodes
            for node in self.nodes.values():
                current_trust = self.get_node_trust(node.id, iteration)
                self.enhanced_metrics.record_trust_evolution(
                    iteration=iteration,
                    node_id=str(node.id),
                    trust_score=current_trust,
                    is_malicious=node.is_malicious
                )
                
                # Record detection results (predicted vs actual)
                tau = float(getattr(self, 'trust_threshold', 0.5) or 0.5)
                predicted_malicious = current_trust < tau  # Trust < threshold means predicted malicious
                actual_malicious = node.is_malicious
                self.enhanced_metrics.record_detection(
                    predicted=current_trust,
                    actual=1.0 if actual_malicious else 0.0,
                    threshold=tau,
                )
            
            # Record performance metrics (real timing snapshot)
            perf_start = time.perf_counter()
            current_mem_mb = 0.0
            if self._perf_monitor and self._perf_monitor.get('process'):
                try:
                    rss = self._perf_monitor['process'].memory_info().rss
                    self._perf_monitor['mem_peak_bytes'] = max(self._perf_monitor['mem_peak_bytes'], rss)
                    current_mem_mb = rss / (1024 ** 2)
                except Exception:
                    current_mem_mb = 0.0

            execution_time = time.perf_counter() - perf_start

            self.enhanced_metrics.record_performance(
                execution_time=execution_time,
                memory_usage=current_mem_mb,
                operation='trust_calculation'
            )
            
            # Record attack impact proxy when attacks are active.
            # Impact is defined as fraction of malicious nodes still above trust threshold.
            if getattr(self, 'attack_type', None):
                attack_label = str(self.attack_type).lower()
                if attack_label not in {'none', 'benign', 'normal', ''}:
                    # Impact defined as fraction of malicious nodes still above threshold
                    malicious_nodes = [n for n in self.nodes.values() if n.is_malicious]
                    if malicious_nodes:
                        undetected = sum(1 for n in malicious_nodes if self.get_node_trust(n.id) >= tau)
                        impact = float(undetected / len(malicious_nodes))
                    else:
                        impact = 0.0
                    detection_time = iteration if impact <= 0.5 else None
                    self.enhanced_metrics.record_attack_impact(
                        attack_type=attack_label,
                        impact_score=impact,
                        detection_time=detection_time,
                    )
            
            self.logger.debug(f"Enhanced metrics recorded for iteration {iteration}")
            
            # Persist per-round metrics to DB using trust_scores
            try:
                tau = float(getattr(self, 'trust_threshold', 0.5) or 0.5)
                compute_metrics_for_iteration(self.db_manager, iteration, tau=tau)
                # New: store node_round and round_metrics
                try:
                    from evaluation.metrics.enhanced_metrics import (
                        build_node_round_rows,
                        compute_round_metrics_from_node_round,
                    )
                    exp_id = self.config.get('simulation', {}).get('run_id') or self.config.get('seed') or 'default'
                    rows = build_node_round_rows(self.db_manager, exp_id, iteration, tau=tau)
                    if rows:
                        self.db_manager.store_node_round_rows(exp_id, iteration, rows)
                        agg = compute_round_metrics_from_node_round(rows)
                        self.db_manager.store_round_metrics(exp_id, iteration, agg)
                except Exception as _e:
                    self.logger.debug(f"node_round/round_metrics build skipped: {_e}")
            except Exception as mexc:
                self.logger.error(f"Error computing/storing per-round metrics at iter {iteration}: {mexc}")

        except Exception as e:
            self.logger.error(f"Error recording enhanced metrics for iteration {iteration}: {e}", exc_info=True)
    # --- Akhir Fungsi Helper --- 
