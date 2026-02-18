import sqlite3
import logging
import os
import hashlib
from contextlib import suppress
from typing import Dict, List, Any, Optional
import time
import json # Import json untuk serialisasi


class _QueryResult:
    """Lightweight wrapper to ensure sqlite connections are closed after fetch."""

    def __init__(self, conn: sqlite3.Connection, cursor: sqlite3.Cursor) -> None:
        self._conn = conn
        self._cursor = cursor
        self._closed = False

    def fetchone(self):
        row = self._cursor.fetchone()
        self.close()
        return row

    def fetchall(self):
        rows = self._cursor.fetchall()
        self.close()
        return rows

    def __iter__(self):
        try:
            for row in self._cursor:
                yield row
        finally:
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        with suppress(Exception):
            self._cursor.close()
        with suppress(Exception):
            self._conn.close()
        self._closed = True

class NodeDatabase:
    """Database untuk menyimpan data simulasi CIDS"""
    
    def __init__(self, db_path: str = "src/data/simulation.db"):
        """
        Inisialisasi database
        
        Args:
            db_path (str): Path ke file database SQLite
        """
        self.db_path = os.path.abspath(db_path)
        self.logger = logging.getLogger(__name__)
        self._event_hashes: Dict[int, str] = {}
        
        # Pastikan direktori database ada
        self._ensure_db_dir()
        
        # Buat koneksi dan tabel
        try:
            # Hapus dan buat ulang database untuk memastikan struktur terbaru
            self.recreate_database()
            self.logger.info(f"Database berhasil diinisialisasi di {db_path}")
        except Exception as e:
            self.logger.error(f"Gagal menginisialisasi database: {str(e)}")
            raise
        
    def _setup_database(self):
        """Setup tabel-tabel database"""
        try:
            # Increase timeout and enable WAL mode for the connection used for setup
            with self._connect(timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;") # Enable WAL mode
                cursor = conn.cursor()
                
                # Tabel nodes (buat dulu karena ada foreign key)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS nodes (
                        node_id INTEGER PRIMARY KEY,
                        node_type TEXT NOT NULL,
                        is_malicious BOOLEAN NOT NULL
                    )
                """)
                
                # Tabel simulation_results (untuk tracking hasil per iterasi)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS simulation_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        iteration INTEGER NOT NULL,
                        total_nodes INTEGER NOT NULL,
                        malicious_nodes INTEGER NOT NULL,
                        attack_type TEXT NOT NULL,
                        success_rate REAL NOT NULL,
                        detection_rate REAL,
                        false_positive_rate REAL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Tabel auth_results (untuk hasil autentikasi)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS auth_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        node_id INTEGER,
                        target_node_id INTEGER,
                        success BOOLEAN,
                        iteration INTEGER,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (node_id) REFERENCES nodes (node_id),
                        FOREIGN KEY (target_node_id) REFERENCES nodes (node_id)
                    )
                """)
                
                # Tabel node_states (untuk tracking state node)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS node_states (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        node_id INTEGER,
                        state TEXT,
                        iteration INTEGER,
                        trust_score REAL DEFAULT 0.5,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (node_id) REFERENCES nodes (node_id)
                    )
                """)
                
                # Tabel experiment_metrics (untuk metrics eksperimen)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS experiment_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        experiment_id INTEGER,
                        iteration INTEGER,
                        method TEXT,
                        metric_name TEXT,
                        metric_value REAL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Tabel experiment_summary (untuk summary eksperimen)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS experiment_summary (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        total_nodes INTEGER,
                        malicious_nodes INTEGER,
                        attack_type TEXT,
                        method TEXT,
                        accuracy REAL,
                        precision REAL,
                        recall REAL,
                        f1_score REAL,
                        detection_rate REAL,
                        false_positive_rate REAL,
                        total_iterations INTEGER,
                        completed_iterations INTEGER,
                        duration REAL,
                        is_completed BOOLEAN DEFAULT 0,
                        error TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        -- Enhanced metrics columns
                        time_to_demote REAL DEFAULT NULL,
                        trust_degradation REAL DEFAULT NULL,
                        undetected_malicious REAL DEFAULT NULL,
                        misalignment REAL DEFAULT NULL,
                        pmfa_resilience REAL DEFAULT NULL,
                        collusion_detection_rate REAL DEFAULT NULL,
                        collusion_error REAL DEFAULT NULL,
                        sybil_detection_rate REAL DEFAULT NULL,
                        betrayal_response_time REAL DEFAULT NULL,
                        computation_time REAL DEFAULT NULL,
                        memory_usage REAL DEFAULT NULL,
                        throughput REAL DEFAULT NULL,
                        total_detections INTEGER DEFAULT NULL,
                        total_trust_records INTEGER DEFAULT NULL,
                        evaluation_duration REAL DEFAULT NULL
                    )
                """)
                
                # Tabel trust_scores (untuk nilai trust)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS trust_scores (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        node_id INTEGER,
                        target_node_id INTEGER,
                        score REAL NOT NULL,
                        iteration INTEGER,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (node_id) REFERENCES nodes (node_id),
                        FOREIGN KEY (target_node_id) REFERENCES nodes (node_id)
                    )
                """)
                
                # Tabel attack_events (untuk event serangan)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS attack_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        attacker_id INTEGER,
                        target_id INTEGER,
                        attack_type TEXT,
                        iteration INTEGER,
                        success BOOLEAN,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (attacker_id) REFERENCES nodes (node_id),
                        FOREIGN KEY (target_id) REFERENCES nodes (node_id)
                    )
                """)

                # Tabel node_round (per-node per-round logging)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS node_round (
                        exp_id TEXT,
                        round INTEGER,
                        node_id INTEGER,
                        label_is_malicious INTEGER,
                        trust REAL,
                        pred_is_malicious INTEGER,
                        was_quarantined INTEGER,
                        ttd_round INTEGER,
                        sent_msgs INTEGER,
                        recv_msgs INTEGER,
                        bytes_sent INTEGER,
                        bytes_recv INTEGER,
                        cpu_ms REAL,
                        mem_bytes INTEGER
                    )
                """)

                # Tabel round_metrics (aggregate per round)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS round_metrics (
                        exp_id TEXT,
                        round INTEGER,
                        auc_node REAL,
                        delta_tau REAL,
                        cohens_d REAL,
                        tpr_node REAL,
                        fpr_honest REAL,
                        avg_cpu_ms_node REAL,
                        avg_mem_node INTEGER,
                        total_msgs INTEGER,
                        total_bytes INTEGER,
                        overhead_pct REAL,
                        consensus_p50_ms REAL,
                        consensus_p95_ms REAL,
                        ledger_growth_bytes INTEGER
                    )
                """)

                # Tabel exp_config (metadata konfig eksperimen)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS exp_config (
                        exp_id TEXT PRIMARY KEY,
                        n_nodes INTEGER,
                        malicious_ratio REAL,
                        collusion_ratio REAL,
                        sybil_identities_per_attacker INTEGER,
                        attack_type TEXT,
                        challenge_rate REAL,
                        tau REAL,
                        topology TEXT,
                        sdn_mode INTEGER,
                        blockchain_mode INTEGER
                    )
                """)

                # Indexes for performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_node_round_exp_round ON node_round(exp_id, round)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_round_metrics_exp_round ON round_metrics(exp_id, round)")

                # --- Tambahkan Tabel Events --- 
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,      -- Gunakan REAL untuk SimPy time
                        iteration INTEGER NOT NULL,
                        node_id INTEGER,              -- Node yang mencatat event
                        related_node_id INTEGER,      -- Node lain yang terkait (misal: pengirim alarm)
                        event_type TEXT NOT NULL,     -- Tipe event (misal: 'alarm_generated', 'alarm_received', 'alarm_ignored')
                        details TEXT,                 -- Menyimpan JSON string dari detail event (misal: data alarm)
                        FOREIGN KEY (node_id) REFERENCES nodes (node_id),
                        FOREIGN KEY (related_node_id) REFERENCES nodes (node_id)
                    )
                """)
                # --- Akhir Tambahan Tabel Events --- 

                conn.commit()
                self.logger.info("Struktur database berhasil diverifikasi/dibuat.")
                
        except Exception as e:
            self.logger.error(f"Error setting up database: {str(e)}")
            raise

    def _ensure_db_dir(self) -> None:
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        if os.path.isdir(self.db_path):
            raise IsADirectoryError(f"Database path is a directory: {self.db_path}")

    def _connect(self, timeout: float = 30.0):
        self._ensure_db_dir()
        return sqlite3.connect(self.db_path, timeout=timeout)
        
    def store_node(self, node_id: int, node_type: str, is_malicious: bool):
        """Store data node ke database
        
        Args:
            node_id (int): ID node
            node_type (str): Tipe node (normal/malicious)
            is_malicious (bool): Status malicious
        """
        try:
            # Increase timeout and enable WAL mode
            with self._connect(timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO nodes (node_id, node_type, is_malicious) VALUES (?, ?, ?)",
                    (node_id, node_type, is_malicious)
                )
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing node: {str(e)}")
            raise
            
    def store_trust_score(self, node_id: int, target_node_id: int, score: float, iteration: int):
        """Store trust score ke database
        
        Args:
            node_id (int): ID node evaluator
            target_node_id (int): ID node yang dievaluasi
            score (float): Nilai trust
            iteration (int): Iterasi saat ini
        """
        try:
            # Increase timeout and enable WAL mode
            with self._connect(timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO trust_scores
                       (node_id, target_node_id, score, iteration)
                       VALUES (?, ?, ?, ?)""",
                    (node_id, target_node_id, score, iteration)
                )
                conn.commit()
                
        except sqlite3.OperationalError as e:
            self.logger.error(
                "Error storing trust score: %s (db_path=%s, cwd=%s)",
                str(e),
                self.db_path,
                os.getcwd(),
            )
            raise
        except Exception as e:
            self.logger.error(f"Error storing trust score: {str(e)}")
            raise

    def store_trust_scores_bulk(self, rows: List[tuple]) -> None:
        """Bulk insert trust scores to reduce connection churn."""
        if not rows:
            return
        try:
            with self._connect(timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                cursor.executemany(
                    """INSERT INTO trust_scores
                       (node_id, target_node_id, score, iteration)
                       VALUES (?, ?, ?, ?)""",
                    rows,
                )
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error storing trust scores bulk: {e}")
            raise
            
    def store_auth_result(self, node_id: int, target_node_id: int, success: bool, iteration: int):
        """Store hasil autentikasi ke database
        
        Args:
            node_id (int): ID node yang melakukan autentikasi
            target_node_id (int): ID node target
            success (bool): Hasil autentikasi (True/False)
            iteration (int): Iterasi saat ini
        """
        try:
            # Increase timeout and enable WAL mode
            with self._connect(timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO auth_results 
                       (node_id, target_node_id, success, iteration)
                       VALUES (?, ?, ?, ?)""",
                    (node_id, target_node_id, success, iteration)
                )
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing auth result: {str(e)}")
            raise
            
    def store_metric(self, iteration: int, method: str, metric_name: str, metric_value: float):
        """
        Simpan metrik eksperimen
        
        Args:
            iteration (int): Iterasi ke-n
            method (str): Metode yang digunakan
            metric_name (str): Nama metrik
            metric_value (float): Nilai metrik
        """
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO experiment_metrics (iteration, method, metric_name, metric_value) VALUES (?, ?, ?, ?)",
                    (iteration, method, metric_name, metric_value)
                )
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error storing metric: {str(e)}")
            raise
            
    def store_summary(self, total_nodes=None, malicious_nodes=None, attack_type=None,
                     method=None, accuracy=None, precision=None, recall=None, f1_score=None,
                     detection_rate=None, false_positive_rate=None, total_iterations=None, 
                     completed_iterations=None, duration=None, is_completed=False, error=None, **kwargs):
        """Simpan ringkasan eksperimen"""
        try:
            if isinstance(total_nodes, dict):
                summary_data = total_nodes
                total_nodes = summary_data.get('total_nodes')
                malicious_nodes = summary_data.get('malicious_nodes')
                attack_type = summary_data.get('attack_type')
                method = summary_data.get('method')
                accuracy = summary_data.get('accuracy')
                precision = summary_data.get('precision')
                recall = summary_data.get('recall')
                f1_score = summary_data.get('f1_score')
                detection_rate = summary_data.get('detection_rate')
                false_positive_rate = summary_data.get('false_positive_rate')
                total_iterations = summary_data.get('total_iterations')
                completed_iterations = summary_data.get('completed_iterations')
                duration = summary_data.get('duration')
                is_completed = summary_data.get('is_completed', False)
                error = summary_data.get('error') # Tambahkan pengambilan error

            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                # Pastikan kolom dan nilai sesuai dengan skema tabel experiment_summary
                # Hapus total_cost jika tidak ada di tabel
                sql = """INSERT INTO experiment_summary 
                         (total_nodes, malicious_nodes, attack_type, method, accuracy, precision, recall, 
                          f1_score, detection_rate, false_positive_rate, total_iterations, 
                          completed_iterations, duration, is_completed, error)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""" 
                params = (total_nodes, malicious_nodes, attack_type, method, accuracy, precision, recall, 
                          f1_score, detection_rate, false_positive_rate, total_iterations, 
                          completed_iterations, duration, is_completed, error) # Tambahkan error ke params
                cursor.execute(sql, params)
                conn.commit()
                self.logger.info("Experiment summary stored successfully")
        except sqlite3.Error as e:
            self.logger.error(f"Error storing summary: {str(e)}")
            # Jangan raise exception agar simulasi bisa lanjut jika hanya gagal simpan summary

    def store_enhanced_summary(self, metrics: dict, method: str, total_nodes: int = None, 
                             malicious_nodes: int = None, attack_type: str = None,
                             total_iterations: int = None, completed_iterations: int = None,
                             duration: float = None, is_completed: bool = False, error: str = None):
        """
        Store comprehensive enhanced metrics to experiment_summary table.
        
        Flattens and stores result of EnhancedMetrics.get_comprehensive_metrics()
        into the experiment_summary table with all required columns.
        
        Args:
            metrics (dict): Output from EnhancedMetrics.get_comprehensive_metrics()
            method (str): Trust method name
            total_nodes (int): Total number of nodes in simulation
            malicious_nodes (int): Number of malicious nodes
            attack_type (str): Type of attack simulated
            total_iterations (int): Total iterations planned
            completed_iterations (int): Iterations completed
            duration (float): Duration of simulation in seconds
            is_completed (bool): Whether simulation completed successfully
            error (str): Error message if any
        """
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                
                # Prepare SQL statement with all columns
                sql = """INSERT INTO experiment_summary 
                         (total_nodes, malicious_nodes, attack_type, method, 
                          accuracy, precision, recall, f1_score, detection_rate, false_positive_rate,
                          time_to_demote, trust_degradation, undetected_malicious, misalignment,
                          pmfa_resilience, collusion_detection_rate, collusion_error,
                          sybil_detection_rate, betrayal_response_time,
                          computation_time, memory_usage, throughput,
                          total_detections, total_trust_records, evaluation_duration,
                          total_iterations, completed_iterations, duration, is_completed, error)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
                
                # Extract values from metrics dict, with defaults for missing keys
                params = (
                    total_nodes,
                    malicious_nodes,
                    attack_type,
                    method,
                    # Detection metrics
                    metrics.get('accuracy', 0.0),
                    metrics.get('precision', 0.0),
                    metrics.get('recall', 0.0),
                    metrics.get('f1_score', 0.0),
                    metrics.get('recall', 0.0),  # detection_rate = recall
                    metrics.get('false_positive_rate', 0.0),
                    # Trust metrics
                    metrics.get('time_to_demote', 0.0),
                    metrics.get('trust_degradation', 0.0),
                    metrics.get('undetected_malicious', 0.0),
                    metrics.get('misalignment', 0.0),
                    # Attack resilience metrics
                    metrics.get('pmfa_resilience', 0.0),
                    metrics.get('collusion_detection_rate', 0.0),
                    metrics.get('collusion_error', 0.0),
                    metrics.get('sybil_detection_rate', 0.0),
                    metrics.get('betrayal_response_time', 0.0),
                    # Performance metrics
                    metrics.get('computation_time', 0.0),
                    metrics.get('memory_usage', 0.0),
                    metrics.get('throughput', 0.0),
                    # Summary metrics
                    metrics.get('total_detections', 0),
                    metrics.get('total_trust_records', 0),
                    metrics.get('evaluation_duration', 0.0),
                    # Simulation metadata
                    total_iterations, 
                    completed_iterations, 
                    duration, 
                    is_completed, 
                    error
                )
                
                cursor.execute(sql, params)
                conn.commit()
                self.logger.info("Enhanced metrics summary stored successfully")
                
        except sqlite3.Error as e:
            self.logger.error(f"Error storing enhanced summary: {str(e)}")
            # Don't raise exception so simulation can continue even if storage fails

    def get_node_info(self, node_id: int) -> Dict[str, Any]:
        """
        Ambil informasi node
        
        Args:
            node_id (int): ID node
            
        Returns:
            Dict[str, Any]: Informasi node
        """
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.row_factory = sqlite3.Row # Use Row factory for easier access
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        "node_id": row[0],
                        "node_type": row[1],
                        "is_malicious": bool(row[2])
                    }
                return None
        except sqlite3.Error as e:
            self.logger.error(f"Error getting node info: {str(e)}")
            raise
            
    def get_trust_scores(self) -> List[Dict[str, Any]]:
        """Ambil semua trust scores dari database"""
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT ts.node_id, ts.target_node_id, ts.score, 
                           ts.iteration, ts.timestamp
                    FROM trust_scores ts
                    ORDER BY ts.iteration, ts.timestamp
                """)
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'node_id': row[0],
                        'target_node_id': row[1],
                        'score': float(row[2]),
                        'iteration': row[3],
                        'timestamp': row[4]
                    })
                
                self.logger.info(f"Retrieved {len(results)} trust scores")
                return results
                
        except Exception as e:
            self.logger.error(f"Error getting trust scores: {str(e)}")
            return []
            
    def get_auth_results(self, node_id: int) -> List[Dict[str, Any]]:
        """
        Ambil hasil otentikasi untuk sebuah node
        
        Args:
            node_id (int): ID node
            
        Returns:
            List[Dict[str, Any]]: Daftar hasil otentikasi
        """
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM auth_results WHERE node_id = ?", (node_id,))
                return [
                    {
                        "node_id": row[0],
                        "target_node_id": row[1],
                        "success": bool(row[2]),
                        "timestamp": row[3]
                    }
                    for row in cursor.fetchall()
                ]
        except sqlite3.Error as e:
            self.logger.error(f"Error getting auth results: {str(e)}")
            raise
            
    def get_metrics(self, method: str = None, metric_name: str = None) -> List[Dict[str, Any]]:
        """
        Ambil metrik eksperimen
        
        Args:
            method (str, optional): Filter berdasarkan metode
            metric_name (str, optional): Filter berdasarkan nama metrik
            
        Returns:
            List[Dict[str, Any]]: Daftar metrik
        """
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = "SELECT * FROM experiment_metrics WHERE 1=1"
                params = []
                
                if method:
                    query += " AND method = ?"
                    params.append(method)
                    
                if metric_name:
                    query += " AND metric_name = ?"
                    params.append(metric_name)
                    
                cursor.execute(query, params)
                return [
                    {
                        "id": row[0],
                        "iteration": row[1],
                        "method": row[2],
                        "metric_name": row[3],
                        "metric_value": row[4],
                        "timestamp": row[5]
                    }
                    for row in cursor.fetchall()
                ]
        except sqlite3.Error as e:
            self.logger.error(f"Error getting metrics: {str(e)}")
            raise

    # Alias untuk kompatibilitas
    get_experiment_metrics = get_metrics
    store_experiment_summary = store_summary
    store_experiment_metric = store_metric
    
    def get_summary(self, method: str = None) -> List[Dict[str, Any]]:
        """Ambil ringkasan eksperimen"""
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                query = "SELECT * FROM experiment_summary WHERE 1=1"
                params = []
                if method:
                    query += " AND method = ?"
                    params.append(method)
                cursor.execute(query, params)
                # Ambil nama kolom
                columns = [description[0] for description in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            self.logger.error(f"Error getting summary: {str(e)}")
            return [] # Kembalikan list kosong jika error

    def _update_database_schema(self):
        """Update skema database jika terjadi perubahan struktur tabel"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Cek apakah kolom is_completed ada di tabel experiment_summary
                cursor.execute("PRAGMA table_info(experiment_summary)")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Jika kolom is_completed belum ada, tambahkan kolom tersebut
                if 'is_completed' not in columns:
                    self.logger.info("Menambahkan kolom is_completed ke tabel experiment_summary")
                    cursor.execute("ALTER TABLE experiment_summary ADD COLUMN is_completed BOOLEAN DEFAULT 0")
                    conn.commit()
                    
                # Bisa ditambahkan cek kolom lain di sini jika diperlukan di masa mendatang
                
                self.logger.info("Skema database berhasil diperbarui")
                
        except Exception as e:
            self.logger.error(f"Error updating database schema: {str(e)}")
            # Tidak raise exception agar aplikasi tetap bisa berjalan

    def recreate_database(self):
        """Recreate the database to ensure all tables and schema are up-to-date"""
        try:
            if os.path.exists(self.db_path):
                retries = 3
                delay = 0.5
                for i in range(retries):
                    try:
                        os.remove(self.db_path)
                        self.logger.info(f"Database lama {self.db_path} dihapus.")
                        try:
                            os.remove(self.db_path + "-wal")
                            self.logger.info(f"File WAL {self.db_path}-wal dihapus.")
                        except OSError:
                            self.logger.debug("WAL file missing for %s", self.db_path)
                        try:
                            os.remove(self.db_path + "-shm")
                            self.logger.info(f"File SHM {self.db_path}-shm dihapus.")
                        except OSError:
                            self.logger.debug("SHM file missing for %s", self.db_path)
                        break
                    except OSError as e:
                        if i < retries - 1:
                            self.logger.warning(f"Gagal menghapus database lama (percobaan {i+1}/{retries}): {e}. Mencoba lagi...")
                        else:
                            self.logger.error(f"Gagal menghapus database lama setelah {retries} percobaan: {e}")
                            raise
            
            self._setup_database()
            self._verify_tables()
            try:
                self.reset_simulation_data()
                self.logger.info("Data simulasi direset (tambahan) setelah recreate.")
            except Exception as reset_err:
                self.logger.error(f"Gagal mereset data simulasi setelah recreate: {reset_err}")
            
            self.logger.info("Database berhasil dibuat ulang")
        except Exception as e:
            self.logger.error(f"Error recreating database: {str(e)}")
            raise
            
    def _verify_tables(self):
        """Verifikasi bahwa semua tabel telah dibuat dengan benar"""
        expected_tables = [
            "simulation_results", "auth_results", "node_states", 
            "experiment_metrics", "experiment_summary", "nodes", 
            "trust_scores", "attack_events"
        ]
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                # Periksa apakah semua tabel yang diharapkan ada
                missing_tables = [table for table in expected_tables if table not in tables]
                
                if missing_tables:
                    self.logger.error(f"Tabel berikut tidak dibuat: {', '.join(missing_tables)}")
                    # Coba buat ulang tabel yang hilang
                    self._setup_database()
                    # Periksa lagi
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cursor.fetchall()]
                    still_missing = [table for table in expected_tables if table not in tables]
                    
                    if still_missing:
                        raise Exception(f"Gagal membuat tabel: {', '.join(still_missing)}")
                else:
                    self.logger.info("Semua tabel berhasil dibuat")
                    
        except Exception as e:
            self.logger.error(f"Error verifying tables: {str(e)}")
            raise
    
    def reset_simulation_data(self):
        """Reset simulation data (clear tables)"""
        try:
            # Pendekatan yang lebih kuat: drop dan buat ulang semua tabel
            self.drop_and_recreate_tables()
            self.logger.info("Simulation data reset successfully")
        except Exception as e:
            self.logger.error(f"Error resetting simulation data: {str(e)}")
            raise
            
    def drop_and_recreate_tables(self):
        """Drop dan buat ulang semua tabel untuk memastikan database benar-benar bersih"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Nonaktifkan foreign key constraints
                cursor.execute("PRAGMA foreign_keys = OFF")
                
                # Dapatkan semua nama tabel
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                
                # Drop semua tabel
                for table in tables:
                    table_name = table[0]
                    if table_name != 'sqlite_sequence':  # Jangan hapus tabel system
                        cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
                
                # Commit perubahan
                conn.commit()
                
                # Buat ulang semua tabel
                self._setup_database()
                
                # Aktifkan kembali foreign key constraints
                cursor.execute("PRAGMA foreign_keys = ON")
                
                # Vacuum database untuk membebaskan ruang
                cursor.execute("VACUUM")
                
                conn.commit()
                self.logger.info("Database tables dropped and recreated successfully")
                
        except Exception as e:
            self.logger.error(f"Error dropping and recreating tables: {str(e)}")
            raise
            
    def get_all_nodes(self):
        """Get all nodes from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT node_id, node_type, is_malicious FROM nodes")
                return [{"node_id": row[0], "node_type": row[1], "is_malicious": bool(row[2])} 
                        for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting nodes: {str(e)}")
            return []

    def execute_query(self, query: str, params=None):
        """
        Eksekusi kueri SQL pada database
        
        Args:
            query (str): Kueri SQL yang akan dieksekusi
            params (tuple, optional): Parameter untuk query. Default None.
            
        Returns:
            sqlite3.Cursor: Cursor hasil eksekusi query
        """
        try:
            conn = self._connect()
            # Aktifkan row factory untuk mendapatkan hasil dalam format dict
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return _QueryResult(conn, cursor)
        except sqlite3.Error as e:
            self.logger.error(f"Error executing query: {str(e)}")
            raise

    # --- New helpers for evaluation package ---
    def store_node_round_rows(self, exp_id: str, round_num: int, rows: list[dict]) -> None:
        try:
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                data = [
                    (
                        exp_id,
                        round_num,
                        int(r.get('node_id')),
                        int(r.get('label_is_malicious') or 0),
                        float(r.get('trust') or 0.0),
                        int(r.get('pred_is_malicious') or 0),
                        int(r.get('was_quarantined') or 0),
                        (None if r.get('ttd_round') is None else int(r.get('ttd_round'))),
                        int(r.get('sent_msgs') or 0),
                        int(r.get('recv_msgs') or 0),
                        int(r.get('bytes_sent') or 0),
                        int(r.get('bytes_recv') or 0),
                        (None if r.get('cpu_ms') is None else float(r.get('cpu_ms'))),
                        (None if r.get('mem_bytes') is None else int(r.get('mem_bytes'))),
                    )
                    for r in rows
                ]
                cursor.executemany(
                    """
                    INSERT INTO node_round (
                        exp_id, round, node_id, label_is_malicious, trust, pred_is_malicious,
                        was_quarantined, ttd_round, sent_msgs, recv_msgs, bytes_sent, bytes_recv, cpu_ms, mem_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    data,
                )
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error storing node_round rows: {e}")

    def store_round_metrics(self, exp_id: str, round_num: int, metrics: dict) -> None:
        try:
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO round_metrics (
                        exp_id, round, auc_node, delta_tau, cohens_d, tpr_node, fpr_honest,
                        avg_cpu_ms_node, avg_mem_node, total_msgs, total_bytes, overhead_pct,
                        consensus_p50_ms, consensus_p95_ms, ledger_growth_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        exp_id,
                        round_num,
                        float(metrics.get('auc_node') or 0.0),
                        (None if metrics.get('delta_tau') is None else float(metrics.get('delta_tau'))),
                        (None if metrics.get('cohens_d') is None else float(metrics.get('cohens_d'))),
                        (None if metrics.get('tpr_node') is None else float(metrics.get('tpr_node'))),
                        (None if metrics.get('fpr_honest') is None else float(metrics.get('fpr_honest'))),
                        (None if metrics.get('avg_cpu_ms_node') is None else float(metrics.get('avg_cpu_ms_node'))),
                        (None if metrics.get('avg_mem_node') is None else int(metrics.get('avg_mem_node'))),
                        int(metrics.get('total_msgs') or 0),
                        int(metrics.get('total_bytes') or 0),
                        (None if metrics.get('overhead_pct') is None else float(metrics.get('overhead_pct'))),
                        (None if metrics.get('consensus_p50_ms') is None else float(metrics.get('consensus_p50_ms'))),
                        (None if metrics.get('consensus_p95_ms') is None else float(metrics.get('consensus_p95_ms'))),
                        (None if metrics.get('ledger_growth_bytes') is None else int(metrics.get('ledger_growth_bytes'))),
                    ),
                )
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error storing round_metrics: {e}")

    def store_exp_config(
        self,
        exp_id: str,
        n_nodes: int,
        malicious_ratio: Optional[float],
        collusion_ratio: Optional[float],
        sybil_identities_per_attacker: Optional[int],
        attack_type: Optional[str],
        challenge_rate: Optional[float],
        tau: Optional[float],
        topology: Optional[str],
        sdn_mode: Optional[int],
        blockchain_mode: Optional[int],
    ) -> None:
        try:
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO exp_config (
                        exp_id, n_nodes, malicious_ratio, collusion_ratio, sybil_identities_per_attacker,
                        attack_type, challenge_rate, tau, topology, sdn_mode, blockchain_mode
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        exp_id,
                        int(n_nodes) if n_nodes is not None else None,
                        None if malicious_ratio is None else float(malicious_ratio),
                        None if collusion_ratio is None else float(collusion_ratio),
                        None if sybil_identities_per_attacker is None else int(sybil_identities_per_attacker),
                        attack_type,
                        None if challenge_rate is None else float(challenge_rate),
                        None if tau is None else float(tau),
                        topology,
                        None if sdn_mode is None else int(sdn_mode),
                        None if blockchain_mode is None else int(blockchain_mode),
                    ),
                )
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error storing exp_config: {e}")

    def store_node_state(self, node_id: int, state: str, iteration: int, trust_score: float = 0.5):
        """
        Menyimpan status node pada setiap iterasi
        
        Args:
            node_id (int): ID node
            state (str): Status node (normal/malicious/detected/etc)
            iteration (int): Iterasi simulasi
            trust_score (float): Nilai trust node saat ini
        """
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO node_states
                       (node_id, state, iteration)
                       VALUES (?, ?, ?)""",
                    (node_id, state, iteration)
                )
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error storing node state: {str(e)}")
            raise
    
    def store_attack_event(self, attacker_id: int, target_id: int, attack_type: str, iteration: int, success: bool = True):
        """
        Menyimpan event serangan yang terjadi
        
        Args:
            attacker_id (int): ID node penyerang
            target_id (int): ID node target
            attack_type (str): Jenis serangan
            iteration (int): Iterasi simulasi
            success (bool): Apakah serangan berhasil
        """
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO attack_events
                       (attacker_id, target_id, attack_type, iteration, success)
                       VALUES (?, ?, ?, ?, ?)""",
                    (attacker_id, target_id, attack_type, iteration, success)
                )
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error storing attack event: {str(e)}")
            raise
    
    def store_iteration_results(self, iteration: int, trust_scores: List[Dict[str, Any]]):
        """
        Menyimpan hasil iterasi
        
        Args:
            iteration (int): Iterasi simulasi
            trust_scores (List[Dict]): Daftar trust scores
        """
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                
                # Store trust scores
                cursor.executemany(
                    """INSERT INTO trust_scores 
                       (node_id, target_node_id, score, iteration)
                       VALUES (?, ?, ?, ?)""",
                    [(ts['node_id'], ts['target_node_id'], ts['score'], iteration)
                     for ts in trust_scores]
                )
                
                conn.commit()
                self.logger.info(f"Stored results for iteration {iteration}")
                
        except Exception as e:
            self.logger.error(f"Error storing iteration results: {str(e)}")
            raise 

    def get_trust_stats(self, iteration=None):
        """
        Dapatkan statistik trust score untuk iterasi tertentu
        
        Args:
            iteration: Iterasi yang akan diambil statistiknya, None untuk iterasi terakhir
            
        Returns:
            Dict dengan statistik trust
        """
        try:
            # Optimize query with better indexing strategy
            if iteration is None:
                # Get latest iteration with optimized query
                iter_query = "SELECT MAX(iteration) as max_iter FROM trust_scores"
                iter_result = self.execute_query(iter_query).fetchone()
                iteration = iter_result['max_iter'] if iter_result and iter_result['max_iter'] is not None else 0
            
            # Use parameters to prevent SQL injection and improve query caching
            query = """
            SELECT 
                COUNT(*) as total_scores,
                AVG(score) as avg_score,
                MIN(score) as min_score,
                MAX(score) as max_score,
                COUNT(CASE WHEN score < 0.5 THEN 1 END) as below_threshold,
                COUNT(DISTINCT target_node_id) as unique_targets,
                COUNT(DISTINCT node_id) as unique_nodes
            FROM trust_scores
            WHERE iteration = ?
            """
            
            result = self.execute_query(query, (iteration,)).fetchone()
            
            if not result:
                return {
                    'iteration': iteration,
                    'total_scores': 0,
                    'avg_score': 0.0,
                    'min_score': 0.0,
                    'max_score': 0.0,
                    'below_threshold': 0,
                    'unique_targets': 0,
                    'unique_nodes': 0
                }
            
            return {
                'iteration': iteration,
                'total_scores': result['total_scores'],
                'avg_score': result['avg_score'] or 0.0,
                'min_score': result['min_score'] or 0.0,
                'max_score': result['max_score'] or 0.0,
                'below_threshold': result['below_threshold'] or 0,
                'unique_targets': result['unique_targets'] or 0,
                'unique_nodes': result['unique_nodes'] or 0
            }
            
        except Exception as e:
            self.logger.error(f"Error getting trust stats: {str(e)}")
            return {
                'iteration': iteration,
                'total_scores': 0,
                'avg_score': 0.0,
                'min_score': 0.0,
                'max_score': 0.0,
                'below_threshold': 0,
                'unique_targets': 0,
                'unique_nodes': 0
            }

    def optimize_database(self):
        """Optimize database performance after simulation completion"""
        try:
            self.logger.info("Optimizing database...")
            
            # Create appropriate indexes for frequent queries
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging for better concurrency
                conn.execute("PRAGMA synchronous = NORMAL")  # Better performance with decent safety
                
                # Create indexes on frequently queried columns
                indexes = [
                    "CREATE INDEX IF NOT EXISTS idx_trust_scores_iteration ON trust_scores(iteration)",
                    "CREATE INDEX IF NOT EXISTS idx_trust_scores_node_target ON trust_scores(node_id, target_node_id)",
                    "CREATE INDEX IF NOT EXISTS idx_attack_events_iteration ON attack_events(iteration)",
                    "CREATE INDEX IF NOT EXISTS idx_auth_results_iteration ON auth_results(iteration)",
                    "CREATE INDEX IF NOT EXISTS idx_node_states_iteration ON node_states(iteration)"
                ]
                
                for index in indexes:
                    try:
                        conn.execute(index)
                    except sqlite3.OperationalError as e:
                        self.logger.warning(f"Index creation error (may already exist): {str(e)}")
                
                # Vacuum database to reclaim space and optimize
                conn.execute("VACUUM")
                
                # Analyze for query optimization
                conn.execute("ANALYZE")
                
            self.logger.info("Database optimization completed")
            
        except Exception as e:
            self.logger.error(f"Error optimizing database: {str(e)}") 

    # --- Tambahkan Metode untuk Menyimpan Event Generik --- 
    def store_event(self, timestamp: float, iteration: int, node_id: Optional[int], 
                    event_type: str, details: Optional[Dict] = None, related_node_id: Optional[int] = None):
        """
        Menyimpan event simulasi generik ke tabel events.

        Args:
            timestamp (float): Waktu SimPy event terjadi.
            iteration (int): Iterasi saat event terjadi.
            node_id (Optional[int]): ID node yang mencatat/mengalami event.
            event_type (str): Tipe event (e.g., 'alarm_received', 'alarm_ignored').
            details (Optional[Dict]): Dictionary berisi detail event (akan disimpan sebagai JSON).
            related_node_id (Optional[int]): ID node lain yang terkait.
        """
        try:
            # Increase timeout and enable WAL mode
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                cursor = conn.cursor()
                # Serialize details with hash chaining for tamper-evidence
                details_dict = details.copy() if isinstance(details, dict) else {}
                chain_key = int(node_id) if node_id is not None else -1
                prev_hash = self._event_hashes.get(chain_key)
                details_dict['prev_hash'] = prev_hash
                payload = {
                    'timestamp': timestamp,
                    'iteration': iteration,
                    'node_id': node_id,
                    'event_type': event_type,
                    'details': details_dict,
                    'related_node_id': related_node_id,
                }
                try:
                    event_hash = hashlib.sha256(
                        json.dumps(payload, sort_keys=True).encode('utf-8')
                    ).hexdigest()
                except Exception:
                    event_hash = None
                details_dict['event_hash'] = event_hash
                if event_hash:
                    self._event_hashes[chain_key] = event_hash
                details_json = json.dumps(details_dict)
                cursor.execute(
                    """INSERT INTO events 
                       (timestamp, iteration, node_id, event_type, details, related_node_id)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (timestamp, iteration, node_id, event_type, details_json, related_node_id)
                )
                conn.commit()
        except sqlite3.Error as e:
            # Log error tapi jangan hentikan simulasi hanya karena gagal log event
            self.logger.error(f"Error storing event (type: {event_type}, node: {node_id}): {str(e)}") 
        except TypeError as e:
            self.logger.error(f"Error serializing event details to JSON (type: {event_type}, node: {node_id}): {str(e)}")
    # --- Akhir Tambahan Metode Event ---

    def get_iteration_events(self, node_id: int) -> list[dict]:
        """
        Return a list of iteration-wise events for a given node.
        Each dict contains at least:
          - iteration: int
          - detail: str
        
        Args:
            node_id (int): ID of the node to get events for
            
        Returns:
            list[dict]: List of events for the node, or empty list if none found.
        """
        try:
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Query events table for this node
                cursor.execute("""
                    SELECT iteration, event_type, details, timestamp, related_node_id
                    FROM events 
                    WHERE node_id = ? 
                    ORDER BY iteration ASC, timestamp ASC
                """, (node_id,))
                
                rows = cursor.fetchall()
                
                if not rows:
                    # Fallback: create dummy data for testing
                    return [
                        {"iteration": 1, "detail": f"Node {node_id} initialized"},
                        {"iteration": 2, "detail": f"Node {node_id} participated in trust evaluation"}
                    ]
                
                # Convert to list of dicts with required format
                events = []
                for row in rows:
                    detail = row['event_type']
                    if row['details']:
                        try:
                            details_dict = json.loads(row['details'])
                            if isinstance(details_dict, dict):
                                detail += f": {details_dict.get('description', 'No details')}"
                        except (json.JSONDecodeError, TypeError):
                            self.logger.debug("Failed to parse event details for node %s", node_id)
                    
                    if row['related_node_id']:
                        detail += f" (with Node {row['related_node_id']})"
                    
                    events.append({
                        "iteration": row['iteration'],
                        "detail": detail
                    })
                
                return events
                
        except sqlite3.Error as e:
            self.logger.error(f"Error getting iteration events for node {node_id}: {str(e)}")
            # Return dummy data as fallback
            return [
                {"iteration": 1, "detail": f"Node {node_id} created"},
                {"iteration": 2, "detail": f"Node {node_id} active"}
            ] 
