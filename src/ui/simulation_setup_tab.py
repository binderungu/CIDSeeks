import customtkinter as ctk
from typing import Dict, Any, Optional
import time
import logging
from pathlib import Path
from simulation.modules.database.node_database import NodeDatabase
import threading
import tkinter.messagebox as messagebox
from simulation.core.simulation_engine import SimulationEngine
import tkinter as tk
from tkinter import ttk
import yaml  # type: ignore[import-untyped]

# Setup logger
logger = logging.getLogger(__name__)


def _safe_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(value, upper))


def _load_setup_bounds_from_canonical_config() -> Dict[str, int]:
    """Load GUI slider bounds/defaults from canonical `config.yaml`."""
    defaults = {
        "node_min": 10,
        "node_max": 1000,
        "node_default": 50,
        "malicious_min": 0,
        "malicious_max": 500,
        "malicious_default": 10,
        "iter_min": 1,
        "iter_max": 1000,
        "iter_default": 100,
    }

    config_path = Path(__file__).resolve().parents[2] / "config.yaml"
    payload: Dict[str, Any] = {}
    try:
        if config_path.exists():
            loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                payload = loaded
    except Exception as exc:
        logger.warning("Failed to load canonical config for UI bounds: %s", exc)

    simulation_cfg = payload.get("simulation", {})
    if not isinstance(simulation_cfg, dict):
        simulation_cfg = {}
    ui_cfg = payload.get("ui", {})
    if not isinstance(ui_cfg, dict):
        ui_cfg = {}
    setup_cfg = ui_cfg.get("simulation_setup", {})
    if not isinstance(setup_cfg, dict):
        setup_cfg = {}

    node_min = _safe_int(setup_cfg.get("node_min"), defaults["node_min"])
    node_min = max(1, node_min)
    node_max = _safe_int(setup_cfg.get("node_max"), defaults["node_max"])
    node_max = max(node_min, node_max)

    node_default_from_sim = _safe_int(
        simulation_cfg.get("total_nodes"),
        defaults["node_default"],
    )
    node_default = _safe_int(
        setup_cfg.get("node_default"),
        node_default_from_sim,
    )
    node_default = _clamp(node_default, node_min, node_max)

    malicious_min = _safe_int(setup_cfg.get("malicious_min"), defaults["malicious_min"])
    malicious_min = max(0, malicious_min)
    malicious_max = _safe_int(setup_cfg.get("malicious_max"), node_max)
    malicious_max = max(malicious_min, malicious_max)

    ratio = _safe_float(simulation_cfg.get("malicious_ratio"), 0.2)
    ratio = max(0.0, min(ratio, 1.0))
    malicious_default_from_sim = int(round(node_default * ratio))
    malicious_default = _safe_int(
        setup_cfg.get("malicious_default"),
        malicious_default_from_sim,
    )
    malicious_default = _clamp(malicious_default, malicious_min, malicious_max)

    iter_min = _safe_int(setup_cfg.get("iter_min"), defaults["iter_min"])
    iter_min = max(1, iter_min)
    iter_max = _safe_int(setup_cfg.get("iter_max"), defaults["iter_max"])
    iter_max = max(iter_min, iter_max)
    iter_default_from_sim = _safe_int(
        simulation_cfg.get("iterations"),
        defaults["iter_default"],
    )
    iter_default = _safe_int(
        setup_cfg.get("iter_default"),
        iter_default_from_sim,
    )
    iter_default = _clamp(iter_default, iter_min, iter_max)

    return {
        "node_min": node_min,
        "node_max": node_max,
        "node_default": node_default,
        "malicious_min": malicious_min,
        "malicious_max": malicious_max,
        "malicious_default": malicious_default,
        "iter_min": iter_min,
        "iter_max": iter_max,
        "iter_default": iter_default,
    }


class SimulationSetupTab(ctk.CTkFrame):
    """
    Tab untuk mengatur parameter simulasi CIDS.
    
    Attributes:
        parent (ctk.CTkTabview): Parent widget
        db (NodeDatabase): Database untuk menyimpan hasil simulasi
        simulation_start_time (float): Waktu mulai simulasi
        current_iteration (int): Iterasi saat ini
        total_iterations (int): Total iterasi yang diinginkan
        attack_vars (Dict[str, ctk.BooleanVar]): Status checkbox untuk setiap jenis serangan
    """
    
    def __init__(self, parent: ctk.CTkTabview, db: NodeDatabase):
        """
        Inisialisasi tab simulasi.

        Args:
            parent: Parent widget
            db: Database untuk menyimpan hasil simulasi
        """
        super().__init__(master=parent, fg_color="transparent")  # Panggil konstruktor parent
        self.parent = parent
        self.db = db
        self.simulation_start_time: Optional[float] = None
        self.current_iteration: int = 0
        self.total_iterations: int = 0

        bounds = _load_setup_bounds_from_canonical_config()
        self._node_min = bounds["node_min"]
        self._node_max = bounds["node_max"]
        self._node_default = bounds["node_default"]
        self._malicious_min = bounds["malicious_min"]
        self._malicious_max = bounds["malicious_max"]
        self._malicious_default = bounds["malicious_default"]
        self._iter_min = bounds["iter_min"]
        self._iter_max = bounds["iter_max"]
        self._iter_default = bounds["iter_default"]

        # Nonaktifkan widget propagation dan update sementara selama setup UI
        self.pack_propagate(False)

        # Cache variabel untuk mengurangi update UI yang tidak perlu
        self._cached_values = {
            'nodes': self._node_default,
            'malicious': self._malicious_default,
            'iterations': self._iter_default
        }
        
        # Batasi frekuensi update UI untuk slider
        self._last_update_time = 0
        self._update_interval = 100  # milliseconds
        
        # Setup UI
        self._setup_ui()
        logger.info("Tab simulasi berhasil diinisialisasi")
        
    def _setup_ui(self):
        """Setup komponen UI untuk tab simulasi."""
        try:
            # Gunakan self langsung sebagai container utama
            self.container = self

            # Create main frame to hold both panels
            main_frame = ctk.CTkFrame(self.container, fg_color="transparent")
            main_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Create two-column layout (pack layout lebih ringan)
            left_panel = ctk.CTkFrame(main_frame, fg_color="#2b2b2b", corner_radius=10)
            left_panel.pack(side="left", fill="both", expand=True, padx=(0,5), pady=0)
            
            right_panel = ctk.CTkFrame(main_frame, fg_color="#333333", corner_radius=10, width=250)
            right_panel.pack(side="right", fill="y", padx=(5,0), pady=0)
            right_panel.pack_propagate(False)  # Prevent frame from shrinking
            
            # Setup panels
            self._setup_left_panel(left_panel)
            self.update_idletasks()  # Update UI setelah left panel
            
            self._setup_right_panel(right_panel)
            self.update_idletasks()  # Update UI setelah right panel
            
            # Bind events dengan throttling untuk mengurangi overhead
            self.nodes_slider.configure(command=self._throttled_update_nodes)
            self.malicious_slider.configure(command=self._throttled_update_malicious)
            self.iterations_slider.configure(command=self._throttled_update_iterations)
            
            # Bind checkbox events dengan fungsi tunggal untuk mengurangi overhead
            self.pmfa_var.trace_add("write", lambda *args: self._batch_update_ui())
            self.collusion_var.trace_add("write", lambda *args: self._batch_update_ui())
            self.sybil_var.trace_add("write", lambda *args: self._batch_update_ui())
            self.betrayal_var.trace_add("write", lambda *args: self._batch_update_ui())
                
            # Initial update
            self._update_summary()
            
            # Aktifkan widget propagation kembali
            self.pack_propagate(True)
            
        except Exception as e:
            logger.error(f"Error saat setup UI: {str(e)}")
            raise
    
    def _throttled_update_nodes(self, value):
        """Update nodes value dengan throttling untuk mengurangi beban UI"""
        current_time = time.time() * 1000  # milliseconds
        if current_time - self._last_update_time > self._update_interval:
            self._last_update_time = current_time
            self._update_nodes(value)
    
    def _throttled_update_malicious(self, value):
        """Update malicious value dengan throttling untuk mengurangi beban UI"""
        current_time = time.time() * 1000  # milliseconds
        if current_time - self._last_update_time > self._update_interval:
            self._last_update_time = current_time
            self._update_malicious(value)
    
    def _throttled_update_iterations(self, value):
        """Update iterations value dengan throttling untuk mengurangi beban UI"""
        current_time = time.time() * 1000  # milliseconds
        if current_time - self._last_update_time > self._update_interval:
            self._last_update_time = current_time
            self._update_iterations(value)
    
    def _batch_update_ui(self, *args):
        """Update UI secara batch untuk checkbox"""
        # Menghindari multiple updates dengan scheduling single update
        self.after_cancel(getattr(self, '_update_job', 'no'))
        self._update_job = self.after(100, self._update_summary)  # Delay 100ms
            
    def _setup_left_panel(self, panel: ctk.CTkFrame):
        """
        Setup komponen panel kiri.
        
        Args:
            panel: Frame untuk panel kiri
        """
        # Tambahkan padding internal pada panel
        content_frame = ctk.CTkFrame(panel, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Number of Nodes slider - menggunakan compound widgets untuk mengurangi jumlah widget bebas
        slider_frame1 = ctk.CTkFrame(content_frame, fg_color="transparent")
        slider_frame1.pack(fill="x", pady=5)
        
        ctk.CTkLabel(slider_frame1, text="Number of Nodes:", anchor="w", font=("Arial", 12)).pack(fill="x")
        node_steps = max(1, self._node_max - self._node_min)
        self.nodes_slider = ctk.CTkSlider(
            slider_frame1,
            from_=self._node_min,
            to=self._node_max,
            number_of_steps=node_steps,
            height=16,
            button_color="#0066cc",
            button_hover_color="#004c99",
            progress_color="#0066cc"
        )
        self.nodes_slider.pack(fill="x", pady=(5,0), side="left", expand=True)
        self.nodes_value = ctk.CTkLabel(slider_frame1, text=str(self._node_default), width=30, font=("Arial", 12))
        self.nodes_value.pack(side="right", padx=(5,0))
        self.nodes_slider.set(self._node_default)
        
        # Number of Malicious Nodes slider
        slider_frame2 = ctk.CTkFrame(content_frame, fg_color="transparent")
        slider_frame2.pack(fill="x", pady=10)
        
        ctk.CTkLabel(slider_frame2, text="Number of Malicious Nodes:", anchor="w", font=("Arial", 12)).pack(fill="x")
        malicious_steps = max(1, self._malicious_max - self._malicious_min)
        self.malicious_slider = ctk.CTkSlider(
            slider_frame2,
            from_=self._malicious_min,
            to=self._malicious_max,
            number_of_steps=malicious_steps,
            height=16,
            button_color="#0066cc",
            button_hover_color="#004c99",
            progress_color="#0066cc"
        )
        self.malicious_slider.pack(fill="x", pady=(5,0), side="left", expand=True)
        self.malicious_value = ctk.CTkLabel(slider_frame2, text=str(self._malicious_default), width=30, font=("Arial", 12))
        self.malicious_value.pack(side="right", padx=(5,0))
        self.malicious_slider.set(self._malicious_default)
        
        # Number of Iterations slider
        slider_frame3 = ctk.CTkFrame(content_frame, fg_color="transparent")
        slider_frame3.pack(fill="x", pady=10)
        
        ctk.CTkLabel(slider_frame3, text="Number of Iterations:", anchor="w", font=("Arial", 12)).pack(fill="x")
        iter_steps = max(1, self._iter_max - self._iter_min)
        self.iterations_slider = ctk.CTkSlider(
            slider_frame3,
            from_=self._iter_min,
            to=self._iter_max,
            number_of_steps=iter_steps,
            height=16,
            button_color="#0066cc",
            button_hover_color="#004c99",
            progress_color="#0066cc"
        )
        self.iterations_slider.pack(fill="x", pady=(5,0), side="left", expand=True)
        self.iterations_value = ctk.CTkLabel(slider_frame3, text=str(self._iter_default), width=30, font=("Arial", 12))
        self.iterations_value.pack(side="right", padx=(5,0))
        self.iterations_slider.set(self._iter_default)
        
        # Active Trust Method (Fixed - no selection needed)
        method_info_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        method_info_frame.pack(fill="x", pady=(15, 10))
        
        ctk.CTkLabel(method_info_frame, text="Active Trust Method:", anchor="w", font=("Arial", 12, "bold")).pack(fill="x")
        
        # Display active method name
        method_display_frame = ctk.CTkFrame(method_info_frame, fg_color="#0066cc", corner_radius=5)
        method_display_frame.pack(fill="x", pady=(5, 0))
        
        ctk.CTkLabel(
            method_display_frame, 
            text="CIDSeeks - 3-Level Challenge Trust Method", 
            anchor="center", 
            font=("Arial", 12, "bold"),
            text_color="white"
        ).pack(pady=8)
        
        # Method description
        method_desc = "Hierarchical trust mechanism with Basic, Advanced, and Final Challenge designed to counter PMFA, Collusion, Sybil, and Betrayal attacks"
        ctk.CTkLabel(
            method_info_frame, 
            text=method_desc, 
            anchor="w", 
            font=("Arial", 10), 
            text_color="#cccccc",
            wraplength=400
        ).pack(fill="x", pady=(5, 0))
        
        # Attack Types selection - dalam frame terpisah
        attack_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        attack_frame.pack(fill="x", pady=(15,5))
        
        ctk.CTkLabel(attack_frame, text="Select Attack Types", anchor="w", font=("Arial", 12)).pack(fill="x")
        
        # Frame untuk checkbox dengan grid untuk lebih efisien
        checkbox_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        checkbox_frame.pack(fill="x", pady=(0, 5))
        
        # Gunakan grid untuk mengurangi overhead layout
        checkbox_frame.columnconfigure(0, weight=1)
        checkbox_frame.columnconfigure(1, weight=1)
        
        # Inisialisasi variabel untuk setiap checkbox
        self.pmfa_var = ctk.BooleanVar(value=False)
        self.collusion_var = ctk.BooleanVar(value=False)
        self.sybil_var = ctk.BooleanVar(value=False)
        self.betrayal_var = ctk.BooleanVar(value=False)
        
        # Inisialisasi Three Level Challenge checkbox (selalu dipilih karena metode utama)
        self.three_level_var = ctk.BooleanVar(value=True)
        
        # Buat checkbox dengan variabel yang sesuai - menggunakan grid untuk lebih efisien
        checkbox_opts = {
            "fg_color": "#0066cc", 
            "hover_color": "#0052a3",
            "corner_radius": 5,
            "border_width": 2, 
            "checkbox_width": 20,
            "checkbox_height": 20,
            "font": ("Arial", 12)
        }
        
        self.pmfa_checkbox = ctk.CTkCheckBox(
            checkbox_frame, 
            text="PMFA Attack",
            variable=self.pmfa_var,
            **checkbox_opts
        )
        self.pmfa_checkbox.grid(row=0, column=0, sticky="w", pady=5)
        
        self.collusion_checkbox = ctk.CTkCheckBox(
            checkbox_frame,
            text="Collusion Attack",
            variable=self.collusion_var,
            **checkbox_opts
        )
        self.collusion_checkbox.grid(row=0, column=1, sticky="w", pady=5)
        
        self.sybil_checkbox = ctk.CTkCheckBox(
            checkbox_frame,
            text="Sybil Attack",
            variable=self.sybil_var,
            **checkbox_opts
        )
        self.sybil_checkbox.grid(row=1, column=0, sticky="w", pady=5)
        
        self.betrayal_checkbox = ctk.CTkCheckBox(
            checkbox_frame,
            text="Betrayal Attack",
            variable=self.betrayal_var,
            **checkbox_opts
        )
        self.betrayal_checkbox.grid(row=1, column=1, sticky="w", pady=5)
        
        # Control buttons
        button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=(15,0))
        
        self.start_button = ctk.CTkButton(button_frame, text="Start",
                                         fg_color="#0066cc", hover_color="#0052a3",
                                         corner_radius=6, height=32,
                                         font=("Arial", 12),
                                         command=self._start_simulation)
        self.start_button.pack(side="left", expand=True, padx=(0,3), fill="x")
        
        self.stop_button = ctk.CTkButton(button_frame, text="Stop",
                                        fg_color="#333333", hover_color="#404040",
                                        state="disabled", height=32,
                                        corner_radius=6,
                                        font=("Arial", 12),
                                        command=self._stop_simulation)
        self.stop_button.pack(side="right", expand=True, padx=(3,0), fill="x")
        
    def _setup_right_panel(self, panel: ctk.CTkFrame):
        """Setup panel kanan dengan status simulasi"""
        try:
            # Tambahkan padding internal
            content_frame = ctk.CTkFrame(panel, fg_color="transparent")
            content_frame.pack(fill="both", expand=True, padx=15, pady=15)
            
            # Configuration Summary
            ctk.CTkLabel(content_frame, text="Configuration Summary",
                        font=("Arial", 14), text_color="white").pack(pady=(0,10))
            
            # Network Configuration - menggunakan frame tunggal untuk config info
            config_frame = ctk.CTkFrame(content_frame, fg_color="#2b2b2b", corner_radius=8)
            config_frame.pack(fill="x", pady=5)
            
            ctk.CTkLabel(config_frame, text="Network Configuration:",
                        anchor="w", text_color="white", font=("Arial", 12)).pack(fill="x", padx=10, pady=(5,2))
            
            self.network_config = ctk.CTkLabel(config_frame, text="",
                                             anchor="w", justify="left", text_color="light gray", font=("Arial", 11))
            self.network_config.pack(fill="x", padx=10, pady=(0,5))
            
            # Selected Attacks
            ctk.CTkLabel(config_frame, text="Selected Attacks:",
                        anchor="w", text_color="white", font=("Arial", 12)).pack(fill="x", padx=10, pady=(5,2))
            
            self.selected_attacks = ctk.CTkLabel(config_frame, text="None",
                                               anchor="w", justify="left", text_color="light gray", font=("Arial", 11))
            self.selected_attacks.pack(fill="x", padx=10, pady=(0,5))
            
            # Simulation Status section
            ctk.CTkLabel(content_frame, text="Simulation Status", 
                        font=("Arial", 14), text_color="white").pack(pady=(15,10))
            
            # Create status display dalam satu frame
            status_box = ctk.CTkFrame(content_frame, fg_color="#2b2b2b", corner_radius=8)
            status_box.pack(fill="x", pady=5, ipady=5)
            
            self.status_label = ctk.CTkLabel(status_box, text="Ready", text_color="#00b347", font=("Arial", 12))
            self.status_label.pack(pady=2)
            
            self.duration_label = ctk.CTkLabel(status_box, text="Duration: 0s", font=("Arial", 11))
            self.duration_label.pack(pady=2)
            
            self.iteration_label = ctk.CTkLabel(status_box, text="Iteration: 0/0", font=("Arial", 11))
            self.iteration_label.pack(pady=2)
            
        except Exception as e:
            logger.error(f"Error setting up right panel: {str(e)}")
    
    def _set_navigation_state(self, state="normal"):
        """Enable/disable tombol navigasi"""
        return None  # Tidak ada lagi tombol navigasi
    
    def _navigate_to_tab(self, tab_name):
        """Navigasi ke tab tertentu"""
        # Menggunakan warifit untuk mendapatkan root window
        root = self.winfo_toplevel()
        
        # Jika main window memiliki metode switch_to_tab, panggil
        if hasattr(root, 'switch_to_tab'):
            root.switch_to_tab(tab_name)
    
    def update_simulation_status(self, is_running=False, is_completed=False):
        """Update status simulasi dan keadaan tombol navigasi"""
        if is_running:
            self.status_label.configure(text="Running", text_color="#0066cc")
        elif is_completed:
            self.status_label.configure(text="Completed", text_color="#00b347")
        else:
            self.status_label.configure(text="Ready", text_color="gray")
    
    def _update_nodes(self, value: float) -> None:
        """
        Update nilai jumlah node dan ringkasan.
        
        Args:
            value: Nilai baru untuk jumlah node
        """
        try:
            new_value = int(value)
            
            # Cek jika nilai benar-benar berubah untuk menghindari update yang tidak perlu
            if new_value != self._cached_values['nodes']:
                self._cached_values['nodes'] = new_value
                self.nodes_value.configure(text=str(new_value))
                self._update_summary()
        except Exception as e:
            logger.error(f"Error saat update nodes: {str(e)}")
            
    def _update_malicious(self, value: float) -> None:
        """
        Update nilai jumlah node jahat dan ringkasan.
        
        Args:
            value: Nilai baru untuk jumlah node jahat
        """
        try:
            new_value = int(value)
            
            # Cek jika nilai benar-benar berubah untuk menghindari update yang tidak perlu
            if new_value != self._cached_values['malicious']:
                self._cached_values['malicious'] = new_value
                self.malicious_value.configure(text=str(new_value))
                self._update_summary()
        except Exception as e:
            logger.error(f"Error saat update malicious nodes: {str(e)}")
            
    def _update_iterations(self, value: float) -> None:
        """
        Update nilai jumlah iterasi dan ringkasan.
        
        Args:
            value: Nilai baru untuk jumlah iterasi
        """
        try:
            new_value = int(value)
            
            # Cek jika nilai benar-benar berubah untuk menghindari update yang tidak perlu
            if new_value != self._cached_values['iterations']:
                self._cached_values['iterations'] = new_value
                self.iterations_value.configure(text=str(new_value))
                self._update_summary()
        except Exception as e:
            logger.error(f"Error saat update iterations: {str(e)}")
    
    def get_selected_method(self) -> str:
        """
        Mendapatkan method yang dipilih (fixed to three_level_challenge).
        
        Returns:
            str: Method name yang dipilih
        """
        return "three_level_challenge"
            
    def _update_summary(self, *args) -> None:
        """Update teks ringkasan konfigurasi."""
        try:
            # Update network configuration text
            nodes = self._cached_values['nodes']
            malicious = self._cached_values['malicious']
            iterations = self._cached_values['iterations']
            
            network_text = f"Total Nodes: {nodes}\nMalicious Nodes: {malicious}\nIterations: {iterations}"
            self.network_config.configure(text=network_text)
            
            # Update selected attacks text
            selected = []
            if self.pmfa_var.get():
                selected.append("PMFA")
            if self.collusion_var.get():
                selected.append("Collusion")
            if self.sybil_var.get():
                selected.append("Sybil")
            if self.betrayal_var.get():
                selected.append("Betrayal")
                
            attack_text = "None" if not selected else "\n".join(selected)
            self.selected_attacks.configure(text=attack_text)
            
        except Exception as e:
            logger.error(f"Error saat update summary: {str(e)}")
            
    def _start_simulation(self):
        """Placeholder untuk starting simulation"""
        # Log
        logger.info("Start button clicked in SimulationSetupTab")
        # Implementasi sebenarnya dilakukan oleh MainWindow
        # yang meng-override ini dengan command saat setup button
        logger.debug("_start_simulation default handler invoked (no-op)")
        
    def _stop_simulation(self) -> None:
        """Placeholder untuk stopping simulation"""
        # Log
        logger.info("Stop button clicked in SimulationSetupTab")
        # Implementasi sebenarnya dilakukan oleh MainWindow
        # yang meng-override ini dengan command saat setup button
        logger.debug("_stop_simulation default handler invoked (no-op)")
        
    # Getters untuk akses nilai slider
    def get_node_count(self) -> int:
        """Mendapatkan jumlah node yang dipilih user"""
        return self._cached_values['nodes']
        
    def get_malicious_count(self) -> int:
        """Mendapatkan jumlah node malicious yang dipilih user"""
        return self._cached_values['malicious']
        
    def get_iterations(self) -> int:
        """Mendapatkan jumlah iterasi yang dipilih user"""
        return self._cached_values['iterations']
        
    def is_three_level_selected(self) -> bool:
        """Cek apakah Three Level Challenge dipilih"""
        return self.three_level_var.get() if hasattr(self, 'three_level_var') else False

    def get_total_nodes(self) -> int:
        """
        Dapatkan jumlah total node dari slider.
        
        Returns:
            int: Jumlah total node
        """
        return self.get_node_count()

    def get_malicious_percent(self) -> int:
        """
        Dapatkan persentase node malicious (bukan jumlah absolut).
        
        Returns:
            int: Persentase node malicious (0-100)
        """
        total_nodes = self.get_node_count()
        malicious_nodes = self.get_malicious_count()
        
        if total_nodes == 0:
            return 0
        
        return int((malicious_nodes / total_nodes) * 100)
        
    def get_attack_type(self) -> Optional[str]:
        """
        Dapatkan tipe serangan yang dipilih user.
        
        Returns:
            Optional[str]: Nama tipe serangan yang dipilih, atau None jika tidak ada yang dipilih
        """
        # Dictionary attack types dari checkboxes
        attack_types = {
            "PMFA": self.pmfa_var.get(),
            "Collusion": self.collusion_var.get(), 
            "Sybil": self.sybil_var.get(),
            "Betrayal": self.betrayal_var.get()
        }
        
        # Filter nama attack types yang bernilai True (checked)
        selected = [name for name, is_selected in attack_types.items() if is_selected]
        
        # Jika tidak ada yang dipilih, kembalikan None
        if not selected:
            logger.warning("Tidak ada attack type yang dipilih")
            return None
            
        # Jika ada lebih dari satu, ambil yang pertama secara eksplisit (UI kontrol)
        chosen = selected[0]
        if len(selected) > 1:
            logger.warning(f"Multiple attack types selected: {selected}, using {chosen}")

        # Normalisasi ke bentuk kanonik menggunakan settings
        try:
            from config.settings import normalize_attack
            normalized = normalize_attack(chosen)
            if normalized:
                chosen = normalized
        except ImportError:
            logger.debug("normalize_attack unavailable; using raw selected attack", exc_info=True)

        logger.info(f"Selected attack type (canonical): {chosen}")
        return chosen
