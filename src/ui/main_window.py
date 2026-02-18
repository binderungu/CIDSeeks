import os
import sys
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import time
import json
from pathlib import Path
from typing import Dict, Any
import traceback

from ui.data_analysis_tab import DataAnalysisTab
from ui.experiment_summary_tab import ExperimentSummaryTab
from ui.graph_analysis_tab import GraphAnalysisTab
from ui.node_analysis_tab import NodeAnalysisTab
from ui.simulation_setup_tab import SimulationSetupTab
from simulation.modules.database.node_database import NodeDatabase
from simulation.core.simulation_engine import SimulationEngine

class MainWindow(ctk.CTk):
    def __init__(self):
        """
        Initialize the main window:
         - Left panel: Simulation setup (sliders, run/stop)
         - Right panel: Tab view with Data Analysis, Graph Analysis, Node Analysis, Experiment Summary
         - Bottom: Console panel for logging
        """
        # Nonaktifkan animasi sebelum inisialisasi untuk performa lebih baik
        ctk.set_default_color_theme("blue") 
        
        # Inisialisasi window
        super().__init__()
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Setup database
        db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "simulation.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db = NodeDatabase(db_path)
        
        # Window configuration - Nonaktifkan update sementara selama setup UI
        self.withdraw()  # Sembunyikan window saat UI sedang dibangun
        self.title("CIDSeeks Simulator")
        self.geometry("1000x700")
        
        # --- Tambahkan flag status simulasi ---
        self.simulation_running = False 
        
        # Konfigurasikan UI dengan opsi performa lebih baik
        self._setup_ui()
        
        # Kembalikan window setelah setup selesai
        self.update_idletasks()
        self.deiconify()
        
    def _setup_ui(self):
        """Setup UI components with performance optimizations"""
        # Buat main container
        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Setup tab view dengan mode cache untuk performa
        self.tab_view = ctk.CTkTabview(self.main_container, command=self._on_tab_change)
        self.tab_view.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Konfigurasi segmentation color
        self.tab_view.configure(segmented_button_fg_color="#2b2b2b", 
                               segmented_button_selected_color="#0066cc",
                               segmented_button_selected_hover_color="#0052a3")
        
        # Add tabs
        self.tab_view.add("Simulation Setup")
        self.tab_view.add("Data Analysis")
        self.tab_view.add("Graph Analysis")
        self.tab_view.add("Node Analysis")
        self.tab_view.add("Experiment Summary")
        
        # Menyesuaikan tab font dan warna
        for tab_name in ["Simulation Setup", "Data Analysis", "Graph Analysis", "Node Analysis", "Experiment Summary"]:
            self.tab_view.tab(tab_name).configure(fg_color="#1e1e1e")
        
        # Initialize tabs one by one with update between each tab to prevent UI freezing
        self.update_idletasks()  # Update UI setelah membuat tab
        
        # Initialize tabs
        self.simulation_setup = SimulationSetupTab(parent=self.tab_view.tab("Simulation Setup"), db=self.db)
        self.simulation_setup.pack(fill="both", expand=True)
        self.update_idletasks()  # Update UI setelah tab pertama
        
        # Lazy loading untuk tab lain (hanya diinisialisasi ketika benar-benar dibutuhkan)
        self._initialize_inactive_tabs()
        
        # Set default tab
        self.tab_view.set("Simulation Setup")
        
        # Setup simulation controls
        self.simulation_setup.start_button.configure(command=self._run_simulation)
        # Pastikan tombol Stop awalnya disabled
        self.simulation_setup.stop_button.configure(command=self._stop_simulation, state="disabled") 
        
        # Tambahkan status labels sebagai atribut class
        self.status_label = self.simulation_setup.status_label
        self.duration_label = self.simulation_setup.duration_label
        self.iteration_label = self.simulation_setup.iteration_label
        
        self.loaded_tabs = {"Simulation Setup": True}  # Track tab yang sudah diload
        
    def _initialize_inactive_tabs(self):
        """Initialize non-active tabs lazily to improve startup performance"""
        # Dummy placeholders for tabs that will be loaded when clicked
        self.data_analysis = None
        self.graph_analysis = None
        self.node_analysis = None 
        self.experiment_summary = None
    
    def _on_tab_change(self, tab_name=None):
        """Handle tab change event with lazy loading"""
        # Tambahkan pengecekan jika tab_name valid (kadang command bisa mengirim None atau empty string)
        if tab_name is None:
            try:
                tab_name = self.tab_view.get() # Ambil nama tab aktif
                if not tab_name:
                    self.logger.warning("Tab change event received invalid tab name and get() failed.")
                    return
                self.logger.debug(f"Tab name retrieved inside callback: {tab_name}")
            except Exception as e:
                self.logger.error(f"Failed to get tab name inside callback: {e}")
                return # Tidak bisa lanjut tanpa nama tab

        # Pengecekan asli untuk string kosong atau invalid setelah potensi pengambilan nama
        if not isinstance(tab_name, str) or not tab_name:
            self.logger.warning(f"Invalid tab name detected after potential retrieval: {tab_name}")
            return

        self.logger.debug(f"Tab changed to: {tab_name}") # Tambah logging

        # Jika tab belum di-load, lakukan lazy loading
        if tab_name not in self.loaded_tabs:
            self.loaded_tabs[tab_name] = True
            
            # Tampilkan indikator loading
            loading_label = ctk.CTkLabel(self.tab_view.tab(tab_name), 
                                       text="Loading...", 
                                       font=("Arial", 14))
            loading_label.pack(expand=True)
            self.update_idletasks()
            
            # Load tab yang dipilih
            if tab_name == "Data Analysis" and not self.data_analysis:
                loading_label.destroy()
                cfg_da = {
                    'results_dir': 'results',
                    'runs_dir': 'results/_manifests',
                    'project_root': Path.cwd(),
                }
                self.data_analysis = DataAnalysisTab(self.tab_view.tab(tab_name), self.db, cfg_da)
                self.data_analysis.pack(fill="both", expand=True)
                
            elif tab_name == "Graph Analysis" and not self.graph_analysis:
                loading_label.destroy()
                self.graph_analysis = GraphAnalysisTab(self.tab_view.tab(tab_name), self.db)
                self.graph_analysis.pack(fill="both", expand=True)
                
            elif tab_name == "Node Analysis" and not self.node_analysis:
                loading_label.destroy()
                self.node_analysis = NodeAnalysisTab(self.tab_view.tab(tab_name), self.db)
                self.node_analysis.pack(fill="both", expand=True)
                
            elif tab_name == "Experiment Summary" and not self.experiment_summary:
                loading_label.destroy()
                # Inject UI cfg for artifact-driven summary
                cfg_ui = {
                    'results_dir': 'results',
                    'runs_dir': 'results/_manifests',
                    'default_view': 'overview',
                    'auto_refresh_secs': 0,
                }
                self.experiment_summary = ExperimentSummaryTab(self.tab_view.tab(tab_name), cfg_ui)
                self.experiment_summary.pack(fill="both", expand=True)
            
            self.update_idletasks()
            
    def _run_simulation(self):
        """
        Jalankan simulasi berdasarkan parameter yang ditentukan pengguna.
        """
        try:
            # --- Pengecekan flag ---
            if self.simulation_running:
                self.logger.warning("Simulasi sudah berjalan, permintaan Start baru diabaikan.")
                messagebox.showwarning("Simulasi Berjalan", "Simulasi sedang berjalan. Silakan Stop terlebih dahulu jika ingin memulai yang baru.")
                return

            # Validasi parameter
            if not self._validate_simulation_params():
                return
            
            # --- Set flag dan update tombol ---
            self.simulation_running = True
            self.simulation_setup.start_button.configure(state="disabled")
            self.simulation_setup.stop_button.configure(state="normal")
            self.set_busy_cursor(True) # Set busy cursor di awal
            
            # Reset database jika ada masalah
            try:
                # Pastikan database bersih
                self.db.recreate_database()
            except Exception as e:
                self.logger.error(f"Error saat inisialisasi database: {str(e)}")
                traceback.print_exc()
                self._show_error(f"Database error: {str(e)}")
                return
            
            self.logger.info("Memulai simulasi baru")
            
            # Dapatkan nilai parameter dari UI
            total_nodes_ui = self.simulation_setup.get_node_count()
            malicious_nodes_ui = self.simulation_setup.get_malicious_count()
            attack_type_ui = self.simulation_setup.get_attack_type()
            iterations_ui = self.simulation_setup.get_iterations()
            selected_method_ui = "three_level_challenge"
            
            # Kumpulkan parameter UI ke dalam dictionary
            ui_override_params = {
                'total_nodes': total_nodes_ui,
                'malicious_nodes': malicious_nodes_ui,
                'attack_type': attack_type_ui,
                'iterations': iterations_ui,
                'trust_method': selected_method_ui
            }
            self.logger.info(f"Parameter dari UI untuk override: {ui_override_params}")
            
            # Buat instance SimulationEngine baru dengan parameter UI
            config_file_path = "config.yaml" # Asumsi path default
            self.engine = SimulationEngine(
                config_path=config_file_path, 
                db_manager=self.db,
                ui_params=ui_override_params # Teruskan parameter UI
            )

            self.logger.info(f"Engine simulation dibuat dengan parameter UI override.")
            
            # Jalankan simulasi di thread terpisah
            self.simulation_thread = threading.Thread(
                target=self._run_simulation_thread,
                args=(self.engine,),
                daemon=False  # Biarkan thread selesai meskipun main thread berakhir
            )
            self.simulation_thread.start()
            
            self.logger.info(f"Thread simulasi dimulai: {self.simulation_thread.ident}")
            
            # Mulai update status UI setelah sedikit delay agar engine.is_running sudah true
            self.after(200, self._start_status_updates) 
            
            # Tampilkan status simulasi
            if hasattr(self, 'status_label'):
                self.status_label.configure(text="Simulasi sedang berjalan...")
                
        except Exception as e:
            self.logger.error(f"Error saat memulai simulasi: {str(e)}")
            traceback.print_exc()
            self._show_error(f"Simulasi error: {str(e)}")
            self.set_busy_cursor(False)

    def _validate_simulation_params(self):
        """
        Validasi parameter simulasi sebelum dijalankan.
        
        Returns:
            bool: True jika semua parameter valid, False jika tidak.
        """
        try:
            # --- Tambahan Cek: Jangan validasi jika simulasi sudah berjalan ---
            if self.simulation_running:
                self.logger.warning("Validasi parameter diskip karena simulasi sedang berjalan.")
                return False
                
            # Validasi node count
            node_count = self.simulation_setup.get_node_count()
            if node_count <= 0:
                messagebox.showerror("Validation Error", "Jumlah node harus lebih besar dari 0.")
                return False
                
            # Validasi malicious node count
            malicious_node_count = self.simulation_setup.get_malicious_count()
            if malicious_node_count < 0:
                messagebox.showerror("Validation Error", "Jumlah node berbahaya tidak boleh negatif.")
                return False
                
            if malicious_node_count > node_count:
                messagebox.showerror("Validation Error", 
                                 f"Jumlah node berbahaya ({malicious_node_count}) tidak boleh lebih besar dari total node ({node_count}).")
                return False
                
            # Validasi attack type
            attack_type = self.simulation_setup.get_attack_type()
            if not attack_type:
                messagebox.showerror("Validation Error", "Silakan pilih setidaknya satu tipe serangan.")
                return False
                
            # Validasi jumlah iterasi
            iterations = self.simulation_setup.get_iterations()
            if iterations <= 0:
                messagebox.showerror("Validation Error", "Jumlah iterasi harus lebih besar dari 0.")
                return False
                
            return True
                
        except Exception as e:
            self.logger.error(f"Error validating simulation parameters: {str(e)}")
            messagebox.showerror("Validation Error", f"Error validasi parameter simulasi: {str(e)}")
            return False

    def _run_simulation_thread(self, engine):
        """
        Jalankan simulasi dalam thread terpisah untuk mencegah UI freeze.
        """
        try:
            # Tampilkan busy cursor
            self.set_busy_cursor(True)
            
            # Log thread ID dan status
            current_thread_id = threading.get_ident()
            self.logger.info(f"Thread simulasi dimulai dengan ID: {current_thread_id}")
            self.logger.info(f"Menjalankan simulasi dengan {engine.total_nodes} node, {engine.malicious_nodes} node jahat")
            self.logger.info(f"Status engine sebelum run: is_running={engine.is_running}, is_completed={engine.is_completed}")
            
            # Dapatkan jumlah iterasi (sudah ada di engine jika di-pass dari UI)
            iterations = engine.total_iterations # Ambil dari engine
            self.logger.info(f"Menjalankan simulasi dengan {iterations} iterasi")
            
            # Run simulasi
            engine.run(iterations=iterations)
            
            # Status setelah simulasi selesai
            self.logger.info(f"Simulasi selesai dengan thread ID: {current_thread_id}")
            self.logger.info(f"Status engine setelah run: is_running={engine.is_running}, is_completed={engine.is_completed}")
            
            # Notifikasi UI untuk update
            self.after(100, self._update_ui_after_simulation)
        except Exception as e:
            error_message = f"Simulasi error: {str(e)}" # Tangkap pesan error
            self.logger.error(f"Error dalam thread simulasi: {error_message}")
            # Gunakan traceback di engine jika diperlukan, di sini cukup pesan error
            # traceback.print_exc() 
            # Notifikasi UI tentang error dengan pesan yang sudah ditangkap
            self.after(100, lambda msg=error_message: self._show_error(msg))
        finally:
            # Pastikan cursor dikembalikan
            self.set_busy_cursor(False)
    
    def _update_ui_after_simulation(self):
        """Update UI components after simulation completes successfully."""
        # Reset cursor and set status
        self.set_busy_cursor(False)
        self.logger.info("Updating UI after simulation completion")

        # Update status label
        if hasattr(self, 'status_label'):
            self.status_label.configure(text="Completed", text_color="green")

        # Fetch final results
        final_duration_text = "Duration: N/A"
        final_iteration_text = "Iteration: N/A"
        if hasattr(self, 'engine'):
            try:
                results = self.engine.get_results()
                sim_info = results.get('simulation_info', {})
                duration_val = sim_info.get('duration')
                if duration_val is not None:
                    final_duration_text = f"Duration: {duration_val:.2f}s"
                completed_iter = sim_info.get('completed_iterations')
                total_iter = sim_info.get('total_iterations')
                if completed_iter is not None and total_iter is not None:
                    final_iteration_text = f"Iteration: {completed_iter}/{total_iter}"
            except Exception as e:
                self.logger.error(f"Error fetching simulation results for UI update: {e}")

        # Update UI labels
        if hasattr(self, 'duration_label'):
            self.duration_label.configure(text=final_duration_text)
        if hasattr(self, 'iteration_label'):
            self.iteration_label.configure(text=final_iteration_text)

        # Redraw UI to reflect changes
        self.update_idletasks()

        # Schedule asynchronous refreshes for analysis tabs
        self.after(50, self._ensure_all_tabs_loaded_async)
        delay_ms = 150
        if hasattr(self, 'data_analysis') and self.data_analysis:
            self.logger.info(f"Scheduling refresh for Data Analysis tab in {delay_ms}ms")
            self.after(delay_ms, self.data_analysis.refresh_analysis)
            delay_ms += 100
        if hasattr(self, 'graph_analysis') and self.graph_analysis:
            self.logger.info(f"Scheduling refresh for Graph Analysis tab in {delay_ms}ms")
            self.after(delay_ms, self.graph_analysis.refresh_analysis)
            delay_ms += 100
        if hasattr(self, 'node_analysis') and self.node_analysis:
            self.logger.info(f"Scheduling refresh for Node Analysis tab in {delay_ms}ms")
            self.after(delay_ms, self.node_analysis.refresh_analysis)
            delay_ms += 100
        if hasattr(self, 'experiment_summary') and self.experiment_summary:
            self.logger.info(f"Scheduling refresh for Experiment Summary tab in {delay_ms}ms")
            # Force Summary to pick latest run from manifest
            self.after(delay_ms, lambda: [
                self.experiment_summary.refresh_from_manifest(),
                self._verify_attack_consistency()
            ])
            delay_ms += 100

        # Reset UI controls
        self.simulation_running = False
        self.simulation_setup.start_button.configure(state="normal")
        self.simulation_setup.stop_button.configure(state="disabled")

    def _ensure_all_tabs_loaded_async(self):
        """Ensure all analysis tabs are loaded asynchronously."""
        self.logger.debug("Ensuring all analysis tabs are loaded (async)...")
        tabs_to_load = ["Data Analysis", "Graph Analysis", "Node Analysis", "Experiment Summary"]
        current_delay = 10 # Start with a small delay
        
        for tab_name in tabs_to_load:
            if tab_name not in self.loaded_tabs:
                self.logger.debug(f"Scheduling lazy loading for tab: {tab_name} in {current_delay}ms")
                # Use lambda to capture the current tab_name for the delayed call
                self.after(current_delay, lambda name=tab_name: self._load_tab_if_needed(name))
                current_delay += 50 # Increase delay for the next tab load slightly
                
        self.logger.debug("Finished scheduling checks for tab loading.")

    def _load_tab_if_needed(self, tab_name):
        """Loads a specific tab if it hasn't been loaded yet. Called via self.after."""
        if tab_name not in self.loaded_tabs:
            self.logger.info(f"Executing lazy load for tab: {tab_name}")
            self._on_tab_change(tab_name=tab_name) # Call the original handler
            self.update_idletasks() # Allow UI to update after loading
        else:
            self.logger.debug(f"Tab {tab_name} was already loaded.")
    
    def _update_ui_on_error(self, error_msg):
        """Update UI state after an error occurs during simulation."""
        # Set engine status
        if hasattr(self, 'engine'):
            self.engine.is_running = False
            self.engine.is_completed = False
        
        # Reset UI state
        self.simulation_running = False
        
        # Log error
        self.logger.error(f"Simulation failed: {error_msg}")
        
        # Update UI elements
        self.simulation_setup.update_simulation_status()
        self.simulation_setup.start_button.configure(state="normal")
        self.simulation_setup.stop_button.configure(state="disabled")
        self.tab_view.configure(state="normal")
        
        # Tampilkan pesan error
        messagebox.showerror("Simulation Error", f"Error saat menjalankan simulasi:\n{error_msg}")
        
        # Set terminal status
        self.update_terminal_status(f"ERROR: {error_msg}")
    
    def _ensure_all_tabs_loaded(self):
        """Ensures all tabs are loaded and updated with results."""
        try:
            # Inisialisasi tab yang belum dibuat
            tabs_to_initialize = [
                ("Data Analysis", "data_analysis", DataAnalysisTab),
                ("Graph Analysis", "graph_analysis", GraphAnalysisTab),
                ("Node Analysis", "node_analysis", NodeAnalysisTab),
                ("Experiment Summary", "experiment_summary", ExperimentSummaryTab)
            ]

            for tab_name, attr_name, tab_class in tabs_to_initialize:
                try:
                    if not hasattr(self, attr_name) or getattr(self, attr_name) is None:
                        logger_msg = f"Initializing {tab_name} tab"
                        self.logger.info(logger_msg)
                        tab_widget = self.tab_view.tab(tab_name)
                        if tab_name == "Data Analysis":
                            cfg_da = {
                                'results_dir': 'results',
                                'runs_dir': 'results/_manifests',
                                'project_root': Path.cwd(),
                            }
                            tab_instance = tab_class(tab_widget, self.db, cfg_da)
                        elif tab_name == "Experiment Summary":
                            cfg_ui = {
                                'results_dir': 'results',
                                'runs_dir': 'results/_manifests',
                                'default_view': 'overview',
                                'auto_refresh_secs': 0,
                            }
                            tab_instance = tab_class(tab_widget, cfg_ui)
                        else:
                            tab_instance = tab_class(tab_widget, self.db)
                        tab_instance.pack(fill="both", expand=True)
                        setattr(self, attr_name, tab_instance)
                        self.loaded_tabs[tab_name] = True
                except Exception as tab_error:
                    self.logger.error(f"Error initializing {tab_name} tab: {str(tab_error)}")
                    # Continue with other tabs even if one fails
            
            # Update tabs dengan hasil jika simulasi telah selesai
            if hasattr(self, 'engine') and self.engine.is_completed and hasattr(self.engine, 'get_results'):
                results = self.engine.get_results()
                if results:
                    for attr_name in ["data_analysis", "graph_analysis", "node_analysis", "experiment_summary"]:
                        try:
                            tab_instance = getattr(self, attr_name, None)
                            if tab_instance:
                                tab_instance.refresh_analysis(results)
                        except Exception as refresh_error:
                            self.logger.error(f"Error refreshing {attr_name}: {str(refresh_error)}")
            
            self.logger.info("All tabs loaded and updated successfully")
        except Exception as e:
            self.logger.error(f"Error ensuring all tabs are loaded: {str(e)}")
            traceback.print_exc()
        finally:
            # Memastikan cursor kembali normal
            self.configure(cursor="")
    
    # Menambahkan fungsi pembantu untuk pindah tab dari luar
    def switch_to_tab(self, tab_name):
        """Helper function untuk pindah tab dari kode"""
        if tab_name in ["Simulation Setup", "Data Analysis", "Graph Analysis", "Node Analysis", "Experiment Summary"]:
            # Trigger lazy loading jika belum dimuat
            self._on_tab_change(tab_name)
            # Set tab aktif
            self.tab_view.set(tab_name)
            # Update UI
            self.update_idletasks()

    def _stop_simulation(self):
        """Stop the current simulation."""
        if hasattr(self, 'engine'):
            # --- Panggil stop engine jika sedang berjalan ---
            if self.engine.is_running:
                 self.engine.stop() # Panggil metode stop engine
                 self.logger.info("Perintah stop dikirim ke engine.")
            else:
                 self.logger.warning("Tombol stop ditekan, tapi engine tidak berjalan.")
                 # Tetap reset UI untuk konsistensi
            
            # --- Set flag dan update tombol ---
            self.simulation_running = False 
            self.simulation_setup.start_button.configure(state="normal")
            self.simulation_setup.stop_button.configure(state="disabled")
            self.set_busy_cursor(False) # Kembalikan cursor
            
            # Aktifkan kembali tab_view
            # self.tab_view.configure(state="normal") # Mungkin tidak perlu jika tidak dinonaktifkan
            
            # Reset simulation status di UI
            if hasattr(self, 'status_label'):
                self.status_label.configure(text="Stopped", text_color="orange")
            # Mungkin reset duration/iteration juga? Tergantung kebutuhan.
            # self.duration_label.configure(text="Duration: 0s")
            # self.iteration_label.configure(text="Iteration: 0/0")

            # Reset engine status (opsional, engine.stop sudah set is_running=False)
            # self.engine.is_completed = False 
            
            # Force UI update
            self.update_idletasks()
            
            # Update status pada database? Mungkin tidak perlu jika hanya stop manual
            # if hasattr(self.engine, 'update_status'):
            #     self.engine.update_status("idle")
            self._stop_status_updates() # Panggil stop update status
        else:
             # Jika engine belum ada tapi tombol stop ditekan (kasus jarang)
             self.logger.warning("Tombol stop ditekan, tapi engine belum diinisialisasi.")
             self.simulation_running = False 
             self.simulation_setup.start_button.configure(state="normal")
             self.simulation_setup.stop_button.configure(state="disabled")
             self.set_busy_cursor(False)

    def _get_selected_attack_type(self) -> str:
        """Get selected attack type."""
        # Dictionary attack types dari checkboxes
        attack_types = {
            "PMFA": self.simulation_setup.pmfa_var.get(),
            "Collusion": self.simulation_setup.collusion_var.get(), 
            "Sybil": self.simulation_setup.sybil_var.get(),
            "Betrayal": self.simulation_setup.betrayal_var.get()
        }
        
        # Filter nama attack types yang bernilai True (checked)
        selected = [name for name, is_selected in attack_types.items() if is_selected]
        
        # Jika tidak ada yang dipilih, kembalikan None
        if not selected:
            self.logger.warning("Tidak ada attack type yang dipilih")
            return None
            
        # Jika ada lebih dari satu, kembalikan yang pertama, tapi log semua yang dipilih
        if len(selected) > 1:
            self.logger.info(f"Multiple attack types selected: {selected}, using {selected[0]}")
            
        # Return attack type pertama yang dipilih
        self.logger.info(f"Selected attack type: {selected[0]}")
        return selected[0]

    def _start_status_updates(self):
        """Update status display periodically."""
        # Log pemanggilan fungsi
        self.logger.debug("_start_status_updates called.")

        if not hasattr(self, 'engine'):
            self.logger.debug("_start_status_updates: No engine found. Stopping updates.")
            return

        engine_running = getattr(self.engine, 'is_running', False)
        engine_completed = getattr(self.engine, 'is_completed', False)
        self.logger.debug(f"_start_status_updates: Engine state - running={engine_running}, completed={engine_completed}")

        # Hanya update jika engine ada dan sedang berjalan
        if not engine_running:
            self.logger.debug("_start_status_updates: Engine not running. Stopping updates.")
            # Jika sudah selesai, pastikan label final diset (meskipun _update_ui_after_simulation juga melakukannya)
            if engine_completed and hasattr(self, 'status_label'):
                 self.status_label.configure(text="Completed", text_color="green")
            return

        # Update label status
        if hasattr(self, 'status_label'):
            self.status_label.configure(text="Running", text_color="#0066cc") # Jika running pasti ini

        # Update duration
        start_time = getattr(self.engine, 'start_time', None)
        if start_time and hasattr(self, 'duration_label'):
            elapsed = int(time.time() - start_time)
            self.logger.debug(f"_start_status_updates: Updating duration to {elapsed}s")
            self.duration_label.configure(text=f"Duration: {elapsed}s")

        # Update iteration - gunakan property yang thread-safe
        current_iter = self.engine.current_iteration_safe if hasattr(self.engine, 'current_iteration_safe') else getattr(self.engine, 'current_iteration', 0)
        total_iter = getattr(self.engine, 'total_iterations', 0)
        
        # ---> TAMBAHKAN LOGGING DETAIL <--- 
        self.logger.debug(f"_start_status_updates: Reading engine state - running={engine_running}, completed={engine_completed}, current_iter={current_iter}, total_iter={total_iter}, start_time={start_time}")
        
        if hasattr(self, 'iteration_label'):
            self.logger.debug(f"_start_status_updates: Updating iteration label to {current_iter}/{total_iter}")
            self.iteration_label.configure(text=f"Iteration: {current_iter}/{total_iter}")

        # Paksa UI untuk menggambar ulang perubahan label
        self.update_idletasks()

        # Selalu coba reschedule, tapi batalkan jika engine tidak running lagi
        if hasattr(self, 'status_update_after_id'):
            # Batalkan jadwal sebelumnya jika ada
            try:
                self.after_cancel(self.status_update_after_id)
            except ValueError:
                self.logger.debug("status_update_after_id already cancelled: %s", self.status_update_after_id)
        
        # Jadwalkan pemanggilan berikutnya JIKA engine masih berjalan
        if engine_running:
            self.logger.debug("_start_status_updates: Scheduling next update (engine running).")
            self.status_update_after_id = self.after(1000, self._start_status_updates)
        else:
            # Engine belum running (mungkin masih startup). Coba lagi setelah 500ms.
            if not engine_completed:
                self.logger.debug("_start_status_updates: Engine not yet running, rescheduling status check in 500ms.")
                self.status_update_after_id = self.after(500, self._start_status_updates)
            else:
                self.logger.debug("_start_status_updates: Engine stopped/completed, not scheduling further updates.")
                self.status_update_after_id = None # Reset ID

    def _stop_status_updates(self):
        # Hentikan pembaruan status UI jika sedang berjalan
        if hasattr(self, 'status_update_after_id') and self.status_update_after_id:
            self.logger.debug("Stopping periodic status updates via _stop_status_updates.")
            try:
                self.after_cancel(self.status_update_after_id)
            except ValueError:
                self.logger.warning("Failed to cancel status update (already cancelled?)")
            self.status_update_after_id = None # Reset ID
        else:
            self.logger.debug("_stop_status_updates called, but no active update scheduled.")
            
    def set_busy_cursor(self, busy=True):
        """
        Mengatur cursor ke mode sibuk atau normal
        """
        cursor = "watch" if busy else ""
        # --- Tambahkan pengecekan winfo_exists() ---
        try:
            if self.winfo_exists():  # Cek apakah window masih ada
                self.configure(cursor=cursor)
        except tk.TclError as e:
            # Tangkap error jika window sudah destroyed saat dicek
            self.logger.warning(f"Gagal mengatur kursor (window mungkin sudah ditutup): {e}")
        
    def _show_error(self, message):
        """
        Menampilkan pesan error dalam dialog
        """
        # --- Set flag dan update tombol (saat error) ---
        self.simulation_running = False
        self.simulation_setup.start_button.configure(state="normal")
        self.simulation_setup.stop_button.configure(state="disabled")
        self.set_busy_cursor(False) # Pastikan kursor normal saat error

        messagebox.showerror("Error Simulasi", message)
        self.logger.error(f"Menampilkan dialog error: {message}")

    def _verify_attack_consistency(self) -> None:
        """Verify attack type consistency between UI selection and exported results."""
        try:
            if not hasattr(self, 'experiment_summary') or not self.experiment_summary:
                return
            if not hasattr(self, 'simulation_setup') or not self.simulation_setup:
                return
            
            # Get UI-selected attack
            ui_attack = self.simulation_setup.get_attack_type()
            
            # Get meta attack from current artifacts
            art = self.experiment_summary._current_artifacts
            if art and hasattr(art, 'meta') and isinstance(art.meta, dict):
                meta_attack = art.meta.get('attack')
                
                if ui_attack and meta_attack and ui_attack != meta_attack:
                    self.logger.warning(f"Attack type mismatch: UI={ui_attack}, Results={meta_attack}")
                    messagebox.showwarning(
                        "Attack Type Mismatch",
                        f"Warning: Selected attack type ({ui_attack}) differs from results ({meta_attack}).\n"
                        f"This may indicate a configuration issue.\n\n"
                        f"The Experiment Summary shows results for: {meta_attack}"
                    )
                    
        except Exception as e:
            self.logger.debug(f"Attack consistency check failed: {e}")
