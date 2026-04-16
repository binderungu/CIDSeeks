import sqlite3
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Any, Dict, List, Optional

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import numpy as np
import logging
import tkinter.messagebox as messagebox
import threading
import queue  # Import the queue module

from ui.services.experiment_store import RunArtifacts, RunIndex

class DataAnalysisTab(ttk.Frame):
    def __init__(self, parent, db, cfg: Optional[dict] = None):
        super().__init__(parent)
        self.db = db
        self.logger = logging.getLogger(__name__)
        self.current_method = "proposed"

        cfg = cfg or {}
        self.results_dir = Path(cfg.get("results_dir", "results"))
        self.runs_dir = Path(cfg.get("runs_dir", "results/_manifests"))
        
        # State for iteration list
        self.selected_iteration = None
        
        # Dictionary: iteration -> metadata for detail view
        self.iteration_data: Dict[int, Dict] = {}
        self.iteration_source = "db"
        self._artifact_iterations: Optional[List[Dict]] = None
        self._latest_artifact_summary: Optional[Dict] = None
        
        # State untuk mengelola refresh
        self.last_iteration_count = 0
        self.simulation_active = False
        self.refresh_in_progress = False # Flag to prevent overlapping refreshes

        # Queue for thread-safe communication
        self.ui_update_queue: queue.Queue[Any] = queue.Queue()
        
        self._init_ui()
        
        # Start the queue processor in the main thread
        self.after(100, self._process_queue)
        
        # Otomatis refresh saat tab dibuat
        self.after(200, self.refresh_analysis)  # Delay sedikit untuk memastikan UI sudah siap
        
        # Bind event saat tab menjadi aktif
        self.bind("<Visibility>", self._on_tab_selected)
        
        # Auto refresh (increased interval)
        self.after(5000, self._auto_refresh) # Increased interval to 5 seconds
        
    def _init_ui(self):
        """Initialize UI components"""
        # Main container
        self.main_container = ttk.Frame(self)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Iteration List Frame
        list_frame = ttk.LabelFrame(self.main_container, text="Daftar Iterasi")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create Treeview for iterations
        columns = ("iteration", "total_nodes", "trust_values", "below_threshold")
        self.iteration_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20)
        
        # Configure columns
        self.iteration_tree.heading("iteration", text="Iterasi")
        self.iteration_tree.heading("total_nodes", text="Total Nodes")
        self.iteration_tree.heading("trust_values", text="Nilai Trust")
        self.iteration_tree.heading("below_threshold", text="Nodes < Threshold")
        
        self.iteration_tree.column("iteration", width=100, anchor="center")
        self.iteration_tree.column("total_nodes", width=100, anchor="center")
        self.iteration_tree.column("trust_values", width=300, anchor="w")  # Lebih lebar untuk nilai trust
        self.iteration_tree.column("below_threshold", width=150, anchor="center")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.iteration_tree.yview)
        scrollbar.pack(side="right", fill="y")
        
        self.iteration_tree.configure(yscrollcommand=scrollbar.set)
        self.iteration_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind click event
        self.iteration_tree.bind("<Double-1>", self.on_iteration_select)

    def _on_tab_selected(self, event):
        """Handler saat tab menjadi aktif"""
        self.refresh_analysis()

    def refresh_analysis(self, results=None):
        """Initiates the analysis refresh process in a background thread."""
        if self.refresh_in_progress:
            self.logger.debug("Refresh already in progress. Skipping.")
            return
            
        self.logger.debug(f"Refreshing DataAnalysisTab. Received results: {bool(results)}")
        self.refresh_in_progress = True

        # Clear existing items and show loading state
        # This part MUST run in the main thread
        try:
            for item in self.iteration_tree.get_children():
                self.iteration_tree.delete(item)
            self.iteration_tree.insert("", tk.END, values=("Loading data...", "", "", ""), tags=('loading',))
            self.iteration_tree.tag_configure('loading', foreground='gray')
            self.update_idletasks() # Ensure loading message is shown
        except Exception as e:
            self.logger.error(f"Error preparing UI for refresh: {e}")
            # If UI update fails here, maybe log it and proceed? 
            # Or handle more gracefully depending on the error.
            
        # Start background thread for data fetching and processing
        thread = threading.Thread(target=self._do_refresh_background, args=(results,), daemon=True)
        thread.start()

    def _do_refresh_background(self, results):
        """Load iteration overview either from the simulation DB or latest artifacts."""
        processed_data = None
        is_message = False
        try:
            check_query = "SELECT COUNT(*) as count FROM experiment_summary"
            try:
                cursor = self.db.execute_query(check_query)
                count_row = cursor.fetchone() if cursor else None
                if cursor is not None:
                    try:
                        cursor.connection.close()
                    except Exception:
                        self.logger.debug("Failed to close check_query cursor connection", exc_info=True)
            except Exception:
                count_row = None
            simulation_active = count_row and count_row['count'] > 0

            if not simulation_active:
                processed_data = [("Simulasi belum dimulai", "", "", "")]
                is_message = True
                self.ui_update_queue.put(('data', processed_data, is_message))
                return

            threshold = 0.5
            iterations: list = []
            self.iteration_source = "db"

            db_cursor = None
            try:
                query = """
                    SELECT
                        nr.round AS iteration,
                        COUNT(*) AS total_nodes,
                        AVG(nr.trust) AS avg_trust,
                        AVG(CASE WHEN nr.label_is_malicious = 0 THEN nr.trust END) AS honest_trust,
                        AVG(CASE WHEN nr.label_is_malicious = 1 THEN nr.trust END) AS malicious_trust,
                        SUM(CASE WHEN nr.trust < ? THEN 1 ELSE 0 END) AS nodes_below_threshold,
                        SUM(CASE WHEN nr.label_is_malicious = 1 THEN 1 ELSE 0 END) AS malicious_nodes,
                        SUM(CASE WHEN nr.label_is_malicious = 1 AND nr.trust < ? THEN 1 ELSE 0 END) AS detected_malicious,
                        SUM(CASE WHEN nr.label_is_malicious = 0 AND nr.trust < ? THEN 1 ELSE 0 END) AS false_positives
                    FROM node_round nr
                    GROUP BY nr.round
                    ORDER BY nr.round
                """
                db_cursor = self.db.execute_query(query, (threshold, threshold, threshold))
                if db_cursor:
                    iterations = db_cursor.fetchall()
                    self.logger.info("Fetched %s iterations from node_round table", len(iterations))
            except sqlite3.Error as db_err:
                self.logger.debug("node_round query failed: %s", db_err)
            finally:
                if db_cursor is not None:
                    try:
                        db_cursor.connection.close()
                    except Exception:
                        self.logger.debug("Failed to close node_round cursor connection", exc_info=True)

            if not iterations:
                self.logger.info("Iteration data not found in DB. Loading latest run artifacts.")
                artifact_rows = self._load_latest_artifact_iterations()
                if artifact_rows:
                    iterations = artifact_rows
                    self.iteration_source = "artifact"
                else:
                    processed_data = [("No iteration data available", "", "", "")]
                    is_message = True
                    self.ui_update_queue.put(('data', processed_data, is_message))
                    return

            processed_data = []
            self.iteration_data.clear()

            for row in iterations:
                if isinstance(row, sqlite3.Row):
                    iter_num = int(row['iteration'])
                    total_nodes = int(row['total_nodes'] or 0)
                    below_threshold = int(row['nodes_below_threshold'] or 0)
                    malicious_count = int(row['malicious_nodes'] or 0)
                    detected_malicious = int(row['detected_malicious'] or 0)
                    false_positives = int(row['false_positives'] or 0)
                    avg_trust = float(row['avg_trust'] or 0.0)
                    honest_trust = float(row['honest_trust'] or 0.0)
                    malicious_trust = float(row['malicious_trust'] or 0.0)

                    self.iteration_data[iter_num] = {
                        'total_nodes': total_nodes,
                        'avg_trust': avg_trust,
                        'honest_trust': honest_trust,
                        'malicious_trust': malicious_trust,
                        'below_threshold': below_threshold,
                        'malicious_nodes': malicious_count,
                        'detected_malicious': detected_malicious,
                        'false_positives': false_positives,
                        'source': 'db',
                    }

                    trust_info = f"Honest μ {honest_trust:.3f} | Malicious μ {malicious_trust:.3f}"
                    threshold_percentage = (below_threshold/total_nodes*100) if total_nodes > 0 else 0.0
                    processed_data.append((
                        f"Iterasi {iter_num}",
                        str(total_nodes),
                        trust_info,
                        f"{below_threshold} ({threshold_percentage:.1f}%)"
                    ))
                else:
                    iter_num = int(row['iteration'])
                    total_nodes = int(row.get('total_nodes', 0) or 0)
                    honest_trust = float(row.get('honest_trust', 0.0) or 0.0)
                    malicious_trust = float(row.get('malicious_trust', 0.0) or 0.0)
                    gap = float(row.get('trust_gap', honest_trust - malicious_trust) or 0.0)

                    self.iteration_data[iter_num] = {
                        'total_nodes': total_nodes,
                        'avg_trust': (honest_trust + malicious_trust) / 2,
                        'honest_trust': honest_trust,
                        'malicious_trust': malicious_trust,
                        'trust_gap': gap,
                        'below_threshold': None,
                        'malicious_nodes': row.get('malicious_nodes'),
                        'detected_malicious': None,
                        'false_positives': None,
                        'source': 'artifact',
                        'artifact': row,
                    }

                    trust_info = f"Honest μ {honest_trust:.3f} | Malicious μ {malicious_trust:.3f} | Gap {gap:.3f}"
                    processed_data.append((
                        f"Iterasi {iter_num}",
                        str(total_nodes) if total_nodes else "–",
                        trust_info,
                        "–"
                    ))

            self.ui_update_queue.put(('data', processed_data, is_message))

        except Exception as e:
            self.logger.error(f"Error in background refresh thread: {e}")
            error_data = [(f"Error loading data: {e}", "", "", "")]
            is_message = True
            self.ui_update_queue.put(('data', error_data, is_message))
        finally:
            self.ui_update_queue.put(('complete', None, None))

    def _load_latest_artifact_iterations(self) -> Optional[List[Dict]]:
        """Load iteration-level metrics from the most recent run artifacts."""
        try:
            index = RunIndex(self.results_dir, self.runs_dir)
            run_path = index.get_last_run_results_path()
            if not run_path or not run_path.exists():
                self.logger.info("No canonical manifest-backed run found for %s", self.results_dir)
                return None

            artifacts = RunArtifacts.load(run_path)
            summary = artifacts.meta.get('summary', {}) if isinstance(artifacts.meta, dict) else {}
            self._latest_artifact_summary = summary

            df = artifacts.trust_gap_per_round.copy()
            if df.empty and hasattr(artifacts, 'trust_means'):
                df = getattr(artifacts, 'trust_means')
            if df.empty and not artifacts.metrics_per_round.empty:
                df = artifacts.metrics_per_round
            if df.empty:
                return None

            total_nodes = (
                summary.get('total_nodes')
                or summary.get('N')
                or int((df.get('n_honest', pd.Series(dtype=float)).fillna(0) +
                        df.get('n_malicious', pd.Series(dtype=float)).fillna(0)).max() or 0)
            )
            malicious_nodes = summary.get('malicious_nodes') or summary.get('malicious')

            rows: List[Dict] = []
            for _, record in df.iterrows():
                iteration = int(record.get('round', record.get('iteration', 0)))
                honest = float(record.get('mean_honest', record.get('honest_trust', 0.0)) or 0.0)
                malicious = float(record.get('mean_malicious', record.get('malicious_trust', 0.0)) or 0.0)
                gap = float(record.get('gap', honest - malicious) or 0.0)
                rows.append({
                    'iteration': iteration,
                    'total_nodes': int(total_nodes) if total_nodes else None,
                    'honest_trust': honest,
                    'malicious_trust': malicious,
                    'trust_gap': gap,
                    'malicious_nodes': malicious_nodes,
                })

            # cache for detail fallback
            self._artifact_iterations = rows
            return rows
        except Exception as err:
            self.logger.error(f"Failed to load artifact iterations: {err}")
            return None

    def _process_queue(self):
        """Processes items from the UI update queue in the main thread."""
        try:
            while True:
                try:
                    message_type, data, is_message = self.ui_update_queue.get_nowait()
                except queue.Empty:
                    break

                if message_type == 'data':
                    self._update_ui_with_data(data, is_message)
                elif message_type == 'complete':
                    self.refresh_in_progress = False # Reset flag only when complete message is received
                    self.logger.debug("Refresh process marked as complete.")

        except Exception as e:
            self.logger.error(f"Error processing UI update queue: {e}")
            self.refresh_in_progress = False # Ensure flag is reset even on error

        # Reschedule itself to run again
        self.after(100, self._process_queue) # Check queue every 100ms
            
    def _update_ui_with_data(self, data_to_display, is_message):
        """Updates the Treeview in the main UI thread with processed data."""
        try:
            # Clear loading/previous items
            for item in self.iteration_tree.get_children():
                self.iteration_tree.delete(item)
            
            # Populate with new data
            for values in data_to_display:
                 tags = ('message',) if is_message else ()
                 self.iteration_tree.insert("", tk.END, values=values, tags=tags)
                 
            self.iteration_tree.tag_configure('message', foreground='gray')
            # Removed logger message from here, it's better placed after queue processing signals completion
        except Exception as e:
             self.logger.error(f"Error updating DataAnalysisTab UI: {str(e)}")
             # Attempt to show error in the tree itself
             try:
                 for item in self.iteration_tree.get_children(): self.iteration_tree.delete(item)
                 self.iteration_tree.insert("", tk.END, values=(f"UI Update Error: {str(e)}", "", "", ""), tags=('message',))
                 self.iteration_tree.tag_configure('message', foreground='red')
             except Exception:
                 self.logger.debug("Failed to render fallback error row in DataAnalysisTab", exc_info=True)

    def show_iteration_details(self, iteration):
        """Tampilkan detail untuk iterasi yang dipilih"""
        source = self.iteration_data.get(iteration, {}).get('source', self.iteration_source)
        if source != 'db':
            messagebox.showinfo(
                "Detail Tidak Tersedia",
                "Detail node per iterasi hanya tersedia ketika simulasi dijalankan langsung dari aplikasi."
            )
            return

        try:
            query = """
                SELECT 
                    node_id,
                    label_is_malicious,
                    trust,
                    pred_is_malicious,
                    was_quarantined,
                    ttd_round
                FROM node_round
                WHERE round = ?
                ORDER BY node_id
            """

            cursor = self.db.execute_query(query, (iteration,))
            details = cursor.fetchall() if cursor else []
            if cursor is not None:
                try:
                    cursor.connection.close()
                except Exception:
                    self.logger.debug("Failed to close iteration detail cursor connection", exc_info=True)

            if not details:
                messagebox.showwarning("No Data", f"Tidak ada data detail untuk iterasi {iteration}")
                return
            
            # Buat window popup
            detail_win = tk.Toplevel(self)
            detail_win.title(f"Detail Iterasi {iteration}")
            detail_win.geometry("1000x700")  # Diperbesar untuk menampung legend
            
            # Frame untuk informasi umum
            info_frame = ttk.LabelFrame(detail_win, text="Informasi Iterasi")
            info_frame.pack(fill=tk.X, padx=5, pady=5)
            
            # Hitung statistik
            total_nodes = len(details)
            nodes_below = 0
            malicious_nodes = 0
            detected_malicious = 0
            false_positives = 0
            for record in details:
                trust_val = record['trust'] if record['trust'] is not None else 0.5
                is_malicious = bool(record['label_is_malicious'])
                below = trust_val < 0.5
                nodes_below += 1 if below else 0
                malicious_nodes += 1 if is_malicious else 0
                if is_malicious and below:
                    detected_malicious += 1
                if not is_malicious and below:
                    false_positives += 1

            false_negatives = malicious_nodes - detected_malicious
            threshold_percentage = (nodes_below / total_nodes) * 100 if total_nodes else 0.0
            detection_rate = (detected_malicious / malicious_nodes) * 100 if malicious_nodes else 0.0

            info_text = f"""
            Total Nodes: {total_nodes}
            Malicious Nodes (Ground Truth): {malicious_nodes}
            Nodes di bawah threshold (0.5): {nodes_below}
            Persentase di bawah threshold: {threshold_percentage:.1f}%

            True Positive (Malicious terdeteksi): {detected_malicious}
            False Positive (Normal salah deteksi): {false_positives}
            False Negative (Malicious lolos): {false_negatives}
            Detection Rate: {detection_rate:.1f}%

            Threshold 0.5 menentukan:
              • Trust < 0.5 ⇒ node dianggap malicious
              • Trust ≥ 0.5 ⇒ node dianggap normal
            """
            ttk.Label(info_frame, text=info_text).pack(padx=5, pady=5)

            legend_frame = ttk.LabelFrame(detail_win, text="Keterangan Warna")
            legend_frame.pack(fill=tk.X, padx=5, pady=5)
            legend_items = [
                ("Merah", "Malicious terdeteksi (True Positive)", "red"),
                ("Oranye", "Malicious belum terdeteksi (False Negative)", "orange"),
                ("Ungu", "Normal salah deteksi (False Positive)", "purple"),
                ("Hijau", "Normal terdeteksi benar", "green"),
            ]
            for idx, (label, desc, color) in enumerate(legend_items):
                ttk.Label(legend_frame, text="■", foreground=color, font=("Arial", 14)).grid(row=idx, column=0, padx=5, pady=2)
                ttk.Label(legend_frame, text=f"{label}: {desc}").grid(row=idx, column=1, sticky="w", padx=5, pady=2)

            detail_frame = ttk.Frame(detail_win)
            detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            columns = ("node_id", "node_type", "is_malicious", "trust_score", "status")
            detail_tree = ttk.Treeview(detail_frame, columns=columns, show="headings")
            detail_tree.heading("node_id", text="Node ID")
            detail_tree.heading("node_type", text="Type")
            detail_tree.heading("is_malicious", text="Malicious (GT)")
            detail_tree.heading("trust_score", text="Trust")
            detail_tree.heading("status", text="Status")

            detail_tree.column("node_id", width=80, anchor="center")
            detail_tree.column("node_type", width=100, anchor="center")
            detail_tree.column("is_malicious", width=130, anchor="center")
            detail_tree.column("trust_score", width=100, anchor="center")
            detail_tree.column("status", width=240, anchor="w")

            for record in details:
                trust_score = record['trust'] if record['trust'] is not None else 0.5
                is_malicious = bool(record['label_is_malicious'])
                below = trust_score < 0.5
                if is_malicious and below:
                    status = "Malicious (Terdeteksi)"
                    tag = "true_positive"
                elif is_malicious and not below:
                    status = "Malicious (Belum Terdeteksi)"
                    tag = "false_negative"
                elif not is_malicious and below:
                    status = "Normal (Salah Deteksi)"
                    tag = "false_positive"
                else:
                    status = "Normal"
                    tag = "true_negative"

                detail_tree.insert(
                    "",
                    tk.END,
                    values=(
                        f"Node {record['node_id']}",
                        "malicious" if is_malicious else "normal",
                        "Yes" if is_malicious else "No",
                        f"{trust_score:.3f}",
                        status,
                    ),
                    tags=(tag,),
                )

            detail_tree.tag_configure("true_positive", foreground="red")
            detail_tree.tag_configure("false_negative", foreground="orange")
            detail_tree.tag_configure("false_positive", foreground="purple")
            detail_tree.tag_configure("true_negative", foreground="green")

            scrollbar = ttk.Scrollbar(detail_frame, orient="vertical", command=detail_tree.yview)
            scrollbar.pack(side="right", fill="y")
            detail_tree.configure(yscrollcommand=scrollbar.set)
            detail_tree.pack(fill=tk.BOTH, expand=True)

        except Exception as e:
            self.logger.error(f"Error showing iteration details: {e}")
            messagebox.showerror("Error", f"Gagal menampilkan detail: {e}")

    def on_iteration_select(self, event):
        """Callback saat baris iterasi di-double click untuk menampilkan detail evaluasi iterasi."""
        selected = self.iteration_tree.focus()
        if not selected:
            return
        values = self.iteration_tree.item(selected, "values")
        if not values:
            return
        iteration = int(values[0].split()[1])
        self.show_iteration_details(iteration)

    def _auto_refresh(self):
        """Periodically triggers a refresh if the previous one is complete."""
        if not self.refresh_in_progress:
            self.logger.debug("Auto-refresh triggered.")
            self.refresh_analysis()
        else:
             self.logger.debug("Skipping auto-refresh as previous refresh is still in progress.")
             
        # Schedule next auto-refresh
        self.after(5000, self._auto_refresh) # Check every 5 seconds
