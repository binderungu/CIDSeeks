import customtkinter as ctk
from tkinter import ttk
import logging
import pandas as pd
import threading # Import threading
import queue     # Import queue
import tkinter as tk # <-- TAMBAHKAN IMPORT INI
import json

class NodeAnalysisTab(ctk.CTkFrame):
    """
    NodeAnalysisTab provides an interactive table (Treeview) displaying a list of nodes.
    When a user clicks on a specific node row, detailed evaluation data is shown (e.g., counts
    of alarms, authentications, challenges). This design helps keep the initial layout tidy and
    reveals details only when requested.
    """
    
    def __init__(self, parent, db):
        """
        Initialize the NodeAnalysisTab.

        Args:
            parent: The parent container (a ttk or CTk frame).
            db: The NodeDatabase or similar database object from which we'll query node data,
                alarms, authentication events, and challenge data.
        """
        super().__init__(parent)
        self.db = db
        self.logger = logging.getLogger(__name__)
        self.node_details_cache = {}
        
        # Tracking state untuk optimasi refresh
        self.last_iteration = 0
        self.refresh_in_progress = False # Flag to prevent overlapping refreshes
        self.ui_update_queue = queue.Queue() # Queue for thread-safe UI updates
        
        self._init_ui()
        # Bind tab visibility event
        self.bind("<Visibility>", self._on_tab_visible)
        
        # Start the queue processor in the main thread
        self.after(100, self._process_queue)
        
        # Auto refresh setiap 5 detik (lebih lama)
        self.after(5000, self._auto_refresh)
        
    def _init_ui(self):
        """
        Set up the user interface for the node analysis tab, consisting of:
         - A Treeview that displays a list of nodes (table).
         - A detail panel that shows evaluation data (alarms, auth, challenges) for the selected node.
        """
        # Main container
        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Header
        header = ctk.CTkLabel(
            self.main_container,
            text="Node Analysis",
            font=("Arial Bold", 16)
        )
        header.pack(pady=10)
        
        # Split view
        self.paned_window = ttk.PanedWindow(self.main_container, orient="vertical")
        self.paned_window.pack(fill="both", expand=True)
        
        # Top frame for node list
        self.nodes_frame = ctk.CTkFrame(self.paned_window)
        self.paned_window.add(self.nodes_frame, weight=1)
        
        # Bottom frame for details
        self.details_frame = ctk.CTkFrame(self.paned_window)
        self.paned_window.add(self.details_frame, weight=1)
        
        # Setup node list
        self._setup_node_list()
        
        # Setup details view
        self._setup_details_view()

    def _setup_node_list(self):
        """Setup tabel daftar node"""
        # Create Treeview
        columns = ("node_id", "type", "trust", "status", "attacks", "auth")
        self.node_tree = ttk.Treeview(
            self.nodes_frame, 
            columns=columns,
            show="headings",
            height=20
        )
        
        # Configure columns
        self.node_tree.heading("node_id", text="Node ID")
        self.node_tree.heading("type", text="Type")
        self.node_tree.heading("trust", text="Avg Trust")
        self.node_tree.heading("status", text="Status")
        self.node_tree.heading("attacks", text="Attacks (Out/In)")
        self.node_tree.heading("auth", text="Auth")
        
        # Column widths
        self.node_tree.column("node_id", width=100, anchor="center")
        self.node_tree.column("type", width=100, anchor="center") 
        self.node_tree.column("trust", width=100, anchor="center")
        self.node_tree.column("status", width=150, anchor="w")
        self.node_tree.column("attacks", width=150, anchor="center")
        self.node_tree.column("auth", width=100, anchor="center")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.nodes_frame, orient="vertical", command=self.node_tree.yview)
        scrollbar.pack(side="right", fill="y")
        
        self.node_tree.configure(yscrollcommand=scrollbar.set)
        self.node_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bind click event
        self.node_tree.bind("<<TreeviewSelect>>", self._on_node_select)

    def _setup_details_view(self):
        """Sets up the detailed view section with tabs *inside* self.details_frame."""
        # Buat label dan TabView di dalam self.details_frame yang sudah ada
        self.details_label = ctk.CTkLabel(self.details_frame, text="Node Details", font=ctk.CTkFont(weight="bold"))
        self.details_label.pack(pady=(5, 5), padx=5)

        self.details_tab_view = ctk.CTkTabview(self.details_frame)
        self.details_tab_view.pack(fill="both", expand=True, padx=5, pady=5)

        # Add tabs
        self.details_tab_view.add("Overview")
        self.details_tab_view.add("Alarms")
        self.details_tab_view.add("Authentication")
        self.details_tab_view.add("Challenges")

        # Get the frame for each tab
        self.overview_frame = self.details_tab_view.tab("Overview")
        self.alarms_frame = self.details_tab_view.tab("Alarms")
        self.auth_frame = self.details_tab_view.tab("Authentication")
        self.challenges_frame = self.details_tab_view.tab("Challenges")

        # --- Gunakan Scrollable Frame untuk Overview ---
        # Buat scrollable frame di dalam overview_frame
        self.overview_scrollable_frame = ctk.CTkScrollableFrame(self.overview_frame, fg_color="transparent")
        self.overview_scrollable_frame.pack(fill="both", expand=True)

        # Setup content inside the scrollable frame
        self.node_id_label = ctk.CTkLabel(self.overview_scrollable_frame, text="Node ID: N/A", anchor="w")
        self.node_id_label.pack(fill="x", pady=2)
        self.type_label = ctk.CTkLabel(self.overview_scrollable_frame, text="Type: N/A", anchor="w")
        self.type_label.pack(fill="x", pady=2)
        self.status_label = ctk.CTkLabel(self.overview_scrollable_frame, text="Status: N/A", anchor="w")
        self.status_label.pack(fill="x", pady=2)
        self.trust_label = ctk.CTkLabel(self.overview_scrollable_frame, text="Avg Trust: N/A", anchor="w")
        self.trust_label.pack(fill="x", pady=2)
        self.attacks_label = ctk.CTkLabel(self.overview_scrollable_frame, text="Attacks (Out/In): N/A", anchor="w")
        self.attacks_label.pack(fill="x", pady=2)
        self.auths_label = ctk.CTkLabel(self.overview_scrollable_frame, text="Auth Attempts: N/A", anchor="w")
        self.auths_label.pack(fill="x", pady=2)

        # --- Pindahkan Legenda ke dalam Scrollable Frame ---
        legend_frame = ctk.CTkFrame(self.overview_scrollable_frame, fg_color="transparent")
        legend_frame.pack(pady=(10, 0), fill="x")
        ctk.CTkLabel(legend_frame, text="Legend:", font=ctk.CTkFont(weight="bold")).pack(side=tk.LEFT, padx=(0, 5))
        ctk.CTkLabel(legend_frame, text="Malicious (Detected)", text_color="red").pack(side=tk.LEFT, padx=5)
        ctk.CTkLabel(legend_frame, text="Malicious (Undetected)", text_color="orange").pack(side=tk.LEFT, padx=5)
        ctk.CTkLabel(legend_frame, text="Normal (Misdetected)", text_color="purple").pack(side=tk.LEFT, padx=5)
        ctk.CTkLabel(legend_frame, text="Normal", text_color="green").pack(side=tk.LEFT, padx=5)
        # --- Akhir Pindahkan Legenda --

        # Setup Treeviews for other tabs (akan di-populate di _show_node_details)
        self.activity_trees = {}

    def _auto_refresh(self):
        """Auto refresh data jika simulasi sedang berjalan dan refresh sebelumnya selesai."""
        # Panggil refresh hanya jika tidak ada refresh lain yang sedang berjalan
        if not self.refresh_in_progress:
            try:
                # Periksa apakah ada perubahan iterasi (query ini cepat)
                iter_query = "SELECT MAX(iteration) as max_iter FROM trust_scores"
                # Gunakan execute_query yang aman
                cursor = self.db.execute_query(iter_query)
                iter_result = cursor.fetchone() if cursor else None
                current_iteration = iter_result['max_iter'] if iter_result and iter_result['max_iter'] is not None else 0

                # Hanya refresh jika ada perubahan iterasi
                if current_iteration > self.last_iteration:
                    self.logger.debug(f"Auto-refresh triggered for NodeAnalysisTab due to new iteration {current_iteration}")
                    self.refresh_analysis() # Panggil refresh non-blocking
                    self.last_iteration = current_iteration
                else:
                    self.logger.debug("Skipping auto-refresh for NodeAnalysisTab, no new iteration.")

            except Exception as e:
                self.logger.error(f"Error in NodeAnalysisTab auto refresh check: {str(e)}")
        else:
            self.logger.debug("Skipping auto-refresh for NodeAnalysisTab as refresh is in progress.")

        # Schedule next refresh
        self.after(5000, self._auto_refresh) # Cek lagi setelah 5 detik

    def _on_tab_visible(self, event):
        """Handler ketika tab menjadi visible"""
        # Panggil refresh hanya jika tidak ada refresh lain yang sedang berjalan
        if not self.refresh_in_progress:
            try:
                if str(event.widget) == str(self):
                    # Refresh data saat tab dibuka
                    self.logger.info("Node Analysis tab became visible, triggering refresh.")
                    self.refresh_analysis() # Panggil refresh non-blocking
            except Exception as e:
                self.logger.error(f"Error on NodeAnalysisTab tab visible: {str(e)}")
        else:
            self.logger.debug("Node Analysis tab became visible, but refresh already in progress.")

    def refresh_analysis(self, results=None):
        """Initiates the node analysis refresh in a background thread."""
        if self.refresh_in_progress:
            self.logger.debug("NodeAnalysisTab refresh already in progress. Skipping.")
            return
            
        self.logger.debug(f"Refreshing NodeAnalysisTab. Received results: {bool(results)}")
        self.refresh_in_progress = True

        # Clear existing items and show loading state (main thread)
        try:
            for item in self.node_tree.get_children():
                self.node_tree.delete(item)
            self.node_tree.insert("", tk.END, values=("Loading node data...",) + ("",)*(len(self.node_tree["columns"])-1), tags=('loading',))
            self.node_tree.tag_configure('loading', foreground='gray')
            self.update_idletasks() # Ensure loading message is shown
        except Exception as e:
            self.logger.error(f"Error preparing NodeAnalysisTab UI for refresh: {e}")
            # Optionally reset flag if UI preparation fails critically
            # self.refresh_in_progress = False 

        # Start background thread for data fetching and processing
        thread = threading.Thread(target=self._do_refresh_background, args=(results,), daemon=True)
        thread.start()
        
    def _do_refresh_background(self, results):
        """Performs database query and data processing in a background thread."""
        processed_node_data = []
        new_node_details_cache = {}
        error_message = None
        try:
            # --- KEMBALIKAN QUERY ASLI YANG KOMPLEKS ---
            query = '''
            WITH latest_iteration AS (
                SELECT MAX(iteration) as max_iter FROM trust_scores
            ),
            node_stats AS (
                SELECT 
                    n.node_id,
                    n.node_type,
                    n.is_malicious,
                    COUNT(DISTINCT ae_out.id) as attacks_made,    
                    COUNT(DISTINCT ae_in.id) as attacks_received, 
                    COUNT(DISTINCT ar.id) as auth_attempts,      
                    -- Fetch latest trust score using the CTE
                    COALESCE(ts.score, 0.5) as latest_trust        
                FROM nodes n
                -- Join for attacks made by this node
                LEFT JOIN attack_events ae_out ON ae_out.attacker_id = n.node_id
                -- Join for attacks received by this node
                LEFT JOIN attack_events ae_in ON ae_in.target_id = n.node_id
                -- Join for auth results initiated by this node
                LEFT JOIN auth_results ar ON ar.node_id = n.node_id
                -- Join for latest trust score where this node is the target
                LEFT JOIN trust_scores ts ON ts.target_node_id = n.node_id 
                                        AND ts.iteration = (SELECT max_iter FROM latest_iteration)
                GROUP BY n.node_id, n.node_type, n.is_malicious 
            )
            SELECT * FROM node_stats
            ORDER BY node_id
            '''
            # --- AKHIR QUERY ASLI ---
 
            self.logger.debug(f"Executing NodeAnalysisTab query: {query[:150]}...") # Log query singkat
            cursor = self.db.execute_query(query)
            self.logger.debug(f"Query execution finished. Cursor: {bool(cursor)}")

            nodes = []
            if cursor:
                nodes = cursor.fetchall()
                self.logger.info(f"NodeAnalysisTab background thread retrieved {len(nodes)} rows from DB using complex query.")
            else:
                self.logger.warning("NodeAnalysisTab query execution returned no cursor.")

            self.logger.info(f"NodeAnalysisTab background thread retrieved {len(nodes)} nodes")
            
            if not nodes:
                # Prepare message for UI thread
                processed_node_data = [("No node data available",) + ("",)*(len(self.node_tree["columns"])-1)]
                self.ui_update_queue.put(('data', processed_node_data, True, new_node_details_cache))
                return
                
            # Process nodes (CPU bound, okay in background thread)
            for node in nodes:
                node_id = node['node_id']
                node_type = node['node_type']
                is_malicious = bool(node['is_malicious'])
                attacks_made = int(node['attacks_made'] or 0)
                auth_attempts = int(node['auth_attempts'] or 0)
                attacks_received = int(node['attacks_received'] or 0)
                latest_trust = float(node['latest_trust'])
                
                # Build cache data for details panel
                new_node_details_cache[node_id] = {
                    'node_type': node_type,
                    'is_malicious': is_malicious,
                    'attacks_made': attacks_made,
                    'auth_attempts': auth_attempts,
                    'trust_score': latest_trust,
                    'attacks_received': attacks_received
                }
                
                # Status berdasarkan trust score dan tipe
                is_detected_malicious = latest_trust < 0.5
                tag = ""
                status = ""
                if is_malicious and is_detected_malicious:
                    tag = "true_positive"
                    status = "Malicious (Terdeteksi)"
                elif is_malicious and not is_detected_malicious:
                    tag = "false_negative"
                    status = "Malicious (Belum Terdeteksi)"
                elif not is_malicious and is_detected_malicious:
                    tag = "false_positive"
                    status = "Normal (Salah Deteksi)"
                else:
                    tag = "true_negative"
                    status = "Normal"
                
                # Data for Treeview row
                processed_node_data.append((
                        f"Node {node_id}",
                        node_type,
                        f"{latest_trust:.3f}",
                        status,
                    f"{attacks_made} / {attacks_received}",
                    f"{auth_attempts}",
                    tag # Include tag for coloring later
                ))
            
            # Put data into the queue for the main thread
            self.ui_update_queue.put(('data', processed_node_data, False, new_node_details_cache))

        except Exception as e:
            self.logger.error(f"Error in NodeAnalysisTab background refresh thread: {str(e)}")
            error_message = f"Error loading node data: {str(e)}"
            # Put error message into the queue
            error_data_tuple = (error_message,) + ("",)*(len(self.node_tree["columns"])-1)
            self.ui_update_queue.put(('data', [error_data_tuple], True, new_node_details_cache))
        finally:
             # Signal completion to the main thread via the queue
             self.ui_update_queue.put(('complete', None, None, None))

    def _process_queue(self):
        """Processes items from the UI update queue in the main thread."""
        try:
            while True:
                try:
                    message_type, data, is_message, cache_data = self.ui_update_queue.get_nowait()
                except queue.Empty:
                    break

                if message_type == 'data':
                    # Update cache first
                    if cache_data is not None:
                       self.node_details_cache = cache_data 
                    # Update UI
                    self._update_ui_with_data(data, is_message)
                elif message_type == 'complete':
                    self.refresh_in_progress = False # Reset flag
                    self.logger.debug("NodeAnalysisTab refresh process marked as complete.")

        except Exception as e:
            self.logger.error(f"Error processing NodeAnalysisTab UI update queue: {e}")
            self.refresh_in_progress = False # Ensure flag is reset even on error

        # Reschedule itself to run again
        self.after(100, self._process_queue) # Check queue every 100ms
        
    def _update_ui_with_data(self, node_data_list, is_message):
        """Updates the Node Treeview in the main UI thread."""
        # ---> VERSI ASLI (Dengan semua kolom dan tag) <--- 
        self.logger.debug(f"_update_ui_with_data called. is_message={is_message}. Data count: {len(node_data_list)}")
        try:
            # Clear loading/previous items
            for item in self.node_tree.get_children():
                self.node_tree.delete(item)
            
            # Populate with new data
            for node_values in node_data_list:
                 if is_message:
                     tags = ('message',)
                     # Ensure the tuple length matches columns for messages
                     display_values = node_values[:len(self.node_tree["columns"])] 
                 else:
                     # Last element is the tag, first n-1 are values
                     tags = (node_values[-1],) if len(node_values) > len(self.node_tree["columns"]) else ()
                     display_values = node_values[:len(self.node_tree["columns"])]
                     
                 # Gunakan tk.END karena itu konstanta standar tkinter
                 self.node_tree.insert("", tk.END, values=display_values, tags=tags)
                 
            # Configure tags for messages and status
            self.node_tree.tag_configure('message', foreground='gray')
            self.node_tree.tag_configure("true_positive", foreground="red")
            self.node_tree.tag_configure("false_negative", foreground="orange")
            self.node_tree.tag_configure("false_positive", foreground="purple")
            self.node_tree.tag_configure("true_negative", foreground="green")
            
            self.logger.debug("NodeAnalysisTab UI updated with new data.")
        except Exception as e:
             self.logger.error(f"Error updating NodeAnalysisTab UI: {str(e)}")
             # Attempt to show error in the tree itself
             try:
                 for item in self.node_tree.get_children(): self.node_tree.delete(item)
                 # Ensure the error message tuple matches the column count
                 error_display = (f"UI Update Error: {str(e)}",) + ("",)*(len(self.node_tree["columns"])-1)
                 self.node_tree.insert("", tk.END, values=error_display, tags=('message',))
                 self.node_tree.tag_configure('message', foreground='red')
             except Exception:
                 self.logger.debug("Failed to render fallback error row in NodeAnalysisTab", exc_info=True)

    def _on_node_select(self, event):
        """Callback when a node is selected in the Treeview."""
        selection = self.node_tree.selection()
        if not selection:
            return
            
        # Get node data
        node_id = self.node_tree.item(selection[0])['values'][0]
        self._show_node_details(node_id)
        
    def _show_node_details(self, node_id):
        """Displays detailed information for the selected node."""
        selected_item = self.node_tree.focus()
        if not selected_item:
            return

        item_data = self.node_tree.item(selected_item)
        node_id_text = item_data['values'][0]
        try:
            node_id = int(node_id_text.split(" ")[1])
        except (IndexError, ValueError):
            self.logger.error(f"Could not parse node ID from: {node_id_text}")
            return

        self.logger.info(f"Displaying details for Node {node_id}")

        # Fetch cached data
        cached_data = self.node_details_cache.get(node_id)
        if cached_data:
            self.node_id_label.configure(text=f"Node ID: {node_id}")
            self.type_label.configure(text=f"Type: {cached_data['node_type']}")
            status_text = "Malicious" if cached_data['is_malicious'] else "Normal"
            self.status_label.configure(text=f"Status: {status_text}")
            self.trust_label.configure(text=f"Avg Trust: {cached_data['trust_score']:.3f}")
            self.attacks_label.configure(text=f"Attacks (Out/In): {cached_data['attacks_made']} / {cached_data['attacks_received']}")
            self.auths_label.configure(text=f"Auth Attempts: {cached_data['auth_attempts']}")
        else:
            self.logger.warning(f"No cached data found for Node {node_id}. Overview might be incomplete.")
            # Clear labels if no cache
            self.node_id_label.configure(text="Node ID: N/A")
            self.type_label.configure(text="Type: N/A")
            self.status_label.configure(text="Status: N/A")
            self.trust_label.configure(text="Avg Trust: N/A")
            self.attacks_label.configure(text="Attacks (Out/In): N/A")
            self.auths_label.configure(text="Auth Attempts: N/A")

        # Fetch detailed activity data from DB (Alarms, Auth, Challenges)
        # --- PERBAIKI QUERY UNTUK ALARMS & CHALLENGES ---
        query = '''
        SELECT 
            'Attack' as activity_type, 
            timestamp, 
            CASE
                WHEN attacker_id = ? THEN 'Sent to ' || target_id || ', Type: ' || attack_type || ', Success: ' || success
                ELSE 'Received from ' || attacker_id || ', Type: ' || attack_type || ', Success: ' || success
            END as description, 
            CASE 
                WHEN attacker_id = ? THEN 'Target: ' || target_id
                ELSE 'Attacker: ' || attacker_id
            END as details
        FROM attack_events
        WHERE attacker_id = ? OR target_id = ? -- Fixed: include node as target
        UNION ALL
        SELECT 
            'Authentication' as activity_type, 
            timestamp, 
            CASE
                WHEN node_id = ? THEN 'Attempted with ' || target_node_id || ', Success: ' || success
                ELSE 'Received from ' || node_id || ', Success: ' || success
            END as description,
            CASE 
                WHEN node_id = ? THEN 'Target: ' || target_node_id
                ELSE 'Initiator: ' || node_id
            END as details
        FROM auth_results
        WHERE node_id = ? OR target_node_id = ? -- Fixed: include node as target
        UNION ALL
        -- Bagian untuk Alarms (dari tabel events)
        SELECT 
            'Alarms' as activity_type,
            timestamp, -- Timestamp dari tabel events
            CASE 
                WHEN event_type = 'alarm_generated' THEN 'Alarm Generated'
                WHEN event_type = 'alarm_received' THEN 'Alarm Received from ' || COALESCE(related_node_id, 'N/A')
                WHEN event_type = 'alarm_forwarded' THEN 'Alarm Forwarded to ' || COALESCE(related_node_id, 'N/A')
                WHEN event_type = 'alarm_ignored' THEN 'Alarm Ignored from ' || COALESCE(related_node_id, 'N/A')
                ELSE event_type -- Fallback jika ada tipe event alarm lain
            END as description,
            details -- Kolom details berisi JSON alarm
        FROM events
        WHERE node_id = ? AND event_type LIKE 'alarm%'
        UNION ALL
        -- Bagian untuk Challenges (dari tabel events, asumsi)
        SELECT 
            'Challenges' as activity_type,
            timestamp,
            CASE 
                WHEN event_type = 'challenge_sent' THEN 'Challenge Sent to ' || COALESCE(related_node_id, 'N/A')
                WHEN event_type = 'challenge_received' THEN 'Challenge Received from ' || COALESCE(related_node_id, 'N/A')
                WHEN event_type = 'challenge_responded' THEN 'Challenge Responded to ' || COALESCE(related_node_id, 'N/A')
                ELSE event_type
            END as description,
            details -- Kolom details mungkin berisi info challenge
        FROM events
        WHERE (node_id = ? OR related_node_id = ?) AND event_type LIKE 'challenge%'
        -- Urutkan berdasarkan timestamp
        ORDER BY timestamp DESC
        '''
        # Fixed: Jumlah parameter = 11
        params = (node_id,) * 11
        # --- AKHIR PERBAIKAN QUERY ---

        activities = []
        try:
            cursor = self.db.execute_query(query, params)
            if cursor:
                raw_activities = cursor.fetchall()
                self.logger.info(f"Retrieved {len(raw_activities)} activity entries for Node {node_id}")
                if raw_activities:
                   self.logger.debug(f"DEBUG: Raw activities from DB for Node {node_id}: {raw_activities}") # Log seluruh hasil mentah
                else:
                    self.logger.debug(f"DEBUG: No raw activities returned from DB for Node {node_id}")
                    
                for row in raw_activities:
                    # Coba parse JSON di kolom details jika ada
                    details_data = row['details']
                    if isinstance(details_data, str):
                        try:
                            parsed_details = json.loads(details_data)
                            # Format ulang agar lebih mudah dibaca
                            details_str = json.dumps(parsed_details, indent=2)
                        except json.JSONDecodeError:
                            details_str = details_data # Gunakan string asli jika bukan JSON valid
                    else:
                        details_str = str(details_data)
                        
                    activities.append({
                        'activity_type': row['activity_type'],
                        'timestamp': f"{row['timestamp']:.3f}", # Format timestamp
                        'description': row['description'],
                        'details': details_str
                    })
            else:
                self.logger.warning(f"Activity query for Node {node_id} returned no cursor.")
        except Exception as e:
            self.logger.error(f"Error fetching activity details for Node {node_id}: {e}", exc_info=True)

        self._update_activity_tabs(activities)

    def _update_activity_tabs(self, activities):
        """Update tab konten dengan data aktivitas"""
        try:
            # Clear existing content for activity tabs, but leave Overview tab alone
            for tab in ["Alarms", "Authentication", "Challenges"]:
                for widget in self.details_tab_view.tab(tab).winfo_children():
                    widget.destroy()
                    
            # Create treeviews for each tab
            for tab in ["Alarms", "Authentication", "Challenges"]:
                tree = ttk.Treeview(
                    self.details_tab_view.tab(tab),
                    columns=("timestamp", "description", "details"),
                    show="headings",
                    height=10
                )
                
                tree.heading("timestamp", text="Time")
                tree.heading("description", text="Description")
                tree.heading("details", text="Details")
                
                tree.column("timestamp", width=150)
                tree.column("description", width=250)
                tree.column("details", width=100)
                
                # Add scrollbar
                scrollbar = ttk.Scrollbar(self.details_tab_view.tab(tab), orient="vertical", command=tree.yview)
                scrollbar.pack(side="right", fill="y")
                tree.configure(yscrollcommand=scrollbar.set)
                tree.pack(fill="both", expand=True, padx=5, pady=5)
                
                # Filter and populate activities
                self.logger.debug(f"Filtering activities for tab: {tab}") # Log nama tab
                tab_lower = tab.lower()
                filtered = []
                for a in activities:
                    activity_type_lower = a.get('activity_type', '').lower()
                    # Log activity type dari data
                    # self.logger.debug(f"  Checking activity: type='{activity_type_lower}' against tab='{tab_lower}'") 
                    if activity_type_lower == tab_lower:
                        filtered.append(a)
                
                self.logger.debug(f"Found {len(filtered)} activities for tab {tab}") # Log jumlah hasil filter
                
                if not filtered:
                     # Tampilkan pesan jika tidak ada data untuk tab ini
                     tree.insert("", tk.END, values=("-", "No activities found for this category.", "-"), tags=("nodata",))
                     tree.tag_configure('nodata', foreground='gray')

                for activity in filtered:
                    tree.insert("", 0, values=(
                        activity['timestamp'],
                        activity['description'],
                        activity['details']
                    ))
                    
        except Exception as e:
            self.logger.error(f"Error updating activity tabs: {str(e)}")
