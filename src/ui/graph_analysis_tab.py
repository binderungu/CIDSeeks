import customtkinter as ctk
import logging
import json
import tempfile
import os
import webbrowser
import subprocess
import sys
from pathlib import Path
from typing import Optional
import yaml  # type: ignore[import-untyped]

import networkx as nx
from .webview_adapter import create_viewer, get_viewer_capabilities, PYWEBVIEW_AVAILABLE

# Pyvis import with fallback
try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ModuleNotFoundError:
    Network = None
    PYVIS_AVAILABLE = False
    logging.getLogger(__name__).warning("pyvis not installed - some features may be limited")


class GraphAnalysisTab(ctk.CTkFrame):
    """Next-gen Graph Analysis Tab with interactive vis.js network visualization using viewer adapter"""

    def __init__(self, parent, db):
        super().__init__(parent)
        self.db = db
        self.logger = logging.getLogger(__name__)
        self.html_file = None
        self.viewer = None  # Will hold the viewer adapter instance
        self.browser_button = None  # Reference to conditional browser button
        
        # Get viewer capabilities for logging
        capabilities = get_viewer_capabilities()
        self.logger.info(f"GraphAnalysisTab initialized - Viewer: {capabilities['recommended_viewer']}, JS Support: {capabilities['javascript_support']}")
        
        self._init_ui()
        
    def _init_ui(self):
        """Initialize UI with control panel and viewer"""
        # Create frames
        self.control_frame = ctk.CTkFrame(self)
        self.control_frame.pack(side="left", fill="y", padx=5, pady=5)
        
        self.graph_frame = ctk.CTkFrame(self)
        self.graph_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # Create viewer using the adapter pattern
        try:
            self.viewer = create_viewer(self.graph_frame)
            self.viewer.widget().pack(fill="both", expand=True)
            self.logger.info("Viewer adapter created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create viewer: {str(e)}")
            # Create fallback text widget
            fallback_label = ctk.CTkLabel(
                self.graph_frame, 
                text="❌ Failed to initialize viewer\nPlease check the logs for details", 
                font=("Arial", 12)
            )
            fallback_label.pack(expand=True)
        
        # Add controls
        self._add_controls()
        
        # Add viewer information panel
        self._add_viewer_info()
        
        # Auto-render graph when tab loads
        self.after(150, self.show_network_graph)
        
    def _add_controls(self):
        """Add control buttons and options"""
        # Always show interactive graph; no mode selector needed
        self.plot_type = ctk.StringVar(value="network_graph")
        
        ctk.CTkLabel(self.control_frame, text="Network Visualization", font=("Arial", 14, "bold")).pack(pady=(5, 10))
        
        # Refresh button
        ctk.CTkButton(
            self.control_frame,
            text="🔄 Refresh Graph",
            command=self.show_network_graph,
            font=("Arial", 12, "bold")
        ).pack(pady=10, padx=10, fill="x")
        
        # Conditional browser button (only shown for non-JS viewers)
        self._setup_conditional_browser_button()
        
        # Graph options
        ctk.CTkLabel(self.control_frame, text="Graph Options:", font=("Arial", 12, "bold")).pack(pady=(20, 5))
        
        self.physics_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            self.control_frame,
            text="Enable Physics",
            variable=self.physics_var,
            command=self.show_network_graph
        ).pack(pady=2, anchor="w")
        
        self.labels_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            self.control_frame,
            text="Show Node Labels",
            variable=self.labels_var,
            command=self.show_network_graph
        ).pack(pady=2, anchor="w")
        
        # Info panel
        self.info_frame = ctk.CTkFrame(self.control_frame)
        self.info_frame.pack(fill="x", pady=(20, 5), padx=5)
        
        ctk.CTkLabel(self.info_frame, text="Graph Info:", font=("Arial", 10, "bold")).pack(pady=2)
        self.info_label = ctk.CTkLabel(self.info_frame, text="No data loaded", font=("Arial", 9))
        self.info_label.pack(pady=2)
    
    def _setup_conditional_browser_button(self):
        """Setup browser button that only appears when viewer lacks JavaScript support"""
        if self.viewer:
            # Create browser button for non-JS viewers
            self.browser_button = ctk.CTkButton(
                self.control_frame,
                text="🌐 Open Interactive Viewer",
                command=self._open_interactive_viewer,
                font=("Arial", 12, "bold"),
                fg_color="#ff6600",
                hover_color="#e55a00",
                height=35
            )
            # Don't pack yet - will be shown when content is ready
            
    def _open_interactive_viewer(self):
        """Open interactive viewer according to configured mode."""
        if not self.html_file or not os.path.exists(self.html_file):
            self.logger.warning("No HTML file available to open in viewer")
            return
        cfg = self._read_ui_graph_cfg()
        mode = (cfg.get('viewer_mode') or 'python_viewer').lower()
        if mode == 'python_viewer':
            self._open_in_python_viewer(self.html_file)
        else:
            self._open_in_browser(self.html_file)

    def _open_in_python_viewer(self, html_path: str) -> None:
        """Spawn a lightweight Python process to display interactive HTML (pywebview if available)."""
        try:
            cmd = [sys.executable, '-m', 'src.ui.tools.graph_viewer', '--html', str(Path(html_path).resolve())]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.logger.info(f"Launched python viewer for: {html_path}")
        except Exception as e:
            self.logger.error(f"Failed to launch python viewer, falling back to browser: {e}")
            self._open_in_browser(html_path)

    def _open_in_browser(self, html_path: str) -> None:
        try:
            webbrowser.open_new_tab(Path(html_path).resolve().as_uri())
            self.logger.info(f"Opened in default browser: {html_path}")
        except Exception as e:
            self.logger.error(f"Failed to open browser: {e}")

    def _open_current_graph_in_browser(self):
        """Open the current graph HTML file in the default browser"""
        if self.html_file and os.path.exists(self.html_file):
            try:
                # Prefer system browser for full JS support
                webbrowser.open_new_tab(Path(self.html_file).resolve().as_uri())
                self.logger.info(f"Opened graph in browser: {self.html_file}")
                
                # Update button text to indicate success
                if self.browser_button:
                    original_text = self.browser_button.cget("text")
                    self.browser_button.configure(text="✅ Opened in Browser")
                    # Reset text after 2 seconds
                    self.after(2000, lambda: self.browser_button.configure(text=original_text))
                    
            except Exception as e:
                self.logger.error(f"Failed to open browser: {str(e)}")
                # Update button text to indicate error
                if self.browser_button:
                    original_text = self.browser_button.cget("text")
                    self.browser_button.configure(text="❌ Browser Error")
                    self.after(3000, lambda: self.browser_button.configure(text=original_text))
        else:
            self.logger.warning("No HTML file available to open in browser")
            if self.browser_button:
                original_text = self.browser_button.cget("text")
                self.browser_button.configure(text="❌ No File Ready")
                self.after(2000, lambda: self.browser_button.configure(text=original_text))

    def _read_ui_graph_cfg(self) -> dict:
        """Read UI graph configuration from config.yaml if available."""
        try:
            # project_root/config.yaml (this file is src/ui/graph_analysis_tab.py)
            cfg_path = Path(__file__).resolve().parents[3] / 'config.yaml'
            if not cfg_path.exists():
                return {}
            with cfg_path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            return (data.get('ui', {}) or {}).get('graph', {}) or {}
        except Exception as e:
            self.logger.debug(f"Failed to read UI graph cfg: {e}")
            return {}
    
    def _show_browser_button(self):
        """Show the browser button if it exists"""
        if self.browser_button:
            self.browser_button.pack(pady=(5, 10), padx=10, fill="x")
            
    def _hide_browser_button(self):
        """Hide the browser button if it exists"""
        if self.browser_button:
            self.browser_button.pack_forget()
    
    def _add_viewer_info(self):
        """Add information panel about current viewer"""
        capabilities = get_viewer_capabilities()
        
        info_frame = ctk.CTkFrame(self.control_frame, fg_color="#1a1a1a", border_color="#0066cc", border_width=1)
        info_frame.pack(fill="x", pady=(10, 5), padx=5)
        
        # Viewer type indicator
        if capabilities["javascript_support"]:
            title = "✅ Full JavaScript Support"
            msg = f"{capabilities['recommended_viewer']}\nwith interactive features"
            title_color = "#00aa00"
            msg_color = "#aaffaa"
        else:
            title = "⚠️ Basic HTML Support"
            msg = f"{capabilities['recommended_viewer']}\nno JavaScript execution"
            title_color = "#ff8800"
            msg_color = "#ffcc88"
        
        ctk.CTkLabel(
            info_frame,
            text=title,
            font=("Arial", 10, "bold"),
            text_color=title_color
        ).pack(pady=2)
        
        ctk.CTkLabel(
            info_frame,
            text=msg,
            font=("Arial", 8),
            text_color=msg_color,
            justify="center"
        ).pack(pady=(0, 5))
        

            
    def _build_nx_graph(self) -> nx.Graph:
        """Build NetworkX graph from database data"""
        try:
            # Get nodes and trust scores from database
            nodes = self.db.get_all_nodes()
            trust_scores = self.db.get_trust_scores()
            
            if not nodes:
                self.logger.warning("No nodes found in database")
                return nx.Graph()
            
            # Create graph
            G = nx.Graph()
            
            # Add nodes with attributes
            for node in nodes:
                G.add_node(
                    node['node_id'],
                    malicious=bool(node['is_malicious']),
                    attack_type=node.get('attack_type', 'None')
                )
            
            # Process trust scores to create edges (use last iteration > 0)
            if trust_scores:
                # Get the last iteration
                last_iter = max((s.get('iteration', 0) for s in trust_scores), default=0)
                
                # Use only records from last iteration > 0; fallback to any iteration > 0; finally fallback to all
                scores_to_use = (
                    [s for s in trust_scores if s.get('iteration', 0) == last_iter and last_iter > 0]
                    or [s for s in trust_scores if s.get('iteration', 0) > 0]
                    or trust_scores
                )
                
                edge_data: dict[tuple[int, int], list[float]] = {}
                for s in scores_to_use:
                    source = s['node_id']
                    target = s['target_node_id']
                    if source == target:
                        continue
                    key = tuple(sorted([source, target]))
                    edge_data.setdefault(key, []).append(s['score'])
                
                # Add edges with average trust scores
                for (node1, node2), scores in edge_data.items():
                    avg_trust = sum(scores) / len(scores)
                    G.add_edge(node1, node2, weight=avg_trust, trust_scores=scores)
            
            self.logger.info(f"Built graph with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
            return G
            
        except Exception as e:
            self.logger.error(f"Error building NetworkX graph: {str(e)}")
            return nx.Graph()
    
    def _serialize_iteration_data(self) -> dict:
        """Serialize iteration events for all nodes"""
        try:
            nodes = self.db.get_all_nodes()
            if not nodes:
                return {}
            
            iteration_data = {}
            for node in nodes:
                node_id = node['node_id']
                events = self.db.get_iteration_events(node_id)
                iteration_data[node_id] = events
            
            return iteration_data
            
        except Exception as e:
            self.logger.error(f"Error serializing iteration data: {str(e)}")
            return {}
    
    def _generate_pyvis_network(self, G: nx.Graph) -> tuple[str, str]:
        """Generate pyvis network data and return as JSON strings"""
        try:
            if G.number_of_nodes() == 0:
                return "[]", "[]"
            
            if not PYVIS_AVAILABLE:
                # Fallback: manually create node and edge data
                return self._generate_manual_network_data(G)
            
            # Create pyvis network (without showing)
            net = Network(height="600px", width="100%", bgcolor="#ffffff", font_color="black")
            net.barnes_hut(gravity=-2000, central_gravity=0.1, spring_length=150)
            
            # Add nodes
            for node_id in G.nodes():
                node_data = G.nodes[node_id]
                is_malicious = node_data.get('malicious', False)
                attack_type = node_data.get('attack_type', 'None')
                
                color = "#FF4444" if is_malicious else "#44AA44"
                size = 30 if is_malicious else 20
                
                title = f"Node {node_id}<br/>Status: {'Malicious' if is_malicious else 'Normal'}"
                if is_malicious and attack_type != 'None':
                    title += f"<br/>Attack: {attack_type}"
                
                net.add_node(
                    node_id,
                    label=str(node_id) if self.labels_var.get() else "",
                    color=color,
                    size=size,
                    title=title,
                    borderWidth=2,
                    borderWidthSelected=4
                )
            
            # Add edges
            for edge in G.edges(data=True):
                node1, node2, edge_data = edge
                trust_weight = edge_data.get('weight', 0.5)
                
                # Color based on trust level
                if trust_weight >= 0.7:
                    color = "#00AA00"  # High trust - green
                elif trust_weight >= 0.4:
                    color = "#AAAA00"  # Medium trust - yellow
                else:
                    color = "#AA0000"  # Low trust - red
                
                width = max(1, int(trust_weight * 5))  # Width based on trust
                
                net.add_edge(
                    node1, 
                    node2, 
                    color=color, 
                    width=width,
                    title=f"Trust: {trust_weight:.3f}"
                )
            
            # Extract nodes and edges as JSON (compressed)
            nodes_json = json.dumps(net.nodes, separators=(',', ':'))
            edges_json = json.dumps(net.edges, separators=(',', ':'))
            
            return nodes_json, edges_json
            
        except Exception as e:
            self.logger.error(f"Error generating pyvis network: {str(e)}")
            return "[]", "[]"
    
    def _generate_manual_network_data(self, G: nx.Graph) -> tuple[str, str]:
        """Generate network data manually when pyvis is not available"""
        try:
            nodes_data = []
            edges_data = []
            
            # Generate nodes
            for node_id in G.nodes():
                node_data = G.nodes[node_id]
                is_malicious = node_data.get('malicious', False)
                attack_type = node_data.get('attack_type', 'None')
                
                color = "#FF4444" if is_malicious else "#44AA44"
                size = 30 if is_malicious else 20
                
                title = f"Node {node_id}<br/>Status: {'Malicious' if is_malicious else 'Normal'}"
                if is_malicious and attack_type != 'None':
                    title += f"<br/>Attack: {attack_type}"
                
                nodes_data.append({
                    "id": node_id,
                    "label": str(node_id) if self.labels_var.get() else "",
                    "color": color,
                    "size": size,
                    "title": title,
                    "borderWidth": 2,
                    "borderWidthSelected": 4
                })
            
            # Generate edges
            for edge in G.edges(data=True):
                node1, node2, edge_data = edge
                trust_weight = edge_data.get('weight', 0.5)
                
                # Color based on trust level
                if trust_weight >= 0.7:
                    color = "#00AA00"  # High trust - green
                elif trust_weight >= 0.4:
                    color = "#AAAA00"  # Medium trust - yellow
                else:
                    color = "#AA0000"  # Low trust - red
                
                width = max(1, int(trust_weight * 5))  # Width based on trust
                
                edges_data.append({
                    "from": node1,
                    "to": node2,
                    "color": color,
                    "width": width,
                    "title": f"Trust: {trust_weight:.3f}"
                })
            
            # Convert to JSON (compressed)
            nodes_json = json.dumps(nodes_data, separators=(',', ':'))
            edges_json = json.dumps(edges_data, separators=(',', ':'))
            
            return nodes_json, edges_json
            
        except Exception as e:
            self.logger.error(f"Error generating manual network data: {str(e)}")
            return "[]", "[]"
    
    def _compose_html(self, nodes_json: str, edges_json: str, iteration_json: str) -> str:
        """Compose complete HTML with vis.js and Bootstrap"""
        physics_enabled = "true" if self.physics_var.get() else "false"
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Interactive Network Graph</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Vis.js Network CSS -->
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{
            margin: 0;
            padding: 10px;
            background-color: #ffffff;
            font-family: Arial, sans-serif;
        }}
        #network-container {{
            width: 100%;
            height: 600px;
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
        }}
        .info-panel {{
            margin-bottom: 10px;
            padding: 10px;
            background-color: #e9ecef;
            border-radius: 5px;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="info-panel">
        <strong>Interactive Network Graph</strong> - 
        Hover: highlight neighbors | Click: view details | Drag: move nodes
    </div>
    
    <div id="network-container"></div>
    
    <!-- Node Detail Modal -->
    <div class="modal fade" id="nodeDetailModal" tabindex="-1" aria-labelledby="nodeDetailModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="nodeDetailModalLabel">Node Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body" id="nodeDetailContent">
                    <!-- Content will be populated by JavaScript -->
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Data from Python
        var nodes = new vis.DataSet({nodes_json});
        var edges = new vis.DataSet({edges_json});
        var iterationMap = {iteration_json};
        
        // Network configuration
        var container = document.getElementById('network-container');
        var data = {{
            nodes: nodes,
            edges: edges
        }};
        
        var options = {{
            nodes: {{
                shape: "dot",
                size: 20,
                font: {{
                    size: 14,
                    color: "black"
                }},
                borderWidth: 2,
                shadow: true
            }},
            edges: {{
                smooth: {{
                    type: "continuous"
                }},
                shadow: true
            }},
            physics: {{
                enabled: {physics_enabled},
                barnesHut: {{
                    gravitationalConstant: -2000,
                    centralGravity: 0.1,
                    springLength: 150,
                    springConstant: 0.04,
                    damping: 0.09,
                    avoidOverlap: 0.1
                }},
                maxVelocity: 50,
                minVelocity: 0.1,
                solver: 'barnesHut',
                stabilization: {{
                    enabled: true,
                    iterations: 1000,
                    updateInterval: 25
                }}
            }},
            interaction: {{
                hover: true,
                dragNodes: true,
                dragView: true,
                zoomView: true,
                selectConnectedEdges: false
            }}
        }};
        
        // Create network
        var network = new vis.Network(container, data, options);
        
        // Store original colors for reset
        var originalNodeColors = {{}};
        nodes.get().forEach(function(n) {{
            var base = (typeof n.color === 'string') ? n.color :
                       (n.color && n.color.background ? n.color.background : '#97C2FC');
            originalNodeColors[n.id] = base;
        }});
        
        // Hover effects with proper rgba fading
        network.on("hoverNode", function(params) {{
            var nodeId = params.node;
            var connected = new Set(network.getConnectedNodes(nodeId).concat([nodeId]));
            
            var updates = [];
            nodes.get().forEach(function(n) {{
                if (connected.has(n.id)) {{
                    // Keep connected nodes with original color
                    updates.push({{id: n.id, color: originalNodeColors[n.id]}});
                }} else {{
                    // Fade unconnected nodes
                    updates.push({{id: n.id, color: 'rgba(180,180,180,0.25)'}});
                }}
            }});
            nodes.update(updates);
        }});
        
        network.on("blurNode", function() {{
            // Reset all nodes to original colors
            var reset = nodes.get().map(function(n) {{
                return {{id: n.id, color: originalNodeColors[n.id]}};
            }});
            nodes.update(reset);
        }});
        
        // Click handler for node details
        network.on("click", function(params) {{
            if (params.nodes.length > 0) {{
                var nodeId = params.nodes[0];
                var nodeData = nodes.get(nodeId);
                var iterations = iterationMap[nodeId] || [];
                
                // Build modal content
                var modalTitle = document.getElementById('nodeDetailModalLabel');
                var modalContent = document.getElementById('nodeDetailContent');
                
                modalTitle.textContent = 'Node ' + nodeId + ' Details';
                
                var content = '<div class="row">';
                content += '<div class="col-md-6">';
                content += '<h6>Node Information</h6>';
                content += '<p><strong>ID:</strong> ' + nodeId + '</p>';
                content += '<p><strong>Status:</strong> ' + (nodeData.title.includes('Malicious') ? 'Malicious' : 'Normal') + '</p>';
                
                if (nodeData.title.includes('Attack:')) {{
                    var attack = nodeData.title.split('Attack: ')[1];
                    if (attack) {{
                        content += '<p><strong>Attack Type:</strong> ' + attack.split('<')[0] + '</p>';
                    }}
                }}
                
                content += '</div>';
                content += '<div class="col-md-6">';
                content += '<h6>Iteration History</h6>';
                
                if (iterations.length > 0) {{
                    content += '<div style="max-height: 300px; overflow-y: auto;">';
                    iterations.forEach(function(event) {{
                        content += '<div class="mb-2 p-2 border rounded">';
                        content += '<strong>Iteration ' + event.iteration + ':</strong><br/>';
                        content += '<small>' + event.detail + '</small>';
                        content += '</div>';
                    }});
                    content += '</div>';
                }} else {{
                    content += '<p class="text-muted">No iteration history available</p>';
                }}
                
                content += '</div>';
                content += '</div>';
                
                modalContent.innerHTML = content;
                
                // Show modal
                var modal = new bootstrap.Modal(document.getElementById('nodeDetailModal'));
                modal.show();
            }}
        }});
        
        // Console log for debugging
        console.log('Network initialized with', nodes.length, 'nodes and', edges.length, 'edges');
        console.log('Physics enabled:', {physics_enabled});
        console.log('Iteration data available for', Object.keys(iterationMap).length, 'nodes');
    </script>
</body>
</html>
        """
        
        return html_template
    
    def _write_temp_html(self, html_str: str) -> str:
        """Write HTML to temporary file and return path"""
        try:
            # Clean up previous file
            if self.html_file and os.path.exists(self.html_file):
                os.unlink(self.html_file)
            
            # Create new temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
                f.write(html_str)
                self.html_file = f.name
            
            self.logger.info(f"HTML written to temporary file: {self.html_file}")
            return self.html_file
            
        except Exception as e:
            self.logger.error(f"Error writing temporary HTML file: {str(e)}")
            return ""
    
    def show_network_graph(self):
        """Display the interactive network graph"""
        try:
            self.logger.info("Generating interactive network graph...")
            
            # Build graph data
            G = self._build_nx_graph()
            if G.number_of_nodes() == 0:
                self._show_no_data_message()
                return
            
            # Get iteration data
            iteration_data = self._serialize_iteration_data()
            
            # Generate network data
            nodes_json, edges_json = self._generate_pyvis_network(G)
            
            # Compose HTML
            html_content = self._compose_html(
                nodes_json, 
                edges_json, 
                json.dumps(iteration_data, separators=(',', ':'))  # Compressed JSON
            )
            
            # Write to file 
            html_path = self._write_temp_html(html_content)
            if not html_path:
                self._show_error_message("Failed to write HTML file")
                return
            
            # Always load a lightweight placeholder in the in-app viewer
            if not self.viewer:
                self.logger.error("No viewer available to display content")
                self._show_error_message("Viewer not initialized")
                return

            self.logger.info("Loading lightweight placeholder in viewer (browser is primary renderer)")
            placeholder_content = self._build_placeholder(html_path, G.number_of_nodes(), G.number_of_edges())
            try:
                self.viewer.load(html_content=placeholder_content)
                # Always show browser button for convenience
                self._show_browser_button()
            except Exception as e:
                self.logger.error(f"Error loading placeholder: {str(e)}")
                self._show_error_message(f"Failed to load placeholder: {str(e)}")
                return

            # Optionally open in default browser based on config
            ui_graph_cfg = self._read_ui_graph_cfg()
            # Select viewer mode (default python viewer), fallback controlled by config
            viewer_mode = (ui_graph_cfg.get('viewer_mode') or 'python_viewer').lower()
            auto_open = ui_graph_cfg.get('open_in_browser_on_render', True)
            try:
                if viewer_mode == 'python_viewer':
                    self._open_in_python_viewer(html_path)
                else:
                    if auto_open:
                        self._open_in_browser(html_path)
            except Exception as e:
                self.logger.error(f"Auto-open viewer failed: {e}")
            
            # Update info panel
            self.info_label.configure(
                text=f"Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}"
            )
            
        except Exception as e:
            self.logger.error(f"Error showing network graph: {str(e)}")
            self._show_error_message(str(e))
    
    def _build_placeholder(self, html_path: str, num_nodes: int, num_edges: int) -> str:
        """
        Build lightweight placeholder content for viewers that don't support JavaScript
        
        Args:
            html_path: Path to the full HTML file for browser viewing
            num_nodes: Number of nodes in the graph
            num_edges: Number of edges in the graph
            
        Returns:
            Lightweight HTML or text content
        """
        capabilities = get_viewer_capabilities()
        
        if capabilities["html_widget_available"] != "none":
            # HTML-capable viewer (but no JS) - create lightweight HTML
            placeholder_html = f"""
            <div style='padding: 30px; font-family: Arial, sans-serif; text-align: center; background: #f8f9fa;'>
                <div style='background: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);'>
                    <h2 style='color: #0066cc; margin-bottom: 20px;'>🌐 Interactive Network Graph Ready</h2>
                    
                    <div style='background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                        <h3 style='color: #1976d2; margin: 0 0 15px 0;'>📊 Graph Statistics</h3>
                        <div style='display: flex; justify-content: space-around; flex-wrap: wrap;'>
                            <div style='margin: 10px; padding: 15px; background: white; border-radius: 8px;'>
                                <div style='font-size: 24px; color: #0066cc; font-weight: bold;'>{num_nodes}</div>
                                <div style='color: #666; font-size: 14px;'>Nodes</div>
                            </div>
                            <div style='margin: 10px; padding: 15px; background: white; border-radius: 8px;'>
                                <div style='font-size: 24px; color: #00aa00; font-weight: bold;'>{num_edges}</div>
                                <div style='color: #666; font-size: 14px;'>Connections</div>
                            </div>
                        </div>
                    </div>
                    
                    <div style='background: #fff3e0; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                        <h4 style='color: #f57c00; margin: 0 0 15px 0;'>⚠️ JavaScript Required</h4>
                        <p style='color: #666; margin: 10px 0;'>
                            Your current viewer ({capabilities["recommended_viewer"]}) doesn't support JavaScript execution.<br/>
                            The interactive features require a JavaScript-capable browser.
                        </p>
                        <div style='background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0; text-align: left;'>
                            <strong style='color: #333;'>Interactive Features Available in Browser:</strong>
                            <ul style='color: #666; margin: 10px 0; padding-left: 20px;'>
                                <li>🎯 Drag nodes to rearrange layout</li>
                                <li>✨ Hover to highlight neighbors</li>
                                <li>📋 Click nodes for detailed history</li>
                                <li>🔄 Physics simulation controls</li>
                                <li>🔍 Zoom and pan with mouse</li>
                                <li>📱 Responsive Bootstrap modals</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div style='background: #e8f5e8; padding: 20px; border-radius: 8px; margin: 20px 0;'>
                        <h4 style='color: #2e7d32; margin: 0 0 10px 0;'>🚀 Next Steps</h4>
                        <p style='color: #666; margin: 10px 0;'>
                            Click the "Open in Browser" button below to launch the full interactive visualization.
                        </p>
                        <div style='background: #f1f8e9; padding: 10px; border-radius: 5px; font-size: 12px; color: #2e7d32;'>
                            <strong>💡 Pro Tip:</strong> For in-app interactive graphs, install PyWebView:<br/>
                            <code style='background: white; padding: 2px 6px; border-radius: 3px;'>pip install pywebview</code>
                        </div>
                    </div>
                    
                    <div style='margin-top: 20px; padding: 10px; background: #f5f5f5; border-radius: 5px; font-size: 12px; color: #666;'>
                        <strong>File Location:</strong><br/>
                        <code style='background: white; padding: 2px 6px; border-radius: 3px; word-break: break-all;'>{html_path}</code>
                    </div>
                </div>
            </div>
            """
            return placeholder_html
        else:
            # Text-only viewer - create plain text content
            placeholder_text = f"""🌐 Interactive Network Graph Ready

📊 Graph Statistics:
  • Nodes: {num_nodes}
  • Connections: {num_edges}

⚠️ JavaScript Required:
Your current viewer (Text) doesn't support HTML or JavaScript execution.
The interactive features require a JavaScript-capable browser.

🚀 Interactive Features Available in Browser:
  • 🎯 Drag nodes to rearrange layout
  • ✨ Hover to highlight neighbors  
  • 📋 Click nodes for detailed history
  • 🔄 Physics simulation controls
  • 🔍 Zoom and pan with mouse
  • 📱 Responsive Bootstrap modals

💡 Next Steps:
Click the "Open in Browser" button below to launch the full 
interactive visualization.

💡 Pro Tip: For in-app interactive graphs, install PyWebView:
pip install pywebview

📁 File Location:
{html_path}
"""
            return placeholder_text
    
    def _load_content_via_viewer(
        self,
        html_path: Optional[str] = None,
        content: Optional[str] = None,
    ) -> None:
        """Load content using the viewer adapter"""
        if not self.viewer:
            self.logger.error("No viewer available")
            return
        
        try:
            self.viewer.load(html_path, content)
            self.logger.info("Content loaded successfully via viewer adapter")
        except Exception as e:
            self.logger.error(f"Error loading content via viewer: {str(e)}")
            self._show_error_message(f"Failed to load content: {str(e)}")
    
    def _show_no_data_message(self):
        """Show message when no data is available"""
        capabilities = get_viewer_capabilities()
        
        if capabilities["javascript_support"] or capabilities["html_widget_available"] != "none":
            # HTML-capable viewer
            no_data_html = """
            <div style='text-align:center; padding:50px; font-family: Arial, sans-serif;'>
                <h3 style='color: #666;'>📊 No Graph Data Available</h3>
                <p style='color: #888;'>Please run a simulation first to generate network data.</p>
                <hr style='width: 50%; margin: 20px auto;'>
                <p style='color: #999; font-size: 12px;'>The interactive graph will show:</p>
                <ul style='text-align: left; display: inline-block; color: #999; font-size: 12px;'>
                    <li>Node relationships and trust scores</li>
                    <li>Malicious vs normal node identification</li>
                    <li>Interactive hover and click features</li>
                    <li>Iteration history for each node</li>
                </ul>
            </div>
            """
            self._load_content_via_viewer(content=no_data_html)
        else:
            # Text-only viewer
            no_data_text = """📊 No Graph Data Available

Please run a simulation first to generate network data.

The interactive graph will show:
• Node relationships and trust scores
• Malicious vs normal node identification  
• Interactive hover and click features
• Iteration history for each node"""
            self._load_content_via_viewer(content=no_data_text)
        
        self.info_label.configure(text="No data loaded")
    
    def _show_error_message(self, error_msg: str):
        """Show error message in the viewer"""
        capabilities = get_viewer_capabilities()
        
        if capabilities["javascript_support"] or capabilities["html_widget_available"] != "none":
            # HTML-capable viewer
            error_html = f"""
            <div style='text-align:center; padding:50px; font-family: Arial, sans-serif;'>
                <h3 style='color: #d32f2f;'>⚠️ Graph Generation Error</h3>
                <p style='color: #666;'>An error occurred while generating the interactive graph:</p>
                <div style='background: #ffebee; padding: 15px; border-radius: 5px; margin: 20px; border-left: 4px solid #d32f2f;'>
                    <code style='color: #c62828;'>{error_msg}</code>
                </div>
                <p style='color: #888; font-size: 12px;'>Check the console logs for more details.</p>
            </div>
            """
            self._load_content_via_viewer(content=error_html)
        else:
            # Text-only viewer
            error_text = f"""⚠️ Graph Generation Error

{error_msg}

Check the console logs for more details."""
            self._load_content_via_viewer(content=error_text)
        
        self.info_label.configure(text="Error occurred")
    
    def _show_node_statistics(self):
        """Show simple node statistics as fallback"""
        try:
            nodes = self.db.get_all_nodes()
            if not nodes:
                self._show_no_data_message()
                return
            
            total_nodes = len(nodes)
            malicious_nodes = sum(1 for node in nodes if node['is_malicious'])
            normal_nodes = total_nodes - malicious_nodes
            
            capabilities = get_viewer_capabilities()
            
            if capabilities["javascript_support"] or capabilities["html_widget_available"] != "none":
                # HTML-capable viewer
                stats_html = f"""
                <div style='padding: 30px; font-family: Arial, sans-serif;'>
                    <h3 style='color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px;'>📈 Node Statistics</h3>
                    
                    <div style='margin: 20px 0;'>
                        <div style='background: #e3f2fd; padding: 15px; border-radius: 8px; margin: 10px 0;'>
                            <h4 style='color: #1976d2; margin: 0 0 10px 0;'>🔵 Total Nodes: {total_nodes}</h4>
                        </div>
                        
                        <div style='background: #e8f5e8; padding: 15px; border-radius: 8px; margin: 10px 0;'>
                            <h4 style='color: #388e3c; margin: 0 0 10px 0;'>✅ Normal Nodes: {normal_nodes}</h4>
                        </div>
                        
                        <div style='background: #ffebee; padding: 15px; border-radius: 8px; margin: 10px 0;'>
                            <h4 style='color: #d32f2f; margin: 0 0 10px 0;'>⚠️ Malicious Nodes: {malicious_nodes}</h4>
                        </div>
                    </div>
                    
                    <div style='margin-top: 30px; padding: 15px; background: #f5f5f5; border-radius: 8px;'>
                        <p style='margin: 0; color: #666; text-align: center;'>
                            Switch to "Interactive Graph" to see the full network visualization
                        </p>
                    </div>
                </div>
                """
                self._load_content_via_viewer(content=stats_html)
            else:
                # Text-only viewer
                stats_text = f"""📈 Node Statistics

🔵 Total Nodes: {total_nodes}
✅ Normal Nodes: {normal_nodes}
⚠️ Malicious Nodes: {malicious_nodes}

Switch to 'Interactive Graph' to see the full network visualization."""
                self._load_content_via_viewer(content=stats_text)
            
            self.info_label.configure(text=f"Stats: {total_nodes} nodes ({malicious_nodes} malicious)")
            
        except Exception as e:
            self.logger.error(f"Error showing node statistics: {str(e)}")
            self._show_error_message(str(e))
    
    def refresh_analysis(self, results=None):
        """Refresh the analysis based on simulation results"""
        self.logger.debug(f"Refreshing GraphAnalysisTab. Received results: {bool(results)}")
        
        # Always show network graph
        self.show_network_graph()
    
    def __del__(self):
        """Cleanup resources"""
        try:
            # Clean up viewer resources
            if hasattr(self, 'viewer') and self.viewer:
                self.viewer.destroy()
                
            # Clean up temporary files
            if hasattr(self, 'html_file') and self.html_file and os.path.exists(self.html_file):
                os.unlink(self.html_file)
                self.logger.debug(f"Cleaned up temporary HTML file: {self.html_file}")
                
        except Exception as e:
            # Use print instead of logger since logger may not be available during cleanup
            print(f"Warning: Failed to cleanup GraphAnalysisTab resources: {e}")
