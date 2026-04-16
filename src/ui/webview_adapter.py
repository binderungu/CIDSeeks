"""
WebView Adapter Module for GraphAnalysisTab

This module provides a unified interface for different web viewers:
- PyWebView (preferred): Full JavaScript support with native browser engine
- TkinterWeb: Basic HTML support (no JavaScript)
- TkHtmlView: Alternative basic HTML support (no JavaScript)
- Text: Plain text fallback

Architecture:
- BaseViewer: Protocol defining the interface
- Concrete implementations for each viewer type
- Factory function to create the best available viewer
"""

import logging
import os
import tempfile
import threading
import time
import platform
import multiprocessing as mp
from abc import ABC, abstractmethod
from typing import Optional, Protocol

import customtkinter as ctk

# Import availability detection
PYWEBVIEW_AVAILABLE = False
try:
    import webview
    PYWEBVIEW_AVAILABLE = True
except ImportError:
    webview = None  # type: ignore[assignment]

HTML_WIDGET_AVAILABLE = "none"
try:
    from tkinterweb import HtmlFrame
    HTML_WIDGET_AVAILABLE = "tkinterweb"
except ImportError:
    try:
        from tkhtmlview import HTMLLabel
        HTML_WIDGET_AVAILABLE = "tkhtmlview"
    except ImportError:
        HTML_WIDGET_AVAILABLE = "none"

logger = logging.getLogger(__name__)


def _launch_pywebview_window(path: str) -> None:
    """
    Top-level launcher for PyWebView (required by multiprocessing 'spawn' on macOS).
    Runs the Cocoa GUI loop in the child process.
    """
    import webview
    import platform
    import traceback
    import sys
    
    try:
        webview.create_window(
            "Interactive Network Graph - CIDSeeks",
            path,
            width=1200,
            height=800,
            resizable=True,
            shadow=True,
            on_top=False,
            minimized=False
        )
        if platform.system() == "Darwin":
            webview.start(debug=False, gui="cocoa")
        else:
            webview.start(debug=False)
    except Exception as e:
        print(f"[webview child] failed to open: {e}", file=sys.stderr)
        traceback.print_exc()


class BaseViewer(Protocol):
    """Protocol defining the interface for web viewers"""
    
    def widget(self) -> ctk.CTkFrame:
        """Return the main widget to be packed"""
        ...
    
    def load(self, html_path: Optional[str] = None, html_content: Optional[str] = None) -> None:
        """Load HTML content from file path or string"""
        ...
    
    def supports_javascript(self) -> bool:
        """Return True if this viewer can execute JavaScript"""
        ...
    
    def destroy(self) -> None:
        """Clean up resources"""
        ...
    
    def open(self) -> None:
        """Open interactive window if supported (no-op for basic viewers)"""
        ...


class PyWebViewViewer:
    """PyWebView implementation with full JavaScript support"""
    
    def __init__(self, parent: ctk.CTkFrame):
        self.parent = parent
        self._container = ctk.CTkFrame(parent, fg_color="transparent")
        self._webview_window: object | None = None
        self._webview_started = False
        self._current_content: Optional[str] = None
        self._proc: Optional[mp.Process] = None
        self.logger = logging.getLogger(f"{__name__}.PyWebViewViewer")
        
        # Create control panel for webview management
        self._setup_controls()
        
        self.logger.info("PyWebViewViewer initialized")
    
    def _setup_controls(self):
        """Setup control buttons for webview management"""
        control_frame = ctk.CTkFrame(self._container)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            control_frame, 
            text="🌐 Ready to load interactive content", 
            font=("Arial", 10)
        )
        self.status_label.pack(side="left", padx=5)
        
        # Open in window button
        self.open_button = ctk.CTkButton(
            control_frame,
            text="🚀 Open Interactive Graph",
            command=self._open_in_window,
            font=("Arial", 11, "bold"),
            fg_color="#0066cc",
            hover_color="#0052a3",
            width=180
        )
        self.open_button.pack(side="right", padx=5)
        self.open_button.configure(state="disabled")  # Initially disabled
        
        # Placeholder for content
        self.content_frame = ctk.CTkFrame(self._container)
        self.content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.placeholder_label = ctk.CTkLabel(
            self.content_frame,
            text="🌐 Interactive JavaScript Graph Ready\n\nClick 'Open Interactive Graph' to launch\nthe full-featured network visualization\nwith drag, hover, and click interactions.",
            font=("Arial", 12),
            text_color="#666666"
        )
        self.placeholder_label.pack(expand=True)
    
    def widget(self) -> ctk.CTkFrame:
        """Return the main container widget"""
        return self._container
    
    def supports_javascript(self) -> bool:
        """PyWebView fully supports JavaScript execution"""
        return True
    
    def load(self, html_path: Optional[str] = None, html_content: Optional[str] = None) -> None:
        """Load HTML content for webview display"""
        try:
            if html_path and os.path.exists(html_path):
                self._current_content = html_path
                self.open_button.configure(state="normal")
                self.status_label.configure(
                    text="🌐 Interactive graph ready - click to open",
                    text_color="#0066cc"
                )
                self.logger.info(f"HTML content loaded: {html_path}")
                
            elif html_content:
                # Save content to temporary file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
                    f.write(html_content)
                    self._current_content = f.name
                
                self.open_button.configure(state="normal")
                self.status_label.configure(
                    text="🌐 Interactive graph ready - click to open",
                    text_color="#0066cc"
                )
                self.logger.info(f"HTML content saved to temporary file: {self._current_content}")
                
            else:
                # Show text content instead
                if html_content and not self._is_html(html_content):
                    self.placeholder_label.configure(text=html_content)
                    self.open_button.configure(state="disabled")
                    self.status_label.configure(
                        text="📄 Text content displayed",
                        text_color="#888888"
                    )
                else:
                    self.open_button.configure(state="disabled")
                    self.status_label.configure(
                        text="❌ No content to display",
                        text_color="#ff4444"
                    )
                    
        except Exception as e:
            self.logger.error(f"Error loading content: {str(e)}")
            self.status_label.configure(
                text="❌ Error loading content",
                text_color="#ff4444"
            )
    
    def _is_html(self, content: str) -> bool:
        """Check if content is HTML"""
        return any(tag in content.lower() for tag in ['<html', '<head', '<body', '<script', '<div'])
    
    def _open_in_window(self):
        """Open the HTML content in a PyWebView window"""
        if not self._current_content:
            self.logger.warning("No content to display in webview")
            return
        
        try:
            if platform.system() == "Darwin":
                # Run PyWebView in a separate 'spawn' process (macOS-safe)
                if self._proc and self._proc.is_alive():
                    try:
                        self._proc.terminate()
                        self._proc.join(timeout=1.0)
                    except Exception:
                        self.logger.debug("Failed to terminate existing webview process cleanly", exc_info=True)

                ctx = mp.get_context("spawn")
                self._proc = ctx.Process(
                    target=_launch_pywebview_window,
                    args=(self._current_content,),
                    daemon=True
                )
                self._proc.start()
                self.logger.info("Started PyWebView in separate process (macOS spawn mode)")
            else:
                # Non-macOS: existing threaded start is acceptable
                if self._webview_window:
                    try:
                        webview.windows[0].destroy()
                    except Exception:
                        self.logger.debug("Failed to destroy existing webview window", exc_info=True)
                self._webview_window = webview.create_window(
                    "Interactive Network Graph - CIDSeeks",
                    self._current_content,
                    width=1200,
                    height=800,
                    resizable=True,
                    shadow=True,
                    on_top=False,
                    minimized=False
                )
                if not self._webview_started:
                    self._webview_started = True
                    threading.Thread(
                        target=lambda: webview.start(debug=False),
                        daemon=True
                    ).start()

            self.status_label.configure(
                text="🚀 Interactive graph opened in window",
                text_color="#00aa00"
            )
        except Exception as e:
            self.logger.error(f"Failed to open webview window: {str(e)}")
            self.status_label.configure(
                text="❌ Failed to open interactive window",
                text_color="#ff4444"
            )
    
    def open(self) -> None:
        """Public entry to open the interactive window"""
        self._open_in_window()
    
    def destroy(self):
        """Clean up webview resources"""
        try:
            if self._webview_window:
                webview.windows.clear()
                self._webview_window = None
            if self._proc and self._proc.is_alive():
                self._proc.terminate()
                self._proc.join(timeout=1.0)
                self._proc = None
            
            # Clean up temporary files
            if (self._current_content and 
                self._current_content.startswith(tempfile.gettempdir()) and 
                os.path.exists(self._current_content)):
                os.unlink(self._current_content)
                
            self.logger.debug("PyWebViewViewer resources cleaned up")
        except Exception as e:
            self.logger.warning(f"Error during cleanup: {str(e)}")


class TkinterWebViewer:
    """TkinterWeb implementation (no JavaScript support)"""
    
    def __init__(self, parent: ctk.CTkFrame):
        self.parent = parent
        self._container = ctk.CTkFrame(parent)
        self.logger = logging.getLogger(f"{__name__}.TkinterWebViewer")
        
        try:
            from tkinterweb import HtmlFrame
            self._html_widget = HtmlFrame(self._container)
            self._html_widget.pack(fill="both", expand=True)
            self.logger.info("TkinterWebViewer initialized successfully")
        except ImportError as e:
            self.logger.error(f"Failed to initialize TkinterWebViewer: {e}")
            raise
    
    def widget(self) -> ctk.CTkFrame:
        return self._container
    
    def supports_javascript(self) -> bool:
        """TkinterWeb does not support JavaScript execution"""
        return False
    
    def load(self, html_path: Optional[str] = None, html_content: Optional[str] = None) -> None:
        """Load HTML content (JavaScript will be displayed as text)"""
        try:
            if html_path and os.path.exists(html_path):
                self._html_widget.load_file(html_path)
                self.logger.info(f"HTML file loaded: {html_path}")
            elif html_content:
                self._html_widget.load_html(html_content)
                self.logger.info("HTML content loaded from string")
            else:
                self._html_widget.load_html("<p>No content to display</p>")
        except Exception as e:
            self.logger.error(f"Error loading content in TkinterWebViewer: {str(e)}")
    
    def open(self) -> None:
        """Not supported (no JavaScript)"""
        return
    
    def destroy(self):
        """Clean up resources"""
        try:
            self._html_widget.destroy()
            self.logger.debug("TkinterWebViewer cleaned up")
        except Exception as e:
            self.logger.warning(f"Error during TkinterWebViewer cleanup: {str(e)}")


class TkHtmlViewViewer:
    """TkHtmlView implementation (no JavaScript support)"""
    
    def __init__(self, parent: ctk.CTkFrame):
        self.parent = parent
        self._container = ctk.CTkFrame(parent)
        self.logger = logging.getLogger(f"{__name__}.TkHtmlViewViewer")
        
        try:
            from tkhtmlview import HTMLLabel
            self._html_widget = HTMLLabel(self._container, background="white")
            self._html_widget.pack(fill="both", expand=True)
            self.logger.info("TkHtmlViewViewer initialized successfully")
        except ImportError as e:
            self.logger.error(f"Failed to initialize TkHtmlViewViewer: {e}")
            raise
    
    def widget(self) -> ctk.CTkFrame:
        return self._container
    
    def supports_javascript(self) -> bool:
        """TkHtmlView does not support JavaScript execution"""
        return False
    
    def load(self, html_path: Optional[str] = None, html_content: Optional[str] = None) -> None:
        """Load HTML content (JavaScript will be displayed as text)"""
        try:
            if html_content:
                self._html_widget.set_html(html_content)
                self.logger.info("HTML content loaded from string")
            elif html_path and os.path.exists(html_path):
                with open(html_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                self._html_widget.set_html(html_content)
                self.logger.info(f"HTML file loaded: {html_path}")
            else:
                self._html_widget.set_html("<p>No content to display</p>")
        except Exception as e:
            self.logger.error(f"Error loading content in TkHtmlViewViewer: {str(e)}")
    
    def open(self) -> None:
        """Not supported (no JavaScript)"""
        return
    
    def destroy(self):
        """Clean up resources"""
        try:
            self._html_widget.destroy()
            self.logger.debug("TkHtmlViewViewer cleaned up")
        except Exception as e:
            self.logger.warning(f"Error during TkHtmlViewViewer cleanup: {str(e)}")


class TextViewer:
    """Plain text fallback viewer"""
    
    def __init__(self, parent: ctk.CTkFrame):
        self.parent = parent
        self._container = ctk.CTkFrame(parent)
        self.logger = logging.getLogger(f"{__name__}.TextViewer")
        
        self._text_widget = ctk.CTkTextbox(self._container, wrap="word")
        self._text_widget.pack(fill="both", expand=True)
        
        self.logger.info("TextViewer initialized")
    
    def widget(self) -> ctk.CTkFrame:
        return self._container
    
    def supports_javascript(self) -> bool:
        """Text viewer does not support JavaScript execution"""
        return False
    
    def load(self, html_path: Optional[str] = None, html_content: Optional[str] = None) -> None:
        """Display content as plain text"""
        try:
            self._text_widget.delete("1.0", "end")
            
            if html_content and not self._is_html(html_content):
                # Plain text content
                self._text_widget.insert("1.0", html_content)
            elif html_path:
                # Show fallback message with file path
                fallback_msg = f"""🌐 Interactive HTML content cannot be displayed in text mode.

The content has been saved to:
{html_path}

To view the interactive graph:
1. Open the file in your web browser, or
2. Install pywebview for in-app viewing:
   pip install pywebview

Features available in browser:
• Drag nodes to rearrange layout
• Hover to highlight neighbors  
• Click nodes for iteration history
• Zoom and pan with mouse
• Physics simulation controls"""
                self._text_widget.insert("1.0", fallback_msg)
            else:
                self._text_widget.insert("1.0", "No content to display")
                
            self.logger.info("Content loaded in text mode")
            
        except Exception as e:
            self.logger.error(f"Error loading content in TextViewer: {str(e)}")
            self._text_widget.insert("1.0", f"Error loading content: {str(e)}")
    
    def _is_html(self, content: str) -> bool:
        """Check if content appears to be HTML"""
        return any(tag in content.lower() for tag in ['<html', '<head', '<body', '<script', '<div'])
    
    def open(self) -> None:
        """Not supported (text-only)"""
        return
    
    def destroy(self):
        """Clean up resources"""
        try:
            self._text_widget.destroy()
            self.logger.debug("TextViewer cleaned up")
        except Exception as e:
            self.logger.warning(f"Error during TextViewer cleanup: {str(e)}")


def create_viewer(parent: ctk.CTkFrame) -> BaseViewer:
    """
    Factory function to create the best available web viewer
    
    Priority order:
    1. PyWebView (full JavaScript support)
    2. TkinterWeb (basic HTML, no JS)
    3. TkHtmlView (basic HTML, no JS)  
    4. Text (plain text fallback)
    
    Args:
        parent: CustomTkinter frame to contain the viewer
        
    Returns:
        BaseViewer instance
    """
    logger.info("Creating web viewer...")
    
    if PYWEBVIEW_AVAILABLE:
        try:
            pywebview_viewer = PyWebViewViewer(parent)
            logger.info("✅ Created PyWebViewViewer (full JavaScript support)")
            return pywebview_viewer
        except Exception as e:
            logger.warning(f"PyWebView initialization failed: {e}, falling back...")
    
    if HTML_WIDGET_AVAILABLE == "tkinterweb":
        try:
            tkinterweb_viewer = TkinterWebViewer(parent)
            logger.info("✅ Created TkinterWebViewer (basic HTML, no JavaScript)")
            return tkinterweb_viewer
        except Exception as e:
            logger.warning(f"TkinterWeb initialization failed: {e}, falling back...")
    
    if HTML_WIDGET_AVAILABLE == "tkhtmlview":
        try:
            tkhtmlview_viewer = TkHtmlViewViewer(parent)
            logger.info("✅ Created TkHtmlViewViewer (basic HTML, no JavaScript)")
            return tkhtmlview_viewer
        except Exception as e:
            logger.warning(f"TkHtmlView initialization failed: {e}, falling back...")
    
    # Final fallback
    text_viewer = TextViewer(parent)
    logger.info("✅ Created TextViewer (plain text fallback)")
    return text_viewer


def get_viewer_capabilities() -> dict:
    """
    Get information about available viewer capabilities
    
    Returns:
        Dictionary with viewer information
    """
    return {
        "pywebview_available": PYWEBVIEW_AVAILABLE,
        "html_widget_available": HTML_WIDGET_AVAILABLE,
        "javascript_support": PYWEBVIEW_AVAILABLE,  # Only PyWebView supports JS
        "recommended_viewer": "PyWebView" if PYWEBVIEW_AVAILABLE else HTML_WIDGET_AVAILABLE.title() if HTML_WIDGET_AVAILABLE != "none" else "Text",
        "can_execute_js": PYWEBVIEW_AVAILABLE,  # Explicit JS execution flag
        "fallback_mode": not PYWEBVIEW_AVAILABLE  # True if we're using fallback viewers
    }


# Export the main interface
__all__ = [
    "BaseViewer", 
    "PyWebViewViewer", 
    "TkinterWebViewer", 
    "TkHtmlViewViewer", 
    "TextViewer",
    "create_viewer", 
    "get_viewer_capabilities",
    "PYWEBVIEW_AVAILABLE"
]
