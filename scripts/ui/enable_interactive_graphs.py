#!/usr/bin/env python3
"""
Script to enable interactive JavaScript graphs in CIDSeeks
This installs PyWebView with platform-specific dependencies
"""

import sys
import subprocess
import platform
from typing import List


def run_command(cmd: List[str]) -> bool:
    """Run a command safely without shell invocation."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Success: {' '.join(cmd)}")
            return True
        else:
            # Check for externally-managed-environment error
            if "externally-managed-environment" in result.stderr:
                print(f"⚠️ System Python is protected. Retrying with --user flag...")
                user_cmd: List[str] = []
                injected = False
                for token in cmd:
                    user_cmd.append(token)
                    if token == "install" and not injected:
                        user_cmd.append("--user")
                        injected = True
                result = subprocess.run(user_cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ Success with --user flag")
                    return True
            
            print(f"❌ Failed: {' '.join(cmd)}")
            if result.stderr and "externally-managed-environment" not in result.stderr:
                # Only show error if it's not the externally-managed one we already handled
                print(f"   Error: {result.stderr[:200]}...")  # Truncate long errors
            return False
    except Exception as e:
        print(f"❌ Error running command: {e}")
        return False


def main():
    print("=" * 60)
    print("CIDSeeks Interactive Graph Enabler")
    print("=" * 60)
    
    system = platform.system()
    python_cmd = sys.executable
    
    print(f"\n📊 System Info:")
    print(f"   OS: {system}")
    print(f"   Python: {python_cmd}")
    print(f"   Version: {sys.version}")
    
    print("\n🚀 Installing PyWebView and dependencies...")
    
    # Install PyWebView
    print("\n1️⃣ Installing PyWebView...")
    if not run_command([python_cmd, "-m", "pip", "install", "-U", "pywebview"]):
        print("   ⚠️ PyWebView installation failed, but continuing...")
    
    # Platform-specific dependencies
    if system == "Darwin":  # macOS
        print("\n2️⃣ Installing PyObjC for macOS...")
        if not run_command([python_cmd, "-m", "pip", "install", "-U", "pyobjc"]):
            print("   ⚠️ PyObjC installation failed")
            print("   Try: brew install python-tk")
        
        print("\n3️⃣ Installing PyObjC WebKit framework...")
        if not run_command([python_cmd, "-m", "pip", "install", "-U", "pyobjc-framework-WebKit"]):
            print("   ⚠️ WebKit framework installation failed (optional)")
    
    elif system == "Windows":
        print("\n2️⃣ Windows detected - PyWebView should work out of the box")
        print("   If issues occur, install Edge WebView2 Runtime from Microsoft")
    
    elif system == "Linux":
        print("\n2️⃣ Linux detected - You may need system packages:")
        print("   Ubuntu/Debian: sudo apt-get install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.0")
        print("   Fedora: sudo dnf install python3-gobject gtk3 webkit2gtk3")
        print("   Arch: sudo pacman -S python-gobject gtk3 webkit2gtk")
    
    # Test PyWebView import
    print("\n🧪 Testing PyWebView import...")
    try:
        import webview
        print("✅ PyWebView imported successfully!")
        print(f"   Version: {webview.__version__ if hasattr(webview, '__version__') else 'Unknown'}")
        
        # Test viewer capabilities
        print("\n📋 Checking viewer capabilities...")
        try:
            from src.ui.webview_adapter import get_viewer_capabilities
            capabilities = get_viewer_capabilities()
            
            if capabilities["javascript_support"]:
                print("✅ Full JavaScript support enabled!")
                print("   Recommended viewer:", capabilities["recommended_viewer"])
            else:
                print("⚠️ JavaScript support not available")
                print("   Current viewer:", capabilities["recommended_viewer"])
        except ImportError:
            print("   (Run from project root to check capabilities)")
        
    except ImportError as e:
        print(f"❌ PyWebView import failed: {e}")
        print("   Interactive graphs will fall back to HTML-only mode")
    
    print("\n" + "=" * 60)
    print("Setup complete! Next steps:")
    print("1. Restart the CIDSeeks application")
    print("2. Go to Graph Analysis tab")
    print("3. Click 'Refresh Graph' - interactive window should auto-open")
    print("=" * 60)


if __name__ == "__main__":
    main()
