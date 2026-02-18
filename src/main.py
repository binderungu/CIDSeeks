import sys
import os
import customtkinter as ctk
import logging
import tkinter as tk

# Tambahkan root directory ke PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import UI module
from ui.main_window import MainWindow

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)

def main():
    """Main entry point untuk aplikasi"""
    try:
        # Meningkatkan performa tkinter dengan mengurangi sinkronisasi berlebih
        if sys.platform == "darwin":
            os.environ['CTK_DISABLE_MACOS_METAL'] = '1'
            os.environ['TK_DISABLE_MACOS_DRAW_PHASE'] = '1'
        
        # Setup tema aplikasi
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Fix scaling for macOS Retina display
        if sys.platform == "darwin":
            ctk.set_widget_scaling(1.0)  # Kembali ke default
            ctk.set_window_scaling(1.0)  # Kembali ke default
            
            # Nonaktifkan animasi di macOS untuk meningkatkan performa
            ctk.deactivate_automatic_dpi_awareness()
        
        # Inisialisasi window utama
        app = MainWindow()
        app.geometry("1000x700")  # Kembalikan ke ukuran awal
        app.minsize(1000, 700)    # Set ukuran minimum
        app.resizable(True, True)  # Enable window resizing untuk fleksibilitas
        
        # Menonaktifkan animasi transisi untuk performa lebih baik
        try:
            app._set_appearance_mode("dark")  # Menghindari animasi tema
            app.configure(cursor="")  # Pastikan tidak ada kursor khusus yang digunakan
        except Exception:
            logger.debug("Optional UI appearance optimization skipped", exc_info=True)
        
        # Jalankan main loop
        app.mainloop()
        
    except Exception as e:
        logger.error(f"Error dalam aplikasi: {str(e)}")
        raise

if __name__ == "__main__":
    main()
