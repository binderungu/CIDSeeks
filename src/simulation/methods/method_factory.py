# src/simulation/methods/method_factory.py

from typing import Any, Dict, Optional, cast
import logging
from .base_method import BaseMethod

class MethodFactory:
    """
    Factory class untuk membuat instance metode trust dan privacy.
    
    Menerapkan aturan: Factory pattern untuk memungkinkan pemilihan metode
    secara dinamis berdasarkan konfigurasi.
    """
    
    _registered_methods: Dict[str, type[BaseMethod]] = {}
    
    @classmethod
    def register_method(cls, method_name: str, method_class: type[BaseMethod]) -> None:
        """
        Mendaftarkan metode baru ke factory.
        
        Args:
            method_name: Nama unik metode
            method_class: Class yang mengimplementasikan BaseMethod
        """
        if not issubclass(method_class, BaseMethod):
            raise ValueError(f"Method class {method_class} must inherit from BaseMethod")
        
        cls._registered_methods[method_name] = method_class
        logging.getLogger("MethodFactory").info(f"Registered method: {method_name}")
    
    @classmethod
    def create_method(cls, method_name: str, config: Dict[str, Any]) -> Optional[BaseMethod]:
        """
        Membuat instance metode berdasarkan nama.
        
        Args:
            method_name: Nama metode yang akan dibuat
            config: Konfigurasi untuk metode
            
        Returns:
            BaseMethod: Instance metode atau None jika tidak ditemukan
        """
        logger = logging.getLogger("MethodFactory")
        
        if method_name not in cls._registered_methods:
            logger.error(f"Method '{method_name}' not registered. Available methods: {list(cls._registered_methods.keys())}")
            return None
        
        try:
            method_class = cast(Any, cls._registered_methods[method_name])
            
            # Handle different method class constructors
            # Some methods may use different constructor signatures
            try:
                # Try BaseMethod signature first (method_name, config)
                method_instance = method_class(method_name, config)
            except TypeError:
                try:
                    # Try single config parameter (legacy support)
                    method_instance = method_class(config)
                except TypeError:
                    # Try no parameters (for some methods with default config)
                    method_instance = method_class()
                    # Set attributes manually
                    method_instance.method_name = method_name
                    method_instance.config = config
            
            # Validasi konfigurasi jika method mendukung
            if hasattr(method_instance, 'validate_config') and callable(method_instance.validate_config):
                if not method_instance.validate_config():
                    logger.error(f"Invalid configuration for method '{method_name}'")
                    return None
            
            logger.info(f"Created method instance: {method_name}")
            return method_instance
            
        except Exception as e:
            logger.error(f"Failed to create method '{method_name}': {str(e)}")
            import traceback
            logger.debug(traceback.format_exc())
            return None
    
    @classmethod
    def get_available_methods(cls) -> list[str]:
        """
        Mendapatkan daftar metode yang tersedia.
        
        Returns:
            list: Daftar nama metode yang terdaftar
        """
        return list(cls._registered_methods.keys())
    
    @classmethod
    def is_method_available(cls, method_name: str) -> bool:
        """
        Mengecek apakah metode tersedia.
        
        Args:
            method_name: Nama metode
            
        Returns:
            bool: True jika metode tersedia
        """
        return method_name in cls._registered_methods

# Auto-register methods saat module di-import
def _auto_register_methods():
    """Auto-register semua metode yang tersedia."""
    logger = logging.getLogger("MethodFactory")
    
    try:
        # Register metode usulan (CIDSeeks with 3-Level Challenge)
        from .proposed_method.three_level_challenge import ThreeLevelChallengeMethod
        MethodFactory.register_method("three_level_challenge", ThreeLevelChallengeMethod)
        # Register alias untuk backward compatibility
        MethodFactory.register_method("CIDSeeks", ThreeLevelChallengeMethod)
        MethodFactory.register_method("3-level-challenge", ThreeLevelChallengeMethod)
        MethodFactory.register_method("ours", ThreeLevelChallengeMethod)
        # Register Honey-Challenge variant
        from .proposed_method.honey_challenge import HoneyChallengeMethod
        MethodFactory.register_method("honey", HoneyChallengeMethod)
        logger.info("Successfully registered CIDSeeks proposed method")
        
    except ImportError as e:
        logger.error(f"Could not import proposed method: {e}")

# Auto-register saat module di-import
_auto_register_methods() 
