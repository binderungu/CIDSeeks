# runner.py

import argparse
import logging
import os
import sys
import tempfile
import yaml

# Tambahkan src ke path agar bisa import modul simulasi
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'src'))

try:
    from simulation.core.simulation_engine import SimulationEngine
    from simulation.modules.database.node_database import NodeDatabase # Optional, jika ingin provide DB eksternal
except ImportError as e:
    print(f"Error importing simulation modules: {e}")
    print("Pastikan Anda menjalankan skrip ini dari direktori root proyek (CIDSeeks/)")
    print("Dan pastikan PYTHONPATH menyertakan direktori 'src' atau gunakan virtual environment.")
    sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run CIDS Simulation")
    parser.add_argument('--config', type=str, default='config.yaml', 
                        help='Path to the YAML configuration file (default: config.yaml)')
    parser.add_argument(
        '--overwrite',
        action='store_true',
        help='Allow replacing an existing run output directory',
    )
    parser.add_argument(
        '--manifest-keep-last',
        type=int,
        default=None,
        help='Retention policy for run manifests (keep latest N entries)',
    )
    # Tambahkan argumen lain jika perlu, misal override parameter config tertentu
    # parser.add_argument('--iterations', type=int, help='Override number of iterations from config')
    
    args = parser.parse_args()

    # Setup basic logging SEBELUM engine diinisialisasi (jika engine gagal init)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("Runner") # Logger khusus untuk runner

    logger.info(f"Starting simulation using configuration: {args.config}")

    if not os.path.exists(args.config):
        logger.error(f"Configuration file not found: {args.config}")
        sys.exit(1)

    effective_config_path = args.config
    temp_config_path = None
    if args.overwrite or args.manifest_keep_last is not None:
        with open(args.config, "r", encoding="utf-8") as handle:
            config_payload = yaml.safe_load(handle) or {}
        if not isinstance(config_payload, dict):
            logger.error("Configuration root must be a mapping")
            sys.exit(1)
        config_payload.setdefault("output", {})
        config_payload.setdefault("provenance", {})
        config_payload["provenance"]["cli_command"] = " ".join(sys.argv)
        config_payload["provenance"]["experiments_config"] = args.config
        if args.overwrite:
            config_payload["output"]["overwrite"] = True
        if args.manifest_keep_last is not None:
            config_payload["output"]["manifest_keep_last"] = int(args.manifest_keep_last)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
            yaml.safe_dump(config_payload, tmp, sort_keys=False)
            temp_config_path = tmp.name
            effective_config_path = temp_config_path
    else:
        try:
            with open(args.config, "r", encoding="utf-8") as handle:
                config_payload = yaml.safe_load(handle) or {}
            if isinstance(config_payload, dict):
                config_payload.setdefault("provenance", {})
                config_payload["provenance"]["cli_command"] = " ".join(sys.argv)
                config_payload["provenance"]["experiments_config"] = args.config
                with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
                    yaml.safe_dump(config_payload, tmp, sort_keys=False)
                    temp_config_path = tmp.name
                    effective_config_path = temp_config_path
        except Exception:
            logger.debug(
                "Failed to inject CLI provenance metadata from %s; continuing with original config.",
                args.config,
                exc_info=True,
            )

    try:
        # Inisialisasi engine dengan path config
        # Jika ingin menggunakan DB eksternal, bisa inisialisasi di sini:
        # db_manager = NodeDatabase(db_path="path/to/external.db")
        # engine = SimulationEngine(config_path=args.config, db_manager=db_manager)
        engine = SimulationEngine(config_path=effective_config_path)
        
        # Ambil jumlah iterasi dari config engine setelah dimuat
        sim_iterations = engine.total_iterations 
        
        # Jalankan simulasi dengan iterasi dari config
        results = engine.run(iterations=sim_iterations) 
        
        sim_info = results.get('simulation_info', {}) if results else {}
        is_completed = None
        if results:
            if 'is_completed' in results:
                is_completed = results.get('is_completed')
            else:
                is_completed = sim_info.get('is_completed')

        if results and is_completed and not results.get('error'):
             logger.info("Simulation completed successfully.")
             # Print final metrics summary
             metrics = results.get('metrics', {})
             print("\n--- Final Metrics ---")
             if metrics:
                 for key, value in metrics.items():
                     # Handle potential None values from calculations if simulation ends early/no data
                     if value is None:
                         print(f"{key}: N/A")
                     elif isinstance(value, (int, float)):
                         print(f"{key}: {value:.4f}")
                     else:
                         print(f"{key}: {value}")
             else:
                  print("No metrics data available.")
             print("---------------------\n")
             logger.info(f"Results database stored in: {engine.db_manager.db_path}")
             logger.info(f"Run output directory: {engine.output_dir}")
             logger.info(f"Config snapshot: {os.path.join(engine.output_dir, 'config_resolved.yaml')}")
             logger.info(f"Metadata: {os.path.join(engine.output_dir, 'metadata.json')}")
             if engine.plot_enabled:
                  plot_path = os.path.join(engine.output_dir, 'trust_evolution.png')
                  logger.info(f"Trust evolution plot saved to: {plot_path}")
        elif results:
             logger.error(f"Simulation finished with error: {results.get('error')}")
        else:
             logger.error("Simulation run did not return results.")
             
    except Exception as e:
        logger.exception(f"An unhandled error occurred during simulation initialization or execution: {e}") 
        sys.exit(1)
    finally:
        if temp_config_path and os.path.exists(temp_config_path):
            try:
                os.unlink(temp_config_path)
            except OSError:
                logger.debug("Unable to remove temporary config: %s", temp_config_path)

    logger.info("Runner script finished.") 
