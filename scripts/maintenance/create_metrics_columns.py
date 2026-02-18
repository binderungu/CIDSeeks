#!/usr/bin/env python3
"""
Migration script untuk menambahkan kolom-kolom enhanced metrics
ke tabel experiment_summary dan experiment_metrics.

Script ini akan menambahkan kolom-kolom yang dibutuhkan untuk 
mendukung comprehensive metrics collection dari EnhancedMetrics.
"""

import sys
import os
import sqlite3
import logging

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.join(current_dir, '..', '..')
sys.path.append(project_root)

def migrate_experiment_summary_table(db_path: str):
    """Add new columns to experiment_summary table."""
    
    # New columns to add
    new_columns = [
        # Trust metrics
        ('time_to_demote', 'REAL DEFAULT NULL'),
        ('trust_degradation', 'REAL DEFAULT NULL'),
        ('undetected_malicious', 'REAL DEFAULT NULL'),
        ('misalignment', 'REAL DEFAULT NULL'),
        
        # Attack resilience metrics
        ('pmfa_resilience', 'REAL DEFAULT NULL'),
        ('collusion_detection_rate', 'REAL DEFAULT NULL'),
        ('collusion_error', 'REAL DEFAULT NULL'),
        ('sybil_detection_rate', 'REAL DEFAULT NULL'),
        ('betrayal_response_time', 'REAL DEFAULT NULL'),
        
        # Performance metrics
        ('computation_time', 'REAL DEFAULT NULL'),
        ('memory_usage', 'REAL DEFAULT NULL'),
        ('throughput', 'REAL DEFAULT NULL'),
        
        # Summary metrics
        ('total_detections', 'INTEGER DEFAULT NULL'),
        ('total_trust_records', 'INTEGER DEFAULT NULL'),
        ('evaluation_duration', 'REAL DEFAULT NULL'),
    ]
    
    try:
        with sqlite3.connect(db_path, timeout=30.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            cursor = conn.cursor()
            
            # Get existing columns
            cursor.execute("PRAGMA table_info(experiment_summary)")
            existing_columns = [col[1] for col in cursor.fetchall()]
            
            # Add new columns if they don't exist
            for col_name, col_definition in new_columns:
                if col_name not in existing_columns:
                    print(f"Adding column: {col_name}")
                    cursor.execute(f"ALTER TABLE experiment_summary ADD COLUMN {col_name} {col_definition}")
                else:
                    print(f"Column {col_name} already exists, skipping...")
            
            conn.commit()
            print("✅ experiment_summary table migration completed successfully")
            
    except sqlite3.Error as e:
        print(f"❌ Error migrating experiment_summary table: {e}")
        return False
    
    return True

def verify_migration(db_path: str):
    """Verify that all new columns were added successfully."""
    
    expected_columns = [
        'time_to_demote', 'trust_degradation', 'undetected_malicious', 'misalignment',
        'pmfa_resilience', 'collusion_detection_rate', 'collusion_error', 
        'sybil_detection_rate', 'betrayal_response_time', 'computation_time',
        'memory_usage', 'throughput', 'total_detections', 'total_trust_records',
        'evaluation_duration'
    ]
    
    try:
        with sqlite3.connect(db_path, timeout=30.0) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(experiment_summary)")
            existing_columns = [col[1] for col in cursor.fetchall()]
            
            missing_columns = [col for col in expected_columns if col not in existing_columns]
            
            if missing_columns:
                print(f"❌ Missing columns: {missing_columns}")
                return False
            else:
                print("✅ All required columns are present")
                return True
                
    except sqlite3.Error as e:
        print(f"❌ Error verifying migration: {e}")
        return False

def main():
    """Main migration execution."""
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Database path
    db_path = os.path.join(project_root, 'src', 'data', 'simulation.db')
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found at: {db_path}")
        print("Please run the simulation first to create the database.")
        return 1
    
    print(f"🔧 Starting database migration for: {db_path}")
    
    # Run migration
    if migrate_experiment_summary_table(db_path):
        print("🔍 Verifying migration...")
        if verify_migration(db_path):
            print("✅ Database migration completed successfully!")
            return 0
        else:
            print("❌ Migration verification failed!")
            return 1
    else:
        print("❌ Migration failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())