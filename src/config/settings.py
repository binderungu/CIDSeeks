# src/config/settings.py

# Simulation Parameters
DEFAULT_TOTAL_NODES = 20
DEFAULT_MALICIOUS_NODES = 5
DEFAULT_ITERATIONS = 50
# Canonical attack types and aliases
ATTACK_ALIASES = {
    "pmfa": "PMFA",
    "collusion": "Collusion", 
    "sybil": "Sybil",
    "betrayal": "Betrayal",
}
VALID_ATTACK_TYPES = set(ATTACK_ALIASES.values())

def normalize_attack(v: str | None) -> str | None:
    """Normalize attack type string to canonical form."""
    if not v:
        return None
    v = v.strip()
    return ATTACK_ALIASES.get(v.lower(), v.title())

# Trust Model Weights (Digunakan di Node.py)
TRUST_LEARNING_RATE = 0.3  # Lambda untuk basic feedback/interactions

# Bobot untuk Advanced Challenge / Kalkulasi berbasis reputasi, kontribusi, dll.
# (Jika diimplementasikan di Node.evaluate_trust atau metode terkait)
TRUST_WEIGHT_ALPHA = 0.4  # Bobot untuk trust historis
TRUST_WEIGHT_BETA = 0.3   # Bobot untuk reputasi (Rj)
TRUST_WEIGHT_GAMMA = 0.2  # Bobot untuk kontribusi (Cj)
TRUST_WEIGHT_DELTA = 0.1  # Bobot untuk penalti (Pj)

# Bobot untuk Final Challenge / Kalkulasi berbasis otentikasi & biometrik
# (Jika diimplementasikan di Node.evaluate_trust atau metode terkait)
TRUST_WEIGHT_THETA = 0.4    # Bobot untuk trust historis
TRUST_WEIGHT_EPSILON = 0.3  # Bobot untuk status otentikasi (Aj)
TRUST_WEIGHT_ZETA = 0.3    # Bobot untuk data biometrik (Bj)

# Bobot untuk Komponen Biometrik (Bj)
# (Digunakan di Node.calculate_biometric)
BIOMETRIC_WEIGHT_MU = 0.4     # Bobot untuk anomali (Anj)
BIOMETRIC_WEIGHT_NU = 0.3     # Bobot untuk kesesuaian pola (Pnj)
BIOMETRIC_WEIGHT_XI = 0.3     # Bobot untuk stabilitas temporal (Tsj)

# Bobot Kombinasi Total Trust Score (jika Node.evaluate_trust menggabungkan beberapa skor)
# Sesuaikan nama jika Node.evaluate_trust mengimplementasikan w1, w2, w3 secara langsung
TOTAL_TRUST_WEIGHT_W1 = 0.3  # Bobot untuk skor challenge dasar/interaksi
TOTAL_TRUST_WEIGHT_W2 = 0.3  # Bobot untuk skor challenge lanjut (reputasi, dll.)
TOTAL_TRUST_WEIGHT_W3 = 0.4  # Bobot untuk skor challenge final (auth, biometrik)

# Thresholds
TRUST_THRESHOLD = 0.5  # Ambang batas untuk menganggap node tidak tepercaya

# Database Path (Contoh, bisa disesuaikan)
DATABASE_PATH = "src/data/simulation.db" # Mungkin perlu dibuat absolut atau relatif terhadap root

# Logging Configuration (Opsional, bisa dipisah ke file logging_config.py)
LOG_LEVEL = "INFO" # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = "simulation.log" # Jika ingin menyimpan log ke file

# Pastikan validasi bobot (jika diperlukan oleh logika asli)
# Misalnya, alpha+beta+gamma+delta harus == 1
# theta+epsilon+zeta harus == 1
# mu+nu+xi harus == 1
# w1+w2+w3 harus == 1
# Anda mungkin ingin menambahkan fungsi validasi di sini atau di tempat penggunaan
def validate_weights():
    assert abs(TRUST_WEIGHT_ALPHA + TRUST_WEIGHT_BETA + TRUST_WEIGHT_GAMMA + TRUST_WEIGHT_DELTA - 1.0) < 1e-6, "Advanced challenge weights must sum to 1.0"
    assert abs(TRUST_WEIGHT_THETA + TRUST_WEIGHT_EPSILON + TRUST_WEIGHT_ZETA - 1.0) < 1e-6, "Final challenge weights must sum to 1.0"
    assert abs(BIOMETRIC_WEIGHT_MU + BIOMETRIC_WEIGHT_NU + BIOMETRIC_WEIGHT_XI - 1.0) < 1e-6, "Biometric weights must sum to 1.0"
    assert abs(TOTAL_TRUST_WEIGHT_W1 + TOTAL_TRUST_WEIGHT_W2 + TOTAL_TRUST_WEIGHT_W3 - 1.0) < 1e-6, "Total trust weights must sum to 1.0"

# Uncomment baris berikut jika ingin menjalankan validasi saat modul diimpor
# validate_weights() 