import sqlite3
DB_NAME = "phishing_scans.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_url TEXT NOT NULL, normalized_url TEXT NOT NULL,
            registrable_domain TEXT, prediction_label TEXT NOT NULL,
            detection_source TEXT NOT NULL, phishing_probability REAL NOT NULL,
            scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_features (
            feature_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL UNIQUE,
            url_length INTEGER, hostname_length INTEGER, path_length INTEGER,
            subdomain_depth INTEGER, has_ip_address INTEGER, has_at_symbol INTEGER,
            hyphen_count_domain INTEGER, dot_count INTEGER, special_char_count INTEGER,
            digit_ratio_domain REAL, url_entropy REAL, has_redirect_slash INTEGER,
            is_shortened_url INTEGER, has_suspicious_tld INTEGER, sensitive_keyword_count INTEGER,
            FOREIGN KEY (scan_id) REFERENCES scan_history (scan_id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()

def save_scan(raw_url: str, norm_url: str, domain: str, label: str, source: str, prob: float, features: dict):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO scan_history (raw_url, normalized_url, registrable_domain, prediction_label, detection_source, phishing_probability)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (raw_url, norm_url, domain, label, source, round(prob, 4)))
        scan_id = cursor.lastrowid
        cursor.execute("""
            INSERT INTO scan_features (
                scan_id, url_length, hostname_length, path_length, subdomain_depth,
                has_ip_address, has_at_symbol, hyphen_count_domain, dot_count,
                special_char_count, digit_ratio_domain, url_entropy,
                has_redirect_slash, is_shortened_url, has_suspicious_tld, sensitive_keyword_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, features["url_length"], features["hostname_length"], features["path_length"],
            features["subdomain_depth"], features["has_ip_address"], features["has_at_symbol"],
            features["hyphen_count_domain"], features["dot_count"], features["special_char_count"],
            features["digit_ratio_domain"], features["url_entropy"], features["has_redirect_slash"],
            features["is_shortened_url"], features["has_suspicious_tld"], features["sensitive_keyword_count"]
        ))
        conn.commit()
    finally:
        conn.close()

def fetch_history(limit: int = 20) -> list[dict]:
    conn = get_connection()
    rows = conn.execute("""
        SELECT scan_id, raw_url, registrable_domain, prediction_label, detection_source,
               ROUND(phishing_probability * 100, 1) AS risk_percent, scanned_at
        FROM scan_history ORDER BY scanned_at DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def clear_history():
    conn = get_connection()
    conn.execute("DELETE FROM scan_history;")
    conn.commit()
    conn.close()
