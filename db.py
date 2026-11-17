import sqlite3
import pandas as pd

DB_NAME = "phishing_scans.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_url TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            registrable_domain TEXT,
            prediction_label TEXT NOT NULL CHECK (prediction_label IN ('Legitimate', 'Suspicious')),
            phishing_probability REAL NOT NULL,
            model_version TEXT NOT NULL DEFAULT 'rf_v1.0',
            scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_features (
            feature_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL UNIQUE,
            url_length INTEGER NOT NULL,
            hostname_length INTEGER NOT NULL,
            path_length INTEGER NOT NULL,
            subdomain_depth INTEGER NOT NULL,
            has_ip_address INTEGER NOT NULL,
            has_at_symbol INTEGER NOT NULL,
            hyphen_count_domain INTEGER NOT NULL,
            dot_count INTEGER NOT NULL,
            special_char_count INTEGER NOT NULL,
            digit_ratio_domain REAL NOT NULL,
            url_entropy REAL NOT NULL,
            has_redirect_slash INTEGER NOT NULL,
            is_shortened_url INTEGER NOT NULL,
            has_suspicious_tld INTEGER NOT NULL,
            sensitive_keyword_count INTEGER NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scan_history (scan_id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()

def save_scan(raw_url: str, norm_url: str, domain: str, label: str, prob: float, features: dict):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO scan_history (raw_url, normalized_url, registrable_domain, prediction_label, phishing_probability)
            VALUES (?, ?, ?, ?, ?)
        """, (raw_url, norm_url, domain, label, round(prob, 4)))
        
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

def fetch_history(limit: int = 25) -> pd.DataFrame:
    conn = get_connection()
    query = """
        SELECT scan_id AS ID, raw_url AS URL, registrable_domain AS Domain,
               prediction_label AS Status, ROUND(phishing_probability * 100, 1) AS "Risk (%)",
               scanned_at AS Timestamp
        FROM scan_history
        ORDER BY scanned_at DESC
        LIMIT ?
    """
    df = pd.read_sql_query(query, conn, params=(limit,))
    conn.close()
    return df

def clear_history():
    conn = get_connection()
    conn.execute("DELETE FROM scan_history;")
    conn.commit()
    conn.close()