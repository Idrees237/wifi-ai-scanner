import sqlite3
import pandas as pd

DB_NAME = "scans.db"


def get_connection():

    return sqlite3.connect(DB_NAME)


def init_db():

    with get_connection() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS wifi_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid TEXT,
                bssid TEXT,
                channel INTEGER,
                signal REAL,
                security TEXT,
                timestamp TEXT
            )
        """)

        conn.commit()


def save_scan(df):

    if df.empty:
        return

    with get_connection() as conn:

        df.to_sql(
            "wifi_scans",
            conn,
            if_exists="append",
            index=False
        )


def load_scans():

    with get_connection() as conn:

        return pd.read_sql_query(
            """
            SELECT
                ssid AS SSID,
                bssid AS BSSID,
                channel,
                signal,
                security,
                timestamp
            FROM wifi_scans
            ORDER BY timestamp DESC
            """,
            conn
        )