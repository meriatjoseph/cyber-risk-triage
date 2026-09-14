"""
Structured ingestion layer.

All five CSVs are loaded into an in-memory SQLite database. This is
deliberate: assets, vulnerabilities, threat intel, and business services are
relational, exact-match, filterable/joinable records (asset_id -> vuln,
business_service -> business_services, cve -> threat_intelligence). SQL joins
give exact, auditable answers for that kind of data. Nothing in this file is
embedded or fuzzily retrieved — that's reserved for the free-text NIST 800-53
prose (see app/rag.py). See README Q1 for the full rationale.
"""
import sqlite3
from pathlib import Path

import pandas as pd

from app import config


def load_dataframes() -> dict[str, pd.DataFrame]:
    return {
        "assets": pd.read_csv(config.ASSETS_CSV),
        "vulnerabilities": pd.read_csv(config.VULNERABILITIES_CSV),
        "threat_intelligence": pd.read_csv(config.THREAT_INTEL_CSV),
        "business_services": pd.read_csv(config.BUSINESS_SERVICES_CSV),
        "remediation_guidance": pd.read_csv(config.REMEDIATION_GUIDANCE_CSV),
    }


def build_sqlite_db(dfs: dict[str, pd.DataFrame] | None = None, db_path: str = ":memory:") -> sqlite3.Connection:
    if dfs is None:
        dfs = load_dataframes()
    conn = sqlite3.connect(db_path)
    for name, df in dfs.items():
        df.to_sql(name, conn, if_exists="replace", index=False)
    return conn


def read_threat_report() -> str:
    return Path(config.THREAT_REPORT_MD).read_text(encoding="utf-8")


if __name__ == "__main__":
    dfs = load_dataframes()
    for name, df in dfs.items():
        print(f"{name}: {len(df)} rows, columns={list(df.columns)}")
    conn = build_sqlite_db(dfs)
    cur = conn.execute(
        "SELECT a.asset_name, v.vulnerability_name, v.cvss "
        "FROM vulnerabilities v JOIN assets a ON v.asset_id = a.asset_id "
        "ORDER BY v.cvss DESC LIMIT 5"
    )
    print("\nTop 5 by raw CVSS (sanity check only, NOT the real ranking):")
    for row in cur.fetchall():
        print(" ", row)
