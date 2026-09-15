from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")

DATA_DIR = ROOT_DIR / "data"

ASSETS_CSV = DATA_DIR / "assets.csv"
VULNERABILITIES_CSV = DATA_DIR / "vulnerabilities.csv"
THREAT_INTEL_CSV = DATA_DIR / "threat_intelligence.csv"
BUSINESS_SERVICES_CSV = DATA_DIR / "business_services.csv"
REMEDIATION_GUIDANCE_CSV = DATA_DIR / "remediation_guidance.csv"
THREAT_REPORT_MD = DATA_DIR / "synthetic_threat_report.md"

KEV_CATALOG_JSON = DATA_DIR / "kev_catalog.json"
NIST_CHUNKS_JSONL = DATA_DIR / "nist_800_53_chunks.jsonl"
CHROMA_PERSIST_DIR = ROOT_DIR / ".chroma"

TOP_N_RISKS = 5

# Free-tier LLM (optional). If unset, the system uses a deterministic
# template for the "why it ranks here" narrative (see app/explain.py).
GROQ_API_KEY_ENV = "GROQ_API_KEY"
GROQ_MODEL = "openai/gpt-oss-20b"
