"""
Fetch the real NIST SP 800-53 Rev 5 control catalog (OSCAL JSON) and produce a
cleaned JSONL corpus of retrievable chunks (one per control, plus one per
control enhancement) for the RAG layer.

Source: https://github.com/usnistgov/oscal-content (official NIST GitHub repo)

Cleaning rules (per assignment spec):
- keep only id, title, flattened statement prose (incl. nested a/b/c... items),
  and discussion/guidance prose
- drop assessment objectives/procedures and links (retrieval noise)
- skip controls flagged status: withdrawn
- substitute {{ insert: param, <id> }} placeholders with the param's own
  human label, e.g. "[organization-defined frequency]"
- extract enhancements (e.g. SI-2(2)) as their own chunks
"""
import json
import re
import sys
from pathlib import Path

import requests

NIST_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RAW_PATH = DATA_DIR / "nist_800_53_catalog_raw.json"
OUT_PATH = DATA_DIR / "nist_800_53_chunks.jsonl"

PARAM_RE = re.compile(r"\{\{\s*insert:\s*param,\s*([\w.\-]+)\s*\}\}")


def fetch_catalog() -> dict:
    resp = requests.get(NIST_URL, timeout=60)
    resp.raise_for_status()
    return resp.json()


def is_withdrawn(props: list) -> bool:
    for p in props or []:
        if p.get("name") == "status" and p.get("value") == "withdrawn":
            return True
    return False


def display_id(oscal_id: str) -> str:
    """'at-2' -> 'AT-2', 'at-2.1' -> 'AT-2(1)'"""
    if "." in oscal_id:
        base, enh = oscal_id.split(".", 1)
        return f"{base.upper()}({enh})"
    return oscal_id.upper()


def build_param_labels(params: list) -> dict:
    labels = {}
    for p in params or []:
        pid = p.get("id")
        label = p.get("label")
        if pid and label:
            labels[pid] = label
    return labels


def substitute_params(text: str, param_labels: dict) -> str:
    def _sub(m):
        pid = m.group(1)
        label = param_labels.get(pid, "organization-defined parameter")
        return f"[{label}]"

    return PARAM_RE.sub(_sub, text)


def flatten_item_parts(parts: list, param_labels: dict, depth: int = 0) -> list:
    """Flatten nested statement 'item' parts into a list of indented lines."""
    lines = []
    for part in parts or []:
        if part.get("name") != "item":
            continue
        label = ""
        for prop in part.get("props", []):
            if prop.get("name") == "label":
                label = prop.get("value", "")
                break
        prose = substitute_params(part.get("prose", "") or "", param_labels)
        indent = "  " * depth
        if prose:
            lines.append(f"{indent}{label} {prose}".strip())
        lines.extend(flatten_item_parts(part.get("parts"), param_labels, depth + 1))
    return lines


def extract_prose_by_name(parts: list, name: str) -> list:
    return [p for p in (parts or []) if p.get("name") == name]


def build_chunk(control: dict, family_title: str) -> dict | None:
    props = control.get("props", [])
    if is_withdrawn(props):
        return None

    oscal_id = control["id"]
    title = control.get("title", "")
    param_labels = build_param_labels(control.get("params"))

    parts = control.get("parts", [])
    statement_lines = []
    for stmt_part in extract_prose_by_name(parts, "statement"):
        top_prose = substitute_params(stmt_part.get("prose", "") or "", param_labels)
        if top_prose:
            statement_lines.append(top_prose)
        statement_lines.extend(flatten_item_parts(stmt_part.get("parts"), param_labels))
    statement = "\n".join(statement_lines).strip()

    discussion_lines = []
    for disc_part in extract_prose_by_name(parts, "guidance") + extract_prose_by_name(parts, "discussion"):
        prose = substitute_params(disc_part.get("prose", "") or "", param_labels)
        if prose:
            discussion_lines.append(prose)
    discussion = "\n".join(discussion_lines).strip()

    if not statement and not discussion:
        return None

    text = f"{display_id(oscal_id)} {title}\n\nStatement:\n{statement}"
    if discussion:
        text += f"\n\nDiscussion:\n{discussion}"

    return {
        "control_id": display_id(oscal_id),
        "title": title,
        "family": family_title,
        "statement": statement,
        "discussion": discussion,
        "text": text,
    }


def walk_controls(controls: list, family_title: str) -> list:
    chunks = []
    for control in controls or []:
        chunk = build_chunk(control, family_title)
        if chunk is not None:
            chunks.append(chunk)
        # enhancements are nested under 'controls' on the base control
        chunks.extend(walk_controls(control.get("controls"), family_title))
    return chunks


def main() -> None:
    if RAW_PATH.exists():
        print(f"Using cached raw catalog at {RAW_PATH}")
        catalog = json.loads(RAW_PATH.read_text(encoding="utf-8"))
    else:
        print(f"Fetching NIST SP 800-53 Rev 5 catalog from {NIST_URL} ...")
        catalog = fetch_catalog()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        RAW_PATH.write_text(json.dumps(catalog), encoding="utf-8")
        print(f"Cached raw catalog to {RAW_PATH}")

    groups = catalog["catalog"]["groups"]
    all_chunks = []
    for group in groups:
        family_title = group.get("title", group.get("id", ""))
        all_chunks.extend(walk_controls(group.get("controls"), family_title))

    print(f"Built {len(all_chunks)} clean control/enhancement chunks "
          f"from {len(groups)} control families")

    with OUT_PATH.open("w", encoding="utf-8") as f:
        for chunk in all_chunks:
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")
    print(f"Wrote RAG corpus to {OUT_PATH}")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        print(f"ERROR fetching NIST catalog: {e}", file=sys.stderr)
        sys.exit(1)
