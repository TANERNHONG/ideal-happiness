"""Build the console's offline copies of MITRE ATT&CK (Enterprise, and ATT&CK for ICS) from the STIX bundles.

  python -m service.attack_build path/to/enterprise-attack.json
  python -m service.attack_build path/to/ics-attack.json

The bundles come from https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json,
ics-attack/ics-attack.json). The console never fetches them itself: each is downloaded once, reduced here to the
techniques and tactics (ID, name, tactics, platforms, a short description, the page on attack.mitre.org) and kept
beside the code as attack_enterprise.json or attack_ics.json, so matching works offline. The ICS copy also keeps,
per technique, the data components MITRE's detection strategies read (coverage.py: what DAD's logs can see).

ATT&CK is © The MITRE Corporation, used under its terms of use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/),
which ask that the copyright notice be kept with the data; it is stored in the file.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

OUT = Path(__file__).with_name("attack_enterprise.json")
OUT_ICS = Path(__file__).with_name("attack_ics.json")
NOTICE = ("© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. "
          "MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.")


def _external(obj: dict) -> tuple[str, str]:
    ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})
    return ref.get("external_id", ""), ref.get("url", "")


def _plain(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)                  # markdown links: keep their words
    text = re.sub(r"<code>(.*?)</code>", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def _short(text: str, sentences: int = 3, limit: int = 700) -> str:
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z])", text)
    out = " ".join(parts[:sentences])
    return out if len(out) <= limit else out[:limit].rsplit(" ", 1)[0] + "…"


def _components(objects: list[dict]) -> dict[str, list[str]]:
    """Technique STIX ID -> the data components its detection strategies' analytics read (ATT&CK v18 and later)."""
    by_id = {o["id"]: o for o in objects}
    found: dict[str, set] = {}
    for rel in objects:
        if rel["type"] != "relationship" or rel.get("relationship_type") != "detects" or rel.get("revoked"):
            continue
        strategy = by_id.get(rel["source_ref"], {})
        for analytic in (by_id.get(ref, {}) for ref in strategy.get("x_mitre_analytic_refs", [])):
            for source in analytic.get("x_mitre_log_source_references", []):
                component = by_id.get(source.get("x_mitre_data_component_ref", ""), {})
                if component.get("name"):
                    found.setdefault(rel["target_ref"], set()).add(component["name"])
    return {k: sorted(v) for k, v in found.items()}


def build(bundle_path: Path) -> dict:
    objects = json.loads(bundle_path.read_text(encoding="utf-8"))["objects"]
    live = [o for o in objects if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    collection = next((o for o in objects if o["type"] == "x-mitre-collection"), {})
    ics = "ICS" in collection.get("name", "")
    components = _components(objects) if ics else {}
    matrix = next((o for o in live if o["type"] == "x-mitre-matrix"), {})
    tactics_by_ref = {o["id"]: o for o in live if o["type"] == "x-mitre-tactic"}
    order = [tactics_by_ref[r] for r in matrix.get("tactic_refs", []) if r in tactics_by_ref] or list(tactics_by_ref.values())
    tactics = [{"id": _external(t)[0], "short": t["x_mitre_shortname"], "name": t["name"], "url": _external(t)[1]} for t in order]
    techniques = []
    for o in live:
        if o["type"] != "attack-pattern":
            continue
        tid, url = _external(o)
        if not tid:
            continue
        techniques.append({
            "id": tid, "name": o["name"], "url": url,
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") in ("mitre-attack", "mitre-ics-attack")],
            "platforms": o.get("x_mitre_platforms", []),
            "description": _short(_plain(o.get("description", ""))),
            **({"components": components.get(o["id"], [])} if ics else {}),
        })
    names = {t["id"]: t["name"] for t in techniques}
    for t in techniques:                                                  # "Brute Force: Password Guessing"
        if "." in t["id"]:
            parent = names.get(t["id"].split(".")[0])
            if parent:
                t["name"] = f"{parent}: {t['name']}"
    techniques.sort(key=lambda t: [int(x) if x.isdigit() else x for x in re.split(r"[T.]", t["id"]) if x])
    return {"source": "MITRE ATT&CK for ICS" if ics else "MITRE ATT&CK Enterprise", "version": collection.get("x_mitre_version", ""),
            "modified": collection.get("modified", "")[:10], "notice": NOTICE, "tactics": tactics, "techniques": techniques}


if __name__ == "__main__":
    data = build(Path(sys.argv[1]))
    out = OUT_ICS if data["source"].endswith("ICS") else OUT
    out.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"{len(data['techniques'])} techniques, {len(data['tactics'])} tactics, version {data['version']} -> {out}")
