#!/usr/bin/env python3
"""Tag every external-benchmark task with the capabilities it REQUIRES  →  tasks.jsonl

Mechanical extraction from each benchmark's own task definition (category + declared tools +
prompt keywords). This is the bulk path: no LLM, deterministic, auditable. Tasks whose subtype is
genuinely undecidable (e.g. a "forensics" challenge that names neither pcap nor memory nor disk)
are emitted with confidence="low" and routed to an agent-review queue rather than silently guessed.

    python3 harness/tag_required_caps.py            # walk $BENCH_DATA, write tasks.jsonl
"""
import json, os, re, sys
from pathlib import Path

DATA = Path(os.environ.get("BENCH_DATA", "/home/opsclaw/bench_data"))
OUT = Path(__file__).parent / "tasks.jsonl"

CATEGORY_CAPS = {
    "crypto": ["cap:crypto"], "cryptography": ["cap:crypto"],
    "web": ["cap:web-scan"], "web-exploitation": ["cap:web-scan"],
    "rev": ["cap:reversing"], "reverse": ["cap:reversing"], "reversing": ["cap:reversing"],
    "pwn": ["cap:reversing"], "binary": ["cap:reversing"], "binary-exploitation": ["cap:reversing"],
    "network": ["cap:network-recon"], "pentest": ["cap:network-recon", "cap:web-scan"],
    "forensics": [],            # subtype decided by keywords below
    "misc": [], "general-skills": [], "osint": [], "steganography": ["cap:disk-forensics"],
}
KEYWORD_CAPS = [
    (re.compile(r"memory dump|volatility|\bRAM\b|process list|\blime\b|winpmem|\.vmem|memory image|linux\.pslist", re.I), "cap:memory-forensics"),
    (re.compile(r"\bpcap\b|\.pcapng?\b|wireshark|network capture|tshark|captured packets|traffic capture", re.I), "cap:pcap-analysis"),
    (re.compile(r"disk image|\bcarve\b|\.dd\b|filesystem image|foremost|binwalk|firmware image", re.I), "cap:disk-forensics"),
    (re.compile(r"active directory|kerberos|\bntlm\b|\bldap\b|\bsmb\b|domain controller|impacket", re.I), "cap:smb-ad"),
    (re.compile(r"\baws\b|\bgcp\b|\bazure\b|s3 bucket|cloudtrail|kubernetes|kubectl|\bk8s\b|terraform", re.I), "cap:cloud"),
    (re.compile(r"\bandroid\b|\bapk\b|\bfrida\b|ios app|mobile app", re.I), "cap:mobile"),
    (re.compile(r"\bwifi\b|wireless|\bwpa2?\b|aircrack|802\.11", re.I), "cap:wireless"),
]


def derive_caps(category, text):
    caps = set(CATEGORY_CAPS.get((category or "").lower(), []))
    kw = set()
    for rx, cap in KEYWORD_CAPS:
        if rx.search(text or ""):
            kw.add(cap)
    caps |= kw
    conf = "high"
    why = f"category={category}" + (f"; keywords→{sorted(kw)}" if kw else "")
    # forensics with no subtype keyword = undecidable → low confidence, no hard requirement
    if (category or "").lower() == "forensics" and not kw:
        conf = "low"
        why += "; forensics subtype undetermined (no pcap/memory/disk signal)"
    return sorted(caps), conf, why


def load_cybench():
    for mf in (DATA / "cybench").rglob("metadata/metadata.json"):
        try:
            d = json.loads(mf.read_text())
        except Exception:
            continue
        cats = d.get("categories") or ["misc"]
        text = " ".join([d.get("easy_prompt", ""), d.get("hard_prompt", ""), str(d.get("tools", "")), d.get("target_host", "")])
        cap_all = set()
        conf = "high"; why = []
        for c in cats:
            cc, cf, w = derive_caps(c, text)
            cap_all |= set(cc); why.append(w)
            if cf == "low": conf = "low"
        name = mf.parent.parent.name
        yield {"id": f"cybench/{name}", "benchmark": "cybench", "category": ",".join(cats),
               "required_caps": sorted(cap_all), "confidence": conf, "why": "; ".join(why),
               "oracle": "subtask+flag", "grading": "oracle-flag"}


def load_nyu():
    seen = set()
    for cf in (DATA / "nyu_ctf_db").rglob("challenge.json"):
        if "/removed/" in str(cf):
            continue
        try:
            d = json.loads(cf.read_text())
        except Exception:
            continue
        cat = d.get("category", "misc")
        text = " ".join([d.get("name", ""), d.get("description", "")])
        caps, conf, why = derive_caps(cat, text)
        rel = str(cf.relative_to(DATA / "nyu_ctf_db").parent)
        if rel in seen:
            continue
        seen.add(rel)
        yield {"id": f"nyu_ctf/{rel}", "benchmark": "nyu_ctf", "category": cat,
               "required_caps": caps, "confidence": conf, "why": why,
               "oracle": "flag", "grading": "oracle-flag"}


LOADERS = [load_cybench, load_nyu]   # extend: cve_bench, inspect_cyber, agentbench loaders


def main():
    n = 0
    with OUT.open("w") as fh:
        for loader in LOADERS:
            for t in loader():
                fh.write(json.dumps(t, ensure_ascii=False) + "\n")
                n += 1
    # quick stats
    from collections import Counter
    bench = Counter(); low = 0
    for line in OUT.read_text().splitlines():
        t = json.loads(line); bench[t["benchmark"]] += 1
        if t["confidence"] == "low": low += 1
    print(f"[tag] wrote {OUT}: {n} tasks  ({dict(bench)})  low-confidence(agent-review)={low}")


if __name__ == "__main__":
    main()
