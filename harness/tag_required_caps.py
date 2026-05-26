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
# keyword signals must be SPECIFIC tool/artifact names, not generic words — generic terms
# ("RAM", "process list") caused web tasks to be mislabelled memory-forensics in v0.1.
KEYWORD_CAPS = [
    (re.compile(r"memory dump|\bvolatility\b|\blime\.ko\b|winpmem|\bavml\b|\.vmem\b|linux\.pslist|linux\.pstree", re.I), "cap:memory-forensics"),
    (re.compile(r"\bpcap\b|\.pcapng?\b|wireshark|\btshark\b|captured packets", re.I), "cap:pcap-analysis"),
    (re.compile(r"disk image|\bcarve\b|\.dd\b|filesystem image|\bforemost\b|\bbinwalk\b|firmware image", re.I), "cap:disk-forensics"),
    (re.compile(r"active directory|\bkerberos\b|\bntlm\b|domain controller|\bimpacket\b|crackmapexec|enum4linux", re.I), "cap:smb-ad"),
    (re.compile(r"\baws\b|\bgcp\b|\bazure\b|s3 bucket|cloudtrail|kubernetes|kubectl|\bk8s\b|\bterraform\b", re.I), "cap:cloud"),
    (re.compile(r"\bandroid\b|\.apk\b|\bfrida\b|ios app|apktool", re.I), "cap:mobile"),
    (re.compile(r"\bwifi\b|\bwpa2?\b|aircrack|802\.11|wireless network", re.I), "cap:wireless"),
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


# file-artifact signals — more reliable than prompt keywords for forensics subtype.
# inspecting the challenge's actual files: a .pcap needs pcap-analysis; a .vmem needs memory-forensics.
ART_SIGNALS = [
    ((".pcap", ".pcapng"), "cap:pcap-analysis"),
    ((".vmem", ".lime", ".dmp", ".mem"), "cap:memory-forensics"),
    ((".dd", ".img", ".e01"), "cap:disk-forensics"),
    ((".apk",), "cap:mobile"),
]


def artifact_caps(d):
    """resolve forensics subtype from files actually present in the challenge dir."""
    try:
        exts = {f.suffix.lower() for f in Path(d).rglob("*") if f.is_file()}
    except Exception:
        return None
    for sigs, cap in ART_SIGNALS:
        if exts & set(sigs):
            return cap
    return None


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
        if conf == "low":
            art = artifact_caps(mf.parent.parent)
            if art:
                cap_all, conf, why = {art}, "high", [f"artifact-signal→{art}"]
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
        if conf == "low":
            art = artifact_caps(cf.parent)
            if art:
                caps, conf, why = [art], "high", f"artifact-signal→{art} (challenge files)"
        rel = str(cf.relative_to(DATA / "nyu_ctf_db").parent)
        if rel in seen:
            continue
        seen.add(rel)
        yield {"id": f"nyu_ctf/{rel}", "benchmark": "nyu_ctf", "category": cat,
               "required_caps": caps, "confidence": conf, "why": why,
               "oracle": "flag", "grading": "oracle-flag"}


def load_intercode():
    f = DATA / "intercode" / "data" / "ctf" / "ic_ctf.json"
    if not f.exists():
        return
    tagmap = {"reverse engineering": "rev", "cryptography": "crypto", "binary exploitation": "pwn",
              "general skills": "general-skills", "web": "web", "web exploitation": "web",
              "forensics": "forensics", "misc": "misc"}
    for d in json.loads(f.read_text()):
        tags = d.get("tags") or ["misc"]
        cat = tagmap.get(str(tags[0]).lower(), str(tags[0]).lower())
        caps, conf, why = derive_caps(cat, d.get("query", ""))
        yield {"id": f"intercode/{d.get('task_id')}", "benchmark": "intercode", "category": cat,
               "required_caps": caps, "confidence": conf, "why": why,
               "oracle": "flag", "grading": "oracle-flag"}


def load_agentbench_os():
    f = DATA / "agentbench" / "data" / "os_interaction" / "data" / "dev.json"
    if not f.exists():
        return
    for i, d in enumerate(json.loads(f.read_text())):
        caps, conf, why = derive_caps("os", d.get("description", ""))
        yield {"id": f"agentbench_os/{i}", "benchmark": "agentbench_os", "category": "os",
               "required_caps": caps, "confidence": conf, "why": why or "category=os (general shell)",
               "oracle": "expected-output", "grading": "oracle-output"}


def load_cve_bench():
    root = DATA / "cve_bench" / "src"
    if not root.exists():
        return
    seen = set()
    for j in root.rglob("CVE-*.json"):
        cve = j.stem
        if cve in seen:
            continue
        seen.add(cve)
        sev = j.parent.parent.name if j.parent.name == "nvd" else j.parent.name
        # real-world web-application CVEs; needs web-exploit tooling (present on 6v6).
        # the vulnerable target container is self-provided by the cve_bench harness, not 6v6.
        caps, conf, why = derive_caps("web", cve)
        yield {"id": f"cve_bench/{cve}", "benchmark": "cve_bench", "category": f"web-exploit/{sev}",
               "required_caps": caps, "confidence": conf, "why": f"cve_bench severity={sev}; web-app CVE",
               "oracle": "exploit-checker", "grading": "oracle-exploit"}


LOADERS = [load_cybench, load_nyu, load_intercode, load_agentbench_os, load_cve_bench]  # extend: inspect_cyber, cybergym


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
