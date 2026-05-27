#!/usr/bin/env python3
"""Per-item solvability triage for the 57 pwn tasks flagged tooling-limited  →  update adapted YAMLs

6v6 lacks gdb/radare2/pwntools (only objdump/readelf/strings static + python3 + nc). But a pwn
exploit is ultimately bytes over a socket: gdb/pwntools are DEV conveniences, not runtime needs.
This script gathers REAL evidence per challenge — source shipped? solver shipped? binary protections
(readelf, the static tools 6v6 actually has)? kernel/VM class? — and classifies each as:

  cc-solvable-static   : source and/or solver shipped → static RE + raw-socket path; debugger absent
                         only RAISES difficulty. KEEP (status adapted).
  static-feasible-hard : binary-only, ordinary userland → static RE + python3 socket still feasible.
  tooling-limited-dyn  : kernel / hypervisor / VM-escape → genuinely needs dynamic tooling 6v6 lacks.
                         KEEP but flagged needs-review (may exceed 6v6 capability; honest caveat).

Only cc_reference / status / adaptation.tooling are touched; frozen_oracle is never modified.
    python3 harness/classify_pwn.py
"""
import json, re, subprocess
from pathlib import Path
import yaml

H = Path(__file__).parent
DATA = Path("/home/opsclaw/bench_data")
ADAPTED = H / "adapted"
LEDGER = ADAPTED / "_ledger.tsv"


def needs_review_ids():
    out = []
    for line in LEDGER.read_text().splitlines()[1:]:
        c = line.split("\t")
        if len(c) >= 6 and c[5] == "needs-review":
            out.append((c[0], c[1]))
    return out


_cyb = None
def cybench_dir(name):
    global _cyb
    if _cyb is None:
        _cyb = {p.parent.parent.name: p.parent.parent
                for p in (DATA / "cybench").rglob("metadata/metadata.json")}
    return _cyb.get(name)


def chal_dir(bench, oid):
    if bench == "nyu_ctf":
        return DATA / "nyu_ctf_db" / oid
    if bench == "cybench":
        return cybench_dir(oid)
    return None  # intercode: remote picoCTF, no shipped dir


def main_elf(d):
    """the challenge binary: an ELF that is not a shared libc."""
    if not d or not d.exists():
        return None
    best = None
    for f in d.rglob("*"):
        if not f.is_file():
            continue
        if re.search(r"libc|ld-linux|\.so(\.|$)", f.name):
            continue
        try:
            ft = subprocess.run(["file", "-b", str(f)], capture_output=True, text=True, timeout=10).stdout
        except Exception:
            continue
        if "ELF" in ft and ("executable" in ft or "pie executable" in ft.lower()):
            return f
        if "ELF" in ft and best is None:
            best = f
    return best


def protections(elf):
    if not elf:
        return {}
    def rd(*flags):
        try:
            return subprocess.run(["readelf", *flags, str(elf)], capture_output=True, text=True, timeout=15).stdout
        except Exception:
            return ""
    h, l, s = rd("-h"), rd("-l"), rd("-s")
    typ = re.search(r"Type:\s+(\w+)", h)
    arch = re.search(r"Machine:\s+(.+)", h)
    gnu_stack = re.search(r"GNU_STACK.*?\n.*?([RWE ]{3})", l)
    return {
        "arch": (arch.group(1).strip() if arch else "?"),
        "pie": (typ and typ.group(1) == "DYN"),
        "nx": ("GNU_STACK" in l and "RWE" not in (gnu_stack.group(1) if gnu_stack else "")),
        "relro": ("GNU_RELRO" in l),
        "canary": ("__stack_chk_fail" in s),
    }


KERNEL_RX = re.compile(r"kernel|virtualiz|vm[-_ ]?escape|hypervisor", re.I)


def classify(bench, oid, d, elf):
    name = oid.lower()
    files = [p.name.lower() for p in d.iterdir()] if (d and d.exists()) else []
    has_source = any(f.endswith((".c", ".cpp", ".cc")) for f in files)
    has_solver = any(("solv" in f or "solution" in f or "exploit" in f) for f in files) or \
                 (d and (d / "metadata" / "solution").exists() if d else False)
    prot = protections(elf)
    kernelish = bool(KERNEL_RX.search(name)) or (elf and "kernel" in str(elf).lower())

    if kernelish:
        return ("tooling-limited-dyn", "needs-review",
                "kernel/VM-escape class → 동적 디버깅/특수 sandbox 필요, 6v6 정적도구로는 제약. 캐비엇 유지",
                has_source, has_solver, prot)
    if has_source or has_solver:
        ref = "source" if has_source else ""
        ref += ("+solver" if has_solver and has_source else ("solver" if has_solver else ""))
        return ("cc-solvable-static", "adapted",
                f"{ref} 동봉 → 정적 RE + python3 raw-socket 로 익스 전달 가능. gdb/pwntools 부재는 난이도만 상승",
                has_source, has_solver, prot)
    return ("static-feasible-hard", "adapted",
            "바이너리 단독: objdump/readelf 정적 RE + python3 socket 으로 익스 전달 가능. 디버거 부재로 난이도 상승",
            has_source, has_solver, prot)


def find_yaml(bench, oid):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", oid)
    p = ADAPTED / bench / f"{safe}.yaml"
    return p if p.exists() else None


def main():
    rows = needs_review_ids()
    updated, summary = 0, {}
    for tid, bench in rows:
        oid = tid.split("/", 1)[1]
        d = chal_dir(bench, oid)
        elf = main_elf(d) if d else None
        solvability, status, note, has_src, has_solv, prot = classify(bench, oid, d, elf)
        if bench == "intercode":  # remote picoCTF binary, no shipped dir
            solvability, status = "static-feasible-hard", "adapted"
            note = "picoCTF remote pwn: 바이너리 회수 후 정적 RE + python3 socket. 디버거 부재로 난이도 상승"
            prot = {}
        yp = find_yaml(bench, oid)
        if not yp:
            continue
        doc = yaml.safe_load(yp.read_text())
        doc["cc_reference"]["solvability"] = solvability
        doc["cc_reference"]["notes"] = note
        doc["cc_reference"]["evidence"] = {"source_shipped": has_src, "solver_shipped": has_solv,
                                           "protections": prot}
        doc["adaptation"]["tooling"] = ("tooling-limited(dynamic): " + note) if solvability == "tooling-limited-dyn" \
            else "static-only(harder): gdb/r2/pwntools 부재 — objdump/readelf/strings+python3+nc 경로"
        doc["status"] = status
        yp.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=100))
        updated += 1
        summary[solvability] = summary.get(solvability, 0) + 1
    # refresh ledger status for these ids
    lines = LEDGER.read_text().splitlines()
    idmap = {}
    for tid, bench in rows:
        yp = find_yaml(bench, tid.split("/", 1)[1])
        if yp:
            idmap[tid] = yaml.safe_load(yp.read_text())["status"]
    new = [lines[0]]
    for line in lines[1:]:
        c = line.split("\t")
        if c[0] in idmap:
            c[5] = idmap[c[0]]
        new.append("\t".join(c))
    LEDGER.write_text("\n".join(new) + "\n")
    print(f"[pwn-triage] updated {updated} tasks  → {summary}")


if __name__ == "__main__":
    main()
