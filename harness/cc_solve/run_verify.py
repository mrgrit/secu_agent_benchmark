#!/usr/bin/env python3
"""CC-solve verification runner — OFFLINE solver-backed tasks (rev/crypto/misc/...).

Empirical verification (NOT faking): we run each challenge's OWN shipped reference solver in its
challenge dir and require the produced output to contain the FROZEN oracle flag. The solver is the
third-party reference; running it to completion and recovering the frozen flag proves the task is
solvable with what 6v6 provides (python3 + static tools). Network-target categories (web/pwn) are
handled by the deploy runner, not here.

Records to results.jsonl. Failures are recorded honestly as failed:<reason> (never skipped silently).

    python3 harness/cc_solve/run_verify.py --categories rev,crypto,misc,general,forensics [--limit N]
"""
import json, os, re, subprocess, sys, time, datetime
from pathlib import Path

H = Path(__file__).parent.parent           # harness/
DATA = Path("/home/opsclaw/bench_data")
AD = H / "adapted"
RESULTS = H / "cc_solve" / "results.jsonl"

NET_CATS = {"web", "pwn"}                  # need a live target → deploy runner, skip here
SOLVER_RX = re.compile(r"(solve|solver|exploit|sol)\.py$", re.I)


def done_ids():
    if not RESULTS.exists():
        return set()
    return {json.loads(l)["id"] for l in RESULTS.read_text().splitlines() if l.strip()}


def cyb_index():
    return {p.parent.parent.name: p.parent.parent for p in (DATA / "cybench").rglob("metadata/metadata.json")}


def chal_dir(b, oid, cyb):
    if b == "nyu_ctf":
        return DATA / "nyu_ctf_db" / oid
    if b == "cybench":
        return cyb.get(oid)
    return None


def find_solvers(d):
    if not d or not d.exists():
        return []
    out = []
    for p in d.rglob("*"):
        if p.is_file() and SOLVER_RX.search(p.name):
            out.append(p)
    # also shell solution scripts (cybench)
    for p in d.rglob("solution*.sh"):
        out.append(p)
    return sorted(out, key=lambda x: (0 if "solve" in x.name.lower() else 1, len(str(x))))


def ensure_deps():
    for mod, pkg in [("Crypto", "pycryptodome"), ("requests", "requests"),
                     ("pwn", "pwntools"), ("gmpy2", "gmpy2"), ("sympy", "sympy")]:
        try:
            __import__(mod)
        except Exception:
            subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--user", pkg],
                           capture_output=True, timeout=180)


def run_solver(solver, flag, timeout=120):
    """run a shipped solver in its dir; return (ok, evidence)."""
    d = solver.parent
    is_sh = solver.suffix == ".sh"
    cmd = (["bash", str(solver)] if is_sh else [sys.executable, str(solver)])
    try:
        r = subprocess.run(cmd, cwd=str(d), capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "PYTHONUNBUFFERED": "1"})
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, f"exec-error:{repr(e)[:60]}"
    blob = (r.stdout or "") + "\n" + (r.stderr or "")
    if flag and flag in blob:
        return True, f"flag in solver output ({solver.name})"
    # some solvers print only the inner part — compare core
    core = flag[5:-1] if flag.startswith("flag{") and flag.endswith("}") else flag
    if core and len(core) > 4 and core in blob:
        return True, f"flag-core in solver output ({solver.name})"
    tail = blob.strip().replace("\n", " ")[-160:]
    return False, f"no-flag-in-output ({solver.name}); tail={tail!r}"


def main():
    cats = set((sys.argv[sys.argv.index("--categories")+1] if "--categories" in sys.argv
                else "rev,crypto,misc,general,forensics").split(","))
    limit = int(sys.argv[sys.argv.index("--limit")+1]) if "--limit" in sys.argv else 10**9
    ensure_deps()
    cyb = cyb_index()
    done = done_ids()
    rows = [l.split("\t") for l in (AD / "_ledger.tsv").read_text().splitlines()[1:]]
    # offline runner: nyu_ctf flag-oracle with a shipped solver only. cybench(subtask) / non-flag /
    # no-solver / web/pwn are left PENDING (routed to the deploy runner or manual CC) — not recorded.
    rows = [r for r in rows if r[5] == "adapted" and r[2] in cats and r[2] not in NET_CATS and r[1] == "nyu_ctf"]

    n = 0
    import yaml
    with RESULTS.open("a") as fh:
        for tid, b, cat, *_ in rows:
            if tid in done or n >= limit:
                continue
            oid = tid.split("/", 1)[1]
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", oid)
            yp = AD / b / f"{safe}.yaml"
            if not yp.exists():
                continue
            doc = yaml.safe_load(yp.read_text())
            flag = doc["frozen_oracle"]["value"] if doc["frozen_oracle"]["kind"] in ("flag", "gold") else None
            d = chal_dir(b, oid, cyb)
            solvers = find_solvers(d)
            if not flag or not solvers:
                continue   # leave pending for deploy runner / manual; do not record
            ok, ev = False, ""
            for s in solvers[:3]:
                ok, ev = run_solver(s, flag)
                if ok:
                    break
            status = "solved-verified" if ok else f"failed:{ev}"
            rec = {"id": tid, "benchmark": b, "category": cat, "deployed": "offline (local solver run)",
                   "solve_method": f"shipped solver: {ev}" if ok else "offline solver run",
                   "flag_obtained": flag if ok else "", "oracle": flag, "matches_oracle": ok,
                   "status": status, "ts": datetime.datetime.utcnow().isoformat()+"Z"}
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n"); fh.flush()
            n += 1
            tag = "OK " if ok else "-- "
            print(f"{tag}{tid.split('/')[-1][:34]:34s} {status[:70]}")
    # summary
    from collections import Counter
    allr = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()]
    c = Counter(r["status"].split(":")[0] for r in allr)
    print(f"\n[run_verify] processed {n} this run. results.jsonl total={len(allr)}  {dict(c)}")


if __name__ == "__main__":
    main()
