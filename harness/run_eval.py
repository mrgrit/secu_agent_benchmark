#!/usr/bin/env python3
"""Sealed-oracle evaluation orchestrator.

For each IN-SCOPE task: the agent (bastion) attempts it, and a SEPARATE grader checks the agent's
output against the task's SEALED oracle (the third-party flag / gold answer that the agent never
sees and cannot edit). Oracle pass-rate is the credible score.

Two modes:
  (default) DRY-RUN  — resolve every in-scope task's sealed oracle and report coverage. No GPU,
                       no agent calls. Proves the grading side is fully wired.
  --go [--limit N] [--eg-mode full|off]
                     — actually run the agent. GPU-GUARDED: aborts if an EG ablation runner is
                       active on the shared 0.109 GPU (no concurrent chat — single-GPU rule).

Never run --go autonomously while the shared GPU may be in use; coordinate first.
"""
import json, os, re, shlex, subprocess, sys, time
from pathlib import Path

H = Path(__file__).parent
DATA = Path(os.environ.get("BENCH_DATA", "/home/opsclaw/bench_data"))
RESULTS = H / "results_eval.jsonl"
SSH = ("sshpass -p 1 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
       "-o LogLevel=ERROR -o ConnectTimeout=10 ccc@192.168.0.103")
API_KEY = "ccc-api-key-2026"

# ---- sealed oracle resolution (per benchmark) — the answer key, kept away from the agent ----
_intercode = None
def _intercode_gold(tid):
    global _intercode
    if _intercode is None:
        f = DATA / "intercode/data/ctf/ic_ctf.json"
        _intercode = {str(d["task_id"]): d.get("gold", "") for d in json.loads(f.read_text())} if f.exists() else {}
    return _intercode.get(str(tid).split("/")[-1], "")

def sealed_oracle(task):
    """return (kind, grader) where grader(output)->bool, or (None, None) if not resolvable."""
    b, tid = task["benchmark"], task["id"]
    if b == "intercode":
        gold = _intercode_gold(tid)
        if gold:
            return "exact-flag", (lambda out, g=gold: g in out)
    if b == "cybench":
        # flag/subtask answers live in the challenge's metadata.json
        for mf in (DATA / "cybench").rglob("metadata/metadata.json"):
            if mf.parent.parent.name == tid.split("/", 1)[1]:
                d = json.loads(mf.read_text())
                ans = [s.get("answer", "") for s in d.get("subtasks", []) if s.get("answer")]
                if ans:
                    return "subtask-answers", (lambda out, A=ans: any(a in out for a in A))
                break
    if b == "nyu_ctf":
        cj = DATA / "nyu_ctf_db" / (tid.split("/", 1)[1]) / "challenge.json"
        if cj.exists():
            d = json.loads(cj.read_text())
            flag = d.get("flag") or d.get("flag_format")
            if flag:
                return "flag", (lambda out, f=flag: f in out)
    if b == "agentbench_os":
        return "checker-script", None   # evaluation is an env checker — run inside container (deferred)
    if b == "cve_bench":
        return "exploit-checker", None  # cve_bench provides its own success checker (deferred)
    return None, None

# ---- agent solve (bastion) — GPU path, gated ----
def gpu_busy():
    out = subprocess.run(f"{SSH} {shlex.quote('pgrep -af runner.py | grep -v grep | head -1')}",
                         shell=True, capture_output=True, text=True, timeout=30).stdout
    return bool(out.strip())

def solve_with_bastion(prompt, eg_mode="full", target_vm="attacker", max_time=900):
    payload = json.dumps({"message": prompt, "stream": False, "course": "secbench-eval",
                          "session_id": "secbench", "eg_mode": eg_mode,
                          "context": {"target_vm": target_vm}, "auto_approve": True}, ensure_ascii=False)
    inner = (f"docker exec -u ccc 6v6-bastion curl -s -X POST --max-time {max_time} "
             f"-H 'X-API-Key: {API_KEY}' -H 'Content-Type: application/json' "
             f"-d {shlex.quote(payload)} http://localhost:9100/chat")
    raw = subprocess.run(f"{SSH} {shlex.quote(inner)}", shell=True, capture_output=True,
                         text=True, timeout=max_time + 40).stdout
    i = raw.find("{")
    if i < 0:
        return ""
    try:
        evs = json.loads(raw[i:]).get("events", [])
    except json.JSONDecodeError:
        return ""
    tool = "\n".join(str(e.get("output", "")) for e in evs if e.get("event") == "skill_result")
    final = "".join(e.get("token", "") for e in evs if e.get("event") == "stream_token")
    return tool + "\n" + final


def main():
    tasks = [json.loads(l) for l in (H / "inscope.jsonl").read_text().splitlines() if l.strip()]
    go = "--go" in sys.argv
    eg_mode = "off" if "--eg-mode" in sys.argv and sys.argv[sys.argv.index("--eg-mode")+1] == "off" else "full"
    limit = int(sys.argv[sys.argv.index("--limit")+1]) if "--limit" in sys.argv else len(tasks)

    if not go:
        from collections import Counter
        cov = Counter()
        for t in tasks:
            kind, grader = sealed_oracle(t)
            cov["gradeable" if grader else f"deferred:{kind or 'none'}"] += 1
        print("=== DRY-RUN: sealed-oracle coverage over in-scope set ===")
        print(f"  in-scope tasks: {len(tasks)}")
        for k, n in cov.most_common():
            print(f"    {k:28s} {n}")
        print("\n  → 'gradeable' tasks can be scored automatically against the sealed oracle.")
        print("  → run with --go --limit N --eg-mode full|off to actually evaluate (GPU-guarded).")
        return

    if gpu_busy():
        print("[abort] an EG runner is active on the shared GPU — refusing concurrent chat (single-GPU rule).")
        sys.exit(3)
    done = 0
    with RESULTS.open("a") as fh:
        for t in tasks[:limit]:
            kind, grader = sealed_oracle(t)
            if not grader:
                continue
            out = solve_with_bastion(t.get("prompt") or t["id"], eg_mode=eg_mode)
            ok = grader(out)
            rec = {"id": t["id"], "benchmark": t["benchmark"], "eg_mode": eg_mode,
                   "oracle_kind": kind, "passed": ok, "ts": time.strftime("%FT%TZ", time.gmtime())}
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n"); fh.flush()
            done += 1
            print(f"  [{done}] {t['id']:40s} eg={eg_mode} → {'PASS' if ok else 'fail'}")
            time.sleep(5)   # cooling between sequential GPU calls
    print(f"[done] evaluated {done} tasks → {RESULTS}")


if __name__ == "__main__":
    main()
