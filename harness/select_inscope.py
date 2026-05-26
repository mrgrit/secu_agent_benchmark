#!/usr/bin/env python3
"""Select the in-scope subset for THIS infrastructure  →  inscope / dropped / review

The whole anti-pollution argument lives here:
  * a task is KEPT only if every required capability is PRESENT in capability_inventory.json
  * a task is DROPPED only with a *falsifiable* citation — the missing capability AND the live
    probe evidence that it is absent. "not confident" is never a reason; absence is proven.
  * a task whose subtype the tagger could not decide (confidence=low) is NOT silently dropped —
    it is routed to review_queue.jsonl for an agent to resolve, then re-run.

No LLM. Deterministic set intersection over the probed inventory.

    python3 harness/select_inscope.py
"""
import json
from pathlib import Path

H = Path(__file__).parent
inv = json.loads((H / "capability_inventory.json").read_text())
caps = inv["capabilities"]
present = {k for k, v in caps.items() if v.get("present")}


def evidence(cap):
    e = caps.get(cap, {})
    return e.get("evidence", "capability not probed (unknown to inventory)")


tasks = [json.loads(l) for l in (H / "tasks.jsonl").read_text().splitlines() if l.strip()]
inscope, dropped, review = [], [], []

for t in tasks:
    if t.get("confidence") == "low":
        t["route"] = "agent-review: " + t.get("why", "")
        review.append(t)
        continue
    missing = [c for c in t["required_caps"] if c not in present]
    if missing:
        t["dropped_because"] = [{"missing_cap": c, "probe_evidence": evidence(c)} for c in missing]
        dropped.append(t)
    else:
        t["kept_because"] = {c: evidence(c) for c in t["required_caps"]} or {"(no special capability required)": "general tooling present"}
        inscope.append(t)


def dump(name, rows):
    (H / name).write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + ("\n" if rows else ""))


dump("inscope.jsonl", inscope)
dump("dropped.jsonl", dropped)
dump("review_queue.jsonl", review)

from collections import Counter
print(f"=== infra-fit selection ({inv['infra']}, probed {inv['probed_at']}) ===")
print(f"  total tasks      : {len(tasks)}")
print(f"  IN-SCOPE (keep)  : {len(inscope)}")
print(f"  DROPPED (absent) : {len(dropped)}")
print(f"  REVIEW (agent)   : {len(review)}")
drop_caps = Counter(d["missing_cap"] for t in dropped for d in t["dropped_because"])
if drop_caps:
    print("\n  drop reasons (missing capability → #tasks, all falsifiable):")
    for cap, n in drop_caps.most_common():
        print(f"    {cap:24s} {n:4d}   « {evidence(cap)[:70]}")
print("\n  in-scope by benchmark:", dict(Counter(t["benchmark"] for t in inscope)))
print("  dropped  by benchmark:", dict(Counter(t["benchmark"] for t in dropped)))
print(f"\n  → harness/inscope.jsonl ({len(inscope)}) feeds the agent run; dropped.jsonl is the auditable exclusion ledger.")
