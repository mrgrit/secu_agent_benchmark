# Benchmark inventory — what is actually secured

Verified by inspecting `$BENCH_DATA` on 2026-05-27 (not just "git said done"): file counts,
LFS-pointer smudging, submodule population. Machine status: `make ledger`.

> **"small" ≠ "incomplete".** Several entries are *framework / task-definition* repos whose actual
> challenge environments are docker images built or pulled **at eval runtime** (inspect_cyber,
> threecb) or whose huge corpus is a **separate opt-in download** (cybergym). That is by design.

| id | size | grading | what's in it | status |
|----|------|---------|--------------|--------|
| cybench | 2.9G | oracle-flag | 40 pro CTF, 7488 files, per-task docker contexts; LFS run-logs smudged | ✅ complete |
| nyu_ctf_db | 3.7G | oracle-flag | 200 CTF challenges, 25k files | ✅ (1 LFS blob in `removed/` = 404 upstream, dead challenge — ignore) |
| nyu_ctf_agents | 1.1M | oracle-flag | NYU CTF agent harness + challenge metadata | ✅ |
| intercode | 320M | oracle-flag | interactive CTF / bash / sql / python tasks | ✅ |
| agentbench | 59M | oracle-output | 8 envs; OS subset (file/proc/user/perm) | ✅ |
| cve_bench | 272M | oracle-exploit | real-world web CVE exploitation (ICML25) | ✅ |
| cybergym | 476K | oracle-repro | **framework only** — corpus is separate (see cybergym_data) | ⚠️ framework only |
| purplellama | 144M | classifier | CyberSecEval 1/2/3 + Llama Guard prompts | ✅ |
| └ CyberSOCEval_data | 142M | classifier | CrowdStrike CyberSOC eval (hybrid-analysis + reports), 231 files | ✅ (direct-cloned; shallow-submodule didn't populate) |
| harmbench | 469M | classifier | 400+ red-team prompts; cyber subset | ✅ |
| inspect_evals | 263M | mixed | **UK-AISI meta**, 3767 files; bundles cybench/cyberseceval/sevenllm/secqa/gdm | ✅ |
| inspect_cyber | 1.3M | oracle-solvability | **UK-AISI cyber-range framework** (CTF→AD→enterprise→CNI); envs at runtime | ✅ framework |
| caibench | 362M | mixed | **Alias-Robotics meta**, 5 categories | ✅ (3 submodules = dup of seceval/cybermetric/cti_bench, pinned commit gone upstream — data held standalone) |
| seceval | 4.0M | mcq | 2204 Q, 9 security domains | ✅ |
| wmdp | 1.5M | mcq | WMDP code (cyber/bio/chem hazard proxy) | ✅ |
| threecb | 1.1M | oracle | Catastrophic Cyber Capabilities Benchmark tasks; envs at runtime | ✅ framework |
| cybermetric | 6.8M | mcq | CyberMetric 80/500/2000/10000 QA | ✅ |
| cti_bench | 7.4M | mixed (hf) | Cyber Threat Intelligence benchmark | ✅ |
| secqa | 220K | mcq (hf) | Security QA v1/v2 | ✅ |
| wmdp_data | 1.5M | mcq (hf) | wmdp-cyber/bio/chem datasets | ✅ |
| cybergym_data | ~240G | oracle-repro | CyberGym FULL corpus (real vuln reproduction env) | 🔄 fetching (HF) |

**Summary:** 19/19 base benchmarks secured (~11G) with content verified. Two meta-benchmarks
(inspect_evals, caibench) bundle dozens of sub-evals. The single large optional corpus
(cybergym_data, ~240G) is fetching separately.

## Known caveats (honest)
- **caibench submodules** point at commits force-pushed away upstream → cannot init. The three
  datasets they reference (SecEval, CyberMetric, cti-bench) are already held as standalone entries,
  so no data is missing — only CAIBench's internal symlinks.
- **nyu_ctf_db** has one LFS object (`removed/2021/CSAW-Finals/.../App0.zip`) returning 404 — it is
  under `removed/`, a deliberately retired challenge. Not part of the live set.
- **inspect_cyber / threecb / cybergym** ship task definitions + harness; the runnable environments
  are docker images instantiated at eval time, not stored here.
