# secu_agent_benchmark

A reproducible procurement + harness layer for evaluating **security agents** against
**externally-published, third-party benchmarks** — and for auto-fitting that universe to a
concrete cyber-range infrastructure (the CCC **6v6** range) without polluting the test.

## Why this exists

A self-authored benchmark that you also optimize, run, and grade is structurally gameable.
The fix is to anchor on benchmarks whose **answer keys are frozen by a third party** so neither
the agent under test nor the orchestrator can make the test easier. This repo procures those
benchmarks and records exactly which commit of each was used.

## Two grading classes (this is the whole point)

| class | meaning | benchmarks |
|-------|---------|------------|
| **oracle** | flag / expected-output / exploit-success fixed by a third party → **un-gameable** | cybench, nyu_ctf, intercode, agentbench, cve_bench, cybergym, inspect_cyber, threecb |
| **classifier / mcq** | judged by a guard model or multiple-choice key | purplellama (CyberSecEval), harmbench, seceval, cybermetric, wmdp, cti_bench, secqa |

Two of the entries are **meta-benchmarks** that themselves bundle many sub-evals:
`inspect_evals` (UK AI Security Institute) and `caibench` (Alias Robotics).

## Data is not committed

Benchmark data is large and carries upstream licenses, so it is **never committed**. The repo
holds only the `catalog.tsv` (source + pinned commit + license), the fetch scripts, and a ledger.
Running the fetcher materializes everything into `$BENCH_DATA` (default `/home/opsclaw/bench_data`,
exposed here as `./data`).

```bash
make fetch              # fetch everything pending (resumable)
make fetch-cybench      # fetch one
make ledger             # status table (DONE/FAIL + commit + size)
make status             # disk usage per benchmark
```

The fetcher is **resumable** (per-dir `.fetch_done` marker) and **continue-on-error** (one bad
source is logged in `data/_ledger.tsv`, the rest proceed). Re-run `make fetch` any time to pick up
what is still pending.

## Layout

```
catalog.tsv              master list: id | category | kind | url | sha | license | grading | notes
scripts/fetch_all.sh     resumable driver (git clone --depth1 | huggingface_hub snapshot_download)
data/ -> $BENCH_DATA     fetched data (gitignored)
data/_ledger.tsv         per-benchmark status (commit, size, ts, note)
data/_fetch.log          full fetch log
```
