BENCH_DATA ?= /home/opsclaw/bench_data
export BENCH_DATA

.PHONY: fetch fetch-% status ledger
fetch:            ## fetch every benchmark still pending
	bash scripts/fetch_all.sh
fetch-%:          ## fetch a single benchmark, e.g. make fetch-cybench
	bash scripts/fetch_all.sh $*
status:           ## show disk usage per benchmark
	@du -sh $(BENCH_DATA)/*/ 2>/dev/null | sort -h || true
ledger:           ## show procurement ledger
	@column -t -s '	' $(BENCH_DATA)/_ledger.tsv 2>/dev/null || cat $(BENCH_DATA)/_ledger.tsv
