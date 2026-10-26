.PHONY: help test lint demo bench bench-live clean

# Prefer the project venv when it exists, so `make demo` works without an
# activated shell. Override with `make PY=...`.
PY := $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)

help:
	@echo "test        run the test suite"
	@echo "demo        ~60s benchmark run, no API key needed (needs root for the sandbox)"
	@echo "bench       full dev replay, with per-scenario progress"
	@echo "bench-live  the three-arm benchmark against a real model (needs env vars)"

test:
	$(PY) -m pytest

lint:
	$(PY) -m compileall -q src bench

demo:
	@$(PY) -m bench.runner --set dev --mode replay --out bench/results/demo --quiet
	@cat bench/results/demo/report.md

bench:
	$(PY) -m bench.runner --set dev --mode replay --runs 1

bench-live:
	$(PY) -m bench.runner --set dev --mode live --runs 3

clean:
	rm -rf .pytest_cache build dist src/*.egg-info bench/results
	find . -name __pycache__ -type d -prune -exec rm -rf {} +