UV ?= uv

.PHONY: install install-all lock format lint typecheck security test check build run

install:
	$(UV) sync --locked

install-all:
	$(UV) sync --locked --all-extras

lock:
	$(UV) lock

format:
	$(UV) run --locked ruff format kairos_execution tests

lint:
	$(UV) run --locked ruff check .
	$(UV) run --locked ruff format --check .

typecheck:
	$(UV) run --locked mypy kairos_execution

security:
	$(UV) run --locked bandit -q -r kairos_execution -x tests

test:
	$(UV) run --locked pytest -q --tb=short

check: lint typecheck security test build

build:
	$(UV) build --no-sources

run:
	$(UV) run --locked python -m kairos_execution
