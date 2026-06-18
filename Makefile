.PHONY: install lint test format run
install:
	pip install -e ".[dev]"
format:
	ruff format kairos_execution tests
lint:
	ruff check kairos_execution tests
test:
	pytest -q
run:
	python -m kairos_execution
