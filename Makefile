# Convenience targets. Nothing here is required - every step is a plain command.
.PHONY: help venv install dev test lint fmt installer clean doctor run

PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

help:
	@echo "make dev        - venv + editable install with dev extras"
	@echo "make test       - pytest"
	@echo "make lint       - ruff + JS syntax + translation catalog"
	@echo "make installer  - build the single-file install.py"
	@echo "make run        - run against ./config.ini (make one from config.example.ini)"
	@echo "make doctor     - environment and port-safety check"
	@echo "make clean      - remove build and cache artefacts"

$(BIN)/python:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip

dev: $(BIN)/python
	$(BIN)/pip install --quiet -e ".[dev]"
	@echo "ready: $(BIN)/smartdns-dashboard --help"

install: $(BIN)/python
	$(BIN)/pip install --quiet .

test: dev
	$(BIN)/pytest -q

lint: dev
	$(BIN)/ruff check src tests
	node --check src/smartdns_dash/static/app.js
	node .github/scripts/check-i18n.mjs

fmt: dev
	$(BIN)/ruff check --fix src tests

installer:
	$(PY) tools/build_installer.py
	$(PY) install.py --check-only

run: dev
	SMARTDNS_DASH_CONFIG=./config.ini $(BIN)/smartdns-dashboard run

doctor: dev
	SMARTDNS_DASH_CONFIG=./config.ini $(BIN)/smartdns-dashboard doctor

clean:
	rm -rf build dist *.egg-info src/*.egg-info .pytest_cache .ruff_cache \
	       .coverage htmlcov install.py
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
