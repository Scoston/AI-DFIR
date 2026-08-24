PYTHON ?= python3

.PHONY: install install-enterprise fixtures test test-full release-check workbench

install:
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

install-enterprise:
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/pip install -r requirements-enterprise.txt

fixtures:
	$(PYTHON) tests/generate_test_corpus.py

test: fixtures
	$(PYTHON) scripts/release_check.py --quick

test-full: fixtures
	$(PYTHON) scripts/release_check.py --full

release-check: test-full

workbench:
	$(PYTHON) analyst_dashboard.py --case-root ./cases --host 127.0.0.1 --port 8877
