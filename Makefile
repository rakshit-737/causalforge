.PHONY: test run migrate lint typecheck security lock-check check

PYTHON ?= python

test:
	$(PYTHON) -m pytest

run:
	$(PYTHON) -m uvicorn causalforge.main:app --app-dir backend --host 127.0.0.1 --port 8000

migrate:
	$(PYTHON) -m alembic -c backend/alembic.ini upgrade head

lint:
	$(PYTHON) -m ruff check backend

typecheck:
	$(PYTHON) -m mypy backend/causalforge

security:
	$(PYTHON) -m bandit -q -r backend/causalforge

lock-check:
	uv lock --check

check:
	$(PYTHON) -m compileall -q backend
	$(PYTHON) -m pytest
