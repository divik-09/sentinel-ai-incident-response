.PHONY: install run test cov lint typecheck evaluate evaluate-check ci audit clean

install:
	python -m pip install -r requirements-dev.txt

run:
	uvicorn backend.app.main:create_app --factory --reload --host 127.0.0.1 --port 8000

test:
	python -m pytest

cov:
	python -m pytest --cov --cov-report=term-missing

lint:
	ruff check . && ruff format --check .

typecheck:
	mypy

evaluate:
	python scripts/run_evaluation.py --summary

evaluate-check:
	python scripts/run_evaluation.py --check

audit:
	pip-audit -r requirements.txt

ci: lint typecheck cov evaluate-check

clean:
	rm -f sentinel.db sentinel.db-shm sentinel.db-wal .coverage
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov
