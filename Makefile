.PHONY: setup test lint run-pipeline

setup:
	uv sync --extra dev

test:
	uv run pytest

lint:
	uv run ruff check .

run-pipeline:
	uv run python -m offline.pipeline
