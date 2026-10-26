.PHONY: help test demo lint clean

help:
	@echo "test   run the test suite"
	@echo "demo   run the three-minute Seatbelt demo"

test:
	python -m pytest

lint:
	python -m compileall -q src

demo:
	@echo "demo lands in T4"

clean:
	rm -rf .pytest_cache build dist src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
