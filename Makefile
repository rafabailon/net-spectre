.DEFAULT_GOAL := help
PYTHON ?= python3

.PHONY: help install develop test coverage compile check menu network host interfaces clean clean-logs

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

install: ## Install the package (provides the net-spectre command)
	$(PYTHON) -m pip install .

develop: ## Editable install with optional dependencies
	$(PYTHON) -m pip install -e ".[full]"

test: ## Run the unittest suite
	$(PYTHON) -m unittest discover -s tests -v

coverage: ## Run the suite with coverage
	$(PYTHON) -m coverage run -m unittest discover -s tests
	$(PYTHON) -m coverage report

compile: ## Byte-compile the package to catch syntax errors
	$(PYTHON) -m compileall -q src

check: compile test ## Compile and test

menu: ## Open the interactive menu
	$(PYTHON) -m src menu

network: ## Discover the network of the default interface
	$(PYTHON) -m src network

host: ## Scan one host (usage: make host TARGET=192.168.1.1)
	$(PYTHON) -m src host $(TARGET)

interfaces: ## Show interfaces, local networks and the default route
	$(PYTHON) -m src interfaces

clean-logs: ## Remove generated reports but keep the logs directory
	find logs -type f ! -name '.gitkeep' -delete

clean: clean-logs ## Remove reports and Python caches
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .coverage htmlcov
