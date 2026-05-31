.SILENT:
.ONESHELL:
.PHONY: \
	setup_uv setup_dev setup_lychee \
	lint autofix check_types check_complexity lint_md lint_links \
	test test_cov retest validate \
	smoke \
	changelog_new changelog_preview changelog_release \
	clean help
.DEFAULT_GOAL := help

VERBOSE ?=
ifndef VERBOSE
  RUFF_QUIET := --quiet
  PYTEST_QUIET := -q --tb=short --no-header
  PYRIGHT_QUIET := > /dev/null
endif

# Override at the CLI to install a pinned lychee build, e.g.:
#   make setup_lychee LYCHEE_URL=https://github.com/lycheeverse/lychee/releases/download/lychee-v0.18.0/lychee-x86_64-unknown-linux-gnu.tar.gz
LYCHEE_URL ?= https://github.com/lycheeverse/lychee/releases/latest/download/lychee-x86_64-unknown-linux-gnu.tar.gz
LYCHEE_BIN ?= $(HOME)/.local/bin/lychee


# MARK: SETUP


setup_uv:  ## Install uv (if missing)
	if command -v uv > /dev/null 2>&1; then
		echo "uv already installed: $$(uv --version)"
	else
		curl --proto '=https' --tlsv1.2 -LsSf https://astral.sh/uv/install.sh | sh
		echo "NOTE: restart your shell or run 'source $$HOME/.local/bin/env'"
	fi

setup_dev: setup_uv  ## uv sync (default groups: dev + test)
	uv sync

setup_lychee:  ## Install lychee link checker (override LYCHEE_URL / LYCHEE_BIN to customize)
	tmp=$$(mktemp -d)
	curl -sSfL $(LYCHEE_URL) | tar xz -C "$$tmp"
	mkdir -p $(dir $(LYCHEE_BIN))
	install -m 755 "$$tmp"/lychee-*/lychee $(LYCHEE_BIN)
	rm -rf "$$tmp"
	echo "lychee version: $$($(LYCHEE_BIN) --version)"


# MARK: QUALITY


lint:  ## ruff check
	echo "--- lint"
	uv run ruff check $(RUFF_QUIET) .

autofix:  ## ruff format + ruff check --fix
	uv run ruff format $(RUFF_QUIET) . && uv run ruff check --fix $(RUFF_QUIET) .

check_types:  ## pyright type check on src/
	echo "--- check_types"
	uv run pyright src $(PYRIGHT_QUIET)

check_complexity:  ## complexipy cognitive complexity gate (max 10)
	echo "--- check_complexity"
	uv run complexipy src --max-complexity-allowed 10

lint_md:  ## markdownlint *.md (uses .markdownlint.json)
	echo "--- lint_md"
	npx --yes markdownlint-cli --config .markdownlint.json '**/*.md' \
	  --ignore '.venv/**' --ignore 'node_modules/**' \
	  --ignore 'changelog.d/**'

lint_links:  ## lychee broken-link checker (network — slow; mandatory in CI)
	echo "--- lint_links"
	lychee --config .lychee.toml .

test:  ## pytest
	echo "--- test"
	uv run pytest $(PYTEST_QUIET)

test_cov:  ## pytest with coverage (--cov-fail-under=0 until 2b lands tests; brief mandates 70 from 2b on)
	echo "--- test_cov"
	uv run pytest --cov=src --cov-fail-under=0 $(PYTEST_QUIET)

retest:  ## rerun last failed tests only
	uv run pytest --lf -x

validate:  ## CI gate: lint + check_types + check_complexity + lint_md + lint_links + test_cov
	set -e
	$(MAKE) -s lint
	$(MAKE) -s check_types
	$(MAKE) -s check_complexity
	$(MAKE) -s lint_md
	$(MAKE) -s lint_links
	$(MAKE) -s test_cov


# MARK: RUN


smoke:  ## End-to-end CLI run against tests/fixtures/feed-min.jsonl (fixture lands in 2b)
	echo "--- smoke"
	uv run python -m gha_sec_feed_eval \
	  --feed-url file://$(CURDIR)/tests/fixtures/feed-min.jsonl \
	  --output-dir $(CURDIR)/data


# MARK: CHANGELOG


changelog_new:  ## create + stage a new changelog fragment under changelog.d/
	uv run scriv create --add

changelog_preview:  ## preview the assembled release entry without consuming fragments
	uv run scriv print

changelog_release:  ## collect fragments into CHANGELOG.md (VERSION=X.Y.Z required); run before bump-my-version
	test -n "$(VERSION)" || (echo "VERSION required, e.g. make changelog_release VERSION=0.1.0"; exit 2)
	uv run scriv collect --version $(VERSION)


# MARK: CLEAN


clean:  ## remove caches
	rm -rf .pytest_cache .ruff_cache .pyright_cache .coverage htmlcov
	find . -name "__pycache__" -type d -exec rm -rf {} +
	find . -name "*.pyc" -delete


# MARK: HELP


help:  ## show available recipes grouped by section
	echo "Usage: make [recipe] [VERBOSE=1]"
	echo ""
	awk '/^# MARK:/ { \
		section = substr($$0, index($$0, ":")+2); \
		printf "\n\033[1m%s\033[0m\n", section \
	} \
	/^[a-zA-Z0-9_-]+:.*?##/ { \
		helpMessage = match($$0, /## (.*)/); \
		if (helpMessage) { \
			recipe = $$1; \
			sub(/:/, "", recipe); \
			printf "  \033[36m%-18s\033[0m %s\n", recipe, substr($$0, RSTART + 3, RLENGTH) \
		} \
	}' $(MAKEFILE_LIST)
