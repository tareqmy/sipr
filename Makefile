# sipr — convenience targets. Run `make` or `make help` for the list.
#
# Overridable variables (e.g. `make run-uac RATE=100 TARGET=10.0.0.2:5060`):
PORT    ?= 5060                 # local port for the UAS demo / interop
TARGET  ?= 127.0.0.1:$(PORT)    # remote host:port for the UAC demo
RATE    ?= 50                   # calls per second
CALLS   ?= 1000                 # total calls (-m)
SCENARIO ?=                     # path to a -sf scenario (blank = embedded)
SIPP_BIN ?= $(HOME)/development/cprojects/sipp/sipp   # real sipp for interop

CARGO   ?= cargo
BIN     := ./target/release/sipr

.DEFAULT_GOAL := help

# ---- development gates -------------------------------------------------

.PHONY: build
build: ## Debug build of the whole workspace
	$(CARGO) build --workspace

.PHONY: release
release: ## Optimized build (used by run-*/bench)
	$(CARGO) build --release

.PHONY: test
test: ## Run the full test suite
	$(CARGO) test --workspace

.PHONY: fmt
fmt: ## Apply rustfmt to the workspace
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without changing files
	$(CARGO) fmt --all -- --check

.PHONY: clippy
clippy: ## Lint with clippy, warnings denied
	$(CARGO) clippy --workspace --all-targets -- -D warnings

.PHONY: deny
deny: ## Check dependency licenses, advisories, and sources (cargo-deny)
	$(CARGO) deny check

.PHONY: check
check: fmt-check clippy test ## Run every CI gate locally (fmt + clippy + test)
	@echo "all gates passed"

# ---- running -----------------------------------------------------------

.PHONY: run-uas
run-uas: release ## Run the embedded UAS on $(PORT)
	$(BIN) -sn uas -i 127.0.0.1 -p $(PORT)

.PHONY: run-uac
run-uac: release ## Place $(CALLS) calls at $(RATE) cps to $(TARGET)
	$(BIN) -sn uac -r $(RATE) -m $(CALLS) $(TARGET)

.PHONY: run
run: release ## Run a custom scenario: make run SCENARIO=x.xml TARGET=host
	@test -n "$(SCENARIO)" || { echo "set SCENARIO=path/to.xml"; exit 2; }
	$(BIN) -sf $(SCENARIO) -r $(RATE) -m $(CALLS) $(TARGET)

.PHONY: check-scenario
check-scenario: build ## Lint a scenario and print its IR: make check-scenario SCENARIO=x.xml
	@test -n "$(SCENARIO)" || { echo "set SCENARIO=path/to.xml"; exit 2; }
	$(CARGO) run -q -- -sf $(SCENARIO) --check

.PHONY: dump
dump: build ## Print an embedded scenario: make dump NAME=uac
	$(CARGO) run -q -- -sd $(or $(NAME),uac)

# ---- interop & benchmarks ---------------------------------------------

.PHONY: interop
interop: ## Interop tests against real sipp (set SIPP_BIN if not on PATH)
	SIPP_BIN=$(SIPP_BIN) $(CARGO) test --test interop -- --nocapture

.PHONY: bench
bench: release ## Loopback throughput: sipr-UAC vs sipr-UAS at $(RATE) cps
	@echo "starting UAS on $(PORT)..."; \
	$(BIN) -sn uas -i 127.0.0.1 -p $(PORT) -m $(CALLS) -timeout 120 2>/tmp/sipr-bench-uas.log & \
	UAS=$$!; sleep 0.4; \
	$(BIN) -sn uac -r $(RATE) -m $(CALLS) -d 10 -timeout 120 127.0.0.1:$(PORT); \
	wait $$UAS; tail -1 /tmp/sipr-bench-uas.log

# ---- releasing ---------------------------------------------------------

.PHONY: publish
publish: ## Publish every crate to crates.io in dependency order (CD does this on tag)
	$(CARGO) publish --workspace --locked

.PHONY: publish-dry-run
publish-dry-run: ## Check that every crate packages cleanly, without publishing
	$(CARGO) publish --workspace --locked --dry-run

# ---- housekeeping ------------------------------------------------------

.PHONY: doc
doc: ## Build and open the API docs
	$(CARGO) doc --workspace --no-deps --open

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean

.PHONY: help
help: ## Show this help
	@echo "sipr make targets:"; \
	grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort \
	  | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo; echo "Overridable vars: PORT TARGET RATE CALLS SCENARIO NAME SIPP_BIN"
