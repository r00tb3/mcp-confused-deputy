PYTHON ?= python3

.PHONY: help run run-clean demo record verify verify-vuln verify-clean test clean

help:
	@echo "make run           start the broker in vuln mode on :8765"
	@echo "make run-clean     start the broker in clean mode on :8765"
	@echo "make demo          run the agent against a fresh vuln broker"
	@echo "make record        re-record demo/demo.cast (needs asciinema)"
	@echo "make verify        run both verifier modes"
	@echo "make test          run the unittest suite"

run:
	$(PYTHON) lab/broker.py --mode vuln

run-clean:
	$(PYTHON) lab/broker.py --mode clean

demo:
	@log=$$(mktemp); \
	$(PYTHON) lab/broker.py --mode vuln --port 0 > "$$log" 2>&1 & \
	pid=$$!; \
	trap 'kill $$pid 2>/dev/null; wait $$pid 2>/dev/null; rm -f "$$log"' EXIT; \
	for i in $$(seq 1 100); do \
	  grep -q "broker listening on" "$$log" 2>/dev/null && break; \
	  sleep 0.05; \
	done; \
	url=$$(sed -n 's/^broker listening on \(http[^ ]*\).*/\1/p' "$$log" | head -1); \
	if [ -z "$$url" ]; then echo "broker did not start"; exit 1; fi; \
	$(PYTHON) lab/agent.py --base-url "$$url" --smuggle; \
	echo "--- audit ---"; \
	$(PYTHON) -c 'import json,sys,urllib.request; print(json.dumps(json.load(urllib.request.urlopen(sys.argv[1] + "/audit")), indent=2))' "$$url"

record:
	asciinema rec --overwrite --idle-time-limit 1.2 --cols 100 --rows 28 \
		-c ./demo/record.sh demo/demo.cast

verify: verify-vuln verify-clean

verify-vuln:
	@$(PYTHON) verify/verify_priv_esc.py --mode vuln; code=$$?; \
	if [ $$code -eq 0 ]; then echo "verify-vuln: expected exit 0"; else echo "verify-vuln: FAILED (exit $$code)"; exit $$code; fi

verify-clean:
	@$(PYTHON) verify/verify_priv_esc.py --mode clean; code=$$?; \
	if [ $$code -eq 1 ]; then echo "verify-clean: expected exit 1"; else echo "verify-clean: FAILED (exit $$code)"; exit 1; fi

test:
	$(PYTHON) -m unittest discover -s tests -v

clean:
	rm -f lab/state/service-state.json
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
