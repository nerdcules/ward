#!/bin/sh
# Stands in for `claude -p --output-format json` in the tests: answers "no"
# for every CVE named at the start of a line of the question, and appends a
# line to $WARD_STUB_CALLS for each call.
echo x >> "$WARD_STUB_CALLS"
ids=$(grep -o '^CVE-[0-9-]*' | sed 's/.*/{"cve":"&","applies":"no","priority":"later","why":"stub"}/' | paste -sd, -)
inner="{\"verdicts\":[$ids],\"mitigation\":\"\"}"
python3 -I -c 'import json,sys; print(json.dumps({"is_error": False, "total_cost_usd": 0.01, "result": sys.argv[1]}))' "$inner"
