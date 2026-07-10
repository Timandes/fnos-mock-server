# Request Fixture Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture, sanitize, deduplicate, and store client WebSocket requests only for response types added on the current branch relative to `main`.

**Architecture:** Compute a one-time `req` allowlist from newly added response fixtures, capture only the current fnOS WebSocket TCP connections, and extract client-to-server JSON messages into a temporary candidate directory. Review candidates before adding stable `requests/<req>/case-N.json` files. Permanent tests validate format, deduplication, numbering, response linkage, and sensitive-data rules without depending on Git branch state.

**Tech Stack:** Python 3.14, pytest, temporary Scapy runtime via `uv run --with scapy`, macOS `tcpdump`, JSON fixtures.

## Global Constraints

- Only read-only fnOS UI navigation is permitted.
- Persist only request types whose response files were added by `git diff --diff-filter=A main...HEAD -- 'responses/*.json'`.
- Never persist WebSocket signatures, `req: encrypted`, passwords, tokens, keys, session material, or raw environment identifiers.
- Store cases as `requests/<req>/case-N.json`, preserving existing case numbers and appending only canonical new cases.
- Do not change mock-server runtime routing.
- Raw captures and temporary extraction code must not remain in the repository.
- Use Conventional Commits in English and never add `Co-Authored-By`.

---

### Task 1: Freeze the branch-derived request allowlist

**Files:**
- Create temporarily: `/tmp/fnos-request-allowlist.txt`
- Verify: `responses/*.json`

**Interfaces:**
- Consumes: response files added between `main` and the current branch.
- Produces: one allowed `req` stem per line for the capture extractor.

- [ ] **Step 1: Generate the allowlist**

```bash
git diff --diff-filter=A --name-only main...HEAD -- 'responses/*.json' \
  | sed -E 's#^responses/##; s#\.json$##' \
  | LC_ALL=C sort -u > /tmp/fnos-request-allowlist.txt
```

- [ ] **Step 2: Verify the expected scope**

```bash
test "$(wc -l < /tmp/fnos-request-allowlist.txt | tr -d ' ')" = 78
test "$(sort /tmp/fnos-request-allowlist.txt | uniq -d | wc -l | tr -d ' ')" = 0
```

Expected: both commands exit 0; the allowlist contains 78 unique request types.

---

### Task 2: Add request-corpus contract tests

**Files:**
- Create: `tests/test_request_fixtures.py`
- Test: `tests/test_request_fixtures.py`

**Interfaces:**
- Consumes: `requests/<req>/case-N.json` and `responses/<req>.json`.
- Produces: permanent validation for request case layout and canonical uniqueness.

- [ ] **Step 1: Write the failing corpus test**

Create `tests/test_request_fixtures.py` with these core contracts:

```python
import json
import re
from collections import defaultdict
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
REQUESTS_DIR = ROOT / "requests"
RESPONSES_DIR = ROOT / "responses"
CAPTURED_REQID = "0000000000000000000000000000"
CASE_PATTERN = re.compile(r"case-([1-9][0-9]*)\.json")


def request_cases() -> list[Path]:
    return sorted(REQUESTS_DIR.glob("*/case-*.json"))


def canonical_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def test_request_fixture_corpus_is_not_empty():
    assert request_cases()


@pytest.mark.parametrize("case_path", request_cases(), ids=lambda path: str(path.relative_to(ROOT)))
def test_request_case_contract(case_path: Path):
    request = json.loads(case_path.read_text(encoding="utf-8"))
    assert isinstance(request, dict)
    assert isinstance(request.get("req"), str)
    assert request["req"] == case_path.parent.name
    if "reqid" in request:
        assert request["reqid"] == CAPTURED_REQID
    response_path = RESPONSES_DIR / f"{request['req']}.json"
    response = json.loads(response_path.read_text(encoding="utf-8"))
    assert response.get("reqid") == CAPTURED_REQID


def test_request_case_numbers_are_contiguous_and_cases_are_unique():
    cases_by_req: dict[str, list[Path]] = defaultdict(list)
    for case_path in request_cases():
        cases_by_req[case_path.parent.name].append(case_path)
    for req, paths in cases_by_req.items():
        numbers = sorted(int(CASE_PATTERN.fullmatch(path.name).group(1)) for path in paths)
        assert numbers == list(range(1, len(numbers) + 1)), req
        canonical_cases = {
            canonical_json(json.loads(path.read_text(encoding="utf-8"))) for path in paths
        }
        assert len(canonical_cases) == len(paths), req
```

Add the recursive sensitive-key test below to the same file; use the exact URL/IP/email/MAC/path
allowlists from `test_captured_response_sensitive_values_are_allowlisted` in
`tests/test_mock_server_integration.py` for its string-value checks:

```python
SENSITIVE_KEY_PARTS = {
    "licensecode",
    "passwd",
    "password",
    "privatekey",
    "publickey",
    "secret",
    "session",
    "signature",
    "token",
}


def assert_request_value_is_sanitized(value, key=""):
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            assert_request_value_is_sanitized(child_value, child_key)
        return
    if isinstance(value, list):
        for child_value in value:
            assert_request_value_is_sanitized(child_value, key)
        return
    if not isinstance(value, str):
        return
    normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
    if any(part in normalized_key for part in SENSITIVE_KEY_PARTS):
        assert value in {"", "<redacted>"}


@pytest.mark.parametrize("case_path", request_cases(), ids=lambda path: str(path.relative_to(ROOT)))
def test_request_case_contains_no_authentication_material(case_path: Path):
    request = json.loads(case_path.read_text(encoding="utf-8"))
    assert request["req"] != "encrypted"
    assert_request_value_is_sanitized(request)
```

- [ ] **Step 2: Run the test to verify RED**

Run:

```bash
.venv/bin/pytest -q tests/test_request_fixtures.py
```

Expected: FAIL at `test_request_fixture_corpus_is_not_empty` because `requests/` does not exist yet.

---

### Task 3: Start a connection-scoped request capture

**Files:**
- Create temporarily: `/tmp/fnos-requests-round3.pcap`
- Create temporarily: `/tmp/fnos-requests-round3.pid`
- Create temporarily: `/tmp/fnos-requests-round3.log`

**Interfaces:**
- Consumes: current Chrome TCP connections to the fnOS service on port 5666.
- Produces: raw packets containing masked client WebSocket frames.

- [ ] **Step 1: Discover active client ports**

```bash
netstat -anv -p tcp \
  | awk '$5 ~ /\.5666$/ && $6 == "ESTABLISHED" {print $4}' \
  | sed -E 's/.*\.([0-9]+)$/\1/' \
  | LC_ALL=C sort -nu > /tmp/fnos-request-ports.txt
test -s /tmp/fnos-request-ports.txt
```

Expected: one or more local ephemeral ports. Confirm each connection belongs to the open fnOS tabs before continuing.

- [ ] **Step 2: Start tcpdump with only those ports**

Build the BPF expression from the discovered ports and start the capture:

```bash
ports=($(cat /tmp/fnos-request-ports.txt))
bpf="(tcp port ${ports[1]}"
for port in "${ports[@]:1}"; do bpf="$bpf or tcp port $port"; done
bpf="$bpf)"
sudo /usr/sbin/tcpdump -i en0 -s 0 -U \
  -w /tmp/fnos-requests-round3.pcap "$bpf" \
  >/tmp/fnos-requests-round3.log 2>&1 &
echo $! >/tmp/fnos-requests-round3.pid
```

Run it in the background, save its PID in `/tmp/fnos-requests-round3.pid`, and redirect diagnostics to `/tmp/fnos-requests-round3.log`.

- [ ] **Step 3: Verify client request frames are entering**

Read a snapshot of the PCAP and confirm masked WebSocket payload bytes are present without printing raw secrets. Report readiness to the user and ask them to navigate only read-only pages. Do not reload or log in because that changes TCP ports and may generate authentication traffic.

- [ ] **Step 4: Wait for the user's `点击完成` message**

Do not stop early. Continue monitoring capture size and connection state while the user clicks.

---

### Task 4: Decode and normalize request candidates

**Files:**
- Create temporarily: `/tmp/fnos_request_capture.py`
- Create temporarily: `/tmp/test_fnos_request_capture.py`
- Create temporarily: `/tmp/fnos-request-candidates/`

**Interfaces:**
- Consumes: PCAP path and `/tmp/fnos-request-allowlist.txt`.
- Produces: sanitized, canonical candidate objects grouped by `req`.
- Functions: `decode_frames(data: bytes, expect_mask: bool)`, `parse_json_message(payload: bytes)`, `sanitize_request(value, key="")`, `extract_requests(pcap_path: Path)`, `merge_cases(candidates, requests_dir)`.

- [ ] **Step 1: Write temporary decoder tests first**

`/tmp/test_fnos_request_capture.py` must cover:

```python
def test_decodes_masked_text_frame():
    payload = b'{"req":"example.get","reqid":"abc"}'
    frame = build_masked_frame(payload, mask=b"\x01\x02\x03\x04")
    messages, remainder = decode_frames(frame, expect_mask=True)
    assert messages == [payload]
    assert remainder == b""


def test_parser_skips_signature_prefix():
    request = parse_json_message(b"signature-prefix" + b'{"req":"example.get"}')
    assert request == {"req": "example.get"}


def test_normalizes_volatile_and_sensitive_fields():
    request = sanitize_request({
        "req": "example.get",
        "reqid": "live-id",
        "token": "live-token",
        "path": "/vol9/private",
    })
    assert request == {
        "req": "example.get",
        "reqid": "0000000000000000000000000000",
        "token": "<redacted>",
        "path": "/vol1/example",
    }
```

- [ ] **Step 2: Run temporary tests to verify RED**

```bash
uv run --with pytest --with scapy pytest -q /tmp/test_fnos_request_capture.py
```

Expected: FAIL because the decoder and sanitizer functions do not exist.

- [ ] **Step 3: Implement the minimal extractor**

Use Scapy only for PCAP/Ether/IP/TCP decoding. Reassemble each TCP direction by sequence number, parse WebSocket payload lengths `<=125`, `126`, and `127`, unmask client frames, join continuation frames, and parse JSON from the first `{` onward. Canonicalize with:

```python
REQID_PLACEHOLDER = "0000000000000000000000000000"
SENSITIVE_PARTS = (
    "password", "passwd", "token", "secret", "privatekey",
    "publickey", "signature", "licensecode", "session",
)


def canonical_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sanitize_request(value, key=""):
    normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
    if isinstance(value, dict):
        return {child_key: sanitize_request(child, child_key) for child_key, child in value.items()}
    if isinstance(value, list):
        return [sanitize_request(child, key) for child in value]
    if normalized_key == "reqid":
        return REQID_PLACEHOLDER
    if isinstance(value, str) and any(part in normalized_key for part in SENSITIVE_PARTS):
        return "<redacted>"
    if isinstance(value, str):
        return sanitize_string(value)
    return value
```

Reject `req == "encrypted"`, missing/non-string `req`, and any `req` absent from the allowlist. Write candidates only to `/tmp/fnos-request-candidates`, not the repository.

- [ ] **Step 4: Run temporary tests to verify GREEN**

```bash
uv run --with pytest --with scapy pytest -q /tmp/test_fnos_request_capture.py
```

Expected: all temporary decoder and sanitizer tests pass.

- [ ] **Step 5: Stop capture and extract candidates**

Stop the exact PID from `/tmp/fnos-requests-round3.pid`, make the PCAP readable by the current user, and run:

```bash
uv run --with scapy python /tmp/fnos_request_capture.py \
  --pcap /tmp/fnos-requests-round3.pcap \
  --allowlist /tmp/fnos-request-allowlist.txt \
  --output /tmp/fnos-request-candidates
```

Expected report fields: total client messages, parsed JSON messages, allowlisted messages, rejected sensitive messages, unique request types, and unique canonical cases.

---

### Task 5: Review and add request case files

**Files:**
- Create: `requests/<req>/case-N.json`
- Test: `tests/test_request_fixtures.py`

**Interfaces:**
- Consumes: reviewed candidate JSON files from `/tmp/fnos-request-candidates`.
- Produces: stable SDK request examples.

- [ ] **Step 1: Perform a pre-write candidate audit**

Verify every candidate:

```python
assert candidate["req"] in allowed_reqs
assert candidate["req"] != "encrypted"
assert candidate.get("reqid", CAPTURED_REQID) == CAPTURED_REQID
assert Path("responses", candidate["req"] + ".json").exists()
```

Run recursive URL/IP/email/MAC/path/sensitive-key checks. Reject a candidate on any violation; do not repair ambiguous sensitive data automatically.

- [ ] **Step 2: Merge without overwriting existing cases**

For each `req`, load existing `case-*.json`, compare canonical JSON, and append only unseen candidates as `case-{max_number + 1}.json`. Use `apply_patch` to add the reviewed JSON files with two-space indentation, sorted keys, and trailing newlines.

- [ ] **Step 3: Run request fixture tests to verify GREEN**

```bash
.venv/bin/pytest -q tests/test_request_fixtures.py
```

Expected: all request corpus, numbering, uniqueness, linkage, and security tests pass.

- [ ] **Step 4: Commit the request corpus**

```bash
git add tests/test_request_fixtures.py requests
git commit -m "feat: add captured fnOS API request fixtures"
```

Verify the commit message contains no `Co-Authored-By` trailer.

---

### Task 6: Full verification and raw-data cleanup

**Files:**
- Verify: `requests/**/*.json`
- Verify: `responses/*.json`
- Delete: all `/tmp/fnos-request-*` and `/tmp/fnos-requests-round3.*` artifacts

**Interfaces:**
- Consumes: final committed request corpus.
- Produces: test and audit evidence with no raw capture residue.

- [ ] **Step 1: Run the complete project test suite**

Start the local server and run:

```bash
.venv/bin/pytest -q
git diff --check
```

Expected: all tests pass and `git diff --check` exits 0.

- [ ] **Step 2: Verify extraction scope**

```bash
find requests -mindepth 2 -maxdepth 2 -name 'case-*.json' -print \
  | sed -E 's#^requests/([^/]+)/.*#\1#' \
  | LC_ALL=C sort -u \
  | comm -23 - /tmp/fnos-request-allowlist.txt
```

Expected: no output. Also report observed allowlisted request types and total unique cases.

- [ ] **Step 3: Remove raw and temporary artifacts**

```bash
rm -rf /tmp/fnos-request-allowlist.txt \
  /tmp/fnos-request-ports.txt \
  /tmp/fnos-request-candidates \
  /tmp/fnos_request_capture.py \
  /tmp/test_fnos_request_capture.py \
  /tmp/fnos-requests-round3.pcap \
  /tmp/fnos-requests-round3.pid \
  /tmp/fnos-requests-round3.log
```

If a root-owned capture remains, stop and remove it with explicit administrator authorization before claiming completion.

- [ ] **Step 4: Verify repository and temporary-directory cleanliness**

```bash
git status -sb
find . -type f \( -name '*.pcap' -o -name '*request_capture*' \) -print
```

Expected: only intentional committed changes and no repository capture artifacts.
