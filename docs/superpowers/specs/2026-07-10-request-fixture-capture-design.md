# Request Fixture Capture Design

## Goal

Capture client-to-server fnOS WebSocket JSON request bodies and store sanitized,
deduplicated SDK reference cases under `requests/<req>/case-N.json`.

## Scope

The capture allowlist is derived from response files added on the current branch relative to
the repository baseline branch `main`:

```bash
git diff --diff-filter=A --name-only main...HEAD -- 'responses/*.json'
```

Each added response filename contributes its stem as an allowed `req` value. At the time of
this design, the branch adds 78 response files. Requests for response types already present on
`main` are ignored even if they appear in the packet capture.

The feature adds reference data and validation only. The mock server does not load request
fixtures at runtime.

## Storage Contract

Each retained request is a standalone JSON object:

```text
requests/
└── <req>/
    ├── case-1.json
    └── case-2.json
```

- The directory name exactly matches the JSON `req` value.
- Case numbers start at 1 and remain contiguous within a directory.
- Existing cases are never overwritten or renumbered.
- A later capture appends the next case number only when its normalized JSON differs from every
  existing case for that `req`.
- Files use UTF-8, two-space indentation, sorted keys, and a trailing newline.

## Capture and Parsing

The user performs read-only navigation in the existing authenticated Chrome session. Packet
capture is limited to the current fnOS WebSocket TCP connections. The parser:

1. Reassembles client-to-server TCP streams.
2. Decodes masked WebSocket text frames.
3. Removes the HMAC/signature prefix by locating the JSON object boundary.
4. Parses the JSON object and reads its `req` value.
5. Discards requests whose `req` is not in the branch-derived allowlist.
6. Discards opaque authentication requests such as `req: encrypted`; encrypted payloads and
   login credentials are never persisted.

Raw packet captures and temporary parsing artifacts remain outside the repository and are
deleted after successful extraction and verification.

## Normalization and Deduplication

Deduplication compares canonical JSON after sanitization and normalization, not raw frame bytes.
The canonical representation uses sorted object keys and compact JSON encoding.

- `reqid` becomes `0000000000000000000000000000`.
- Signatures, passwords, tokens, secrets, keys, session values, and opaque identifiers become
  `<redacted>`.
- Usernames, email addresses, hostnames, IP addresses, MAC addresses, device identifiers,
  storage paths, mount paths, serial numbers, disk fingerprints, and timestamps use the same
  documented synthetic values already enforced for captured response fixtures.
- Array order and business parameters are preserved because they may affect SDK behavior.
- Two requests with identical field structure but different sanitized business parameter values
  remain separate cases.
- Repeated polling requests collapse to one case after volatile values are normalized.

## Failure Handling

- Malformed WebSocket frames or invalid JSON are skipped and counted in the extraction report.
- Missing or non-string `req` values are skipped.
- A request that cannot be safely sanitized is rejected instead of being written.
- Existing case files that are invalid, duplicated, or non-contiguous cause validation to fail;
  extraction does not silently rewrite them.
- If no allowlisted request is observed, the run reports zero additions without changing the
  repository.

## Verification

Automated tests validate every `requests/*/case-*.json` file:

- it is one JSON object;
- its directory name equals its string `req` value;
- `reqid` uses the fixed placeholder when present;
- case numbers are contiguous and canonical cases are unique within each `req` directory;
- sensitive strings, addresses, paths, identifiers, and authentication material satisfy the
  same allowlist-based audit used by captured response fixtures;
- every request directory has a matching captured response fixture whose top-level `reqid` is
  `0000000000000000000000000000`.

The one-time extraction report separately verifies that every persisted `req` belongs to the
allowlist computed from response files added on the current branch relative to `main`. Keeping
that branch-dependent check out of the permanent test suite ensures the tests continue to pass
after the feature branch is merged into `main`.

The full test suite must pass before the raw capture is removed and the new request fixtures are
reported as complete.
