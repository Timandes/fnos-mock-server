"""Contract and sanitization tests for captured fnOS request fixtures."""

import json
import re
from collections import defaultdict
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import pytest


ROOT = Path(__file__).resolve().parents[1]
REQUESTS_DIR = ROOT / "requests"
RESPONSES_DIR = ROOT / "responses"
CAPTURED_REQID = "0000000000000000000000000000"
CASE_PATTERN = re.compile(r"case-([1-9][0-9]*)\.json")

ALLOWED_URL_HOSTS = {"www.timandes.cn"}
ALLOWED_IPV4 = {
    "192.0.2.0",
    "192.0.2.1",
    "192.0.2.2",
    "192.0.2.255",
    "255.255.255.0",
}
ALLOWED_IP_LITERALS = ALLOWED_IPV4 | {"2001:db8::1"}
ALLOWED_EMAILS = {"user@example.com"}
ALLOWED_MACS = {"00:00:5E:00:53:01"}
SENSITIVE_KEY_PARTS = {
    "apikey",
    "authorization",
    "cookie",
    "credential",
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
EXACT_SENSITIVE_KEYS = {
    "accesskey",
    "authcode",
    "backid",
    "deviceid",
    "key",
    "machineid",
    "otp",
    "serialnumber",
    "sign",
    "tid",
    "totp",
    "uuid",
    "verifycode",
}
IDENTITY_KEYS = {"creator", "nickname", "owner", "realname", "user", "username"}
EMAIL_KEYS = {"email", "secureemail"}
DEVICE_NAME_KEYS = {"devicename"}
PATH_KEYS = {
    "directory",
    "dirpath",
    "filepath",
    "folderpath",
    "mountpath",
    "mountpoint",
    "path",
    "savedir",
}
ALLOWED_TIMESTAMPS = {1_704_067_200, 1_704_067_200_000, 4_102_444_800_000}
ALLOWED_DATE_STRINGS = {"2024-01-01T00:00:00Z"}
ADDRESS_KEYS = {
    "addr",
    "address",
    "domain",
    "fqdn",
    "host",
    "hostname",
    "hwaddr",
    "ip",
    "ipv4",
    "ipv4addr",
    "ipv4broad",
    "ipv4dns",
    "ipv4gateway",
    "ipv4mask",
    "ipv6",
    "ipv6dns",
    "ipv6gateway",
    "mac",
    "macaddr",
    "macaddress",
    "serveraddress",
    "server",
}
IP_VALUE_KEYS = {
    "addr",
    "ip",
    "ipv4",
    "ipv4addr",
    "ipv4broad",
    "ipv4dns",
    "ipv4gateway",
    "ipv4mask",
    "ipv6",
    "ipv6dns",
    "ipv6gateway",
}
ALLOWED_ADDRESS_VALUES = ALLOWED_IP_LITERALS | ALLOWED_MACS | {
    "",
    "www.timandes.cn",
    "http://www.timandes.cn",
    "https://www.timandes.cn",
}
ALLOWED_DOTTED_VALUES = {"browser.namesakeConf", "www.timandes.cn"}

URL_PATTERN = re.compile(r"(?:https?|wss?|file)://[^\s\"<>]+", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
EMAIL_PATTERN = re.compile(
    r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE
)
MAC_PATTERN = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", re.IGNORECASE)
VOLUME_PATTERN = re.compile(r"/vol\d+(?:/[^\s,;\"']*)?")
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![\w.])/(?:Users|etc|home|media|mnt|opt|private|root|srv|tmp|var)"
    r"(?:/[^\s,;\"']*)?"
)
UUID_PATTERN = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
OPAQUE_ID_PATTERN = re.compile(r"(?:[0-9a-fA-F]{16,}|[A-Za-z0-9+/_=-]{24,})")
DOMAIN_PATTERN = re.compile(
    r"(?i)(?<![@\w])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![\w])"
)
RAW_FINGERPRINT_PATTERN = re.compile(
    r"nas-11|/Users/|Fanxiang|ZHITAI|TiPlus|H240509|ZTA22003|"
    r"iPad|iPhone|Mac OS|Windows-Google|ghcr\.io/timandes",
    re.IGNORECASE,
)


def request_cases() -> list[Path]:
    """Return every captured request case in deterministic order."""
    return sorted(REQUESTS_DIR.glob("*/case-*.json"))


def canonical_json(value: dict) -> str:
    """Serialize JSON deterministically for duplicate detection."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def assert_value_is_sanitized(value, key: str = "") -> None:
    """Recursively enforce the captured-fixture sensitive value allowlist."""
    normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
    sensitive_key = normalized_key in EXACT_SENSITIVE_KEYS or any(
        part in normalized_key for part in SENSITIVE_KEY_PARTS
    )
    identity_key = (
        normalized_key in IDENTITY_KEYS
        or "account" in normalized_key
        or normalized_key.endswith("username")
    )
    time_key = (
        "time" in normalized_key
        or "timestamp" in normalized_key
        or normalized_key.endswith("date")
    )
    path_key = "path" in normalized_key or normalized_key in PATH_KEYS
    address_key = (
        normalized_key in ADDRESS_KEYS
        or normalized_key in IP_VALUE_KEYS
        or normalized_key in EMAIL_KEYS
    )
    device_key = "device" in normalized_key or "model" in normalized_key
    process_key = "process" in normalized_key
    interface_key = normalized_key == "interface" or "ifname" in normalized_key
    group_key = "group" in normalized_key
    id_key = normalized_key in {"pid", "uid"} or normalized_key.endswith(
        ("userid", "processid", "groupid")
    )
    protected_container_key = (
        sensitive_key
        or identity_key
        or id_key
        or time_key
        or path_key
        or address_key
        or device_key
        or process_key
        or interface_key
        or group_key
    )
    if isinstance(value, dict):
        assert not protected_container_key
        for child_key, child_value in value.items():
            assert_value_is_sanitized(child_value, child_key)
        return
    if isinstance(value, list):
        assert not protected_container_key
        for child_value in value:
            assert_value_is_sanitized(child_value, key)
        return

    if sensitive_key:
        if isinstance(value, str):
            assert value in {"", "<redacted>"} or set(value) == {"0"}
        elif isinstance(value, (int, float)):
            assert value == 0
        else:
            raise AssertionError(f"unsupported sensitive value type for {key}")
    if normalized_key == "pid":
        assert value in {1001, 1002}
    if normalized_key == "uid":
        assert value == 1000
    if normalized_key.endswith("userid"):
        assert value == 1000
    if normalized_key.endswith("processid"):
        assert value in {1001, 1002}
    if normalized_key.endswith("groupid"):
        assert value == 1000
    if identity_key:
        assert value == "user"
    if isinstance(value, (int, float)):
        if time_key:
            assert value in ALLOWED_TIMESTAMPS
        if normalized_key.endswith("userid"):
            assert value == 1000
    if not isinstance(value, str):
        return

    assert not RAW_FINGERPRINT_PATTERN.search(value)
    assert {
        urlsplit(url).hostname for url in URL_PATTERN.findall(value)
    } <= ALLOWED_URL_HOSTS
    assert set(IPV4_PATTERN.findall(value)) <= ALLOWED_IPV4
    assert {email.lower() for email in EMAIL_PATTERN.findall(value)} <= ALLOWED_EMAILS
    assert {mac.upper() for mac in MAC_PATTERN.findall(value)} <= ALLOWED_MACS
    assert set(VOLUME_PATTERN.findall(value)) <= {"/vol1/example"}
    assert not ABSOLUTE_PATH_PATTERN.search(value)
    assert not UUID_PATTERN.search(value)

    for token in re.split(r"[\s,;()\[\]{}]+", value):
        path_candidate = token.strip("'\"")
        if path_candidate.startswith("/") and not path_candidate.startswith("//"):
            assert path_candidate == "/vol1/example"

    for token in re.split(r"[\s,;()\[\]{}]+", value):
        candidate = token.strip("'\"")
        if ":" not in candidate or MAC_PATTERN.fullmatch(candidate):
            continue
        try:
            parsed_address = str(ip_address(candidate))
        except ValueError:
            continue
        assert parsed_address in ALLOWED_IP_LITERALS

    if normalized_key != "req" and value not in ALLOWED_DOTTED_VALUES | ALLOWED_EMAILS:
        assert set(DOMAIN_PATTERN.findall(value)) <= ALLOWED_URL_HOSTS

    if normalized_key == "process":
        assert value in {"example-process", "example-worker"}
    if normalized_key == "group":
        assert value == "group"
    if normalized_key == "ifname":
        assert value == "eth0"
    if normalized_key in EMAIL_KEYS:
        assert value == "user@example.com"
    if normalized_key in DEVICE_NAME_KEYS:
        assert value == "Example Device"
    if "model" in normalized_key:
        assert value == "Example Model"
    if "device" in normalized_key:
        assert value in {"Example Device", "<redacted>"}
    if process_key:
        assert value in {"example-process", "example-worker"}
    if interface_key:
        assert value == "eth0"
    if group_key:
        assert value == "group"
    if path_key:
        assert value == "/vol1/example"
    if time_key:
        assert value in ALLOWED_DATE_STRINGS
    if normalized_key in ADDRESS_KEYS:
        assert value in ALLOWED_ADDRESS_VALUES
    if normalized_key in IP_VALUE_KEYS and value:
        assert str(ip_address(value)) in ALLOWED_IP_LITERALS
    if normalized_key not in {"req", "reqid"} and OPAQUE_ID_PATTERN.fullmatch(value):
        assert value == "<redacted>" or set(value) == {"0"}


def test_request_fixture_corpus_is_not_empty():
    """At least one allowlisted request must have been captured."""
    assert request_cases()


@pytest.mark.parametrize(
    "case_path",
    request_cases(),
    ids=lambda path: str(path.relative_to(ROOT)),
)
def test_request_case_contract(case_path: Path):
    """Each case must match its directory and a captured response fixture."""
    request = json.loads(case_path.read_text(encoding="utf-8"))
    assert isinstance(request, dict)
    assert isinstance(request.get("req"), str)
    assert request["req"] != "encrypted"
    assert request["req"] == case_path.parent.name
    if "reqid" in request:
        assert request["reqid"] == CAPTURED_REQID

    response_path = RESPONSES_DIR / f"{request['req']}.json"
    response = json.loads(response_path.read_text(encoding="utf-8"))
    assert response.get("reqid") == CAPTURED_REQID
    assert_value_is_sanitized(request)


def test_request_case_numbers_are_contiguous_and_cases_are_unique():
    """Case numbering is stable and canonical duplicates are forbidden."""
    cases_by_req: dict[str, list[Path]] = defaultdict(list)
    for case_path in request_cases():
        assert CASE_PATTERN.fullmatch(case_path.name)
        cases_by_req[case_path.parent.name].append(case_path)

    for req, paths in cases_by_req.items():
        numbers = sorted(
            int(CASE_PATTERN.fullmatch(path.name).group(1)) for path in paths
        )
        assert numbers == list(range(1, len(numbers) + 1)), req
        canonical_cases = {
            canonical_json(json.loads(path.read_text(encoding="utf-8")))
            for path in paths
        }
        assert len(canonical_cases) == len(paths), req


def test_requests_tree_contains_only_canonical_case_files():
    """No hidden artifacts, empty request dirs, or noncanonical JSON are allowed."""
    case_paths = request_cases()
    all_files = sorted(path for path in REQUESTS_DIR.rglob("*") if path.is_file())
    assert all_files == case_paths

    request_dirs = sorted(path for path in REQUESTS_DIR.iterdir() if path.is_dir())
    assert request_dirs
    for request_dir in request_dirs:
        assert any(path.parent == request_dir for path in case_paths)

    for case_path in case_paths:
        raw_text = case_path.read_text(encoding="utf-8")
        value = json.loads(raw_text)
        expected = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        assert raw_text == expected


@pytest.mark.parametrize(
    "raw_value",
    [
        pytest.param({"path": "/mnt/private/file.txt"}, id="absolute-path"),
        pytest.param(
            {"value": "550e8400-e29b-41d4-a716-446655440000"}, id="uuid"
        ),
        pytest.param({"createdTime": 1_783_685_045}, id="timestamp"),
        pytest.param({"username": "private-user"}, id="username"),
        pytest.param({"Authorization": "Bearer private-token"}, id="authorization"),
        pytest.param({"Cookie": "session=private-cookie"}, id="cookie"),
        pytest.param({"value": "fe80::1"}, id="ipv6"),
        pytest.param({"server": "private.example.net"}, id="bare-domain"),
        pytest.param({"deviceName": "Private Phone"}, id="device-name"),
        pytest.param({"key": "private-key-material"}, id="bare-key"),
        pytest.param(
            {"value": "0123456789abcdef0123456789abcdef"}, id="opaque-id"
        ),
        pytest.param(
            {"downloadPath": "/data/private/alice"}, id="generic-path-key"
        ),
        pytest.param(
            {"value": "/volume1/private/alice"}, id="generic-absolute-path"
        ),
        pytest.param({"time": 1_783_685_045}, id="generic-time"),
        pytest.param({"date": "2026-07-11T00:00:00Z"}, id="iso-date"),
        pytest.param({"account": "private-user"}, id="account"),
        pytest.param({"userId": 12345}, id="user-id"),
        pytest.param({"model": "Private NAS Model"}, id="device-model"),
        pytest.param({"processName": "private-daemon"}, id="process-name"),
        pytest.param({"interface": "en7"}, id="interface"),
        pytest.param({"groupName": "private-admins"}, id="group-name"),
        pytest.param({"otp": 123456}, id="numeric-otp"),
        pytest.param({"verifyCode": 654321}, id="numeric-verify-code"),
        pytest.param({"token": 987654321}, id="numeric-token"),
        pytest.param({"key": 1234567890}, id="numeric-key"),
        pytest.param({"account": 12345}, id="numeric-account"),
        pytest.param({"deviceId": 987654321}, id="numeric-device-id"),
        pytest.param({"machineId": 876543210}, id="numeric-machine-id"),
        pytest.param({"processId": 43210}, id="numeric-process-id"),
        pytest.param({"groupId": 34567}, id="numeric-group-id"),
        pytest.param({"userId": "private-user-id"}, id="string-user-id"),
        pytest.param(
            {"value": "file:///data/private/alice"}, id="file-uri-path"
        ),
        pytest.param(
            {"token": {"value": "live-token-value"}}, id="object-token"
        ),
        pytest.param(
            {"session": {"id": "private-session"}}, id="object-session"
        ),
        pytest.param(
            {
                "authorization": {
                    "scheme": "Bearer",
                    "value": "private-authorization",
                }
            },
            id="object-authorization",
        ),
        pytest.param(
            {"account": {"name": "private-user"}}, id="object-account"
        ),
        pytest.param(
            {"time": {"value": 1_783_685_045}}, id="object-time"
        ),
        pytest.param(
            {"createdTime": {"value": 1_783_685_045}}, id="object-created-time"
        ),
        pytest.param(
            {"directory": {"value": "private/alice"}}, id="object-directory"
        ),
        pytest.param(
            {"ipv4": ["192.168.1.10"]}, id="object-address-list"
        ),
        pytest.param({"pid": {"value": 54321}}, id="object-pid"),
        pytest.param({"uid": {"value": 12345}}, id="object-uid"),
    ],
)
def test_sensitive_value_audit_rejects_raw_environment_data(raw_value):
    """Known sensitive input classes must make the audit fail closed."""
    with pytest.raises((AssertionError, ValueError)):
        assert_value_is_sanitized(raw_value)
