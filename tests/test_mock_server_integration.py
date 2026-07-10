"""Integration tests for fnOS Mock Server using pyfnos client."""

import asyncio
import json
import re
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from fnos import FnosClient
from server.handlers import route_request


# Test server configuration
TEST_HOST = "localhost"
TEST_PORT = 5666
RESPONSES_DIR = Path(__file__).resolve().parents[1] / "responses"
CAPTURED_REQID = "0000000000000000000000000000"
DYNAMIC_RESPONSE_REQUESTS = {"appcgi.sysinfo.getHostName"}


@pytest.mark.parametrize(
    "response_path",
    sorted(RESPONSES_DIR.glob("*.json")),
    ids=lambda path: path.name,
)
def test_response_file_is_valid_and_routable(response_path: Path):
    """Every response must be a routable JSON object with a replaceable reqid."""
    with response_path.open(encoding="utf-8") as response_file:
        response = json.load(response_file)
    assert isinstance(response, dict)
    assert isinstance(response.get("reqid"), str)
    if "req" in response:
        assert response["req"] == response_path.stem
    routed = route_request({"req": response_path.stem, "reqid": "test-reqid"})
    if response_path.stem in DYNAMIC_RESPONSE_REQUESTS:
        assert routed.get("result") == "succ"
        assert routed.get("req") == response_path.stem
        assert routed.get("reqid") == "test-reqid"
    else:
        expected = {**response, "reqid": "test-reqid"}
        assert routed == expected


def test_unknown_response_is_not_routable():
    """An error response must not satisfy the fixture-routing contract."""
    routed = route_request({"req": "definitely.missing.fixture", "reqid": "test-reqid"})
    assert routed.get("result") == "fail"
    assert routed.get("errmsg") == "Unknown request type: definitely.missing.fixture"


def test_captured_environment_fingerprints_are_synthetic():
    """Captured fixtures must use stable examples instead of NAS fingerprints."""
    cache_devices = json.loads((RESPONSES_DIR / "stor.listCachedev.json").read_text())
    assert [disk["name"] for disk in cache_devices["disk"]] == ["nvme0n1", "nvme1n1"]
    assert [disk["modelName"] for disk in cache_devices["disk"]] == [
        "Example NVMe SSD 2TB",
        "Example NVMe SSD 1TB",
    ]
    assert {disk["firmwareVersion"] for disk in cache_devices["disk"]} == {"1.0.0"}
    assert [disk["size"] for disk in cache_devices["disk"]] == [
        2_000_000_000_000,
        1_000_000_000_000,
    ]

    entry_list = json.loads(
        (RESPONSES_DIR / "appcgi.sac.entry.v1.getEntryList.json").read_text()
    )
    desktop = json.loads(
        (RESPONSES_DIR / "appcgi.sac.entry.v1.getUserDesktop.json").read_text()
    )
    expected_installed_entries = {"trim.media": "entry:1001", "trim.vm": "entry:1002"}
    assert {
        entry["appName"]: entry["entryKey"]
        for entry in entry_list["data"]["list"]
        if entry["appName"] in expected_installed_entries
    } == expected_installed_entries
    assert {
        item["entry"]["appName"]: item["entryKey"]
        for item in desktop["data"]["list"]
        if item["entry"]["appName"] in expected_installed_entries
    } == expected_installed_entries

    mount_list = json.loads((RESPONSES_DIR / "appcgi.mountmgr.list.json").read_text())
    assert {mount["time"] for mount in mount_list["rsp"]} == {1_704_067_200}
    group_list = json.loads((RESPONSES_DIR / "user.groupList.json").read_text())
    assert group_list["uver"] == 111_677_748_019_200
    license_info = json.loads((RESPONSES_DIR / "appcgi.license.soft.get.json").read_text())
    ipc_license = json.loads(
        (RESPONSES_DIR / "appcgi.license.soft.ipc.get.json").read_text()
    )
    certificate = json.loads((RESPONSES_DIR / "appcgi.netsvr.cert.list.json").read_text())
    assert (license_info["data"]["validFrom"], license_info["data"]["validTo"]) == (
        1_704_067_200_000,
        4_102_444_800_000,
    )
    assert (ipc_license["data"]["validFrom"], ipc_license["data"]["validTo"]) == (
        1_704_067_200_000,
        4_102_444_800_000,
    )
    assert (certificate["data"][0]["validFrom"], certificate["data"][0]["validTo"]) == (
        1_704_067_200_000,
        4_102_444_800_000,
    )

    image_list = json.loads(
        (RESPONSES_DIR / "appcgi.dockermgr.imageList.json").read_text()
    )
    assert [image["RepoTags"] for image in image_list["rsp"]] == [
        ["example/app:latest"],
        ["example/worker:1.0"],
    ]
    assert {image["Created"] for image in image_list["rsp"]} == {1_704_067_200}
    image_ids = [image["Id"] for image in image_list["rsp"]]
    assert len(image_ids) == len(set(image_ids))
    assert [image["RepoDigests"][0].rsplit("@", 1)[1] for image in image_list["rsp"]] == image_ids

    network_list = json.loads(
        (RESPONSES_DIR / "appcgi.dockermgr.networkList.json").read_text()
    )
    network_ids = [network["Id"] for network in network_list["rsp"]]
    assert len(network_ids) == len(set(network_ids))
    container_ids = {
        container_id
        for network in network_list["rsp"]
        for container_id in network["Containers"]
    }
    assert container_ids.isdisjoint(network_ids)

    network_info = json.loads(
        (RESPONSES_DIR / "appcgi.network.net.info.json").read_text()
    )["data"]["ifs"]
    assert [slave["name"] for slave in network_info["slaves"]] == ["eth1", "eth2"]
    assert network_info["ipv4"] == ["192.0.2.2"]
    assert network_info["ipv4Addr"] == "192.0.2.2"
    assert network_info["ipv4Broad"] == "192.0.2.255"
    assert network_info["ipv4Gateway"] == "192.0.2.1"
    assert network_info["ipv4Mask"] == "255.255.255.0"

    process_list = json.loads(
        (RESPONSES_DIR / "appcgi.resmon.proc.list.json").read_text()
    )
    assert [process["name"] for process in process_list["data"]["list"]] == [
        "example-service",
        "example-worker",
    ]
    assert [process["pid"] for process in process_list["data"]["list"]] == [1001, 1002]

    traffic = json.loads(
        (RESPONSES_DIR / "appcgi.security.flowaudit.traffic.json").read_text()
    )
    assert [process["process"] for process in traffic["data"]] == [
        "example-service",
        "example-worker",
    ]
    assert [process["pid"] for process in traffic["data"]] == [1001, 1002]

    directory = json.loads((RESPONSES_DIR / "file.lsDir.json").read_text())
    assert directory["uver"] == 111_677_748_019_200
    assert [item["name"] for item in directory["files"]] == [
        "example-folder",
        "example.txt",
    ]
    assert {item["mtim"] for item in directory["files"]} == {1_704_067_200}
    assert {item["btim"] for item in directory["files"]} == {1_704_067_200}

    removable = json.loads((RESPONSES_DIR / "stor.listRemovable.json").read_text())
    assert [disk["modelName"] for disk in removable["removable"]] == [
        "Example Removable SSD 1TB",
        "Example Removable SSD 2TB",
    ]
    assert {disk["firmwareVersion"] for disk in removable["removable"]} == {"1.0.0"}
    assert [disk["fssize"] for disk in removable["removable"]] == [
        1_000_000_000_000,
        2_000_000_000_000,
    ]

    login_devices = json.loads(
        (RESPONSES_DIR / "user.listLoginDevice.json").read_text()
    )
    assert [device["deviceName"] for device in login_devices["loginDevice"]] == [
        "Example Browser",
        "Example Mobile Device",
    ]
    assert {device["loginTime"] for device in login_devices["loginDevice"]} == {
        1_704_067_200
    }


def test_captured_response_sensitive_values_are_allowlisted():
    """Captured fixtures must not regain raw environment identifiers or secrets."""
    allowed_url_hosts = {"www.timandes.cn"}
    allowed_ipv4 = {
        "192.0.2.0",
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.255",
        "255.255.255.0",
    }
    allowed_emails = {"user@example.com"}
    allowed_macs = {"00:00:5E:00:53:01"}
    allowed_ip_literals = allowed_ipv4 | {"2001:db8::1"}
    exact_sensitive_keys = {
        "accesskey",
        "backid",
        "deviceid",
        "machineid",
        "serialnumber",
        "sign",
        "tid",
        "uuid",
    }
    sensitive_key_fragments = {
        "apikey",
        "licensecode",
        "passwd",
        "password",
        "privatekey",
        "publickey",
        "secret",
        "signature",
        "token",
    }
    address_keys = {
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
    }
    ip_value_keys = {
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
    allowed_address_values = allowed_ip_literals | allowed_macs | {
        "",
        "www.timandes.cn",
        "http://www.timandes.cn",
        "https://www.timandes.cn",
    }
    url_pattern = re.compile(r"https?://[^\s\"<>]+", re.IGNORECASE)
    ipv4_pattern = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
    email_pattern = re.compile(
        r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE
    )
    mac_pattern = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", re.IGNORECASE)
    volume_pattern = re.compile(r"/vol\d+(?:/[^\s,;\"']*)?")
    raw_fingerprint_pattern = re.compile(
        r"nas-11|/Users/|Fanxiang|ZHITAI|TiPlus|H240509|ZTA22003|"
        r"iPad|iPhone|Mac OS|Windows-Google|ghcr\.io/timandes",
        re.IGNORECASE,
    )

    captured_paths = []
    for response_path in RESPONSES_DIR.glob("*.json"):
        response = json.loads(response_path.read_text())
        if response.get("reqid") != CAPTURED_REQID:
            continue
        captured_paths.append(response_path)

        def inspect_value(value, key=""):
            if isinstance(value, dict):
                for child_key, child_value in value.items():
                    inspect_value(child_value, child_key)
                return
            if isinstance(value, list):
                for child_value in value:
                    inspect_value(child_value, key)
                return
            if not isinstance(value, str):
                return

            assert not raw_fingerprint_pattern.search(value), response_path
            assert {
                urlsplit(url).hostname for url in url_pattern.findall(value)
            } <= allowed_url_hosts, response_path
            assert set(ipv4_pattern.findall(value)) <= allowed_ipv4, response_path
            assert {
                email.lower() for email in email_pattern.findall(value)
            } <= allowed_emails, response_path
            assert {
                mac.upper() for mac in mac_pattern.findall(value)
            } <= allowed_macs, response_path
            assert set(volume_pattern.findall(value)) <= {"/vol1/example"}, response_path

            normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
            if normalized_key in address_keys:
                assert value in allowed_address_values, response_path
            if normalized_key in ip_value_keys and value:
                assert str(ip_address(value)) in allowed_ip_literals, response_path
            if normalized_key in exact_sensitive_keys or any(
                fragment in normalized_key for fragment in sensitive_key_fragments
            ):
                assert value in {"", "<redacted>"} or set(value) == {"0"}, response_path

        inspect_value(response)

    assert len(captured_paths) == 78


@pytest.fixture
async def client():
    """Create and connect a test client."""
    client = FnosClient()
    await client.connect(f"{TEST_HOST}:{TEST_PORT}")
    yield client
    await client.close()


@pytest.mark.asyncio
async def test_websocket_connection(client: FnosClient):
    """Test that WebSocket connection can be established."""
    assert client.connected is True


@pytest.mark.asyncio
async def test_get_rsa_public_key(client: FnosClient):
    """Test util.crypto.getRSAPub request."""
    assert client.public_key is not None
    assert "BEGIN PUBLIC KEY" in client.public_key
    assert "END PUBLIC KEY" in client.public_key


@pytest.mark.asyncio
async def test_get_hostname(client: FnosClient):
    """Test appcgi.sysinfo.getHostName request."""
    # Wait for getHostName response to arrive
    await asyncio.sleep(0.5)
    assert client.host_name is not None
    assert client.host_name == "www.timandes.cn"
    assert client.trim_version is not None


@pytest.mark.asyncio
async def test_user_login(client: FnosClient):
    """Test user.login request."""
    result = await client.login("testuser", "testpass")
    assert result is not None
    assert result.get("result") == "succ"
    assert "token" in result
    assert "longToken" in result
    assert "secret" in result


@pytest.mark.asyncio
async def test_get_decrypted_secret(client: FnosClient):
    """Test that secret is properly decrypted."""
    await client.login("testuser", "testpass")
    # Mock server doesn't support real encryption, so we just check that login succeeded
    # The secret field exists in the response even if it can't be properly decrypted
    assert client.login_response is not None
    assert "secret" in client.login_response


@pytest.mark.asyncio
async def test_user_info_request(client: FnosClient):
    """Test user.info request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("user.info", {})
    assert response is not None
    assert response.get("req") == "user.info"
    assert response.get("result") == "succ"


@pytest.mark.asyncio
async def test_resource_monitor_cpu(client: FnosClient):
    """Test appcgi.resmon.cpu request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.resmon.cpu", {})
    assert response is not None
    assert response.get("req") == "appcgi.resmon.cpu"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "cpu" in response["data"]


@pytest.mark.asyncio
async def test_resource_monitor_memory(client: FnosClient):
    """Test appcgi.resmon.mem request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.resmon.mem", {})
    assert response is not None
    assert response.get("req") == "appcgi.resmon.mem"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "mem" in response["data"]


@pytest.mark.asyncio
async def test_resource_monitor_gpu(client: FnosClient):
    """Test appcgi.resmon.gpu request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.resmon.gpu", {})
    assert response is not None
    assert response.get("req") == "appcgi.resmon.gpu"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "gpu" in response["data"]


@pytest.mark.asyncio
async def test_storage_general(client: FnosClient):
    """Test stor.general request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("stor.general", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "array" in response
    assert "block" in response


@pytest.mark.asyncio
async def test_resource_monitor_general(client: FnosClient):
    """Test appcgi.resmon.gen request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.resmon.gen", {})
    assert response is not None
    assert response.get("req") == "appcgi.resmon.gen"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "item" in response["data"]


@pytest.mark.asyncio
async def test_storage_state2(client: FnosClient):
    """Test stor.state2 request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("stor.state2", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "state" in response


@pytest.mark.asyncio
async def test_app_store_list(client: FnosClient):
    """Test appcgi.sac.entry.v1.appStoreList request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.sac.entry.v1.appStoreList", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "data" in response
    assert "list" in response["data"]


@pytest.mark.asyncio
async def test_liveupdate_check(client: FnosClient):
    """Test liveupdate.check request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("liveupdate.check", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "packages" in response


@pytest.mark.asyncio
async def test_notify_list(client: FnosClient):
    """Test notify.list request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("notify.list", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "notifyList" in response
    assert "total" in response


@pytest.mark.asyncio
async def test_get_uptime(client: FnosClient):
    """Test appcgi.sysinfo.getUptime request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.sysinfo.getUptime", {})
    assert response is not None
    assert response.get("req") == "appcgi.sysinfo.getUptime"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "uptime" in response["data"]


@pytest.mark.asyncio
async def test_desktop_get_config(client: FnosClient):
    """Test appcgi.sac.desktop.v1.getConfig request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.sac.desktop.v1.getConfig", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "data" in response
    assert "userPreference" in response["data"]


@pytest.mark.asyncio
async def test_team_ls_dir(client: FnosClient):
    """Test file.team.lsDir request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("file.team.lsDir", {})
    assert response is not None
    assert "files" in response
    assert "uver" in response


@pytest.mark.asyncio
async def test_get_machine_id(client: FnosClient):
    """Test appcgi.sysinfo.getMachineId request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.sysinfo.getMachineId", {})
    assert response is not None
    assert response.get("req") == "appcgi.sysinfo.getMachineId"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "machineId" in response["data"]


@pytest.mark.asyncio
async def test_get_hardware_info(client: FnosClient):
    """Test appcgi.sysinfo.getHardwareInfo request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.sysinfo.getHardwareInfo", {})
    assert response is not None
    assert response.get("req") == "appcgi.sysinfo.getHardwareInfo"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "cpu" in response["data"]
    assert "mem" in response["data"]


@pytest.mark.asyncio
async def test_network_net_list(client: FnosClient):
    """Test appcgi.network.net.list request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.network.net.list", {})
    assert response is not None
    assert response.get("req") == "appcgi.network.net.list"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "net" in response["data"]
    assert "ifs" in response["data"]["net"]


@pytest.mark.asyncio
async def test_user_list(client: FnosClient):
    """Test user.list request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("user.list", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "users" in response
    assert "uver" in response


@pytest.mark.asyncio
async def test_get_hostname_request(client: FnosClient):
    """Test appcgi.sysinfo.getHostName request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.sysinfo.getHostName", {})
    assert response is not None
    assert response.get("req") == "appcgi.sysinfo.getHostName"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "hostName" in response["data"]


@pytest.mark.asyncio
async def test_network_net_detect(client: FnosClient):
    """Test appcgi.network.net.detect request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.network.net.detect", {})
    assert response is not None
    assert response.get("req") == "appcgi.network.net.detect"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "ifs" in response["data"]


@pytest.mark.asyncio
async def test_get_time_setting(client: FnosClient):
    """Test appcgi.sysinfo.getTimeSetting request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.sysinfo.getTimeSetting", {})
    assert response is not None
    assert response.get("req") == "appcgi.sysinfo.getTimeSetting"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "timezone" in response["data"]


@pytest.mark.asyncio
async def test_stor_list_stor(client: FnosClient):
    """Test stor.listStor request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("stor.listStor", {})
    assert response is not None
    assert "array" in response


@pytest.mark.asyncio
async def test_stor_state(client: FnosClient):
    """Test stor.state request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("stor.state", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "state" in response


@pytest.mark.asyncio
async def test_stor_disk_health(client: FnosClient):
    """Test stor.diskHealth request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("stor.diskHealth", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "diskHealth" in response


@pytest.mark.asyncio
async def test_stor_list_disk(client: FnosClient):
    """Test stor.listDisk request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("stor.listDisk", {})
    assert response is not None
    assert "disk" in response


@pytest.mark.asyncio
async def test_stor_disk_smart(client: FnosClient):
    """Test stor.diskSmart request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("stor.diskSmart", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "smart" in response


@pytest.mark.asyncio
async def test_resource_monitor_net(client: FnosClient):
    """Test appcgi.resmon.net request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.resmon.net", {})
    assert response is not None
    assert response.get("req") == "appcgi.resmon.net"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "ifs" in response["data"]


@pytest.mark.asyncio
async def test_resource_monitor_disk(client: FnosClient):
    """Test appcgi.resmon.disk request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.resmon.disk", {})
    assert response is not None
    assert response.get("req") == "appcgi.resmon.disk"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "disk" in response["data"]


@pytest.mark.asyncio
async def test_stor_calc_space(client: FnosClient):
    """Test stor.calcSpace request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("stor.calcSpace", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "storTotal" in response
    assert "fssizeStor" in response
    assert "frsizeStor" in response


@pytest.mark.asyncio
async def test_get_trim_version(client: FnosClient):
    """Test appcgi.sysinfo.getTrimVersion request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.sysinfo.getTrimVersion", {})
    assert response is not None
    assert response.get("req") == "appcgi.sysinfo.getTrimVersion"
    assert response.get("result") == "succ"
    assert "data" in response
    assert "trimVersion" in response["data"]


@pytest.mark.asyncio
async def test_ups_status(client: FnosClient):
    """Test appcgi.sac.ups.v1.status request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.sac.ups.v1.status", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "data" in response
    assert "upsEnabled" in response["data"]
    assert "currentUps" in response["data"]


@pytest.mark.asyncio
async def test_user_is_admin(client: FnosClient):
    """Test user.isAdmin request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("user.isAdmin", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "admin" in response


@pytest.mark.asyncio
async def test_user_list_ug(client: FnosClient):
    """Test user.listUG request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("user.listUG", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "users" in response
    assert "groups" in response


@pytest.mark.asyncio
async def test_user_group_users(client: FnosClient):
    """Test user.groupUsers request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("user.groupUsers", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "groups" in response


@pytest.mark.asyncio
async def test_file_ls(client: FnosClient):
    """Test file.ls request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("file.ls", {})
    assert response is not None
    assert "files" in response
    assert "uver" in response


@pytest.mark.asyncio
async def test_file_mkdir(client: FnosClient):
    """Test file.mkdir request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("file.mkdir", {})
    assert response is not None
    assert response.get("result") == "succ"


@pytest.mark.asyncio
async def test_file_rm(client: FnosClient):
    """Test file.rm request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("file.rm", {})
    assert response is not None
    assert "taskId" in response
    assert "sysNotify" in response


@pytest.mark.asyncio
async def test_heartbeat_ping(client: FnosClient):
    """Test ping/pong heartbeat mechanism."""
    # Ping is sent automatically by the client
    # We just need to verify the connection is still alive
    await asyncio.sleep(1)
    assert client.connected is True


@pytest.mark.asyncio
async def test_multiple_concurrent_clients():
    """Test handling multiple concurrent clients."""
    clients = []
    try:
        # Create and connect 5 clients
        for i in range(5):
            client = FnosClient()
            await client.connect(f"{TEST_HOST}:{TEST_PORT}")
            clients.append(client)

        # All clients should be connected
        for client in clients:
            assert client.connected is True

    finally:
        # Clean up
        for client in clients:
            try:
                await client.close()
            except Exception:
                pass


@pytest.mark.asyncio
async def test_invalid_request_type(client: FnosClient):
    """Test handling of unknown request types."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("invalid.request.type", {})
    assert response is not None
    assert response.get("result") == "fail"


@pytest.mark.asyncio
async def test_missing_reqid_field(client: FnosClient):
    """Test handling of requests without reqid."""
    # This test verifies that the server properly validates requests
    # The client handles reqid generation, so this is more of a documentation test
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("user.info", {})
    assert response is not None
    assert "reqid" in response


@pytest.mark.asyncio
async def test_login_via_token(client: FnosClient):
    """Test login via token."""
    # First login to get tokens
    login_result = await client.login("testuser", "testpass")
    token = login_result.get("token")
    long_token = login_result.get("longToken")
    secret = client.get_decrypted_secret()

    # Close and reconnect
    await client.close()
    client = FnosClient()
    await client.connect(f"{TEST_HOST}:{TEST_PORT}")

    # Login via token
    result = await client.login_via_token(token, long_token, secret)
    assert result is not None
    assert result.get("result") == "succ"


@pytest.mark.asyncio
async def test_reconnection():
    """Test client reconnection functionality."""
    client = FnosClient()
    await client.connect(f"{TEST_HOST}:{TEST_PORT}")
    await client.login("testuser", "testpass")

    # Close connection
    await client.close()
    assert client.connected is False

    # Reconnect
    await client.reconnect()
    assert client.connected is True

    await client.close()


@pytest.mark.asyncio
async def test_docker_compose_list(client: FnosClient):
    """Test appcgi.dockermgr.composeList request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.dockermgr.composeList", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "rsp" in response
    assert isinstance(response["rsp"], list)


@pytest.mark.asyncio
async def test_docker_container_list(client: FnosClient):
    """Test appcgi.dockermgr.containerList request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.dockermgr.containerList", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "rsp" in response
    assert isinstance(response["rsp"], list)


@pytest.mark.asyncio
async def test_docker_stats(client: FnosClient):
    """Test appcgi.dockermgr.stats request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.dockermgr.stats", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "rsp" in response
    assert isinstance(response["rsp"], dict)


@pytest.mark.asyncio
async def test_docker_system_setting_get(client: FnosClient):
    """Test appcgi.dockermgr.systemSettingGet request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.dockermgr.systemSettingGet", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "rsp" in response
    assert "mirrorsV2" in response["rsp"]
    assert "autoBoot" in response["rsp"]
    assert "status" in response["rsp"]


@pytest.mark.asyncio
async def test_eventlogger_common_list(client: FnosClient):
    """Test appcgi.eventlogger.common.list request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.eventlogger.common.list", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert response.get("req") == "appcgi.eventlogger.common.list"
    assert "data" in response
    assert "total" in response["data"]
    assert "rows" in response["data"]


@pytest.mark.asyncio
async def test_share_smb_opt(client: FnosClient):
    """Test appcgi.share.smb.opt request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("appcgi.share.smb.opt", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert response.get("req") == "appcgi.share.smb.opt"
    assert "data" in response
    assert "smbEnable" in response["data"]
    assert "option" in response["data"]
    assert "timeMachine" in response["data"]


@pytest.mark.asyncio
async def test_file_get_acl(client: FnosClient):
    """Test file.getAcl request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("file.getAcl", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "data" in response
    assert "uver" in response
    assert isinstance(response["data"], list)


@pytest.mark.asyncio
async def test_notify_unread_total(client: FnosClient):
    """Test notify.unreadTotal request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("notify.unreadTotal", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "unreadTotal" in response


@pytest.mark.asyncio
async def test_stor_get_user_storage(client: FnosClient):
    """Test stor.getUserStorage request."""
    await client.login("testuser", "testpass")
    response = await client.request_payload_with_response("stor.getUserStorage", {})
    assert response is not None
    assert response.get("result") == "succ"
    assert "stor" in response
    assert "uid" in response
    assert isinstance(response["stor"], list)
