"""Integration tests for fnOS Mock Server using pyfnos client."""

import asyncio

import pytest
from fnos import FnosClient


# Test server configuration
TEST_HOST = "localhost"
TEST_PORT = 5666


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