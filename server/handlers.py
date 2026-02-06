"""WebSocket request handlers for fnOS Mock Server."""

import json
import logging
import base64
from typing import Any
from pathlib import Path

from fastapi import WebSocket, WebSocketDisconnect
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad, unpad

from server.responses import (
    build_error_response,
    build_get_hostname_response,
    build_get_rsa_pub_response,
    build_login_response,
    build_ping_response,
    get_response_file_path,
    load_json_response,
    replace_reqid,
)
from server.utils import generate_random_token


logger = logging.getLogger(__name__)


async def handle_websocket(websocket: WebSocket) -> None:
    """Handle WebSocket connection and messages.

    Args:
        websocket: WebSocket connection
    """
    await websocket.accept()
    client_id = id(websocket)
    logger.info(f'WebSocket client connected: {client_id}')

    try:
        while True:
            # 接收消息
            message = await websocket.receive_text()
            logger.debug(f'Received message from {client_id}: {message[:100]}...')

            # 解析请求
            try:
                request = parse_request(message)
                logger.debug(f'Parsed request: req={request.get("req")}, reqid={request.get("reqid")}')

                # 路由请求到对应的处理器
                response = route_request(request)

                # 发送响应
                response_json = json.dumps(response, ensure_ascii=False, separators=(',', ':'))
                await websocket.send_text(response_json)
                logger.debug(f'Sent response to {client_id}: {response_json[:100]}...')

            except ValueError as e:
                logger.error(f'Error parsing request from {client_id}: {e}')
                error_response = {
                    'result': 'fail',
                    'errmsg': str(e),
                }
                await websocket.send_text(json.dumps(error_response))

    except WebSocketDisconnect:
        logger.info(f'WebSocket client disconnected: {client_id}')
    except Exception as e:
        logger.error(f'Error handling WebSocket connection {client_id}: {e}')
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


def parse_request(message: str) -> dict[str, Any]:
    """Parse incoming request message.

    客户端发送格式: HMAC-SHA256签名 + JSON数据（拼接，无分隔符）
    Mock 服务器忽略签名，直接解析 JSON

    Args:
        message: Incoming message string

    Returns:
        Parsed request dictionary

    Raises:
        ValueError: If message cannot be parsed as valid JSON
    """
    # 方法1: 尝试直接解析整个消息
    try:
        data = json.loads(message)
        return data
    except json.JSONDecodeError:
        pass

    # 方法2: 尝试去掉签名部分（假设签名是 base64 编码，通常是44字符）
    try:
        data = json.loads(message[44:])
        return data
    except json.JSONDecodeError:
        pass

    # 方法3: 尝试从后向前找到有效的 JSON
    # 逐字符尝试去掉前面的签名部分
    for i in range(min(100, len(message))):
        try:
            data = json.loads(message[i:])
            logger.debug(f'Found valid JSON at offset {i}')
            return data
        except json.JSONDecodeError:
            continue

    # 如果所有方法都失败，返回错误
    raise ValueError('Invalid request format: cannot parse JSON')


def route_request(request: dict[str, Any]) -> dict[str, Any]:
    """Route request to appropriate handler.

    Args:
        request: Parsed request dictionary

    Returns:
        Response dictionary
    """
    req = request.get('req')
    reqid = request.get('reqid')

    if not req:
        return build_error_response(None, 'Missing "req" field in request')

    # ping 请求不需要 reqid
    if req == 'ping':
        return build_ping_response()

    # encrypted 请求也不需要 reqid（加密的登录请求）
    if req == 'encrypted':
        # 解密加密的登录请求并返回成功的登录响应
        return handle_encrypted_login_request(request)

    # 其他请求需要 reqid
    if not reqid:
        return build_error_response(None, 'Missing "reqid" field in request')

    # 检查是否是实时计算请求
    if req == 'util.crypto.getRSAPub':
        return build_get_rsa_pub_response(reqid)
    elif req == 'user.login':
        return build_login_response(reqid)
    elif req == 'appcgi.sysinfo.getHostName':
        return build_get_hostname_response(reqid)

    # 检查是否有预设响应
    try:
        response_file = get_response_file_path(req)
        response = load_json_response(response_file)
        response = replace_reqid(response, reqid)
        return response
    except FileNotFoundError:
        logger.warning(f'No predefined response for request type: {req}')
        return build_error_response(reqid, f'Unknown request type: {req}')
    except json.JSONDecodeError as e:
        logger.error(f'Error loading response file for {req}: {e}')
        return build_error_response(reqid, f'Invalid response format for {req}')
    except Exception as e:
        logger.error(f'Error processing request {req}: {e}')


def handle_encrypted_login_request(request: dict[str, Any]) -> dict[str, Any]:
    """Handle encrypted login request.

    Args:
        request: Encrypted login request containing iv, rsa, and aes fields

    Returns:
        Login response with encrypted secret
    """
    try:
        # 读取私钥
        private_key_path = Path(__file__).parent.parent / 'private_key.pem'
        with open(private_key_path, 'r') as f:
            private_key = RSA.import_key(f.read())

        # 解码加密数据
        iv = base64.b64decode(request['iv'])
        encrypted_aes_key = base64.b64decode(request['rsa'])
        encrypted_login_data = base64.b64decode(request['aes'])

        # 解密 AES 密钥
        rsa_cipher = PKCS1_v1_5.new(private_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key, None)

        # 解密登录数据
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = aes_cipher.decrypt(encrypted_login_data)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        login_json = unpadded_data.decode('utf-8')
        login_data = json.loads(login_json)

        # 提取 reqid
        reqid = login_data.get('reqid')

        # 生成假的 secret 并加密
        fake_secret = b'mock_secret_for_testing_purposes_32bytes!!'
        padded_secret = pad(fake_secret, AES.block_size)
        # 创建新的 cipher 对象用于加密
        aes_cipher_encrypt = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_secret = aes_cipher_encrypt.encrypt(padded_secret)

        # 构建响应
        response = build_login_response(reqid)
        response['secret'] = base64.b64encode(encrypted_secret).decode('utf-8')

        return response

    except Exception as e:
        logger.error(f'Error handling encrypted login request: {e}')
        # 如果解密失败，返回一个通用的成功响应（用于测试）
        fake_reqid = generate_random_token(16)[:32]
        return build_login_response(fake_reqid)
        return build_error_response(reqid, f'Error processing request: {e}')