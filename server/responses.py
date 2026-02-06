"""Response builders for fnOS Mock Server."""

import json
import logging
import os
from typing import Any

from server.utils import (
    generate_encrypted_secret,
    generate_random_token,
    generate_session_id,
    get_fixed_rsa_public_key,
)


logger = logging.getLogger(__name__)


# 响应文件缓存
_response_cache: dict[str, dict[str, Any]] = {}


def load_json_response(file_path: str) -> dict[str, Any]:
    """Load JSON response from file with caching.

    Args:
        file_path: Path to JSON response file

    Returns:
        Loaded response dictionary

    Raises:
        FileNotFoundError: If file does not exist
        json.JSONDecodeError: If file is not valid JSON
    """
    # 检查缓存
    if file_path in _response_cache:
        logger.debug(f'Using cached response for {file_path}')
        return _response_cache[file_path].copy()

    # 加载文件
    if not os.path.exists(file_path):
        raise FileNotFoundError(f'Response file not found: {file_path}')

    with open(file_path, 'r', encoding='utf-8') as f:
        response = json.load(f)

    # 缓存响应
    _response_cache[file_path] = response.copy()
    logger.debug(f'Loaded response from {file_path}')

    return response


def replace_reqid(response: dict[str, Any], reqid: str) -> dict[str, Any]:
    """Replace reqid field in response with provided reqid.

    Args:
        response: Response dictionary
        reqid: New reqid to use

    Returns:
        Response dictionary with updated reqid
    """
    # 创建副本以避免修改原始数据
    result = response.copy()

    # 如果响应中有 reqid 字段，替换它
    if 'reqid' in result:
        result['reqid'] = reqid
        logger.debug(f'Replaced reqid with {reqid}')

    # 如果响应中有嵌套的 data 字段，也检查其中的 reqid
    if 'data' in result and isinstance(result['data'], dict):
        data = result['data'].copy()
        if 'reqid' in data:
            data['reqid'] = reqid
            result['data'] = data

    return result


def build_error_response(reqid: str | None, errmsg: str) -> dict[str, Any]:
    """Build error response.

    Args:
        reqid: Request ID (optional)
        errmsg: Error message

    Returns:
        Error response dictionary
    """
    response = {
        'result': 'fail',
        'errmsg': errmsg,
    }

    if reqid:
        response['reqid'] = reqid

    logger.debug(f'Built error response: {errmsg}')
    return response


def get_response_file_path(req: str, responses_dir: str = 'responses') -> str:
    """Get response file path for a given request type.

    Args:
        req: Request type (e.g., 'appcgi.resmon.cpu')
        responses_dir: Directory containing response files

    Returns:
        Full path to response file
    """
    return os.path.join(responses_dir, f'{req}.json')


def build_get_rsa_pub_response(reqid: str) -> dict[str, Any]:
    """Build response for util.crypto.getRSAPub request.

    Args:
        reqid: Request ID

    Returns:
        Response dictionary with RSA public key and session ID
    """
    public_key = get_fixed_rsa_public_key()
    session_id = generate_session_id()

    response = {
        'pub': public_key,
        'si': session_id,
        'reqid': reqid,
    }

    logger.debug(f'Built getRSAPub response with session_id={session_id}')
    return response


def build_login_response(reqid: str) -> dict[str, Any]:
    """Build response for user.login request.

    Args:
        reqid: Request ID

    Returns:
        Response dictionary with token, longToken, and secret
    """
    token = generate_random_token(32)
    long_token = generate_random_token(64)
    secret = generate_encrypted_secret()

    response = {
        'result': 'succ',
        'token': token,
        'longToken': long_token,
        'secret': secret,
        'reqid': reqid,
    }

    logger.debug(f'Built login response for reqid={reqid}')
    return response


def build_get_hostname_response(reqid: str) -> dict[str, Any]:
    """Build response for appcgi.sysinfo.getHostName request.

    Args:
        reqid: Request ID

    Returns:
        Response dictionary with host name and trim version
    """
    response = {
        'result': 'succ',
        'req': 'appcgi.sysinfo.getHostName',
        'reqid': reqid,
        'data': {
            'hostName': 'www.timandes.cn',
            'trimVersion': '1.0.0',
        },
    }

    logger.debug(f'Built getHostName response for reqid={reqid}')
    return response


def build_ping_response() -> dict[str, Any]:
    """Build response for ping request.

    Returns:
        Response dictionary with pong
    """
    response = {'res': 'pong'}
    logger.debug('Built ping response')
    return response