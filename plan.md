# fnOS Mock Server Implementation Plan

## 1. System Architecture

### 1.1 High-Level Architecture
```
┌─────────────────┐         WebSocket          ┌─────────────────┐
│  pyfnos Client  │ ◄────────────────────────► │  Mock Server    │
└─────────────────┘                             └─────────────────┘
                                                     │
                                                     │
                          ┌──────────────────────────┴─────────────────────┐
                          │                                                │
                          ▼                                                ▼
                  ┌──────────────┐                               ┌──────────────┐
                  │  Handlers    │                               │  Response    │
                  │  (处理请求)   │◄──────────────────────────────│  Builders    │
                  └──────────────┘                               │  (构建响应)   │
                          │                                        └──────────────┘
                          │                                                │
                          ▼                                                ▼
                  ┌──────────────┐                               ┌──────────────┐
                  │  Utils       │                               │  JSON Files  │
                  │  (工具函数)   │                               │  (预设响应)   │
                  └──────────────┘                               └──────────────┘
```

### 1.2 Component Design

#### 1.2.1 Main Application (`server/main.py`)
- FastAPI 应用入口
- WebSocket 端点定义
- 命令行参数解析
- 应用启动和配置

#### 1.2.2 Request Handler (`server/handlers.py`)
- WebSocket 连接管理
- 请求解析和路由
- 请求分发到对应的处理器

#### 1.2.3 Response Builder (`server/responses.py`)
- 预设响应加载和 reqid 替换
- 实时计算响应生成
- 错误响应构建

#### 1.2.4 Utilities (`server/utils.py`)
- RSA 密钥生成
- 随机 token/secret 生成
- JSON 文件读取
- 日志配置

## 2. Data Models

### 2.1 Request Models
```python
class BaseRequest(BaseModel):
    req: str
    reqid: str
    
class LoginRequest(BaseModel):
    req: str
    reqid: str
    user: str
    password: str
    stay: bool
    deviceType: str
    deviceName: str
    did: str
    si: str
```

### 2.2 Response Models
```python
class BaseResponse(BaseModel):
    result: str
    reqid: str
    
class GetRsaPubResponse(BaseModel):
    pub: str
    si: str
    reqid: str
    
class LoginResponse(BaseModel):
    result: str
    token: str
    longToken: str
    secret: str
    reqid: str
    
class GetHostNameResponse(BaseModel):
    result: str
    reqid: str
    data: dict
```

## 3. API Design

### 3.1 WebSocket Endpoint
```
ws://host:port/websocket?type={main|timer|file}
```

### 3.2 Message Flow
```
Client                              Server
  │                                   │
  │─────── WebSocket Connect ────────►│
  │                                   │
  │◄─────── Connection Ready ─────────│
  │                                   │
  │─────── Request (iz + JSON) ──────►│
  │                                   │
  │        Parse req and reqid        │
  │        Check if predefined       │
  │        Build response            │
  │                                   │
  │◄─────── Response (JSON) ──────────│
  │                                   │
  │─────── Request ... ─────────────►│
  │                                   │
```

## 4. Implementation Strategy

### 4.1 Phase 1: Basic Setup
- 创建项目结构
- 配置依赖（pyproject.toml）
- 实现 FastAPI 应用骨架

### 4.2 Phase 2: WebSocket Server
- 实现 WebSocket 连接处理
- 实现消息接收和发送
- 实现基本的请求解析

### 4.3 Phase 3: Response System
- 实现预设响应加载器
- 实现 reqid 替换逻辑
- 实现实时计算响应

### 4.4 Phase 4: Special Handlers
- 实现 `util.crypto.getRSAPub` 处理
- 实现 `user.login` 处理
- 实现 `appcgi.sysinfo.getHostName` 处理
- 实现 `ping` 处理

### 4.5 Phase 5: Error Handling
- 实现错误响应构建
- 实现日志记录
- 实现异常捕获

### 4.6 Phase 6: Testing
- 编写单元测试
- 编写集成测试
- 使用 pyfnos 客户端测试

## 5. Key Algorithms

### 5.1 Request Parsing
```python
def parse_request(message: str) -> dict:
    # 客户端发送: HMAC-SHA256签名 + JSON数据
    # Mock 服务器忽略签名，直接解析 JSON
    
    # 方法1: 尝试从后向前解析 JSON
    # 方法2: 尝试从头开始解析 JSON（如果签名是 base64）
    
    try:
        # 尝试直接解析整个消息
        data = json.loads(message)
    except json.JSONDecodeError:
        # 如果失败，尝试去掉签名部分
        # 假设签名是 44 字符的 base64 字符串
        try:
            data = json.loads(message[44:])
        except json.JSONDecodeError:
            # 如果还是失败，返回错误
            raise ValueError("Invalid request format")
    
    return data
```

### 5.2 Response Routing
```python
def route_request(request: dict) -> dict:
    req = request.get("req")
    reqid = request.get("reqid")
    
    # 检查是否是实时计算请求
    if req == "util.crypto.getRSAPub":
        return build_get_rsa_pub_response(reqid)
    elif req == "user.login":
        return build_login_response(reqid)
    elif req == "appcgi.sysinfo.getHostName":
        return build_get_hostname_response(reqid)
    elif req == "ping":
        return build_ping_response()
    
    # 检查是否有预设响应
    response_file = f"responses/{req}.json"
    if os.path.exists(response_file):
        return load_and_replace_reqid(response_file, reqid)
    
    # 未知请求
    return build_error_response(reqid, "Unknown request type")
```

### 5.3 RSA Key Generation
```python
def generate_rsa_key():
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    return public_key.decode('utf-8')
```

### 5.4 Random Token Generation
```python
def generate_random_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)
```

### 5.5 Secret Generation
```python
def generate_encrypted_secret():
    # 生成随机 AES 密钥
    aes_key = get_random_bytes(32)
    
    # 生成随机 IV
    iv = get_random_bytes(16)
    
    # 生成随机 secret
    secret = secrets.token_bytes(32)
    
    # 使用 AES 加密 secret
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_secret = pad(secret, AES.block_size)
    encrypted_secret = cipher.encrypt(padded_secret)
    
    # 返回 base64 编码的结果
    return base64.b64encode(encrypted_secret).decode('utf-8')
```

## 6. File Structure

```
fnos-mock-server/
├── server/
│   ├── __init__.py
│   ├── main.py              # FastAPI 应用入口
│   ├── handlers.py          # WebSocket 处理器
│   ├── responses.py         # 响应构建器
│   ├── models.py            # Pydantic 模型
│   └── utils.py             # 工具函数
├── responses/               # 预设响应文件
│   ├── appcgi.resmon.cpu.json
│   ├── appcgi.resmon.mem.json
│   └── ...
├── tests/                   # 测试文件
│   ├── test_handlers.py
│   ├── test_responses.py
│   └── test_utils.py
├── spec.md
├── constitution.md
├── plan.md
├── tasks.md
├── pyproject.toml
└── README.md
```

## 7. Dependencies

### 7.1 Core Dependencies
```toml
[project]
name = "fnos-mock-server"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.104.0",
    "uvicorn[standard]>=0.24.0",
    "websockets>=12.0",
    "pycryptodome>=3.19.0",
    "pydantic>=2.5.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "httpx>=0.25.0",
]
```

### 7.2 Development Tools
- `pytest` - Testing framework
- `pytest-asyncio` - Async test support
- `httpx` - HTTP client for testing

## 8. Configuration

### 8.1 Command Line Arguments
```python
parser = argparse.ArgumentParser(description='fnOS Mock Server')
parser.add_argument('-p', '--port', type=int, default=5666, help='WebSocket server port')
parser.add_argument('--host', type=str, default='0.0.0.0', help='Server host')
parser.add_argument('--log-level', type=str, default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
```

### 8.2 Environment Variables
- `FNOS_MOCK_PORT` - Server port
- `FNOS_MOCK_HOST` - Server host
- `FNOS_MOCK_LOG_LEVEL` - Log level

## 9. Security Considerations

### 9.1 Mock Server Limitations
- Does not verify client signatures
- Does not maintain session state
- Uses random test values for authentication
- Not suitable for production use

### 9.2 Data Protection
- Do not log sensitive data
- Use secure random number generation
- Validate all input data

## 10. Performance Optimization

### 10.1 Response Caching
- Cache RSA public key (static)
- Cache JSON files in memory

### 10.2 Async Operations
- Use async/await for all I/O
- Handle multiple WebSocket connections concurrently

### 10.3 Connection Management
- Implement connection timeout
- Clean up closed connections
- Limit concurrent connections