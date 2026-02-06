# fnOS Mock Server

飞牛 fnOS 的 Mock 服务器，用于测试 pyfnos 客户端。

## 安装

本项目使用 [uv](https://github.com/astral-sh/uv) 进行包管理。

```bash
# 如果尚未安装 uv，请先安装
curl -LsSf https://astral.sh/uv/install.sh | sh

# 安装依赖
uv sync
```

## 使用

启动 mock 服务器：

```bash
uv run python -m server.main
```

或者使用自定义端口和日志级别：

```bash
uv run python -m server.main -p 8080 --log-level DEBUG
```

### 命令行参数

- `-p, --port`: WebSocket 服务器端口（默认：5666）
- `--host`: 服务器主机（默认：0.0.0.0）
- `--log-level`: 日志级别 - DEBUG, INFO, WARNING, ERROR（默认：INFO）

## 功能特性

- 与 pyfnos 客户端兼容的 WebSocket 服务器
- 从 JSON 文件加载预定义响应
- 针对特殊请求的实时计算响应：
  - `util.crypto.getRSAPub` - RSA 公钥
  - `user.login` - 使用 token 和 secret 登录
  - `appcgi.sysinfo.getHostName` - 主机名
  - `ping` - 心跳

## 依赖

本项目依赖与 [pyfnos](https://github.com/Timandes/pyfnos) 完全一致：

- **Python**: >=3.11
- **websockets**: >=15.0
- **pycryptodome**: >=3.23.0

Mock 服务器的额外依赖：
- **fastapi**: >=0.104.0
- **uvicorn[standard]**: >=0.24.0
- **pydantic**: >=2.5.0

## 添加预定义响应

在 `responses/` 目录下创建一个名为 `{req}.json` 的 JSON 文件：

```json
{
  "data": {
    "example": "data"
  },
  "reqid": "example_reqid",
  "result": "succ",
  "rev": "0.1",
  "req": "example.request"
}
```

服务器将自动加载此响应，并将 `reqid` 字段替换为实际的请求 ID。

### 响应文件示例

- `appcgi.resmon.cpu.json` - CPU 监控数据
- `appcgi.resmon.mem.json` - 内存监控数据
- `user.info.json` - 用户信息

## 使用 pyfnos 测试

```python
import asyncio
from fnos import FnosClient

async def test():
    client = FnosClient()
    await client.connect('localhost:5666')
    await client.login('username', 'password')

    # 发送请求
    response = await client.request_payload_with_response("user.info", {})
    print(response)

    await client.close()

asyncio.run(test())
```

## 项目结构

```
fnos-mock-server/
├── server/              # 主应用程序代码
│   ├── __init__.py
│   ├── main.py         # 应用程序入口
│   ├── handlers.py     # WebSocket 处理器
│   ├── responses.py    # 响应构建器
│   └── utils.py        # 工具函数
├── responses/          # 预定义响应 JSON 文件
├── tests/              # 测试文件
├── spec.md            # 功能规范
├── constitution.md    # 项目原则
├── plan.md           # 实现计划
├── tasks.md          # 任务分解
├── pyproject.toml   # 项目配置
└── README.md        # 本文件
```

## 许可证

Apache License 2.0