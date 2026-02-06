# fnOS Mock Server Specification

## 1. User Stories

### 1.1 基本功能
作为一个开发者，我希望有一个飞牛 fnOS 服务端的 Mock 服务器，以便在没有真实 fnOS 设备的情况下测试 pyfnos 客户端。

### 1.2 预设响应
作为一个开发者，我希望能够通过在 `responses/` 目录下添加 JSON 文件来定义各种请求类型的 mock 响应，以便轻松添加新的 mock 功能。

### 1.3 实时计算
作为一个开发者，我希望某些特殊请求（如获取公钥、登录）能够实时计算并返回响应，以便模拟真实服务器的行为。

## 2. Functional Requirements

### 2.1 WebSocket 连接
WHEN pyfnos 客户端连接到 WebSocket 端点 THEN THE SYSTEM SHALL:
- 接受 `ws://host:port/websocket?type=main`（type 可选 main/timer/file）
- 支持 `type` 参数（main、timer、file）
- 默认监听端口 5666
- 支持 `-p` 参数在启动时更改监听端口

### 2.2 请求处理
WHEN 系统收到客户端请求 THEN THE SYSTEM SHALL:
- 解析请求格式：`HMAC-SHA256签名 + JSON数据`（拼接，无分隔符）
- 从 JSON 中提取 `req` 字段识别请求类型
- 从 JSON 中提取 `reqid` 字段获取请求 ID
- 根据 `req` 字段决定返回预设响应还是实时计算响应

### 2.3 预设响应
WHEN `req` 类型对应的 JSON 文件存在于 `responses/` 目录下 THEN THE SYSTEM SHALL:
- 读取 `{req}.json` 文件内容
- 将响应中的 `reqid` 替换为请求中的 `reqid`
- 返回处理后的 JSON 响应

### 2.4 实时计算响应
WHEN 请求类型为以下之一 THEN THE SYSTEM SHALL 实时计算并返回响应：

#### 2.4.1 获取 RSA 公钥
- **请求类型**: `util.crypto.getRSAPub`
- **响应内容**:
  ```json
  {
    "pub": "固定测试公钥",
    "si": "会话ID",
    "reqid": "请求中的reqid"
  }
  ```

#### 2.4.2 用户登录
- **请求类型**: `user.login`（以加密形式发送）
- **响应内容**:
  ```json
  {
    "result": "succ",
    "token": "随机生成的token",
    "longToken": "随机生成的longToken",
    "secret": "随机生成的加密secret",
    "reqid": "请求中的reqid"
  }
  ```

#### 2.4.3 获取主机名
- **请求类型**: `appcgi.sysinfo.getHostName`
- **响应内容**:
  ```json
  {
    "result": "succ",
    "reqid": "请求中的reqid",
    "data": {
      "hostName": "www.timandes.cn",
      "trimVersion": "1.0.0"
    }
  }
  ```

#### 2.4.4 心跳
- **请求类型**: `ping`
- **响应内容**:
  ```json
  {
    "res": "pong"
  }
  ```

### 2.5 响应格式
WHEN 系统返回响应 THEN THE SYSTEM SHALL:
- 直接返回 JSON 格式，不添加签名
- 响应必须包含 `reqid` 字段（使用请求中的 reqid）
- 响应必须包含 `result` 字段（succ/fail）

### 2.6 错误处理
WHEN 请求类型未知或无法处理 THEN THE SYSTEM SHALL:
- 返回错误响应:
  ```json
  {
    "result": "fail",
    "reqid": "请求中的reqid",
    "errmsg": "未知请求类型"
  }
  ```

## 3. Non-Functional Requirements

### 3.1 性能
- 系统应支持多个并发 WebSocket 连接
- 响应时间应在 100ms 以内（预设响应）

### 3.2 可维护性
- 代码结构清晰，易于理解和扩展
- 预设响应文件使用清晰的命名规范：`{req}.json`

### 3.3 可扩展性
- 通过添加新的 JSON 文件即可支持新的请求类型
- 通过添加新的处理函数即可支持新的实时计算请求

## 4. Data Models

### 4.1 请求格式
```json
{
  "req": "请求类型",
  "reqid": "请求ID",
  ...其他参数
}
```

### 4.2 响应格式
```json
{
  "result": "succ/fail",
  "reqid": "请求ID",
  "data": { ... },
  ...其他字段
}
```

### 4.3 预设响应文件结构
```
responses/
├── appcgi.resmon.cpu.json
├── appcgi.resmon.mem.json
├── user.info.json
└── ...
```

## 5. Edge Cases

### 5.1 缺少 reqid
WHEN 请求中缺少 `reqid` 字段 THEN THE SYSTEM SHALL 返回错误响应。

### 5.2 缺少 req 字段
WHEN 请求中缺少 `req` 字段 THEN THE SYSTEM SHALL 返回错误响应。

### 5.3 JSON 文件不存在
WHEN 请求类型对应的 JSON 文件不存在 THEN THE SYSTEM SHALL 返回错误响应。

### 5.4 JSON 文件格式错误
WHEN JSON 文件格式不正确 THEN THE SYSTEM SHALL 返回错误响应并记录日志。

### 5.5 无效的签名
WHEN 客户端发送的签名验证失败 THEN THE SYSTEM SHALL 忽略签名，直接处理请求（Mock 服务器不验证签名）。

## 6. Assumptions

1. Mock 服务器不需要验证客户端发送的 HMAC-SHA256 签名
2. Mock 服务器不需要维护会话状态
3. 所有实时计算的值都可以使用随机生成的测试值
4. Mock 服务器不需要持久化存储任何数据