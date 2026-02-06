# fnOS Mock Server Task List

## Task 1: 项目初始化
**Status**: Pending  
**Priority**: High  
**Estimate**: 1 hour

**Acceptance Criteria**:
- [x] 创建项目目录结构（server/, tests/, responses/）
- [x] 创建所有空的 `__init__.py` 文件
- [x] 创建 `pyproject.toml` 配置文件，包含所有依赖
- [ ] 创建 `server/main.py` 基础骨架
- [ ] 测试项目可以正常导入

## Task 2: FastAPI 应用骨架
**Status**: Pending  
**Priority**: High  
**Estimate**: 1 hour

**Acceptance Criteria**:
- [ ] 实现命令行参数解析（-p/--port, --host, --log-level）
- [ ] 实现 FastAPI 应用初始化
- [ ] 实现基本的日志配置
- [ ] 实现应用启动函数

## Task 3: WebSocket 连接处理
**Status**: Pending  
**Priority**: High  
**Estimate**: 2 hours

**Acceptance Criteria**:
- [ ] 定义 WebSocket 端点：`/websocket?type={main|timer|file}`
- [ ] 实现 WebSocket 连接接收和关闭处理
- [ ] 实现消息接收循环
- [ ] 实现消息发送函数
- [ ] 测试基本的连接和消息收发

## Task 4: 请求解析
**Status**: Pending  
**Priority**: High  
**Estimate**: 2 hours

**Acceptance Criteria**:
- [ ] 实现 `parse_request()` 函数
- [ ] 处理 HMAC 签名 + JSON 格式
- [ ] 提取 `req` 和 `reqid` 字段
- [ ] 验证必要字段存在
- [ ] 处理解析错误并返回错误响应

## Task 5: 响应系统基础
**Status**: Pending  
**Priority**: High  
**Estimate**: 2 hours

**Acceptance Criteria**:
- [ ] 实现 `load_json_response()` 函数
- [ ] 实现 `replace_reqid()` 函数
- [ ] 实现 `build_error_response()` 函数
- [ ] 实现基本的响应路由逻辑
- [ ] 测试预设响应加载和 reqid 替换

## Task 6: RSA 公钥处理
**Status**: Pending  
**Priority**: Medium  
**Estimate**: 1 hour

**Acceptance Criteria**:
- [ ] 生成固定的测试 RSA 公钥
- [ ] 实现 `build_get_rsa_pub_response()` 函数
- [ ] 返回公钥、会话 ID、reqid
- [ ] 测试 `util.crypto.getRSAPub` 请求

## Task 7: 主机名处理
**Status**: Pending  
**Priority**: Medium  
**Estimate**: 0.5 hours

**Acceptance Criteria**:
- [ ] 实现 `build_get_hostname_response()` 函数
- [ ] 返回 hostName="www.timandes.cn"
- [ ] 返回 trimVersion
- [ ] 测试 `appcgi.sysinfo.getHostName` 请求

## Task 8: 心跳处理
**Status**: Pending  
**Priority**: Medium  
**Estimate**: 0.5 hours

**Acceptance Criteria**:
- [ ] 实现 `build_ping_response()` 函数
- [ ] 返回 `{"res":"pong"}`
- [ ] 测试 `ping` 请求

## Task 9: 登录处理
**Status**: Pending  
**Priority**: High  
**Estimate**: 2 hours

**Acceptance Criteria**:
- [ ] 实现 `generate_random_token()` 函数
- [ ] 实现 `generate_encrypted_secret()` 函数
- [ ] 实现 `build_login_response()` 函数
- [ ] 处理加密的登录请求
- [ ] 返回 token、longToken、secret
- [ ] 测试 `user.login` 请求

## Task 10: 完整请求路由
**Status**: Pending  
**Priority**: High  
**Estimate**: 1 hour

**Acceptance Criteria**:
- [ ] 实现完整的 `route_request()` 函数
- [ ] 整合所有特殊请求处理器
- [ ] 整合预设响应加载器
- [ ] 处理未知请求类型
- [ ] 测试完整的请求-响应流程

## Task 11: 错误处理和日志
**Status**: Pending  
**Priority**: Medium  
**Estimate**: 1 hour

**Acceptance Criteria**:
- [ ] 实现全面的异常捕获
- [ ] 记录所有错误和异常
- [ ] 确保错误响应格式一致
- [ ] 测试各种错误场景

## Task 12: 单元测试
**Status**: Pending  
**Priority**: Medium  
**Estimate**: 3 hours

**Acceptance Criteria**:
- [ ] 测试 `parse_request()` 函数
- [ ] 测试 `load_json_response()` 函数
- [ ] 测试 `replace_reqid()` 函数
- [ ] 测试所有响应构建函数
- [ ] 测试请求路由逻辑
- [ ] 测试工具函数（RSA 生成、token 生成等）

## Task 13: 集成测试
**Status**: Pending  
**Priority**: Medium  
**Estimate**: 2 hours

**Acceptance Criteria**:
- [ ] 测试 WebSocket 连接流程
- [ ] 测试完整的登录流程
- [ ] 测试预设响应加载
- [ ] 测试所有特殊请求类型
- [ ] 使用 pyfnos 客户端进行实际测试

## Task 14: 文档和示例
**Status**: Pending  
**Priority**: Low  
**Estimate**: 1 hour

**Acceptance Criteria**:
- [ ] 创建 README.md
- [ ] 添加使用说明
- [ ] 添加示例代码
- [ ] 添加响应文件示例

## Task 15: 性能优化
**Status**: Pending  
**Priority**: Low  
**Estimate**: 1 hour

**Acceptance Criteria**:
- [ ] 实现 RSA 公钥缓存
- [ ] 实现 JSON 文件缓存
- [ ] 测试并发连接性能
- [ ] 优化响应时间

## Total Estimated Time: ~22 hours

---

## Task Dependencies

```
Task 1 (项目初始化)
  └─> Task 2 (FastAPI 应用骨架)
        └─> Task 3 (WebSocket 连接处理)
              ├─> Task 4 (请求解析)
              │     └─> Task 10 (完整请求路由)
              │           └─> Task 11 (错误处理和日志)
              │
              ├─> Task 5 (响应系统基础)
              │     └─> Task 10 (完整请求路由)
              │
              ├─> Task 6 (RSA 公钥处理)
              │     └─> Task 10 (完整请求路由)
              │
              ├─> Task 7 (主机名处理)
              │     └─> Task 10 (完整请求路由)
              │
              ├─> Task 8 (心跳处理)
              │     └─> Task 10 (完整请求路由)
              │
              └─> Task 9 (登录处理)
                    └─> Task 10 (完整请求路由)

Task 1 (项目初始化)
  └─> Task 12 (单元测试)

Task 10 (完整请求路由)
  └─> Task 13 (集成测试)

Task 2 (FastAPI 应用骨架)
  └─> Task 14 (文档和示例)

Task 10 (完整请求路由)
  └─> Task 15 (性能优化)
```

## Execution Order

1. Task 1: 项目初始化
2. Task 2: FastAPI 应用骨架
3. Task 3: WebSocket 连接处理
4. Task 4: 请求解析
5. Task 5: 响应系统基础
6. Task 6: RSA 公钥处理
7. Task 7: 主机名处理
8. Task 8: 心跳处理
9. Task 9: 登录处理
10. Task 10: 完整请求路由
11. Task 11: 错误处理和日志
12. Task 12: 单元测试
13. Task 13: 集成测试
14. Task 14: 文档和示例
15. Task 15: 性能优化