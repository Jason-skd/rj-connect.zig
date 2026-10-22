# RJ Connect

## 项目概览

本仓库提供一个 Zig 库，用于实现锐捷校园网客户端认证所需的协议能力。库负责报文与字段编解码、认证状态和密码学原语；网络收发、系统配置、时钟、随机数和凭据来源由调用方注入。

当前实现集中在离线协议核心，尚不是可连接真实网络的完整客户端。

## 快速开始

需要与 `build.zig.zon` 声明一致的 Zig 版本。

```sh
zig build test
```

通过 Zig 包模块 `mentohust_zig` 使用库，协议能力位于公开命名空间 `protocol`。

## 开发验证

提交前至少执行：

```sh
zig fmt --check src build.zig
zig build test
```

现有测试验证字段编码、已知答案密码学向量和错误边界，不证明真实网络互操作。

## 文档索引

- [锐捷协议研究报告](docs/rj-protocol/index.md)：EAPOL/EAP、私有字段、认证状态机、SAM/SMP 与密码学的可复刻规范。
- [ROADMAP.md](ROADMAP.md)：成品目标、里程碑、验收条件与待确认项。
- [CHANGELOG.md](CHANGELOG.md)：已交付能力和重要限制。
- [AGENTS.md](AGENTS.md)：仓库协作与工程治理。
