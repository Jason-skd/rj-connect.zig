# RJ Connect

## 项目概览

本仓库提供一个 Zig 库，用于实现锐捷校园网认证所需的确定性协议引擎。当前库负责报文与字段编解码、EAP-MD5 与 PEAPv0 认证状态转换、隧道内 EAP-MSCHAPv2 编排、认证后的 SAM/SMP 直接通信、定时截止时间、待发送动作和密码学原语。

本库不创建 socket、不发送链路层报文、不读取系统时钟、不管理凭据，也不实现 TLS 或 MSCHAPv2 密码学。调用方负责驱动网络 I/O、时钟、随机数、TLS、证书验证、MSCHAPv2、凭据和平台状态，并根据库返回的动作完成实际处理。

本库不是完整客户端。调用方可以使用它构建客户端、离线报文验证器或其他协议工具，但网络生命周期和系统适配始终位于库外。

## 快速开始

需要与 `build.zig.zon` 声明一致的 Zig 版本。

```sh
zig build test
```

通过 Zig 包模块 `rj-connect` 使用库。调用方向协议引擎提交已接收的报文、当前时间和外部认证结果，并消费引擎返回的待发送报文、超时截止时间和状态变化。

```zig
const rj = @import("rj-connect");

var session = try rj.session.Session.init(allocator, .{
    .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
});
defer session.deinit();
var outcome = try session.step(now, .start);
defer outcome.deinit(allocator);
```

`session` 是唯一公开生命周期入口。`Session.phase()` 通过 `ActivePhase` 暴露 `idle`、EAP-MD5、PEAP 和 Direct 四类阶段。PEAP 使用 `tunnel_input` 动作把 TLS 字节交给 adapter，adapter 通过 `tunnel_output` 返回待发送 TLS、已解密内层 EAP 和 TLS 状态；MSCHAPv2 由 `authenticate_mschapv2` 与 `verify_mschapv2` 动作交给调用方。

PEAP 成功且完整 DHCP 租约到达后，库用服务器参数和 `PeapConfig` 中的本地参数自动切换到 Direct。缺少参数时返回 `MissingDirectParameters`。EAP-MD5 路径仍通过 `direct_session` 事件显式提交 `DirectSessionConfig`。

启用 PEAP 时，在 `Config` 中允许 `peap` 并提供 `PeapConfig`。其中 V3 应用数据、动态库数据、Direct session ID、SAM/SMP 参数和无法由服务器推导的本地端口必须来自调用方；DHCP 租约必须包含 PEAP 路径所需的 IP、掩码、网关和 DNS。

发送动作中的帧和 `direct_auth_result` 中的服务器文本由 `Outcome` 拥有，调用方完成处理后应调用 `Outcome.deinit`。收到帧、定时器或外部结果时，调用方必须携带当前 `Generation`；旧代次事件返回 `error.StaleGeneration`。`Session.deinit` 释放活动协议机和所有跨调用资源。

`protocol.eapol` 与 `protocol.eap` 提供外层和内层 EAP codec，`protocol.peap` 和 `protocol.ruijie_peap` 提供 PEAP 与锐捷紧凑字段，`protocol.v3` 提供 V3 摘要。`protocol.direct` 提供 Ethernet/IPv4/UDP 与 direct 线格式，`protocol.sam` 和 `protocol.smp` 提供业务消息 codec。

## 开发验证

提交前至少执行：

```sh
zig fmt --check src build.zig
zig build test
```

现有测试验证字段编码、已知答案密码学向量、PEAP 隧道编排、V3 五种模式、分片重组、ACK/重发、时间戳窗口、SAM/SMP 生命周期和错误边界，不证明真实网络、TLS 或 MSCHAPv2 互操作。

## 文档索引

- [锐捷协议研究报告](docs/rj-protocol/index.md)：EAPOL/EAP、PEAP、私有字段、认证状态机、SAM/SMP 与密码学的可复刻规范。
- [ROADMAP.md](ROADMAP.md)：成品目标、里程碑、验收条件与待确认项。
- [CHANGELOG.md](CHANGELOG.md)：已交付能力和重要限制。
- [GLOSSARY.md](GLOSSARY.md)：认证、直接通信和会话生命周期术语。
- [AGENTS.md](AGENTS.md)：仓库协作与工程治理。
