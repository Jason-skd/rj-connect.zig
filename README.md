# RJ Connect

> 本项目仅用于技术交流学习，部分协议的研究与公开并未获得 Ruijie 官方许可，同时所分析的客户端并未见明确的产权/专利保护，若在您的产品中使用本项目的任何成果即认作自负责任。
> 
> 本项目如侵犯了您的合法权利，请通过 github 邮箱联系作者，会及时停止损害、赔礼道歉、赔偿损失！

## 项目概览

RJ Connect 是一个研究 Ruijie（锐捷）校园网认证协议的技术性交流、研究仓库，用于学习复杂网络环境下的加密、多次握手，以及通过心跳持续维持认证状态的工程方法。

核心成果是[锐捷校园网认证协议研究报告](docs/rj-protocol/index.md)。报告按报文、私有字段、认证状态机、直接通信和密码学组织研究结论、字节布局与固定测试向量，供读者独立理解、验证和复刻。协议研究结论及其适用边界以报告为准，里程碑与验收目标见 [ROADMAP.md](ROADMAP.md)。

`src/` 中的 Zig 代码提供对研究成果的一次实例复刻，以确定性协议引擎演示字段编解码、EAP-MD5 与 PEAPv0 编排、DHCP 衔接和 SAM/SMP 心跳生命周期；离线测试用于核对复刻行为与研究向量。网络 I/O、时钟、随机数、TLS、证书验证、MSCHAPv2 计算和系统适配由调用方提供。

## 快速开始

从[研究报告入口](docs/rj-protocol/index.md)开始阅读，结合[认证流程图](docs/rj-protocol/flow_chart.svg)了解多阶段认证，再按章节查看字段定义和测试向量。

复现 Zig 实例时，使用 `build.zig.zon` 声明的 Zig 版本：

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

`protocol` 提供无会话生命周期的 codec 与密码学原语，`session` 提供统一的 `Session` 生命周期入口。配置、动作所有权、异步事件和已知限制见 [v.0.1.0 使用说明](CHANGELOG.md#v010)。

## 开发验证

提交前至少执行：

```sh
zig fmt --check src build.zig
zig build test
```

现有测试验证字段编码、已知答案密码学向量、PEAP 隧道编排、V3 五种模式、分片重组、ACK/重发、时间戳窗口、SAM/SMP 生命周期和错误边界。离线结果是复刻验证证据；真实网络、TLS 与 MSCHAPv2 互操作仍需外部适配验证。

## 文档索引

- [锐捷协议研究报告](docs/rj-protocol/index.md)：核心成果与阅读入口，覆盖 EAPOL/EAP、PEAP、私有字段、认证状态机、SAM/SMP 与密码学。
- [认证流程图](docs/rj-protocol/flow_chart.svg)：认证、DHCP、Direct 交接与心跳维持的整体流程。
- [ROADMAP.md](ROADMAP.md)：成品目标、里程碑、验收条件与待确认项。
- [CHANGELOG.md](CHANGELOG.md)：版本变化、Zig 复刻使用方法与重要限制。
- [GLOSSARY.md](GLOSSARY.md)：认证、直接通信和会话生命周期术语。

## License

[MIT](LICENSE)
