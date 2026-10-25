# RJ Connect

> 本项目仅用于技术交流学习，部分协议的研究与公开并未获得 Ruijie 官方许可，同时所分析的客户端并未见明确的产权/专利保护，若在您的产品中使用本项目的任何成果即认作自负责任。
> 
> 本项目如侵犯了您的合法权利，请通过 github 邮箱联系作者，会及时停止损害、赔礼道歉、赔偿损失！

## 项目概览

RJ Connect 是一个研究 Ruijie（锐捷）校园网认证协议的技术性交流、研究仓库，用于学习复杂网络环境下的加密、多次握手，以及通过心跳持续维持认证状态的工程方法。

核心成果是[锐捷校园网认证协议研究报告](docs/rj-protocol/index.md)。报告按报文、私有字段、认证状态、直接通信和密码学组织定义、研究结论与固定向量，独立于 Zig 实例及其工程实施。协议研究结论及其适用边界以报告为准，协议信息的分类与放置规则见[协议文档管理原则](docs/rj-protocol/scope.md)，里程碑与验收目标见 [ROADMAP.md](ROADMAP.md)。

`src/` 中的 Zig 代码提供对研究成果的一次实例复刻：公开 `Session` 实现目标 macOS 1.35 有线 EAP-MD5 profile，包括标准 MD5 证明、566 字节私有尾块、V3 摘要、口令链与 Success/Failure 私有通知。PEAP、Direct、SAM/SMP 与旧私有分支保留为 `src/research/` 内部研究模块，不属于公开接口。网络 I/O、时钟、随机数、TLS、证书验证、MSCHAPv2 计算和系统适配由 client 提供。

当前发布版本为 `v0.1.1`。公开 interface 只接受目标 profile 的运行事实与凭据；rj-connect 负责协议语义、字段构造、编号生成、状态转移和校验。client 如何取得或组织这些值不属于本库 interface 的约束，交付边界见 ROADMAP。

## 快速开始

从[研究报告入口](docs/rj-protocol/index.md)开始阅读，按章节查看字段定义、状态关系和测试向量。锐捷客户端的认证、网络完成与会话维持关系见[认证状态机图](docs/rj-protocol/flow_chart.svg)。

复现 Zig 实例时，使用 `build.zig.zon` 声明的 Zig 版本：

```sh
zig build test
```

通过 Zig 包模块 `rj-connect` 使用库。client 向协议引擎提交已接收的报文、当前时间、运行事实与凭据，并消费引擎返回的待发送报文、超时截止时间和状态变化。

```zig
const rj = @import("rj-connect");

var session = try rj.session.Session.init(allocator, .{
    .facts = .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .service_name = "students",
        .alternate_dns_text = "202.116.32.254",
    },
    .credentials = .{ .username = "user", .password = "secret" },
});
defer session.deinit();
var outcome = try session.step(now, .start);
defer outcome.deinit(allocator);
```

`protocol` 提供无会话生命周期的通用 codec 与密码学原语，`session` 提供目标 profile 的 `Session` 生命周期入口。配置、动作所有权、事件和已知限制见 [v0.1.1 使用说明](CHANGELOG.md#v011)。

## 开发验证

提交前至少执行：

```sh
zig fmt --check src build.zig
zig build test
```

现有测试验证标准 EAP-MD5 证明、口令链、尾块布局、V3 固定向量、目标帧形状、facts 更新、重试/超时/取消和错误边界；`src/research/` 中的旧分支保留原有测试。离线结果是复刻验证证据；真实网络互操作仍需联调验证。

## 文档索引

- [锐捷协议研究报告](docs/rj-protocol/index.md)：核心成果与阅读入口，覆盖 EAPOL/EAP、PEAP、私有字段、认证状态机、SAM/SMP 与密码学。
- [协议文档管理原则](docs/rj-protocol/scope.md)：协议信息的六类分类和原地标记规则。
- [锐捷客户端认证状态机图](docs/rj-protocol/flow_chart.svg)：根据协议报告归纳 EAP、DHCP、SAM/SMP、心跳与重认证分支。
- [ROADMAP.md](ROADMAP.md)：成品目标、里程碑、验收条件与待确认项。
- [CHANGELOG.md](CHANGELOG.md)：按版本和提交索引变化、使用方法与重要限制。
- [版本文档归档](AGENTS.md#版本文档归档)：已发布版本的归档规则与历史文档入口。
- [GLOSSARY.md](GLOSSARY.md)：认证、直接通信和会话生命周期术语。

License: [MIT](LICENSE)
