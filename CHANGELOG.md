# Changelog

## v0.1.1

### d479b6a

- 复核 macOS 1.35 目标部署的 7 个 EAP-MD5 challenge 响应：V3 模式 `0`、`2`、`3`、`4` 与内嵌材料按报告构造逐字节复现；两次采集的成功会话响应获得 Success。
- 补充目标部署的运行时 profile、EAP-MD5 实际字段集合、Success 固定段 opaque/记录/编码块值，以及 `0x53` 未出现的边界。
- 明确目标部署不进入 PEAP、不产生 Direct 帧；PEAP 证书、Windows 运行环境和 Direct 时间线仍需其他部署。

### fa43282

- 认证状态机图采用深色背景、亮色文字和连线，蓝、紫、绿、橙边框分别区分主状态、条件、成功与失败。
- 字号调整为 18px，连线与边框加粗；同步 Mermaid 源、SVG 和重新生成命令。

### db032fe

- 归档规则与历史版本文档入口统一至 AGENTS.md 的仓库独有治理。
- 根目录 CHANGELOG 与 ROADMAP 专注当前版本，当前用法在本页完整说明；README 指向统一归档入口。

### 66f6c68

- 按 `v.0.1.0` 发布 tag 原样归档 `ROADMAP.md` 与 `CHANGELOG.md`，冻结 M1–M5 及发布时的说明。
- 将发布后的提交、协议修订与 M6 目标归入 v0.1.1，版本内以实际 commit hash 索引。
- 包版本与 README 同步为 `0.1.1`，新增已发布文档归档的冻结约束。

### 8dba723

- 协议报告按定义、结论、适用边界和固定向量组织，保留六类信息规范；第 5 类使用 `> TODO （后续版本可选实施）`。
- 认证状态机图依据报告中的锐捷客户端行为归纳，覆盖 EAP-MD5、PEAP、DHCP 第二认证、SAM/SMP、心跳、重认证及下线。
- 新增图形的 Mermaid 权威源 `docs/rj-protocol/flow_chart.mmd`，同步生成 `flow_chart.svg`；EAP Success 与 Direct 启动条件分别表达。

### d8ebc9c

- 补充服务器驱动的 SSO、升级、主机检查与 Windows Portal 行为及适用边界。
- 定义 SMP 改密、SAM 服务切换及辅助通知字段；ACL 与主机信息不具备已明确的通用载荷。
- 完善 PEAP 密钥派生、Compound MAC 与 Direct 版本的范围说明。

### 0c6c29e

- 补充 Linux wpa_supplicant、macOS CoreWLAN 与 Windows WLAN API/EAPHost 的接入范围。
- 明确 SAM/SMP 命令分派及业务消息边界；Direct 头默认版本为 `1`，Linux/macOS 的服务器版本值上限为 `2`。

### 670fcae

- 区分客户端内嵌 EAP 方法、具名配置与有线认证分派，补充 EAP-TLS 等方法的支持范围。
- 定义 PEAPv1/v2、EAP-Payload TLV、Cryptobinding、IPMK/CMK 派生及 HMAC-SHA1 校验。

### 9aebd11

- 确认一个 macOS 1.35 部署使用标准形状的 EAP-MD5，响应可带用户名；Start、Identity、MD5-Response 与 Logoff 均携带值为 32 个零字节的 `0x17`。
- 明确三个平台缺失 `0x61` 时默认选择 SAM `9`；记录服务器端口覆盖值与 Direct 会话尚未确认建立的边界。
- 补充 Windows 首发送时间戳、三平台计数器与 Linux 重发保持规则。

### 8d47ae1

- 区分随包学校配置、`AuthMode`、能力位图与服务器实际选择的认证方法，明确不同学校 profile 的适用范围。
- 明确 Windows V2 字段、PEAP provider 与平台密码编码仍存在未决条件。

### cfe2f54

- 明确 Windows 6.85 V3 由进程种子与模块状态派生，不适用 Linux/macOS 的固定 `A`、`D` 数组模型。
- 补充 Windows 磁盘序列号的 20 字节有效上限、客户端名称与版本、IPv6 槽位及条件字段规则。
- 明确 Windows 时间戳空表返回 `0`，并补充三个平台的 Direct 计数生命周期与端口回退。

### 7e4101d

- 给出 Linux/macOS V3 固定材料的长度与 SHA-256，明确材料与客户端构建绑定。
- 定义 Linux/macOS 硬盘标识、IPv6 三槽、可选字段来源及 Direct 本地回退。
- 说明 Linux MSCHAPv2 的密码逐字节展开规则及其平台适用范围。

### 308dcf8

- 建立协议信息六类分类与原位标记规则，区分协议事实、client 输入和未决语义。
- 明确协议与 client 的责任边界，提出 M6 交付边界及协议完整性目标；目标的后续调整归入 v0.1.1。

### 8c0e7fa

- 区分标准 EAP-MD5 口令证明与锐捷私有用户名证明，并给出独立固定向量。
- 区分逐消息 correlation ID 与逐片段 fragment ID，明确 SAM 初始 IPv4/MAC 和 SMP 硬盘序列号。
- 扩充 macOS 1.35、Windows 6.85 的研究范围及 Direct 端口、时间戳回退说明。

### Usage

- 从[研究报告](docs/rj-protocol/index.md)阅读字段与结论，结合[锐捷客户端认证状态机图](docs/rj-protocol/flow_chart.svg)查看路径条件。
- 包版本为 `0.1.1`。通过模块 `rj-connect` 导入，`protocol` 提供无生命周期的 codec，`session.Session` 提供统一会话入口。
- 启用 PEAP 时，在 `Config` 中允许 `peap` 并提供 `PeapConfig`。TLS 字节通过 `tunnel_input`、`tunnel_output` 交互，MSCHAPv2 计算与校验由外部 provider 完成。
- 调用方提交当前时间及携带当前 `Generation` 的输入，并根据返回 deadline 驱动定时器。`Outcome` 拥有返回动作和报文字节，消费后调用 `Outcome.deinit`；会话结束时调用 `Session.deinit`。
- PEAP 成功且完整 DHCP 租约、服务器参数和本地配置齐备后进入 Direct；EAP-MD5 路径通过 `direct_session` 提交 `DirectSessionConfig`。协议报告中的新结论与当前 API 的差异见本页 Limits。
- 状态图以 Mermaid 源为权威，使用 Mermaid CLI 重新生成：

```sh
mmdc -i docs/rj-protocol/flow_chart.mmd -o docs/rj-protocol/flow_chart.svg --no-font-embed -b '#0b1220' -I rj-client-authentication
```

本机使用自有 Chrome 时，可通过 `-p` 提供 Puppeteer 启动配置。

### Limits

- `DirectSessionConfig.session_id` 仍按整场固定值发送；逐逻辑消息递增、SAM/SMP 初始参数正式命名及本地端口 `80/8080` 的回退尚待实现收口，当前库本地端口默认值为 `20000`。
- `Session` 的 EAP-MD5 路径仍为锐捷私有用户名证明；标准分支、PEAPv1/v2 与 Cryptobinding 尚未进入当前确定性会话。
- 目标部署的最小字段集合、V3 材料对应关系、Windows 进程派生机制、PEAP 信任链与非 ASCII 密码行为仍有未决语义。
- 一个 EAP-MD5 会话的 Success 不构成 Direct 已建立的证明；Direct version 2 的完整互操作范围仍未明确。
- 离线测试与状态机图不构成所有校园网互操作的保证；具体协议未知项保留在报告原定义位置。
