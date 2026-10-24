# Changelog

## v0.1.1

当前开发版本，以 `v.0.1.0`（`956dd83`）为基线。版本内按实际提交倒序记录；发布基线中的说明与 M1–M5 保存在[版本归档](docs/archive/v.0.1.0/ROADMAP.md)，后续结论只属于本版本。

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
- 包版本为 `0.1.1`。Zig 实例的既有 API 用法见[发布基线说明](docs/archive/v.0.1.0/CHANGELOG.md#usage)；本版本的协议结论修订不表示对应 API 已同步修正。
- 状态图以 Mermaid 源为权威，使用 Mermaid CLI 重新生成：

```sh
mmdc -i docs/rj-protocol/flow_chart.mmd -o docs/rj-protocol/flow_chart.svg --no-font-embed -b white -I rj-client-authentication
```

本机使用自有 Chrome 时，可通过 `-p` 提供 Puppeteer 启动配置。

### Limits

- `DirectSessionConfig.session_id` 仍按整场固定值发送；逐逻辑消息递增、SAM/SMP 初始参数正式命名及本地端口 `80/8080` 的回退尚待实现收口，当前库本地端口默认值为 `20000`。
- `Session` 的 EAP-MD5 路径仍为锐捷私有用户名证明；标准分支、PEAPv1/v2 与 Cryptobinding 尚未进入当前确定性会话。
- 目标部署的最小字段集合、V3 材料对应关系、Windows 进程派生机制、PEAP 信任链与非 ASCII 密码行为仍有未决语义。
- 一个 EAP-MD5 会话的 Success 不构成 Direct 已建立的证明；Direct version 2 的完整互操作范围仍未明确。
- 离线测试与状态机图不构成所有校园网互操作的保证；具体协议未知项保留在报告原定义位置。

## v.0.1.0

- 发布基线：`956dd83`。
- [版本说明与发布前提交](docs/archive/v.0.1.0/CHANGELOG.md)：与发布 tag 中的 `CHANGELOG.md` 逐字节一致。
- [M1–M5 里程碑与验收](docs/archive/v.0.1.0/ROADMAP.md)：与发布 tag 中的 `ROADMAP.md` 逐字节一致。

归档反映发布时的事实与限制；后续修订及目标调整均记录在 v0.1.1，不回填历史快照。
