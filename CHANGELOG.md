# Changelog

## v0.1.1

### 9e5a0e9

- 公开 `Session` 切换为目标 macOS 1.35 有线 EAP-MD5 profile：标准 MD5 证明、566 字节私有尾块、零 IV/challenge 口令链、V3 摘要与 Success/Failure 私有通知。
- `Config` 收敛为运行事实与凭据；新增 `.facts` 事件；删除 PEAP/Direct 公开类型，PEAP 请求显式 `UnsupportedEapMethod`。
- PEAP/Direct/SAM/SMP 与旧私有分支移至 `src/research/`，公开 `protocol` 只保留通用 codec；新增目标 profile 离线测试与 V3 构建材料。

### 9f296f2

- 修正 EAP-MD5 尾块固定前缀：version 为 `1,35,2,2`；Logoff 的 logoff reason 为 `0x01`，Start 首次值可变且被服务器接受，不能作为固定要求。

### 5dc3924

- 差分复算关闭 `0x2f` 的 IV 问题：无 challenge 值为零 IV 口令链结果，challenge 后密文保留给后续 Start/Identity/Logoff；剩余动态项改为“保留值复位条件”。
- 新增 EAP-MD5 零 IV 口令链测试向量；同步 `0x2f` 在密码学、私有字段、EAP、认证状态与索引中的表述。

### 6c93756

- 冷启动失败场景补充：`Failure` 终端帧可携带 6 字节或 34 字节私有 data；第一次失败由系统 `eapolclient` 对 MD5-Challenge 返回 NAK 引起，不作为目标应用的失败语义。
- 目的 MAC 分派：目标应用首次 Start 发往内嵌锐捷地址，收到服务器帧后的 Identity/MD5-Response/Logoff 发往服务器源 MAC；标准组播只出现在系统 `eapolclient` 的裸帧。
- 报告同步 Failure data 布局和目的 MAC 行为，并缩减待动态调查项。

### 3ec8eae

- 增加 2026-10-25 冷启动采集结论：challenge 前 `0x2f` 为固定初始值、失败重试后重复，`0x4d` 为 128 个零字节，私有尾块按当前状态构造而非复用上一帧缓冲。
- V3 复算累计 9 组（原 7 组 + 冷启动 2 组）全部逐字节一致；Success 固定段结构在冷启动中相同。
- 把已由冷启动回答的动态项从待调查列表移除，保留 `0x2f` 初始值的 IV/口令复算、目的 MAC 选择条件和 Success 消费方式为待动态调查。

### bbe748a

- 记录目标 macOS 1.35 主程序内嵌标准组播与锐捷 NAS 两个目的 MAC 常量；目标部署使用后者，选择条件保留为“当前版本待动态调查”。

### b0907e2

- 记录 legacy DHCP info 在写入 EAP-MD5 私有尾块前逐字节执行 `bit_reverse8(decoded ^ 0xff)`，并增加变换后的已知答案向量。
- `protocol.dhcp.encode` 的注释明确它输出变换前块，避免把原始字节直接当作线上字节。

### 423fb23

- 修正 EAPOL packet type：`EAP-Packet=0`、`Start=1`、`Logoff=2`，与 IEEE 802.1X 和目标部署采集一致；此前的 Start/EAP 映射相反。
- EAP 解码器接受以 Success/Failure code 携带的服务器私有数据，不再要求终端 EAP length 恰好为 4 字节。
- 新增目标形状的会话回归：带私有固定段的 Success 可以进入 authenticated。

### feb0d68

- 协议报告按目标部署运行证据修正：EAPOL packet type、EAP-MD5 私有尾块位于声明长度之外、标准 EAP-MD5 属于当前版本实践范围、实测属性顺序、Success 私有数据位置、legacy DHCP 变换。
- 第 3 类信息增加验证路径标记：“当前版本待动态调查”表示可由目标客户端采集或调试回答；“待 client 上线联调”表示需要我方实现向真实服务器发送报文才能确认。
- 修正 macOS IPv6 槽位顺序、`0x17` 分类、`0x4d` challenge 前全零与 `0x2f` 沿用上次结果等与采集不符或缺失的结论。

### b754794

- 当前版本实践范围收敛为目标部署实际选择的 EAP-MD5 路径；多次认证中未被服务器选择的 PEAP、Direct、`0x53`、安全域/IPD 以及 Windows 运行时项按第 4 类“后续版本可选补齐调查”处理。
- 补充该范围内的可实现边界：已取得的字段集合、V3 构造、密码学参数与 Success 处理足以复刻已观察行为，但与真实服务器的联调仍需实现验证；未观察到不等于协议可选。
- 同步 ROADMAP 待收尾与协议文档的范围标记。

### 8d5cecf

- 将依赖 Windows 运行时抓包或运行环境的第 4 类调查项（V3 派生材料、EAPHost MSCHAPv2、Windows `0x17`、Windows 部署身份、Windows 同会话 Direct 摘要）标记为“后续版本可选补齐调查”，不属于当前版本实践范围。
- 当前版本剩余的第 4 类阻塞收敛为目标部署的 PEAP 与 Direct 触发路径；同步更新 ROADMAP 待收尾说明。

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
- 包版本为 `0.1.1`。通过模块 `rj-connect` 导入，`protocol` 提供通用 EAPOL/EAP/DHCP/V3/密码学 codec，`session.Session` 是目标 EAP-MD5 profile 的会话入口。
- 创建会话时提供 `facts`（源 MAC、服务名、硬盘序列号、IPv6 槽、IPv4 租约、备用 DNS 文本、OS 位宽）与 `credentials`（GBK 原始字节）。Start 前必须已有这些值，因为尾块中的口令链在 Start 帧就需要计算。
- 调用方提交当前时间及携带当前 `Generation` 的报文/定时器输入，并根据返回 deadline 驱动定时器。地址或租约变化时通过 `.facts` 事件提交新快照；该事件不带 generation。`Outcome` 拥有返回动作、报文字节与终端通知，消费后调用 `Outcome.deinit`；会话结束时调用 `Session.deinit`。
- 初始 Start 发往主程序内嵌的锐捷地址；收到服务器帧后使用服务器源 MAC。PEAP 请求返回 `UnsupportedEapMethod`；PEAP、Direct、SAM/SMP 与旧私有分支保留在 `src/research/`，不属于公开接口。
- 状态图以 Mermaid 源为权威，使用 Mermaid CLI 重新生成：

```sh
mmdc -i docs/rj-protocol/flow_chart.mmd -o docs/rj-protocol/flow_chart.svg --no-font-embed -b '#0b1220' -I rj-client-authentication
```

本机使用自有 Chrome 时，可通过 `-p` 提供 Puppeteer 启动配置。

### Limits

- 公开 `Session` 只覆盖目标 macOS 1.35 有线 EAP-MD5 路径；PEAP、Direct、SAM/SMP、DHCP 第二认证与旧私有用户名证明分支保留在 `src/research/`，不是交付接口。
- 与真实服务器的互操作尚未验证：服务器是否要求 Start/Identity/Logoff 尾块、是否校验 challenge 前 `0x2f`/`0x4d`/`0x62`，以及我方标准 EAP-MD5 证明能否被接受。
- `0x2f` 保留值复位为零 IV 默认值的触发条件仍未确定；实现按“新会话默认、challenge 后保留”处理。
- `0x18`、`0x62`、`0x76` 的取值来源仍属动态调查；目标 profile 按观测行为构造，字段值分别由 facts 或帧类型决定。
- V3 的 A/D 材料绑定目标 macOS 1.35 构建；其他构建、Windows 进程派生材料与 PEAP 信任链不在当前 profile 内。
- 离线测试与状态图不构成所有校园网互操作的保证；具体协议未知项保留在报告原定义位置。
- 报告中当前版本的剩余未知项按验证路径标记：“当前版本待动态调查”可由锐捷客户端采集或调试回答；“待 client 上线联调”需要我方实现与真实服务器交互，不能由观察锐捷客户端单独关闭。

## v0.1.2

### 5263654

- 新增公开 `Session.initLegacy`：MentoHUST 0.3.1 有线 EAP-MD5 profile 使用标准 `MD5(id || password || challenge)` proof、16 字节原始摘要和固定 1000 字节帧；Start 使用标准组播地址，后续响应使用服务器源 MAC。
- legacy profile 的私有兼容尾部按 `mh031_tail_prefix.bin` 的固定 110 字节前缀加零填充构造；该材料由两次独立实机成功交换验证，只代表已观测的 MentoHUST 0.3.1 行为，不外推为通用 EAP-MD5 规则。
- 新增 `protocol.eapol.encodeStandardMd5ResponseData`，与锐捷私有用户名摘要分支分开。
- terminal Success/Failure 的 identifier 不匹配改报 `StaleTerminalIdentifier`，不再与普通 request 的 `StaleIdentifier` 混淆。
- 当前公开 API 仍以 macOS `Input/Outcome` 为共同 facade；legacy 不接受 `.facts`，传入时报 `UnsupportedProfileInput`。

### 3220e10

- `Session` 公开只读 `factsSnapshot` 与 `allocationOwner`，client 不再依赖 facade 的内部字段；legacy profile 的 facts 快照为 `null`。
- legacy 凭据复用共享类型，避免 facade 装配时出现名义类型不一致。

### Usage

- 通过模块 `rj-connect` 导入。`Session.init` 选择 macOS 1.35 wired profile；`Session.initLegacy` 选择 MentoHUST 0.3.1 wired profile，只需 `source_mac` 与凭据。
- 调用方提交当前时间及携带当前 `Generation` 的报文/定时器输入，并根据返回 deadline 驱动定时器。`Outcome` 拥有返回动作、报文字节与终端通知，消费后调用 `Outcome.deinit`；会话结束时调用 `Session.deinit`。
- macOS profile 支持 `.facts` 更新；legacy profile 明确拒绝 `.facts` 并返回 `UnsupportedProfileInput`。

### Limits

- MentoHUST profile 的实机证据仅覆盖 Padavan（Linux 3.4.113，MT7621）、eth3、已测校园网和已测用户名长度；其他部署、其他 MentoHUST 构型及省略固定尾部的兼容性未验证。
- `mh031_tail_prefix.bin` 是已观测的兼容材料，不表示 `0x17` 的完整 V2 计算或 `0x18` 的所有取值条件已经明确。
- macOS profile 的既有互操作、V3 材料和其他构建边界见 v0.1.1 条目。
