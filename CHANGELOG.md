# Changelog

## Unreleased

### Changed

- 协议报告区分标准 EAP-MD5 口令证明与锐捷私有用户名证明，并补充各自的固定向量。
- Direct 文档区分逐消息的 correlation ID 与逐片段的 fragment ID，补充 Linux 1.31 的起始值和重发保持规则。
- SAM 初始字段明确为本机 IPv4 和 MAC；SMP hello 第二 TLV 明确为硬盘序列号。
- 补充 Direct 端口、服务器 UTC 缺失时的本地回退，以及原始客户端与当前 adapter 的责任边界。
- 研究范围补充 macOS 1.35 与 Windows 6.85 结构级样本，并明确 V3 材料与客户端构建绑定。
- 新增协议文档管理原则，使用六类标记区分已证明事实、client 输入、当前待调查、后续可选调查、非当前职责和存疑线索。
- README 与 ROADMAP 明确 `v0.1.0` 是研究原型；新增 M6 交付边界收口，要求全部协议信息在原定义位置保留状态记录。
- macOS 1.35 目标认证实测确认服务器选择 EAP-MD5；标准 response 可以由 `value_size=16`、16 字节摘要和可选用户名组成。
- 修正 macOS EAP-MD5 组帧结论：START、Identity、MD5-Response 和 Logoff 均携带 `0x17`，值为 32 个零字节；`EncapRGVerdorSeg` 的直接调用表不足以排除该字段。
- 缺失 `0x61` 时，Linux 1.31、macOS 1.35 与 Windows 6.85 均默认选择 SAM `9`，收到字段时才覆盖；目标 macOS Success 实际省略 `0x61`。
- 静态闭环 Windows Direct 首发送时间戳、三平台计数器及 Linux 超时重发字段保持；目标 macOS 采集实际下发 `0x5a=53`、`0x6e=138`，但未产生 Direct 帧。
- 补充 EAP 可选方法注册与主认证器分派、Windows EAPHost/WLAN API、macOS CoreWLAN 和 Linux wpa_supplicant 的平台边界。
- 修正 Direct 版本结论：头版本默认 `1`，Linux/macOS 可把服务器 `0x79` 限制到 `2` 后写入同一 42 字节头；没有发现 v2 专用布局。
- 恢复 SAM/SMP 命令分派、SMP 改密 TLV、SAM 服务切换、Portal/SSO/升级/主机检查的客户端业务边界。
- 恢复 PEAPv1/v2、EAP-Payload TLV、Cryptobinding、IPMK/CMK 派生和 Compound MAC 校验规则；PEAP key block 标签为 `client PEAP encryption`。
- 关闭 `docs/rj-protocol` 原有六条第 4 类 TODO；第 1、2、3 类当前均为空。

### Limits

- 当前 `DirectSessionConfig.session_id` 仍作为整场固定值发送，尚未复刻 Linux 1.31 的逐逻辑消息递增语义。
- 当前 `local_udp_port` 默认值 `20000` 是库设计选择，不是原客户端回退值 `80`。
- 当前 EAP-MD5 确定性路径只实现锐捷私有用户名证明；标准 EAP-MD5 变体尚未进入 `Session`。
- macOS 1.35 已完成目标认证期采集；该 EAP-MD5 会话未进入 SAM/SMP 发送，Direct 时间戳、计数、重发和心跳仍待服务器实际启动 Direct 的部署验证。
- Windows 6.85 仍只完成结构级静态复核；目标 provider、运行派生摘要和 Direct 实际值不能由 macOS 采集替代。
- 目标 macOS EAP-MD5 的 `0x4d` 摘要已观测，但 V3 mode、材料重算关系，以及 PEAP 证书身份和 TLS 水平尚未闭合，当前不能形成完整交付 profile。
- Direct version 2 尚无已证明的独立线格式；只有目标服务器实际接受相同 42 字节布局的 version 2 时才能启用，否则保持 version 1 或明确失败。
- Windows 实际 PEAP provider `SuEapPeap.dll` 未随安装材料提供；Portal、主机检查、升级和系统无线接入继续属于 client adapter。

## v.0.1.0

### Changed

- 项目定位为锐捷校园网认证协议技术研究仓库，核心成果是完整研究报告，用于学习加密、多次握手和通过心跳维持认证状态的工程方法。
- Zig 代码作为研究成果的一次实例复刻，提供确定性协议编排和离线验证；README 优先引导阅读报告与认证流程图。
- Zig 包版本更新为 `0.1.0`，Git tag 为 `v.0.1.0`。打包清单包含完整报告、流程图、源码及 README 索引的配套文档。

### Fixed

- PEAP 进入 DHCP 等待后，重复的外层 Success 返回 `DuplicateFrame`，保持原有轮询进度和截止时间。
- Direct 服务器明确拒绝认证时，即使消息为空，也返回 `direct_result_rejected`；等待结果超时仍返回 `direct_result_timeout`。

### Usage

- 从 `docs/rj-protocol/index.md` 阅读研究报告，结合 `flow_chart.svg`、各协议章节与固定测试向量理解认证流程。
- Zig 复刻通过包模块 `rj-connect` 导入。`protocol` 提供无生命周期的 codec，`session.Session` 是统一生命周期入口，`Session.phase()` 暴露 `idle`、EAP-MD5、PEAP 和 Direct 阶段。
- 启用 PEAP 时，在 `Config` 中允许 `peap` 并提供 `PeapConfig`。V3 应用数据与动态库数据、Direct session ID、SAM/SMP 参数和无法由服务器推导的本地参数由调用方提供。
- PEAP 使用 `tunnel_input` 将 TLS 字节交给 adapter，adapter 通过 `tunnel_output` 返回待发送 TLS、可选内层 EAP 和 TLS 状态；MSCHAPv2 通过 `authenticate_mschapv2` 和 `verify_mschapv2` 动作交给外部实现。
- PEAP 成功、完整 DHCP 租约与服务器和本地参数齐备后自动进入 Direct；租约需含 IP、掩码、网关和 DNS，缺少 Direct 必需参数时返回 `MissingDirectParameters`。EAP-MD5 路径通过 `direct_session` 显式提交 `DirectSessionConfig`。
- `Outcome` 拥有发送帧、隧道输入、MSCHAPv2 请求和服务器文本；消费动作后使用初始化 Session 的 allocator 调用 `Outcome.deinit`。`Session.deinit` 释放活动协议机及跨调用资源。
- 帧、定时器、隧道输出与外部结果携带当前 `Generation`；旧代次返回 `StaleGeneration`。调用方提交当前时间并按返回的 deadline 驱动定时器。

### Limits

- 主要研究基线为锐捷 1.30、1.31 与 1.33，补充核对 macOS 1.35 与 Windows 6.85；完整跨版本兼容性、部署所需可选字段及 IPv6 部分字段语义仍有待验证。
- Zig 复刻支持 PEAPv0 与隧道内 EAP-MSCHAPv2 编排；PEAPv1/v2 和 cryptobinding 返回 `UnsupportedPeapMode`，Direct 限于 IPv4、IHL 5、无 IP 分片和 direct version 1。
- 网络 I/O、时钟、随机数、凭据、DHCP 系统操作、TLS、证书验证与 MSCHAPv2 计算属于外部适配。离线测试不证明真实校园网互操作。

## 368a85a

### Added

- 新增 PEAPv0 外层阶段、EAP-PEAP TLS 分片重组和拥有型 `tunnel_input` 动作。
- 新增 `tunnel_output` adapter 输入，用于返回待发送 TLS、已解密内层 EAP 和 TLS 状态。
- 新增内层 EAP codec、EAP-MSCHAPv2 外部编排、锐捷紧凑字段及固定 PEAP 口令起始值。
- 新增 PEAP V3 五模式摘要、MD5vz、SHA1vz、RIPEMDvz、Tiger 和 Whirlpool。
- 新增完整 DHCP 租约字段，以及 PEAP 成功后自动构造 SAM/SMP Direct 配置的交接。
- 新增 `MissingDependency`、`MissingDirectParameters`、`UnsupportedPeapMode` 和 `InvalidTunnelInput` 错误身份。

### Changed

- `Config` 现在声明允许的 EAP 方法并可携带 PEAP 配置；PEAP 输入材料由 `Session.init` 复制。
- `ActivePhase` 新增 `peap`，`Input` 新增 `tunnel_output`，`Action` 新增隧道和 MSCHAPv2 外部请求。
- 统一 DHCP external result 现在可携带 netmask、DNS 和备用 DNS；EAP-MD5 原有字段选择保持不变。

### Fixed

- PEAP 外层拒绝重复、乱序、冲突长度和未声明长度不一致的 TLS 分片；TLS 未建立时不再接受内层明文。
- 空口令按一个 16 字节块加密；V3 应用数据与动态库数据超出上限时返回 `InputTooLarge`。
- EAP-MD5 与 PEAP 共用 DHCP `2s × 21` 轮询策略；PEAP 公开轮询计数返回真实值。
- Direct 帧在动作提交失败时不再被重复释放。

### Limits

- PEAP 范围限于 PEAPv0 与隧道内 EAP-MSCHAPv2；PEAPv1/v2 和 cryptobinding 返回 `UnsupportedPeapMode`。
- TLS 握手、证书验证和 MSCHAPv2 计算仍完全由调用方负责。
- 真实校园网互操作、目标认证器的 PEAP 模式与可选字段组合仍需 adapter 验证。

## 87abfde

### Added

- 新增统一的 EAP-MD5/SAM/SMP `Session` 协调器，以 `ActivePhase` 和 `Generation` 表达单活动协议机、协议切换和旧事件失效。
- 新增完整 Ethernet II、IPv4、UDP、42 字节 direct header、MD5 authenticator 和 DES-CBC 的 Direct 收发边界。
- 新增 1358 字节分片、逐片 ACK、3 秒重发、最多 3 次发送、严格有序重组、1 MiB 默认消息上限和片段序列校验。
- 新增服务器时间与单调兼容时间戳模式、61 秒服务器窗口、连续非前进容忍、重组 9 秒超时和片段级重放进度。
- 新增 SAM 最小握手、用户信息、DHCP 认证结果、心跳和重认证生命周期。
- 新增 SMP hello 初始化、可配置 0/30/60 秒请求节奏、10 秒响应窗口、90 秒初始化上限、用户信息、DHCP 状态和活动 hello。
- 新增拥有型 `direct_auth_result` 与 `reauth_required` 动作；GBK 服务器文本由调用方通过 `Outcome.deinit` 释放。
- 新增本地取消、远端 Logoff、协议机释放、`Session.deinit` 和关键分配失败的事务性覆盖。

### Fixed

- 服务器时间换算使用检查减法；超出 `Timestamp` 表示范围时返回 `TimestampOverflow`，不再触发安全模式崩溃。
- SMP hello 响应必须包含完整的业务 TLV 序列；仅含固定头或截断 TLV 的响应不会完成初始化。
- 多片消息重组不再额外分配完整副本，避免峰值内存随完整消息大小翻倍。
- 移除了不参与行为的 `max_version` 配置以及只被测试读取的生产状态。

### Changed

- 公开阶段由单一 `Phase` 改为 `ActivePhase`，EAP-MD5 使用 `EapMd5Phase`，Direct 使用 `DirectPhase`。
- `Session` 现在必须显式 `deinit`；`frame` 事件可承载 EAPOL 或完整 Direct Ethernet 帧，并按 EtherType 分流。
- Direct 会话只能通过 EAP 已认证状态上的显式 `direct_session` 事件启动。SAM/SMP 配置和 GBK 用户名在提交时复制。
- Zig 包模块导入名改为 `rj-connect`，构建图只产生库模块测试，不再安装模板可执行程序。

### Limits

- Direct 当前只实现 IPv4、IHL 5、无 IP 分片和 direct version 1。
- PEAP/TLS、MSCHAPv2 和 M5 隧道编排仍未实现；M4 不自动从 EAP 私有字段推导 Direct 配置。
- 真实服务器互操作、硬件信息字段最小集合、目标服务器最高版本和可选字段组合仍需 adapter 验证。

## 0d457f0

### Changed

- 将确定性会话从 wire codec 目录迁至 `src/session/`，包公开入口改为 `rj.session`；`protocol` 命名空间只保留无会话生命周期的字段和编解码能力。
- 将阶段、deadline、EAP identifier、凭据等待、DHCP 完成和 peer 等运行时字段改为 tagged-union 状态，不再用相互独立的 optional 和布尔值描述同一状态。
- 为 frame、timer 和外部结果增加 `Generation` 门控；新连接尝试会失效旧代次事件并返回 `error.StaleGeneration`。

### Limits

- `rj.protocol.session` 不再存在，调用方需要改用 `rj.session.Session`。
- 当前仍未实现 PEAP 隧道输入，因此 M5 的 `tunnel_input` 不在本轮公开事件联合中。

## 40a592d

### Fixed

- EAPOL logoff 清理完成后内部状态回到 `disconnected`，同时 `Outcome.phase` 仍为本次转换返回 `logoff`，便于调用方观察终止动作。

## 8f703c2

### Fixed

- 认证失败次数不再因后续 EAP identifier 前进而清零，`max_auth_failures > 1` 时可以跨重连累计并在阈值后终止。

## 4d40f61

### Added

- 新增 EAPOL Start、EAP 与 Logoff codec，校验 Ethernet/EAPOL 外层、EAP 长度、已知 code/type 和以太网填充边界。
- 新增 EAP-MD5 Challenge 解码、Identity/Credential/Notification/NAK 响应构造，以及规范记录的 MD5 proof 已知答案实现。
- 新增确定性 `protocol.session.Session`，由调用方提交绝对时间、报文、凭据、定时器和 DHCP 结果，返回拥有的发送报文、凭据请求、轮询动作、截止时间与失败原因。
- 支持 connecting、acquired、authenticating、authenticated、held 和 logoff 状态，以及 held 重试、21 次 DHCP 轮询、第二认证和显式取消。
- 新增旧 identifier、重复帧、非法状态、PEAP 未支持、时间倒退与分配失败的事务性行为覆盖。

### Limits

- 当前只覆盖标准 EAP-MD5 与 DHCP 第二认证编排；锐捷 EAP-MD5 私有载荷、PEAP、SAM/SMP 直接通信仍由后续里程碑负责。
- 测试使用规范向量和注入事件，不代表目标校园网服务器的真实互操作结果。

## 46d55dc

### Changed

- 将 ROADMAP 重构为按里程碑组织的章节，每个里程碑集中记录目标、交付内容、已拍板决策、验收和待验证事项。
- 将设计决策、实施顺序和待确认事项归入对应里程碑，移除独立的重复章节。

### Limits

- 本轮只调整规划文档结构，不改变协议引擎实现状态。

## c92d95a

### Added

- 在 ROADMAP 中记录协议引擎的 `Session` API、allocator 与动作所有权、标准时间类型、统一输入事件、凭据边界和 PEAP 外部隧道边界。
- 明确 EAPOL/EAP、EAP-MD5 状态机、直接通信和 PEAP 编排的实施顺序。

### Limits

- 本轮只形成实施契约，协议引擎和新的 codec 尚未实现。

## 4cbc51d

### Changed

- 明确本库是确定性协议引擎，只负责报文、状态转换、动作、截止时间、分片重组和密码学结果。
- 将 network I/O、系统时钟、定时器、凭据、DHCP 系统操作、TLS 和平台适配列为库外责任。
- 修正 README 与 ROADMAP 中暗示本库应发展为完整客户端的表述。

### Limits

- 调用方仍需根据库返回的动作驱动网络、时钟和外部认证依赖。

## 36e2693

### Added

- 新增锐捷校园网客户端协议研究报告，覆盖 EAPOL/EAP、私有字段、认证状态、DHCP 第二认证、SAM/SMP 直接通信、密码学构造和测试向量。
- 报告以独立复刻为目标，保留固定字节布局、边界条件、失败转移和未确认字段说明。

### Limits

- 报告不替代真实认证服务器上的互操作验证。
- 不同校园网启用的可选字段仍可能不同，IPv6 部分字段的业务名称尚未确定。

## 244a354

### Added

- 新增 `protocol` 公共命名空间。
- 支持锐捷私有字段的紧凑读取与编码。
- 支持固定 DHCP 信息块、直接通信 42 字节报文头及 MD5 authenticator。
- 支持口令链式加密、RC4，以及单 DES/DES-CBC。
- 新增 30 项纯协议测试，覆盖已知答案、边界与错误路径。

### Limits

- 当前尚未提供认证状态机、报文分片重组、链路层收发或系统网络适配器。
- 当前测试不代表真实服务器互操作验证。
