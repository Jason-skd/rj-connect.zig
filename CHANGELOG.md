# Changelog

## c2b4f74

### Added

- 新增统一的 EAP-MD5/SAM/SMP `Session` 协调器，以 `ActivePhase` 和 `Generation` 表达单活动协议机、协议切换和旧事件失效。
- 新增完整 Ethernet II、IPv4、UDP、42 字节 direct header、MD5 authenticator 和 DES-CBC 的 Direct 收发边界。
- 新增 1358 字节分片、逐片 ACK、3 秒重发、最多 3 次发送、严格有序重组、1 MiB 默认消息上限和片段序列校验。
- 新增服务器时间与单调兼容时间戳模式、61 秒服务器窗口、连续非前进容忍、重组 9 秒超时和片段级重放进度。
- 新增 SAM 最小握手、用户信息、DHCP 认证结果、心跳和重认证生命周期。
- 新增 SMP hello 初始化、可配置 0/30/60 秒请求节奏、10 秒响应窗口、90 秒初始化上限、用户信息、DHCP 状态和活动 hello。
- 新增拥有型 `direct_auth_result` 与 `reauth_required` 动作；GBK 服务器文本由调用方通过 `Outcome.deinit` 释放。
- 新增本地取消、远端 Logoff、协议机释放、`Session.deinit` 和关键分配失败的事务性覆盖。

### Changed

- 公开阶段由单一 `Phase` 改为 `ActivePhase`，EAP-MD5 使用 `EapMd5Phase`，Direct 使用 `DirectPhase`。
- `Session` 现在必须显式 `deinit`；`frame` 事件可承载 EAPOL 或完整 Direct Ethernet 帧，并按 EtherType 分流。
- Direct 会话只能通过 EAP 已认证状态上的显式 `direct_session` 事件启动。SAM/SMP 配置和 GBK 用户名在提交时复制。

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
