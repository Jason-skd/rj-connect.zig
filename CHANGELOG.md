# Changelog

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
