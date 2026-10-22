# RJ Connect

## 成品目标

提供一个 Zig 库，实现锐捷校园网认证所需的确定性协议引擎。调用方驱动网络收发、时钟、随机数、TLS、凭据和平台状态；库只计算协议结果和下一步动作。

## 核心范围

- 802.1X/EAPOL 报文编解码与无副作用的认证状态转换。
- 由调用方投递输入事件和当前时间的确定性驱动接口。
- 返回待发送报文、超时截止时间、状态变化和可区分错误。
- EAP-MD5 路径，以及 PEAP 隧道内 EAP 与锐捷私有字段的编排。
- 锐捷私有属性编解码及认证参数协商。
- DHCP 结果处理、SAM/SMP 会话、心跳、重认证与下线的协议状态。
- 直接通信分片、重组、完整性校验和重放窗口。
- 对异常报文、超时、重试、取消和会话结束提供可区分的错误。

## 库外责任

- 创建 socket、抓包、构造链路层发送队列和执行网络 I/O。
- 读取系统时钟、生成随机数、运行定时器和持久化凭据。
- 获取 DHCP 租约、修改路由、DNS 或网卡状态。
- 实现 TLS 握手、证书验证和 MSCHAPv2 密码学交换。
- 图形界面、托盘、消息窗口与自服务页面。
- 客户端升级、密码修改和主机安全提示。
- 平台特定的自动启动与安装流程。

## 非目标

- 提供开箱即用的完整客户端进程。
- 管理网络连接生命周期、后台服务或系统权限。
- 把协议引擎绑定到某个平台、TLS 实现或凭据存储。

## 验收要求

- 上层只提供外部事件、当前时间和依赖结果，就能驱动完整认证及会话状态。
- 相同输入序列必须产生相同报文、动作、截止时间和状态变化。
- 核心模块不得创建线程、计时器、socket 或访问全局可变状态。
- 标准报文与私有报文均有独立的边界测试和已知答案测试。
- 测试覆盖重试、超时、取消、分片乱序、重放和会话终止。
- 不要求运行客户端即可验证状态转换、报文编解码和直接通信重组。

## M1: 离线协议与密码学基础

- 状态：已完成
- 提交：`f0245e9`

### 目标

建立不依赖网络和系统状态的报文与密码学积木，为后续确定性会话提供可复用基础。

### 交付内容

- 锐捷紧凑字段编解码。
- legacy DHCP 信息块与 CRC-16。
- 42 字节直接通信头和 MD5 authenticator。
- 口令链式加密与 RC4。
- 单 DES 与 DES-CBC。
- 已知答案、边界和错误路径测试。

### 已拍板决策

- 基础模块使用显式输入输出缓冲，不读取全局配置。
- 错误通过类型化 error set 返回，不用空值表示损坏数据。
- 密码学实现只承诺旧协议兼容，不作为通用安全建议。

### 验收

- [x] `zig build test` 通过。
- [x] 关键密码学行为具有公开已知答案。
- [x] 截断字段、错误长度和缓冲区不足具有独立错误。

## M2: 锐捷协议研究报告

- 状态：已完成
- 提交：`36e2693`

### 目标

提供不依赖本库代码的协议规范，使开发者可以独立实现报文、认证和直接通信。

### 交付内容

- EAPOL/EAP 与 EAP-MD5 报文定义。
- 锐捷私有字段逐字段布局。
- 认证状态和 DHCP 第二认证。
- SAM/SMP 直接通信、分片和重组。
- 私有摘要、五模式 V3 和测试向量。

### 已拍板决策

- 报告只记录协议结论、边界和复现向量。
- 规范覆盖 1.30、1.31 与 1.33 客户端的共同协议族。
- 部署差异和未命名字段明确保留为未知边界。

### 验收

- [x] 独立开发者无需本库代码即可理解核心报文格式。
- [x] 每个私有算法具有固定输入向量。
- [x] README 已索引报告入口。

### 待验证

- 1.30、1.31 与 1.33 之间私有字段的完整兼容范围。
- 四个 IPv6 槽位的业务语义。

## M3: EAP-MD5 确定性协议引擎

- 状态：已实施
- 提交：`4d40f61`
- 依赖：M1、M2

### 目标

实现 EAPOL/EAP codec 和 EAP-MD5 `Session`，让调用方通过外部事件、时间和凭据驱动完整认证状态。

### 交付内容

- EAPOL Start、EAP、Logoff 编解码。
- EAP Request/Response、identifier 和 MD5 challenge 编解码。
- connecting、acquired、authenticating、authenticated、held、logoff 状态。
- 动作列表、绝对截止时间、凭据请求和失败原因。
- 严格报文检查和只读状态观测。

### 已拍板决策

- 公开入口是一个受控可变的 `Session`，认证、网络完成和直接通信是其内部正交子状态。
- `Session` 不创建线程、定时器或网络资源，不接受回调 provider。
- 绝对时间使用 `std.Io.Timestamp`，时长使用 `std.Io.Duration`。时间倒退返回明确错误。
- `Session.init` 显式接收 allocator。`step` 返回拥有动作和报文字节的 `Outcome`，调用方通过 `Outcome.deinit` 释放。
- 分配失败不得提交部分状态；完整生成并校验本次结果后，才更新内部状态。
- 输入使用统一事件联合，包含 `frame`、`timer`、`credentials` 和 `external_result`。异步输入携带当前尝试代次，借用字节不跨调用保存。
- 凭据通过 `credentials` 事件按需提供。库不持久化密码，不调用凭据 provider。
- DHCP 轮询 `2s × 21` 和 DHCP 结果 `9s` 等协议行为由引擎实现；start、auth、held 超时和重试上限由 `Config` 提供。
- 默认采用严格模式：旧 identifier、重复事件和状态不允许的帧返回可区分错误，不改变会话。
- 只读公开 `phase`、认证子阶段、`next_deadline` 和失败原因，不公开可变内部状态。

### 接口约束

```zig
pub fn step(
    session: *Session,
    now: std.Io.Timestamp,
    input: Input,
) Error!Outcome;
```

`Outcome` 包含动作、`next_deadline` 和状态变化。调用方在截止时间到达时提交 `timer`，并根据返回动作完成实际发送、凭据收集或外部认证。

### 验收

- [x] EAPOL/EAP codec 通过报文边界和已知字节测试。
- [x] EAP-MD5 proof 与规范记录的测试向量一致。
- [x] 正常流程从 disconnected 推进到 authenticated。
- [x] 失败、超时、重试和取消分别产生可区分结果。
- [x] 分配失败后会话状态与调用前一致。
- [x] 旧 identifier、重复帧和非法状态事件不改变会话。

### 待验证

- 目标校园网实际启用的 EAP 方法和服务器能力。
- 真实服务器对 EAP-MD5 字段最小集合的要求。

## M4: 直接通信分片与重组

- 状态：已实施
- 提交：`e148f00`..`87abfde`
- 依赖：M3

### 目标

把 SAM/SMP direct payload 接入统一 `Session`，实现分片、重组、完整性校验、重放窗口和响应动作。

### 交付内容

- 42 字节 direct header 与 message ID 序列。
- flags `1/2/3/4` 对应的单片、首片、中间片和末片语义。
- 1358 字节分片边界与重发动作。
- 按 peer、端口和 session ID 隔离的重组缓冲。
- DES-CBC 加解密、MD5 authenticator 和时间戳窗口。
- SAM/SMP 握手、DHCP 认证结果、心跳和重认证状态。

### 已拍板决策

- M4 保留完整范围：直接通信传输核心与 SAM/SMP 生命周期在同一个 spec 中建模，并通过垂直票据分批实施。
- 重组器不拥有网络连接，所有输入帧由调用方提交。
- 分片和重组在密文上执行，完成重组后才解密。
- 时间验证、长度验证和 authenticator 校验均在把载荷交给 SAM/SMP 解析器之前完成。
- 会话 key、IV、timestamp 和分片缓冲由 `Session` 持有；对端网络生命周期由调用方负责。
- 真实网络互操作由调用方的适配器测试完成，不属于本库进程。
- `Session` 是协调者，只持有至多一个活动协议机；机器拥有自己的阶段、计数、deadline 和动态资源，并共享 allocator、source MAC、时间水位和代次 context。
- 协议机通过只含 `step`、`nextDeadline` 和 `deinit` 的内部 vtable 接入；机器切换采用构造并验证完成后原子替换，失败保留旧机器。
- 阶段对称命名为 `EapMd5Phase` 与 `DirectPhase`，公开为 `ActivePhase` tagged union；没有活动机器时进入 `.idle`。
- `DirectPhase` 为 `initializing`、`awaiting_result`、`active`；内部 ACK、重发和解析状态不公开。
- 新机器激活时递增代次；同一机器内部重发不递增；旁路协议帧返回状态不变的 no-op `Outcome`。
- `Session` 显式拥有动态资源并提供 `deinit`；状态转换采用准备完成后再提交，不复制整个 `Session`。
- 直接会话由已认证 EAP 状态上的显式 `direct_session` 事件启动，不能隐式从私有字段自动启动。
- `DirectSessionConfig` 一次提交并复制生命周期所需内容，包含模式、端点、session ID、key/IV、时间戳模式、用户名、网络信息、SAM/SMP 参数和周期；最高版本仍是 adapter 侧的能力协商信息，输入切片不跨调用保存。
- `DirectSessionConfig` 使用公共字段 struct 加 `mode` union；SAM 与 SMP 的独有字段分别由命名 struct 完整包装，再对两个包装做 tagged union，不把每个字段建模成独立 optional。
- 网络入口和发送动作统一使用完整 Ethernet II 帧，由 EtherType 分流；IPv4 固定 IHL 5、protocol 17、无 IP 分片，并严格校验长度与 checksum。
- 每片通过端点、session、时间戳、authenticator 和序列校验后立即 ACK；ACK 回显 ID/session/端点，`packet_len=42`、`total_len=0`。
- 分片采用严格有序单缓冲重组；同 ID 只重发 ACK、不重复追加，跳号和过旧 ID 丢弃且不 ACK。
- 首片验证 `total_len <= max_message_size`、DES 块和分片规则后，一次分配恰好 `total_len` 字节；默认上限 `1 MiB`，追加前完成边界检查，末片精确补齐。
- 分片发送默认采用 `3s` ACK 等待和最多 `3` 次发送尝试；重发保持 message ID/flags/payload/session ID/长度/端点，更新时间戳并重算 authenticator。
- 未完成重组从首条可接受片段起 `9s` 过期；完成、新首片、会话关闭和 `deinit` 都释放缓冲。
- SMP 初始化默认在 `0s/30s/60s` 发起三次请求，单次请求等待 `10s`，约 `90s` 后终止认证；三个参数可由 `Config` 覆盖。
- 时间戳模式为服务器时间或旧客户端单调兼容模式；服务器时间窗口绝对值小于 `61s`，非前进时间戳最多连续接受 5 个包。
- 服务器时间模式按本地经过秒推进发送时间；单调模式每发送一个帧（包括重发）推进一次。
- 片段通过校验并 ACK 后提交重放进度和追加内容；完整消息解密失败时释放重组缓冲，但保留 key、IV 和片段级重放进度。
- 用户信息发送成功后等待 DHCP 认证结果 `9s`；SAM 与 SMP 结果输出为拥有所有权的 `direct_auth_result` 事件，服务器文本为 GBK 字节。
- 直接结果拒绝、用户信息发送失败和结果超时都终止当前认证尝试；自动重试由调用方外层策略负责。
- 取消和 Logoff 先幂等清理直接资源，再以一次可观察的终止结果回到 `.idle`；远端 Logoff 不重复发送。
- 重认证只产生 `reauth_required` 并回到 `.idle`，不自动选择 EAP-MD5；下一次认证由调用方或 M5 显式启动。
- 公开 API 显式使用 `username_gbk` 和 `server_message_gbk` 等 GBK 字节；字符集转换由调用方负责。
- 服务器下发的心跳、重认证、SMP hello、检测间隔和请求参数在 bootstrap 中标准化；零间隔禁用对应周期。
- SAM 心跳发送无响应要求的握手消息；SMP 按 hello 间隔发送 `0x23`，等待业务响应，连续 3 次失败产生重认证请求；`0x80` flag 只保留观察值。
- `protocol/sam.zig` 与 `protocol/smp.zig` 负责无生命周期业务 codec；`protocol/direct.zig` 只负责帧、header、authenticator 和分片线格式；不提供任意 direct payload 发送入口。

### 验收

- [x] 单片产生 flags `1`，多片依次产生 `2`、`3`、`4`。
- [x] 乱序、重复、跳号和超时片段不会产生错误完整消息。
- [x] 重组完成后才解密，解密失败不改变会话阶段。
- [x] 时间戳倒退超出窗口时丢弃输入。
- [x] SAM 与 SMP 的 DHCP 结果均映射到统一结果。

### 待验证

- 硬件信息、DHCP 第二认证和心跳字段的最小必需集合。
- 目标服务器对直接通信最高版本和可选字段的组合要求。

## M5: PEAP 外部隧道编排

- 状态：待实施
- 依赖：M3、M4

### 目标

实现 PEAP 外层状态和隧道内 EAP/锐捷字段编排，同时把 TLS 和 MSCHAPv2 保持为外部依赖。

### 交付内容

- PEAP 外层事件与隧道动作。
- `tunnel_input`、`tunnel_output` 和 `external_result` 的统一处理。
- 隧道内 EAP codec。
- 隧道内锐捷紧凑字段、口令字段和 V3 摘要。
- PEAP Success 后的 DHCP 与直接通信状态衔接。

### 已拍板决策

- 库不实现 TLS 握手、证书验证或 MSCHAPv2 密码学交换。
- TLS provider 通过不透明隧道字节与库交互，调用方负责证书和凭据策略。
- PEAP 编排仍由统一 `Session` 管理，不创建第二个公开生命周期。
- 目标校园网的证书信任策略属于 adapter 配置，不进入协议状态。

### 验收

- [ ] 不提供 TLS provider 时，PEAP 路径返回明确的依赖缺失状态。
- [ ] 外部 provider 可以只通过字节事件驱动完整 PEAP 编排。
- [ ] 隧道内 EAP 与锐捷字段具有独立边界测试。
- [ ] PEAP 完成后可进入 M4 的直接通信状态。
- [ ] 库内不存在证书读取、socket、线程或系统时钟调用。
