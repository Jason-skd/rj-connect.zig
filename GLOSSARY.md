# RJ Connect

本项目以锐捷校园网认证协议研究为核心，Zig 复刻用于验证确定性协议状态与线格式；这些术语区分报告中的协议概念和复刻实例的会话模型。

## 认证生命周期

**认证尝试**：
从一个 `start` 建立连接到认证终止的一次确定性运行。
_Avoid_: 连接、登录流程

**认证方法策略**：
一次认证尝试允许使用的外层 EAP 方法集合；服务器只能从中选择，不能使调用方静默采用未配置的方法。
_Avoid_: 自动降级、方法回退

## PEAP 与外部隧道

**PEAP**：
承载 TLS 隧道及隧道内 EAP 交换的外层 EAP 方法。
_Avoid_: TLS 连接、MSCHAPv2 登录

**PEAP 外层阶段**：
从服务器选择 PEAP 到隧道认证结束的确定性协议阶段。
_Avoid_: TLS 会话、PEAP provider

**PEAP 主路径**：
由 PEAPv0 外层和隧道内 EAP-MSCHAPv2 组成的 M5 验收认证路径。
_Avoid_: 全部 PEAP 版本、无线登录流程

**TLS adapter**：
由调用方拥有并执行 TLS 握手、记录保护和证书策略的外部组件。
_Avoid_: TLS provider、库内 TLS

**隧道输入**：
服务器 PEAP 载荷中交给 TLS adapter 的不透明 TLS 字节。
_Avoid_: 内层 EAP、解密载荷

**隧道输出**：
TLS adapter 返回的待封装 TLS 字节、可选的已解密内层 EAP 字节和处理状态。
_Avoid_: EAPOL 帧、网络发送结果

**MSCHAPv2 provider**：
由调用方拥有并执行隧道内 MSCHAPv2 认证计算及成功认证器校验的外部组件。
_Avoid_: 凭据存储、EAP codec

**PEAP V3 输入材料**：
计算 PEAP V3 摘要所需、由调用方提供的应用数据和动态库数据。
_Avoid_: 客户端安装路径、运行时文件读取

**PEAP Direct 交接**：
PEAP 完成且租约和直接会话参数齐备后，同一 `Session` 从 PEAP 阶段转入 Direct 阶段的一次转换。
_Avoid_: 第二会话、隐式默认配置

**PEAP Direct 本地回退值**：
服务器未提供 UTC、本地端口或其他可选 Direct 参数时，由客户端策略或 adapter 提供的本地值。
_Avoid_: 协议固定默认值、任意猜测值

## 直接通信

**直接帧**：
承载一个 IPv4/UDP 数据报及其 42 字节 direct header 的完整 Ethernet II 帧。
_Avoid_: UDP 载荷、原始消息

**直接会话**：
绑定本地与对端端点、密钥和时间戳状态的一次 SAM 或 SMP 通信生命周期。
_Avoid_: 直接连接、网络会话

**Direct correlation ID**：
42 字节头字段 `0x18` 的逐逻辑消息关联值；请求的响应回显该值，同一消息的所有片段共用它。
_Avoid_: 固定会话 token、片段 ID

**Direct fragment ID**：
42 字节头字段 `0x02` 的片段编号，在一个发送上下文内逐片段递增。
_Avoid_: correlation ID、SAM 会话参数

**direct payload**：
完成重组和解密后可交给 SAM 或 SMP 解析的业务字节。
_Avoid_: 密文片段、UDP 载荷

**片段**：
完整 DES-CBC 密文中的一个可独立校验和传输的部分。
_Avoid_: direct payload、消息

**SMP 初始化**：
在直接会话建立后获取服务器 SMP 运行参数的握手阶段。
_Avoid_: 心跳、hello

**SAM 客户端参数**：
SAM 初始 TLV `0x04` 的本机 IPv4 和 `0x05` 的本机 MAC。
_Avoid_: 随机 session parameter、远程端点

**SMP hello 主机序列号**：
SMP 初始 TLV `0x03` 携带的硬盘序列号。
_Avoid_: 本机 IPv4、通用 session parameter

**直接认证结果**：
服务器通过 SAM 或 SMP 返回、并归一化后的用户网络认证结果。
_Avoid_: DHCP 租约、SMP 消息

**重认证请求**：
服务器或本地策略要求结束当前直接会话、并由上层重新执行认证的事件。
_Avoid_: 自动登录、心跳
