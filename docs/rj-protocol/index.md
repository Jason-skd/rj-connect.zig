---
title: 锐捷校园网认证协议研究报告
description: 定义 EAPOL/EAP、锐捷私有字段、密码学构造、多阶段认证及 SAM/SMP 会话
contentType: Reference
---

# 锐捷校园网认证协议研究报告

锐捷校园网认证协议由标准 EAPOL/EAP 交换、厂商私有参数、多阶段认证及 SAM/SMP 直接通信组成。本报告按报文、字段、状态与算法定义其线格式、生成关系和适用边界；固定向量给出相应构造的确定性结果。

## 研究范围

主要版本范围为锐捷 1.30、1.31 与 1.33，并涵盖 macOS 1.35 与 Windows 6.85 的部分协议行为。跨版本共同结论限于已明确的线格式和算法；V3 输入材料、可选字段、TLS 身份策略、硬件信息和 Direct 回退行为具有版本或部署边界。

报告覆盖标准与锐捷私有 EAP-MD5、PEAP/MSCHAPv2、锐捷厂商属性、DHCP 第二认证，以及认证后的 SAM/SMP 直接通信。图形界面、托盘、安装器、升级页面、密码修改界面和校园网业务页面不属于核心认证协议；其关联协议字段仍在所属章节定义。

可选字段是否启用取决于服务器策略。某一部署中的字段集合不构成所有校园网的共同要求。

## 当前版本实践范围

当前版本以目标部署实际选择的 EAP-MD5 路径为实践范围：目标 macOS 1.35 客户端通过有线适配器认证，服务器选择 EAP-MD5，Success 之后没有 SAM/SMP Direct 报文。该路径的字段集合、V3 摘要与服务器参数已由 2026-10-24 的运行采集验证。

多次认证中均未被服务器选择的机制按第 4 类“后续版本可选补齐调查”处理，不属于当前版本实践范围：PEAP 部署的服务器证书、身份与 TLS 参数；PEAP/MSCHAPv2 的平台密码处理；SAM/SMP Direct 的启动条件与运行时间线；`0x53`、安全域 `0x55` 和 IPD 结果 `0x64`。未观察到不等于协议可选；进入这些路径前需要重新取得对应部署证据，并重新评估适用边界。

在该范围内，已取得的字段集合、V3 构造、密码学参数和 Success 处理足以实现与目标部署匹配的认证行为；实现是否与服务器完全互操作仍需联调验证。

## 接入介质

无线介质上的扫描、关联与链路密钥协商先于本文所述认证及会话交换。锐捷私有字段位于 EAP 或 Direct 层。

| 平台         | 接入机制                  | EAP 路径                                                      |
| ------------ | ------------------------- | ------------------------------------------------------------- |
| Linux 1.31   | 内嵌 wpa_supplicant 0.7.3 | `key_mgmt=WPA-EAP`、`eap=PEAP`、`phase2="auth=MSCHAPV2"`      |
| macOS 1.35   | CoreWLAN 企业网接入       | 系统 EAP provider 完成认证，应用接收 EAPOL Success 及私有字段 |
| Windows 6.85 | WLAN API 与 OneX profile  | Type `25` 选择 PEAP，凭据由 EAPHost 使用                      |

系统 EAP provider 可支持 EAP-TLS 等其他方法；支持某一方法不等于本次认证选用该方法。802.11 管理帧、系统 provider 接口和凭据存储不属于锐捷私有线格式。

## 报告结构

[锐捷客户端认证状态机图](flow_chart.svg)归纳认证交换、网络完成和 SAM/SMP 会话之间的关系。各分支按客户端版本及部署条件成立，EAP Success 本身不表示 Direct 已启动。

| 页面                                | 定义对象                              |
| ----------------------------------- | ------------------------------------- |
| [EAPOL 与 EAP 报文](eap.md)         | 链路层外层、EAP 方法与凭据响应        |
| [锐捷私有字段](private-fields.md)   | 厂商属性、固定服务器段与字段来源      |
| [认证状态机](authentication.md)     | 状态、定时器、DHCP 第二认证及失败转移 |
| [SAM/SMP 直接通信](direct.md)       | 会话头、分片、重组与业务消息          |
| [密码学与 V3 摘要](cryptography.md) | 口令封装、V3、会话密钥与完整性校验    |
| [测试向量](test-vectors.md)         | 固定输入及其确定性输出                |
| [协议文档管理原则](scope.md)        | 六类信息的表达形式与就地标记          |

## 术语

| 术语               | 定义                                                    |
| ------------------ | ------------------------------------------------------- |
| `username_bytes`   | 用户名在 EAP 载荷中的原始字节。中文账户使用 GBK 编码。  |
| `password_bytes`   | 密码在口令派生前使用的原始字节。中文密码使用 GBK 编码。 |
| `challenge`        | 服务器在 EAP-MD5 请求中下发的 16 字节随机值。           |
| `EAP identifier`   | EAP 请求中的单字节事务编号，响应原样返回。              |
| `vendor attribute` | 以厂商号 `0x00001311` 标识的锐捷私有字段。              |
| `compact field`    | 以 `code:u8, length:u8, value` 编码的紧凑厂商字段。     |
| `direct payload`   | SAM/SMP 直接通信中，DES-CBC 加密前的业务字节串。        |
| `fragment`         | 直接通信中不超过 1358 字节的一段加密载荷。              |
| `V3 digest`        | 依赖 16 字节 challenge 选择的 128 字符私有摘要文本。    |

“必须”“不得”表示线格式或状态关系的必要约束；“应当”表示通常成立的要求；“可”表示可选能力。未决语义以所属章节的分类标记表示，已知布局与未知生成关系分别陈述。

## 分层模型

| 层次       | 协议对象                                     |
| ---------- | -------------------------------------------- |
| 链路帧层   | Ethernet II、EAPOL 与 EAP                    |
| 认证交换层 | 身份、MD5-Challenge、PEAP 与凭据响应         |
| 私有参数层 | 锐捷 TLV、固定服务器段与客户端能力字段       |
| 网络完成层 | DHCP 地址获取、第二 EAP 或 DHCP 认证结果确认 |
| 会话层     | SAM/SMP 直接通信、心跳、重认证与下线         |

各层的有效边界由长度字段、类型和厂商号共同确定。上层字段不改变下层报文已经声明的长度语义。

## 规范依据

标准外层依据 [IEEE 802.1X](https://standards.ieee.org/ieee/802.1X/7345/) 和 [RFC 3748](https://www.rfc-editor.org/rfc/rfc3748) 定义。EAP-MD5 继承 [RFC 3748](https://www.rfc-editor.org/rfc/rfc3748) 的消息模型，口令封装继承 [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865) 的链式 MD5 形式。PEAP 与 MSCHAPv2 使用标准 TLS 和 [RFC 2759](https://www.rfc-editor.org/rfc/rfc2759) 语义。

V3 使用的 MD5、SHA-1、RIPEMD-128、Tiger 与 Whirlpool 基础算法分别依据 [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321)、[RFC 3174](https://www.rfc-editor.org/rfc/rfc3174)、[RIPEMD-160 论文](https://homes.esat.kuleuven.be/~bosselae/ripemd160.html)、[Tiger 论文](https://www.cs.technion.ac.il/~biham/Reports/Tiger/) 与 [Whirlpool 规范](https://web.archive.org/web/20171118115359/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html)。私有构造的差异在[密码学与 V3 摘要](cryptography.md)中逐项定义。
