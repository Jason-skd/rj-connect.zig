---
title: 锐捷校园网认证协议研究报告
description: 研究有线 EAP-MD5、PEAP、锐捷私有字段、加密、多阶段握手及 SAM/SMP 心跳认证维持
contentType: Reference
plan: "#文档计划"
---

# 锐捷校园网认证协议研究报告

本报告是 RJ Connect 的核心研究成果，面向希望学习复杂网络环境下加密、多次握手与心跳维持认证工程方法的读者。报告按协议层次记录锐捷校园网认证的报文格式、状态转换、私有字段和固定密码学构造，使实现者可以独立理解、验证和复刻编码器、解码器与认证状态机。

后续章节以规范形式表达研究结论及复刻约束。仓库中的 Zig 确定性协议引擎提供一次实例复刻，测试验证已实现路径与固定向量；研究结论的定义与适用边界由报告承载。离线复刻通过不等同于真实校园网互操作已经验证。

## 规范范围

本规范覆盖锐捷 1.30、1.31 与 1.33 客户端共同呈现的协议族，主要面向 IEEE 802.1X 有线接入。文本同时定义标准 EAPOL/EAP 外层、EAP-MD5 路径、PEAP/MSCHAPv2 路径的接入边界、锐捷厂商属性、DHCP 第二认证，以及认证后的 SAM/SMP 直接通信。

图形界面、托盘、安装器、升级页面、密码修改界面和校园网业务页面不属于核心认证协议。这些能力可以复用同一字段系统，但不影响最小认证器的报文定义。

本规范描述协议语义，不声明某个校园网必然启用全部可选字段。部署者可要求更严格的字段集合，也可忽略不影响认证主链的展示字段。

## 文档计划

目标读者是实现 802.1X 客户端、协议分析器或离线报文验证器的开发者。阅读本文后，读者应能构造 EAP 身份与口令响应、解析服务器私有参数、完成 DHCP 两阶段认证，并建立带分片与摘要校验的 SAM/SMP 会话。

页面职责如下：

建议先结合[认证流程图](flow_chart.svg)了解 EAP、DHCP、Direct 交接和心跳维持的整体关系，再依照下表阅读。

| 页面                                | 目标                                      |
| ----------------------------------- | ----------------------------------------- |
| [EAPOL 与 EAP 报文](eap.md)         | 编码链路层外层和 EAP-MD5 交换             |
| [锐捷私有字段](private-fields.md)   | 逐字段编码、解析和固定段布局              |
| [认证状态机](authentication.md)     | 定义状态、定时器、DHCP 第二认证和失败转移 |
| [SAM/SMP 直接通信](direct.md)       | 构造原始以太网会话、分片、重组和业务消息  |
| [密码学与 V3 摘要](cryptography.md) | 实现口令、摘要、V3 、会话密钥和完整性校验 |
| [测试向量](test-vectors.md)         | 用固定输入验证独立实现                    |

未决问题限定在部署差异，不影响编码规则：不同校园网启用的可选属性不同；目标服务器的证书信任策略需要由调用方配置；四个 IPv6 属性的业务名称仍未确定，但线上长度和字节布局已经明确。

## 术语

以下术语在后续页面中具有固定含义。

| 术语               | 定义                                                    |
| ------------------ | ------------------------------------------------------- |
| `username_bytes`   | 用户名在 EAP 载荷中的原始字节。中文账户使用 GBK 编码。  |
| `password_bytes`   | 密码在口令派生前使用的原始字节。中文密码使用 GBK 编码。 |
| `challenge`        | 服务器在 EAP-MD5 请求中下发的 16 字节随机值。           |
| `EAP identifier`   | EAP 请求中的单字节事务编号，响应必须原样返回。          |
| `vendor attribute` | 以厂商号 `0x00001311` 标识的锐捷私有字段。              |
| `compact field`    | 以 `code:u8, length:u8, value` 编码的紧凑厂商字段。     |
| `direct payload`   | SAM/SMP 直接通信中，DES-CBC 加密前的业务字节串。        |
| `fragment`         | 直接通信中不超过 1358 字节的一段加密载荷。              |
| `V3 digest`        | 依赖 16 字节 challenge 选择的 128 字符私有摘要文本。    |

本文使用“必须”“不得”“应当”“可”表达规范性要求。“应当”允许实现者有明确理由时不遵循；“可”表示可选能力。

## 分层模型

协议按依赖关系分为五层，实现顺序如下：

1. 链路帧层：Ethernet II、EAPOL 与 EAP。
2. 认证交换层：身份、MD5-Challenge、PEAP 与凭证响应。
3. 私有参数层：锐捷 TLV、固定服务器段和客户端能力字段。
4. 网络完成层：DHCP 地址获取、第二 EAP 或 DHCP 认证结果确认。
5. 会话层：SAM/SMP 直接通信、心跳、重认证和下线。

每一层只解释自身字节，不依赖上层结构的隐式偏移。实现者必须显式验证长度和厂商号，不得用字符串搜索代替结构化解析。

## 规范依据

标准外层依据 [IEEE 802.1X](https://standards.ieee.org/ieee/802.1X/7345/) 和 [RFC 3748](https://www.rfc-editor.org/rfc/rfc3748) 定义。EAP-MD5 继承 [RFC 3748](https://www.rfc-editor.org/rfc/rfc3748) 的消息模型，口令封装继承 [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865) 的链式 MD5 形式。PEAP 与 MSCHAPv2 使用标准 TLS 和 [RFC 2759](https://www.rfc-editor.org/rfc/rfc2759) 语义。

V3 使用的 MD5、SHA-1、RIPEMD-128、Tiger 与 Whirlpool 基础算法分别依据 [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321)、[RFC 3174](https://www.rfc-editor.org/rfc/rfc3174)、[RIPEMD-160 论文](https://homes.esat.kuleuven.be/~bosselae/ripemd160.html)、[Tiger 论文](https://www.cs.technion.ac.il/~biham/Reports/Tiger/) 与 [Whirlpool 规范](https://web.archive.org/web/20171118115359/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html)。私有构造的差异在[密码学与 V3 摘要](cryptography.md)中逐项定义。
