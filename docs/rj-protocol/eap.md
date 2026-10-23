---
title: EAPOL 与 EAP 报文
description: 定义认证外层的字节顺序、EAP-MD5 交互和响应构造规则
contentType: Reference
plan: "index.md#文档计划"
---

# EAPOL 与 EAP 报文

本页定义认证帧的完整外层、请求类型分派和 EAP-MD5 响应构造。实现者完成本页后可以生成 Start、Identity、MD5-Challenge、Notification、NAK 和 Logoff 帧。

EAP-MD5 至少存在两种已观察响应：标准口令证明和锐捷私有用户名证明。它们不能共用同一个 encoder。

## 以太网与 EAPOL 外层

认证帧是以太网 II 帧，EtherType 为大端 `0x888E`。标准目的地址为 `01:80:C2:00:00:03`，锐捷 NAS 模式可使用服务器返回的地址。

| 偏移   | 长度 | 字段               | 编码                           |
| ------ | ---- | ------------------ | ------------------------------ |
| `0x00` | 6    | 目的 MAC           | 以太网地址                     |
| `0x06` | 6    | 源 MAC             | 认证网卡地址                   |
| `0x0c` | 2    | EtherType          | `0x888E`                       |
| `0x0e` | 1    | EAPOL version      | 固定 `1`                       |
| `0x0f` | 1    | packet type        | `0=Start`，`1=EAP`，`2=Logoff` |
| `0x10` | 2    | packet body length | 大端，不含前 4 字节            |
| `0x12` | 可变 | body               | EAP 帧或空                     |

Start 与 Logoff 的 body length 为零。EAP packet type 的线上值为 `0`，不是表格中常用的“类型 0”概念。

## EAP 帧

EAP body 从 EAPOL 偏移 `0x12` 开始。

| 偏移   | 长度 | 字段       | 编码                                                |
| ------ | ---- | ---------- | --------------------------------------------------- |
| `0x00` | 1    | code       | `1=Request`，`2=Response`，`3=Success`，`4=Failure` |
| `0x01` | 1    | identifier | 单字节事务号                                        |
| `0x02` | 2    | length     | 大端，含 code、identifier、length 和 type           |
| `0x04` | 1    | type       | 仅 Request 或 Response 存在                         |
| `0x05` | 可变 | data       | 由 type 定义                                        |

响应必须复用对应请求的 identifier。未知服务器 identifier 的响应应当丢弃，避免旧请求覆盖当前交换。

## 请求与响应分派

服务器 Request 按 EAP type 分派，客户端响应如下：

| 服务器 Request               | 客户端动作                             |
| ---------------------------- | -------------------------------------- |
| Identity，type `1`           | 返回 Identity Response                 |
| Notification，type `2`       | 回报 Notification Response，正文可为空 |
| Legacy NAK，type `3`         | 返回 NAK Response                      |
| MD5-Challenge，type `4`      | 按部署分支计算标准或锐捷私有 MD5 Response |
| OTP，type `5`                | 返回 NAK Response                      |
| Generic Token Card，type `6` | 返回 NAK Response                      |
| Credential，type `7`         | 返回用户名和口令字节                   |
| PEAP，type `25`              | 建立 PEAP/TLS 隧道并按内层方法认证     |

服务器 `Success` code `3` 表示 EAP 方法成功，`Failure` code `4` 表示方法失败。它们不是 EAP Request。

## 身份响应

Identity Response 使用 code `2`、type `1`，data 为 `username_bytes`，不得附加 NUL。

```text
02 id len_hi len_lo 01 username_bytes
```

`len` 等于 `5 + len(username_bytes)`。

## MD5 challenge 请求

MD5-Challenge Request 的 data 按以下顺序解释：

```text
value_size:u8
challenge[value_size]
name[name_length]
```

认证核心要求 `value_size=16`。服务器附带的 name 可用于显示或服务选择，但不参与口令摘要。

## 标准 EAP-MD5 响应

标准分支遵循常见 802.1X EAP-MD5 语义。客户端用单字节 EAP identifier、口令原始字节和 challenge 计算：

```text
proof = MD5(id:u8 || password_bytes || challenge[16])
```

响应 data 为：

```text
10 proof[16]
```

首个字节是值长度 `16`，随后是 16 字节原始摘要，不转换成十六进制文本，也不附加用户名。MentoHUST 的 `checkPass` 走这一分支；Linux 1.31 内嵌的 wpa_supplicant 也保留这一标准路径。

## 锐捷私有 EAP-MD5 响应

锐捷私有分支先计算单字节 EAP identifier、用户名 GBK 字节和 challenge 的标准 MD5：

```text
proof = MD5(id:u8 || username_bytes || challenge[16])
proof_text = lowercase_hex(proof)
```

响应 data 依次为：

| 字段       | 长度 | 值                         |
| ---------- | ---- | -------------------------- |
| value-size | 1    | 固定 `32`                  |
| response   | 32   | `proof_text` 的 ASCII 字节 |
| name       | 可变 | `username_bytes`           |

线上布局为：

```text
02 id len_hi len_lo 04 20 proof_text[32] username_bytes
```

EAP length 等于 `5 + 1 + 32 + len(username_bytes)`。`proof_text` 使用小写十六进制。用户名不参与响应 value-size。该分支随后还可附加 legacy DHCP 信息、口令字段、V3 摘要和其他锐捷私有属性。

Linux 1.31 的 `CStateMachineThread::txRspAuth` 明确构造这一私有响应。它不是 RFC 3748 EAP-MD5 的标准口令证明，文档和实现都必须用独立分支名称区分。

## 凭证响应

type `7` 的响应不使用 MD5 包装：

```text
02 id len_hi len_lo 07 username_len:u8 username_bytes password_bytes
```

`username_len` 取 `username_bytes` 的长度，范围为 `0..255`。`len` 等于 `6 + username_len + len(password_bytes)`。

## 通知与 NAK

Notification Response 使用 code `2`、type `2`，并复用请求 identifier。正文可以为空，也可以复制服务器通知的非敏感状态文本。

NAK Response 使用 code `2`、type `3`。data 的首字节可给出期望的替代方法，后接可选建议方法列表。最小实现返回单个 `4`，表示仅支持 MD5-Challenge。

## 下线帧

Logoff 是以太网外层中的 EAPOL packet type `2`，body length 为零。客户端在用户主动停止或认证会话终态时发送一次 Logoff；发送失败不改变本地会话已经终止的事实。

## 定时与重试

连接、启动、认证和 held 阶段各自拥有独立超时。超时只触发当前状态评估，不得把旧请求的迟到响应应用到新会话。

实现应当遵守以下顺序：

1. 进入 connecting 后发送 Start。
2. 收到有效 Request 后进入 acquired，并返回 Identity。
3. 收到 MD5-Challenge 后进入 authenticating，并返回 MD5 Response。
4. 收到 Success 后执行网络完成阶段。
5. Failure 或认证超时进入 held；held 超时后重试，重试次数超过策略上限后进入 logoff。

具体关闭定时器的位置由[认证状态机](authentication.md)定义。实现不得只依赖重发计时器判断 EAP 成功。

## 错误边界

以下帧必须被拒绝：

- EtherType 不等于 `0x888E`。
- EAPOL version 不等于 `1`。
- EAP length 小于 4，或超过 EAPOL body 长度。
- Request 的 identifier 与会话当前 identifier 不匹配。
- MD5-Challenge 的 `value_size` 不是 16。
- 长度字段指向载荷之外。

被拒绝的帧不得改变当前 challenge、identifier 或状态。
