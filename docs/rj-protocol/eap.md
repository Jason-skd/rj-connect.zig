---
title: EAPOL 与 EAP 报文
description: 定义认证外层的字节顺序、EAP-MD5 交互和响应构造规则
contentType: Reference
---

# EAPOL 与 EAP 报文

本页定义认证帧外层、请求类型及 EAP-MD5 响应，涵盖 Start、Identity、MD5-Challenge、Notification、NAK 与 Logoff。

EAP-MD5 至少存在两种响应分支：标准口令证明和锐捷私有用户名证明。两者的摘要输入、值长度和输出编码不同。

本页未标记的报文布局和固定向量属于[第 1 类已证明事实](scope.md#信息分类)。身份与凭据属于第 2 类 client 输入。

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

### Client 输入：接收帧

| 信息             | 布局                                     |
| ---------------- | ---------------------------------------- |
| 接收 Ethernet 帧 | 从 Ethernet II 目的 MAC 开始的完整帧字节 |

用途：推进 EAPOL Start、Request、Success、Failure 和 Logoff 状态，并按 EtherType 与 EAP type 分派。

client 获取方式：从认证网卡抓包或链路层 socket 读取完整帧，保留原始长度和有效字节，不裁剪 Ethernet 头。

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

### Client 输入：身份与凭据

| 信息             | 布局                                                |
| ---------------- | --------------------------------------------------- |
| `username_bytes` | EAP Identity 和锐捷私有 MD5 证明使用的原始用户名    |
| `password_bytes` | 标准 EAP-MD5 口令证明和锐捷私有口令链使用的原始密码 |

#### `username_bytes`

用途：作为 Identity Response 的正文、锐捷私有 MD5 证明的输入，以及后续 SAM/SMP 业务消息的用户身份。

client 获取方式：取得用户提供的账户名，按目标协议字段要求转换为 GBK 字节。

#### `password_bytes`

用途：参与标准 EAP-MD5 证明，或参与锐捷私有的用户名链式口令加密。PEAP/MSCHAPv2 的密码学语义由 provider 处理。

client 获取方式：从用户秘密输入或 client 自有凭据存储取得，转换为本分支要求的 GBK 字节。命令行、环境、交互和存储策略由 client 决定。

Linux 1.31 同时支持标准 EAP-MD5 和锐捷私有 EAP-MD5：标准路径属于内嵌 wpa_supplicant，私有路径属于有线认证。实际采用的分支取决于部署。

Linux 1.31 和 Windows 6.85 使用相同的 `AuthMode` 字符串映射：

| `AuthMode`    | EAP type |
| ------------- | -------- |
| `EAPMD5`      | `4`      |
| `EAPWIRELESS` | `25`     |
| `EAPTLS`      | `13`     |

Windows 还分别读取 `support_md5`、`support_peap`、`support_tls_wired` 和 `support_tls_wireless`。启动认证时优先使用当前选中的 PEAP 方法；否则若当前方法为 EAP-TLS 则使用 type `13`；其余情况回退 PEAP。当前主路径没有把 `Support=5` 统一解释为 EAP type 位图；实际方法由具名 `AuthMode` 和 profile 字段决定。目标部署的 `AuthMode` 与服务器选用方法是分别确定的会话条件。

Windows 6.85 的 `Support`/`SupportNum` 分别表示能力位图和能力数量：`support_md5`、`support_peap`、`support_tls_wired`、`support_tls_wireless` 分别置 bit `0..3`，count 为置位数量。随包 Windows profile 的 `Support=5` 因而表示 `md5+peap` 能力，不是 EAP type `5`。Linux 1.31 的同名项属于配置保存内容，其认证含义尚未明确。

三个平台的随包配置分别使用学校代码 `SCNU`（Linux）、`gznu`（Windows）和 `gyzyu`（macOS）。Windows 配置还包含 `CustomNameEnglish=GZSFDX_DOT1X` 与 EAP Type `25` 的凭据及 WLAN profile。各配置的学校范围独立。

macOS 1.35 的一个部署使用标准形状的 EAP-MD5：服务器选择 MD5-Challenge，客户端以 `value_size=16`、16 字节原始摘要和用户名响应，服务器返回 Success。其 `authmode=1` 表示接入模式，不等同于 EAP type。

> TODO（当前版本待调查）：其他部署的学校配置、`AuthMode` 与服务器实际选择的 EAP 方法之间的对应关系尚未明确。

## 请求与响应分派

服务器 Request 按 EAP type 分派，客户端响应如下：

| 服务器 Request               | 客户端动作                                |
| ---------------------------- | ----------------------------------------- |
| Identity，type `1`           | 返回 Identity Response                    |
| Notification，type `2`       | 回报 Notification Response，正文可为空    |
| Legacy NAK，type `3`         | 返回 NAK Response                         |
| MD5-Challenge，type `4`      | 按部署分支计算标准或锐捷私有 MD5 Response |
| OTP，type `5`                | 返回 NAK Response                         |
| Generic Token Card，type `6` | 返回 NAK Response                         |
| Credential，type `7`         | 返回用户名和口令字节                      |
| PEAP，type `25`              | 建立 PEAP/TLS 隧道并按内层方法认证        |

### 方法支持与选择范围

Linux 1.31 支持以下内嵌方法（表按 EAP type 排列）：

| EAP type | 方法         | 适用路径                                                  |
| -------- | ------------ | --------------------------------------------------------- |
| `4`      | EAP-MD5      | 私有有线状态机直接分派 MD5-Challenge                      |
| `5`      | EAP-OTP      | 仅内嵌 wpa_supplicant 实现；有线私有状态机收到后返回 NAK  |
| `6`      | EAP-GTC      | 仅内嵌 wpa_supplicant 实现；有线私有状态机收到后返回 NAK  |
| `13`     | EAP-TLS      | 内嵌实现；Windows 的 `AuthMode=EAPTLS` 映射到该 type      |
| `17`     | EAP-LEAP     | 仅内嵌实现；当前网络配置没有选择入口                      |
| `21`     | EAP-TTLS     | 仅内嵌实现；当前网络配置没有选择入口                      |
| `25`     | EAP-PEAP     | 内嵌实现；Windows EAPHost/EAPWIRELESS profile 选择该 type |
| `26`     | EAP-MSCHAPv2 | PEAP/TTLS 可用的内层方法                                  |

内嵌方法集合与有线私有认证的方法集合不同。有线私有路径只直接处理 Identity、Notification、Legacy NAK、MD5-Challenge 与 Credential，并对 OTP/GTC 返回 NAK。Linux 1.31 无线配置固定为 `eap=PEAP` 与 `phase2="auth=MSCHAPV2"`，不含 TTLS、GTC、OTP 或 LEAP 选择项。

EAP-TLS 同时具有内嵌支持与具名选择配置：Windows 的 `AuthMode=EAPTLS` 对应 type `13`，能力项为 `support_tls_wired` 与 `support_tls_wireless`。TLS 记录、证书与身份验证由平台 provider 处理；具体选用条件属于部署范围。

> TODO （后续版本可选实施）：EAP-TLS、EAP-TTLS、EAP-GTC、EAP-LEAP、EAP-OTP 和独立 EAP-MSCHAPv2 外层认证。

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
10 proof[16] [name]
```

首个字节是值长度 `16`，随后是 16 字节原始摘要，不转换成十六进制文本。name 为可选用户名；macOS 1.35 的一个部署使用带用户名的响应，MentoHUST 使用不带 name 的同一摘要分支，Linux 1.31 内嵌 wpa_supplicant 也支持标准路径。name 不参与 proof 计算，也不改变 `value_size`。

> TODO （后续版本可选实施）：标准 EAP-MD5 分支。

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

Linux 1.31 有线私有路径使用这一响应；其用户名证明与 RFC 3748 的标准口令证明属于不同分支。

## 凭证响应

type `7` 的响应不使用 MD5 包装：

```text
02 id len_hi len_lo 07 username_len:u8 username_bytes password_bytes
```

`username_len` 取 `username_bytes` 的长度，范围为 `0..255`。`len` 等于 `6 + username_len + len(password_bytes)`。

## 通知与 NAK

Notification Response 使用 code `2`、type `2`，并复用请求 identifier。正文可以为空，也可以复制服务器通知的非敏感状态文本。

NAK Response 使用 code `2`、type `3`。data 的首字节可给出期望的替代方法，后接可选建议方法列表。单个 `4` 表示仅支持 MD5-Challenge。

## 下线帧

Logoff 是以太网外层中的 EAPOL packet type `2`，body length 为零。客户端在用户主动停止或认证会话终态时发送一次 Logoff；发送失败不改变本地会话已经终止的事实。

## 定时与重试

连接、启动、认证和 held 阶段各自拥有独立超时。超时只触发当前状态评估，不得把旧请求的迟到响应应用到新会话。

基本状态转移如下：

1. 进入 connecting 后发送 Start。
2. 收到有效 Request 后进入 acquired，并返回 Identity。
3. 收到 MD5-Challenge 后进入 authenticating，并返回 MD5 Response。
4. 收到 Success 后执行网络完成阶段。
5. Failure 或认证超时进入 held；held 超时后重试，重试次数超过策略上限后进入 logoff。

定时器与状态关系由[认证状态机](authentication.md)定义。重发计时器到期不表示 EAP 成功。

## 错误边界

以下帧必须被拒绝：

- EtherType 不等于 `0x888E`。
- EAPOL version 不等于 `1`。
- EAP length 小于 4，或超过 EAPOL body 长度。
- Request 的 identifier 与会话当前 identifier 不匹配。
- MD5-Challenge 的 `value_size` 不是 16。
- 长度字段指向载荷之外。

被拒绝的帧不得改变当前 challenge、identifier 或状态。
