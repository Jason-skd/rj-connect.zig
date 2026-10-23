---
title: SAM 与 SMP 直接通信
description: 定义原始以太网会话、42 字节头、分片、重组、加密和业务消息
contentType: Reference
plan: "index.md#文档计划"
---

# SAM 与 SMP 直接通信

本页定义 EAP 成功后的直接通信。客户端使用原始以太网帧承载 IPv4 与 UDP，在 UDP 数据后放置 42 字节私有头和 DES-CBC 密文。

Linux 1.31 的静态证据还区分了“逻辑消息关联 ID”和“片段 ID”。厂商代码沿用 `dwSessionID` 来称呼前者，但它不是整场 Direct 生命周期的固定值，不能据此把所有消息绑定到同一个 ID。

## 帧层次

直接通信帧的层次为：

| 层              | 长度 | 说明                                 |
| --------------- | ---- | ------------------------------------ |
| Ethernet II     | 14   | 目的 MAC、源 MAC、EtherType `0x0800` |
| IPv4            | 20   | IHL 5，TTL 128，protocol 17          |
| UDP             | 8    | 源端口、目的端口、长度、校验和       |
| direct header   | 42   | 本页定义                             |
| encrypted chunk | 可变 | 最多 1358 字节                       |

IPv4 total length 等于 `28 + 42 + len(encrypted_chunk)`。UDP length 等于 `8 + 42 + len(encrypted_chunk)`。IP 头和 UDP 校验和必须按 IPv4 规则重新计算。

## 42 字节头

所有整数使用大端序。

| 偏移   | 长度 | 字段          | 规则                         |
| ------ | ---- | ------------- | ---------------------------- |
| `0x00` | 1    | version       | 固定 `1`                     |
| `0x01` | 1    | code          | `1=data`，`2=response`       |
| `0x02` | 4    | fragment ID   | 同一发送上下文内逐片段递增   |
| `0x06` | 2    | packet length | `42 + len(encrypted_chunk)`  |
| `0x08` | 16   | authenticator | 见完整性校验                 |
| `0x18` | 4    | correlation ID | 逻辑消息关联值              |
| `0x1c` | 8    | timestamp     | 秒为单位的单调值或服务器时间 |
| `0x24` | 1    | message type  | 样本数据消息为 `1`           |
| `0x25` | 1    | flags         | 分片位置                     |
| `0x26` | 4    | total length  | 完整加密载荷长度             |

`packet length` 必须等于当前 UDP 载荷减去 8 字节 UDP 头。`total length` 覆盖全部片段重组后的完整 DES-CBC 密文。

## ID 分配与重发

Linux 1.31 的 `CDirTranThread` 构造时把两个独立计数器初始化为 `1`：

- 逻辑消息关联计数器用于头字段 `0x18`。每次创建一条新的 SAM/SMP 逻辑消息时取当前值并递增。
- 片段计数器用于头字段 `0x02`。每发送一个新片段时递增。

同一片段的超时重发保留原 fragment ID、correlation ID、flags、密文、total length、session 参数和端点。一次建立新的 Direct 发送线程后，计数器重新从 `1` 开始。

原始客户端的 correlation ID 按逻辑消息变化，接收索引不能把它当成整场连接永远不变的 token。实现可以把该字段命名为 `session_id`，但必须明确其实际作用域。

## 分片标志

| flags | 使用条件                 |
| ----- | ------------------------ |
| `1`   | 完整加密载荷只有一个片段 |
| `2`   | 多片段的第一个片段       |
| `3`   | 多片段的中间片段         |
| `4`   | 多片段的最后一个片段     |

每个片段重新生成 42 字节头。fragment ID 在每个片段后递增，correlation ID 在同一逻辑消息的所有片段中相同。`packet length` 使用当前片段长度，`total length` 在所有片段中保持一致。

重发超时片段时沿用该片段上一次的 flags，不创建新的“重试值”。

## 分组与发送

最大密文片段为 `0x54e`，即 1358 字节。设完整密文长度为 `L`：

```text
if L <= 1358:
    send one fragment with flags=1
else:
    send chunks with flags=2, 3, …, 3, 4
```

发送器可以保存已发送片段以支持超时重发。每次重发必须保留原来的 fragment ID、correlation ID、total length 和片段偏移。

## 接收与重组

接收键由源 IPv4、源 UDP 端口和 correlation ID 组成。同一键只能维护一个活动重组缓冲。

接收顺序如下：

1. 验证 Ethernet、IPv4、UDP 和头长度。
2. 验证 version、correlation ID、packet length 和 total length。
3. 验证 timestamp 窗口。
4. 按 flags 重置、追加或完成重组。
5. 累计密文长度等于 total length 后执行 DES-CBC 解密。
6. 把解密后的 direct payload 交给 SAM/SMP 解析器。

fragment ID 允许等于上一片段或上一片段加一。更大的跳号，以及早于上一片段超过一个编号的包，必须丢弃。

末片的追加长度必须刚好补齐 total length。重复片段不得重复追加。重组缓冲在成功解密、会话关闭和超时后释放。

## 时间戳与重放

会话可运行在服务器时间模式或单调时间模式。

服务器时间模式保存服务器 UTC 和本地单调时钟的对应关系。收到的时间戳与本地推算值的绝对差必须小于 61 秒。

单调时间模式下，时间戳大于会话记录值时会更新记录并清零乱序计数。时间戳等于或小于记录值时，接收端最多连续接受 5 个这样的包，并递增乱序计数；超过计数后丢弃。后者是客户端保留的兼容容忍，不应解释为严格单调校验。

时间验证位于解密之前。验证失败的包不得改变重组缓冲。

## 加密边界

direct payload 先零填充到 8 字节整数倍，再使用 DES-CBC 加密：

```text
padded = direct_payload || 0x00 * padding_length
encrypted = DES-CBC(key, initial_iv, padded)
```

分片作用于完整 `encrypted`，不是明文。接收端完成重组后才解密。

每个会话持有 8 字节 DES key 和 8 字节初始 IV。key 与 IV 的来源和导出规则见[密码学与 V3 摘要](cryptography.md)。

## 完整性校验

计算 authenticator 前，把 header 的 `authenticator` 字段视为 16 个零字节：

```text
hash_input =
    header[0..8]
    || zero[16]
    || header[24..42]
    || encrypted_chunk
    || des_key[8]
    || initial_iv[8]

authenticator = MD5(hash_input)
```

把 16 字节摘要写入 header 的 `0x08..0x17`。接收端对每个片段独立校验。ACK 的 `packet_length=42`、`total_length=0`，使用相同规则。

## 会话绑定

每条直接会话至少保存：

| 参数            | 用途                     |
| --------------- | ------------------------ |
| peer IPv4       | 接收与发送端点           |
| peer UDP port   | 接收与发送端点           |
| local UDP port  | response 匹配            |
| correlation ID  | 请求、响应和重组索引     |
| DES key         | 载荷加密与 authenticator |
| initial IV      | 每次消息加密的起点       |
| timestamp state | 防重放                   |
| next fragment ID | 分片编号                |

收到来自其他地址、端口或 correlation ID 的数据时，不得复用当前密钥或重组缓冲。

## SAM 消息

SAM 的业务载荷使用单字节 `type` 和单字节 `length`。最小握手携带：

```text
01 01 02
03 username_len username_bytes
04 04 client_ipv4[4]
05 06 client_mac[6]
```

`01 01 02` 是握手前缀，最后字节 `02` 为握手码。后续字段使用单字节长度 TLV。Linux 1.31 从 DHCP 结果取 `client_ipv4`，从认证适配器取 `client_mac`。两者在 Direct 初始化时确定，不是随机会话参数。

SAM 用户信息消息以 `01 01 08` 开头，随后使用 TLV：

| Code   | 值        |
| ------ | --------- |
| `0x03` | 用户名    |
| `0x04` | IPv4 地址 |
| `0x05` | MAC 地址  |
| `0x0b` | 子网掩码  |
| `0x0c` | 默认网关  |
| `0x0d` | DNS       |

DHCP 认证结果位于外层 TLV `0x09`。其内部字段为：

```text
0x02 length message
0x13 0x01 success:u8
```

成功标志缺省为 false。未知内部 TLV 按长度跳过。

## SMP 消息

SMP direct payload 以 4 字节固定头开始：

```text
01 00 01 command
```

第一个字节为版本 `1`，随后是 16 位值 `1`，最后是命令字。命令后的 TLV 使用 `code:u8 || length:u16be || value`。

核心命令如下：

| Command | 名称        | TLV                                |
| ------- | ----------- | ---------------------------------- |
| `0x23`  | hello       | `0x02` 用户名，`0x03` 硬盘序列号   |
| `0x2d`  | user info   | 用户名和地址信息                   |
| `0x2e`  | DHCP result | `0xce` 成功标志，`0xcf` 消息       |

SMP 的 `0x03` 与 SAM 的 `0x04` 不同：Linux 1.31 从 `tagSmpParaDir.HDSerialNO` 读取硬盘序列号。现有 Zig 公共类型中的 `session_parameter` 是旧占位名，不能据此推断字段来源。

SMP user info 的核心地址字段为：

| Code   | 值            |
| ------ | ------------- |
| `0x03` | 用户名        |
| `0xc9` | IPv4 地址     |
| `0xca` | 子网掩码      |
| `0xcb` | 默认网关      |
| `0xcc` | DNS           |
| `0xcd` | IPv4 端点组合 |
| `0xd3` | 备用 DNS      |

DHCP result 的 `0xce` 长度固定为 1。`0xcf` 为 GBK 文本，可以为空。

SMP hello 连续失败 3 次时，会话返回重连流程。持续失败最终进入 held 或 logoff，不得在旧 key 上继续发送心跳。

## 心跳与重认证

服务器字段 `0x59` 给出心跳间隔，`0x56` 给出重认证间隔，`0x80` 给出心跳策略标志。会话建立后，客户端按这些值安排心跳和重认证。

每条心跳是新的逻辑消息，因此获得新的 correlation ID；key、IV 和端点保持不变。其片段 ID 继续按发送上下文递增。重认证到达时，客户端停止旧会话、清除分片状态，并在新 Direct 初始化中重新建立计数器和关联 ID。

## 端口、时间戳与本地回退

Linux 1.31 在服务器未提供 Direct 端点参数时使用：

| 参数             | 初始回退值 | 服务器覆盖字段 |
| ---------------- | ---------- | -------------- |
| 对端 Direct 端口 | `8080`     | `0x5a`         |
| 本地 Direct 端口 | `80`       | `0x6e`         |

SMP 路径还会对本地端口创建 UDP bind；确定性库本身只生成完整帧，监听、绑定或等价过滤由 adapter 负责。

服务器 UTC 字段 `0x5e` 非零时，发送时间戳使用服务器时间锚点。缺失或为零时，Linux 1.31 使用本地单调发送序列；该状态的记录从零开始，`GetNextTimeStampForSend` 返回下一个值。macOS 1.35 和 Windows 6.85 是否保持相同回退初值仍需样本级验证。

当前 rj-connect 要求调用方在无服务器 UTC 时显式提供单调起点，这是确定性库边界；`local_udp_port = 20000` 则是当前库的默认策略，不是 Linux 1.31 客户端默认值。
