---
title: SAM 与 SMP 直接通信
description: 定义原始以太网会话、42 字节头、分片、重组、加密和业务消息
contentType: Reference
plan: "index.md#文档计划"
---

# SAM 与 SMP 直接通信

本页定义 EAP 成功后的直接通信。客户端使用原始以太网帧承载 IPv4 与 UDP，在 UDP 数据后放置 42 字节私有头和 DES-CBC 密文。

Linux 1.31 的静态证据还区分了“逻辑消息关联 ID”和“片段 ID”。厂商代码沿用 `dwSessionID` 来称呼前者，但它不是整场 Direct 生命周期的固定值，不能据此把所有消息绑定到同一个 ID。

本页未标记的帧层次、头字段、TLV、分片和密码学属于[第 1 类已证明事实](scope.md#信息分类)。Direct 所需的 DHCP、本机网络事实和硬件信息属于第 2 类 client 输入。

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

| 偏移   | 长度 | 字段           | 规则                         |
| ------ | ---- | -------------- | ---------------------------- |
| `0x00` | 1    | version        | 固定 `1`                     |
| `0x01` | 1    | code           | `1=data`，`2=response`       |
| `0x02` | 4    | fragment ID    | 同一发送上下文内逐片段递增   |
| `0x06` | 2    | packet length  | `42 + len(encrypted_chunk)`  |
| `0x08` | 16   | authenticator  | 见完整性校验                 |
| `0x18` | 4    | correlation ID | 逻辑消息关联值               |
| `0x1c` | 8    | timestamp      | 秒为单位的单调值或服务器时间 |
| `0x24` | 1    | message type   | 样本数据消息为 `1`           |
| `0x25` | 1    | flags          | 分片位置                     |
| `0x26` | 4    | total length   | 完整加密载荷长度             |

> TODO（后续版本可选补齐调查）：Direct version 2 的线格式、能力协商和状态差异。

`packet length` 必须等于当前 UDP 载荷减去 8 字节 UDP 头。`total length` 覆盖全部片段重组后的完整 DES-CBC 密文。

## ID 分配与重发

Linux 1.31 的 `CDirTranThread` 构造时把两个独立计数器初始化为 `1`：

- 逻辑消息关联计数器用于头字段 `0x18`。每次创建一条新的 SAM/SMP 逻辑消息时取当前值并递增。
- 片段计数器用于头字段 `0x02`。每发送一个新片段时递增。

同一片段的超时重发保留原 fragment ID、correlation ID、flags、密文、total length、session 参数和端点。一次建立新的 Direct 发送线程后，计数器重新从 `1` 开始。

Linux 1.31 的发送循环在 ACK 超时后回退已提前递增的 fragment ID、恢复输入偏移并按同一片段状态重新发送；
只重新取得 timestamp 并重算 authenticator。Windows 6.85 与 macOS 1.35 使用相同的片段身份语义。

原始客户端的 correlation ID 按逻辑消息变化，接收索引不能把它当成整场连接永远不变的 token。实现可以把该字段命名为 `session_id`，但必须明确其实际作用域。

macOS 1.35 的 fragment ID 和 correlation ID 分别位于 `CDirTranThread + 0x688` 和 `+0x6a8`，片段发送和逻辑消息发送路径分别递增。Windows 6.85 的 `CDirTranThread` 构造（`0x4a56d0`）同样把 fragment ID `+0x6c4` 和 correlation ID `+0x14cc` 初始化为 `1`；发送路径都是先取当前值，再递增。

三平台因此在计数语义上一致：新 Direct 发送上下文从 `1` 开始，每个新片段取得新的 fragment ID，每条新逻辑消息取得新的 correlation ID。当前 Zig 原型仍通过固定 `DirectSessionConfig.session_id` 发送所有消息，这是待修正的实现差异，不是未决协议语义。

Windows 6.85 的时间戳管理器在 Direct 构造时清空。首次发送以对端 IP/端口查表时尚无记录，返回 `0`；
服务器响应路径建立记录后，后续发送从 `1` 开始递增。重建 Direct 上下文会重新进入空表状态。

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

| 参数             | 用途                     |
| ---------------- | ------------------------ |
| peer IPv4        | 接收与发送端点           |
| peer UDP port    | 接收与发送端点           |
| local UDP port   | response 匹配            |
| correlation ID   | 请求、响应和重组索引     |
| DES key          | 载荷加密与 authenticator |
| initial IV       | 每次消息加密的起点       |
| timestamp state  | 防重放                   |
| next fragment ID | 分片编号                 |

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

当前 `SamConfig.session_parameter` 和 `endpoint_parameter` 是早期占位名；协议字段语义已经确认，后续实现应直接命名为 IPv4 和认证网卡 MAC。

### Client 输入：SAM/SMP 初始身份

| 信息               | 布局                                   |
| ------------------ | -------------------------------------- |
| `client_ipv4`      | SAM TLV `0x04` 的 4 字节本机 IPv4 地址 |
| `client_mac`       | SAM TLV `0x05` 的 6 字节认证网卡 MAC   |
| `host_disk_serial` | SMP hello TLV `0x03` 的变长硬盘序列号  |
| `username_gbk`     | SAM/SMP 用户身份 TLV 的 GBK 字节       |

#### `client_ipv4`

用途：标识参与本次 Direct 会话的本机 IPv4 地址。

client 获取方式：从当前认证网卡已经取得的 DHCP 租约或等价系统网络接口状态读取 IPv4 地址，并以网络字节序传入。

#### `client_mac`

用途：标识实际执行 802.1X 认证的网卡。

client 获取方式：从所选网络接口读取硬件地址，确保它与其他 EAPOL/Direct 帧使用的源 MAC 一致。

#### `host_disk_serial`

用途：在 SMP hello 中向服务器提供目标客户端使用的主机磁盘标识。

client 获取方式：从所选系统盘的稳定标识读取。

Linux 1.31 的 `getdiskid` 静态实现已经还原：

1. 读取 `/etc/mtab`，按空格切分，选择以 `/` 开头的设备字段。
2. 删除设备路径末尾连续十进制数字，例如 `/dev/sda1` 转为 `/dev/sda`。
3. 优先通过 `SG_IO` 的 SATA IDENTIFY 数据取得串号；失败时回退 `HDIO_GET_IDENTITY`。
4. 串号字段从设备信息偏移 `0x14` 读取，随后删除所有 ASCII 空格。
5. 不添加固定前缀；成功时把原始串号写入调用方缓冲区，失败返回错误。Linux 客户端传入 64 字节缓冲，`0x54` 编码时最多承载 64 字节。

macOS 1.35 不使用该 Linux 路径。它在应用启动时调用 `/usr/sbin/system_profiler` 的 `SPSerialATADataType`，解析 `Serial Number` 字段，删除空格和换行，并同样限制为 64 字节。

Windows 6.85 的 wrapper（`0x4c4680`）只接受磁盘索引 `0..3`。对每个候选索引依次尝试：

1. 系统卷或设备信息路径，IOCTL `0x560000`。
2. `\\.\PhysicalDrive%d`，IOCTL `0x7c088`。
3. `\\.\Scsi%d` 配合 `SCSIDISK`，IOCTL `0x4d008`。

任一设备信息读取成功后，`0x4c4d10` 从 Identify 串号字段取 10 个 16 位单元，按 SATA/ATA 的字序展开为最多 20 个 ASCII 字节，删除所有 `0x20` 空格。字段 `0x54` 的外层上限仍为 64 字节，因此 Windows 当前实现的有效串号上限是 20 字节。

#### `username_gbk`

用途：作为 SAM/SMP 业务身份，与 EAP 阶段使用的账户对应。

client 获取方式：取得用户账户名，按目标协议字段要求转换为 GBK 字节后传给 rj-connect；原客户端的长度上限仍需按部署 profile 校验。

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

| Command | 名称        | TLV                              |
| ------- | ----------- | -------------------------------- |
| `0x23`  | hello       | `0x02` 用户名，`0x03` 硬盘序列号 |
| `0x2d`  | user info   | 用户名和地址信息                 |
| `0x2e`  | DHCP result | `0xce` 成功标志，`0xcf` 消息     |

SMP 的 `0x03` 与 SAM 的 `0x04` 不同：Linux 1.31 从 `tagSmpParaDir.HDSerialNO` 读取硬盘序列号。现有 Zig 公共类型中的 `session_parameter` 是旧占位名，不能据此推断字段来源。

`SmpConfig.session_parameter` 的协议语义已经确认是主机硬盘序列号；后续实现应移除该占位名。

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

> TODO（后续版本可选补齐调查）：SAM/SMP 的 ACL、密码修改、主机信息和服务切换等辅助业务消息。

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

SMP 路径还会对本地端口创建 UDP bind；确定性库本身只生成完整帧，监听、绑定或等价过滤由 client adapter 负责。

> 当前 Zig 代码暂不实施：UDP socket 创建、绑定和收包。client 提交完整 Ethernet 帧。

服务器 UTC 字段 `0x5e` 非零时，发送时间戳使用服务器时间锚点。缺失或为零时，Linux 1.31 使用本地单调发送序列；该状态的记录从零开始，`GetNextTimeStampForSend` 返回下一个值，因此已有记录上的首个发送值为 `1`。

Linux 1.31 和 macOS 1.35 的 Direct fragment/correlation 计数器都从 `1` 开始。macOS 1.35 与 Windows 6.85 的 Direct 参数构造都设置对端端口 `8080`、本地端口 `80`；Windows 还设置片段 ACK 等待 `3000 ms` 和三次发送尝试。

Windows 6.85 的 `CDirTranThread` 构造先把时间戳管理器指针 `+0x14c8` 清零；Direct 初始化随后调用 `0x55f640` 创建管理器，其时间戳表初始为空。取下一发送时间戳的路径（`0x5635e0`）按目标键查找记录；记录不存在时返回 `0`，存在时把记录中的 64 位值加一并返回。因此 Windows 的全新发送上下文在时间戳表仍为空时，首个发送时间戳是 `0`，不是 Linux 路径的 `1`。服务器时间或对端记录的写入会改变后续值。

当前 rj-connect 要求 client 在无服务器 UTC 时显式提供单调起点；`local_udp_port = 20000` 则是当前库的原型默认策略，不是 Linux 1.31 客户端默认值。

协议默认值已经明确：Linux、macOS 和 Windows 样本都使用对端 `8080`、本地 `80`；服务器字段 `0x5a`、`0x6e` 覆盖回退值。rj-connect 应把端口、时间戳策略和计数器生命周期收口到内部具名 Direct profile，不应继续要求 client 解释这些协议语义。

> 运行调查（认证后 Direct）：保持认证成功后的当前连接，记录实际首发送时间戳、后续记录建立时点、fragment/correlation 递增和重发复用、UDP 端点与端口回退、缺失 `0x61` 时的 SAM/SMP 选择、心跳/重认证/重连时间线，以及同一 Windows 会话不同消息的 `0x4d`/`0x60`。静态代码已给出候选机制，但这些结论依赖真实会话状态和 socket 行为，不能用离线编码结果替代。

2026-10-24 的 macOS 1.35 目标采集确认服务器把端口覆盖为对端 `53`、本地 `138`，但该 EAP-MD5
会话在 Success 后的观察窗口内没有产生 Direct UDP 帧。缺失 `0x61` 时的静态选择已经确认是 SAM `9`；
实际 socket、时间戳、计数器、心跳和重发仍需要在服务器实际启动 Direct 的部署上观察。
