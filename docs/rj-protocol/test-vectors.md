---
title: 协议测试向量
description: 用固定输入验证 EAP、口令、私有摘要、V3、直接通信和分片实现
contentType: Reference
plan: "index.md#文档计划"
---

# 协议测试向量

本页提供不依赖客户端和认证服务器的固定输入。实现者应逐项匹配字节结果，不要只比较显示文本。

本页全部向量属于[第 1 类已证明事实](scope.md#信息分类)。向量中的 MAC、IP、用户名和材料值只用于验证编码，不代表部署默认值。

## 标准 EAP-MD5

输入：

```text
identifier = 0x17
password_bytes = "secret"
challenge = 000102030405060708090a0b0c0d0e0f
```

摘要与响应 data：

```text
proof = 0791b0bc38facd8642ac55319122d6ce
response_data =
  10
  0791b0bc38facd8642ac55319122d6ce
```

第一字节是值长度 16，随后是原始摘要。标准响应不把摘要转换成十六进制文本，也不在 data 中附加用户名。

## 锐捷私有 EAP-MD5

输入：

```text
identifier = 0x17
username_bytes = "alice"
challenge = 000102030405060708090a0b0c0d0e0f
```

摘要与响应 data：

```text
proof = 274e6550014566df49bb07457d33ca38
proof_text = "274e6550014566df49bb07457d33ca38"
response_data =
  20
  3237346536353530303134353636646634396262303734353764333363613338
  616c696365
```

`response_data` 的第一字节是值长度 32，随后是 32 字节小写摘要文本，最后是用户名。

该向量只适用于锐捷私有用户名证明分支，不能用来验证标准 EAP-MD5。

## 口令链

输入：

```text
username_bytes = "alice"
starting_value = 000102030405060708090a0b0c0d0e0f
password_bytes = "secret"
```

填充后的明文为一个 16 字节块，密文为：

```text
560e1bdc df4af351 57eeadb5 32c7ae01
```

多块输入 `0123456789abcdefghij` 的 32 字节密文为：

```text
155a4a9d 8e0bc566 6fd7ccd7 51a3cb67
3f2482ac a4ee88d8 4b37358a caff122a
```

## RC4

公开已知答案：

```text
key = "Key"
plaintext = "Plaintext"
ciphertext = bbf316e8d940af0ad3
```

服务器字段 `0x5c` 和 `0x5d` 使用 ASCII key `com.ruijie.www`。实现者应使用自己的 8 字节密文字段替换本节的公开输入，检查输出长度和值。

## CRC-16

输入 `123456789`，参数为多项式 `0x1021`、初值 `0`、不反射、最终不异或：

```text
crc = 31c3
```

## legacy DHCP info

输入：

```text
dhcp_enabled = true
ip = c000020a
netmask = ffffff00
gateway = c0000201
dns = cb007135
```

编码结果：

```text
00001311 01 c000020a ffffff00 c0000201 cb007135 90ee
```

前 21 字节参与 CRC，末两字节为大端校验和。

## 私有摘要

以下输入均为 ASCII `abc`：

| 算法       | 输出                                                                                                                               |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `MD5vz`    | `d2019111e1f08912b901330e74d0acd6`                                                                                                 |
| `SHA1vz`   | `131dd5dfa657eee89736f363c24c61a2a4be8969`                                                                                         |
| `RIPEMDvz` | `8c8425440ded3c588454bfa20811e895`                                                                                                 |
| Tiger      | `874f688f73634ed4b23fadef27302e5b81ba495285d03032`                                                                                 |
| Whirlpool  | `b3a3ecd0b330ea533e9e563c461d8834207c51aa5b7fc4cc8d831499c1db9347cdbec8311607f33f4492748204c9c4e65339d52c41b25b6f6c5f810c9e9d3de2` |

`MD5vz` 与 `SHA1vz` 的结果必须逐字节匹配。若实现得到标准 MD5 的 `900150983cd24fb0d6963f7d28e17f72` 或标准 SHA-1 的 `a9993e364706816aba3e25717850c26c9cd0d89d`，说明私有差异未实现。

## V3

完整 V3 输入：

```text
app = "app-data"
dll = "dll-data"
challenge = 000102030405060708090a0b0c0d0e0f
```

mode 0 的中间文本为：

```text
MD5vz(app) = 8b9f194d58df330878407f3ff80d2d90
MD5vz(dll) = 842650e8b7f252df13cc30d116fc02f2
even_text = 00020406080a0c0e
odd_text = 01030507090b0d0f
```

mode 0 到 4 的 Whirlpool 输入为：

```text
mode0 =
  8b9f194d58df330878407f3ff80d2d9000020406080a0c0e
  842650e8b7f252df13cc30d116fc02f201030507090b0d0f

mode1 =
  6464a6cfb1f4e5c278239b51670fdfd3507fd0f1
  000102030405
  1583c304cc3a164fa4f127b977d85c5dd7f288b1
  060708090a0b0c0d0e0f

mode2 =
  6464a6cfb1f4e5c278239b51670fdfd3507fd0f1
  000102030405
  eb9dee982eeb10a99b694c0b13fa1c2a
  060708090a0b0c0d0e0f
```

mode 3 与 mode 4：

```text
mode3 =
  d9b6418b25940adc08a5b0c6143bcc41c0e00306e0da4315
  00010203040506070809
  1e58826822dd13fe65ff16b48148c4e8
  0a0b0c0d0e0f

mode4 =
  aff6558a581de405e1750fa3ec8ededf6facc0d9e64ceb01
  0001020304050607
  1583c304cc3a164fa4f127b977d85c5dd7f288b1
  08090a0b0c0d0e0f
```

每个 `modeN` 的相邻文本行按顺序直接拼接。Whirlpool 输出为：

| Mode | 输出                                                                                                                               |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | `a7d145a544344844ecc5fad3c6dff281434ba33cd0a9174bc38bea0f4d70c33d9bbeaca1fea1bb5a534673b6903e18c3f8929174ee7b52aa76e4e386286dc101` |
| `1`  | `e1359f9ebaaa94a5c229357459ea6f79305591df1e1c0c7c4ec6345057e07ce0bb71bfc6aaed3be6a5f5897353dc10c023a116f2230c9b8b80363a0b2150ed85` |
| `2`  | `b08a61780d4609349163772dfa30be0d57f70c8af1a7c0694024d14ddcbea4e277dd01c6b07715e254b879d4ca0b9d858bba21b99c16923c7e59df5a6cd64643` |
| `3`  | `717fb3022cecc0abe02fd540f6c7bdfa463fde8812949df7870cd22a82222ad6102c5f9eaf8f27bbb791929374575b13b8a196fcb68ab083eaaa90f1be2ee6e6` |
| `4`  | `ab9c956b99bbd550d98d4eae3d6df608c34bce7f8439afab905fc7ea4929014436d6f2422dad044b2363ddd90aba7f432488366829cc2ed8215609f1bb6deb3a` |

选择器边界：

```text
challenge[0] = ff
challenge[3] = ff
signed sum = -2
mode = 4
```

## 直接通信头与 authenticator

SAM 最小握手的固定输入：

```text
username_bytes = "alice"
client_ipv4 = c000020a
client_mac = 001122334455
```

编码结果：

```text
010102
03 05 616c696365
04 04 c000020a
05 06 001122334455
```

输入：

```text
version = 1
code = 1
id = 01020304
packet_len = 45
authenticator = 00 * 16
session_id = 11223344
timestamp = 0102030405060708
message_type = 1
flags = 4
total_len = 7
encrypted_chunk = aabbcc
des_key = 0001020304050607
initial_iv = 08090a0b0c0d0e0f
```

编码后的头为：

```text
0101 01020304 002d
00000000000000000000000000000000
11223344 0102030405060708 01 04 00000007
```

MD5 authenticator：

```text
5a04b12c8d43bfd7c877e7a72527e4c0
```

## 分片

对长度 1400 字节的密文，片段长度与 flags 为：

| 片段 | 密文长度 | fragment ID | correlation ID | total length | flags |
| ---- | -------- | ----------- | -------------- | ------------ | ----- |
| 1    | 1358     | 连续值 A    | 本次逻辑消息值 | 1400         | `2`   |
| 2    | 42       | A + 1       | 与首片相同     | 1400         | `4`   |

两个片段的 fragment ID 连续，correlation ID、key、IV 和 total length 不变。测试向量中的 `session_id = 11223344` 只是编码样例，不是原客户端分配规则。

## 验收方法

独立实现至少通过以下检查：

1. 所有原始摘要和 V3 输出逐字节相等。
2. 错误 challenge 长度、错误厂商号和截断字段均返回明确失败。
3. 直接通信分片换序、重复和超时不会把未完成缓冲交给解密器。
4. 单片段与多片段分别产生 flags `1` 和 `2,3,…,4`。
5. 解密或 authenticator 校验失败不改变当前会话的 key、IV 和 timestamp。
