[English](README.md) | **中文**

# strongSwan 国密 (SM2/SM3/SM4) 分支

## 概述

本分支基于 [strongSwan](https://www.strongswan.org/) 6.0.4，新增了中国国密算法 (GM/T) 支持，使 IKEv2/IPsec VPN 能够使用 SM2/SM3/SM4 算法进行密钥协商、认证和数据加密。

所有国密算法通过 OpenSSL 插件实现，要求 OpenSSL 3.0+ 且编译时启用了 SM2/SM3/SM4 支持。

## 支持的国密算法

| 算法 | 标准 | 用途 | 标识符 |
|------|------|------|--------|
| SM2 | GB/T 32918 | 公钥认证（SM2 曲线上的数字签名） | `SIGN_SM2_WITH_SM3` |
| SM3 | GB/T 32905 | 哈希、HMAC 完整性校验（128/256位）、PRF | `HASH_SM3`、`AUTH_HMAC_SM3_128`、`PRF_HMAC_SM3` |
| SM4-CBC | GB/T 32907 | 分组加密（128位密钥） | `ENCR_SM4_CBC` |

## 快速开始

### 编译

```sh
# 安装依赖（以 Ubuntu/Debian 为例）
apt-get install automake autoconf libtool pkg-config bison flex gperf \
    libgmp-dev libssl-dev make gcc g++

# 生成构建系统
./autogen.sh

# 配置（启用国密所需插件）
./configure --enable-openssl --enable-hmac --enable-swanctl --enable-pki \
    --enable-charon --enable-ikev2 --enable-vici

# 编译安装
make -j$(nproc) && make install
```

### 配置

SM2/SM3/SM4 的算法标识位于 IKE 私有范围（>=1024），双端均需启用私有算法接受：

```
# /etc/strongswan.conf
charon {
    accept_private_algs = yes
}
```

所需插件：`openssl`（SM2/SM3/SM4 原语）和 `hmac`（HMAC-SM3 签名与 PRF 构造）。

### 协商关键字

在 `swanctl.conf` 的 proposals 中使用以下关键字：

| 关键字 | 变换类型 | 说明 |
|--------|----------|------|
| `sm4cbc` | 加密 | SM4-CBC 模式，128 位密钥 |
| `sm3` | 完整性 | HMAC-SM3，128 位截断 |
| `prfsm3` | PRF | HMAC-SM3 伪随机函数 |

### 配置示例：全国密 IKEv2

以下示例展示两台主机之间使用全国密算法套件建立 IKEv2 VPN 连接。

**网关 moon（发起方）配置：**

```
# /etc/swanctl/swanctl.conf
connections {
    gm-host {
        local_addrs = 192.168.0.1
        remote_addrs = 192.168.0.2

        local {
            auth = pubkey
            certs = moonCert.pem
            id = moon@example.com
        }
        remote {
            auth = pubkey
            id = sun@example.com
        }
        children {
            gm-child {
                mode = transport
                esp_proposals = sm4cbc-sm3
            }
        }
        version = 2
        proposals = sm4cbc-sm3-x25519
    }
}
```

此配置建立的 IKEv2 SA 使用：
- **加密**：SM4-CBC-128
- **完整性**：HMAC-SM3-128
- **PRF**：PRF-HMAC-SM3
- **密钥交换**：Curve25519
- **认证**：SM2 证书 + SM3 签名

### 生成 SM2 证书

使用 OpenSSL 生成国密证书：

```sh
# 1. 生成 SM2 CA 密钥和自签名证书
openssl genpkey -algorithm SM2 -out ca.key
openssl req -new -x509 -key ca.key -out ca.pem -days 365 \
    -sm3 -subj "/CN=SM2 CA/O=Example" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. 生成终端实体密钥和证书
openssl genpkey -algorithm SM2 -out moon.key
openssl req -new -key moon.key -out moon.csr -sm3 -subj "/CN=moon@example.com"

cat > moon_ext.cnf << 'EOF'
[v3_ee]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectAltName = email:moon@example.com
EOF

openssl x509 -req -in moon.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out moon.pem -days 365 -sm3 \
    -extensions v3_ee -extfile moon_ext.cnf

# 3. 安装到 swanctl 目录
cp ca.pem   /etc/swanctl/x509ca/caCert.pem
cp moon.pem /etc/swanctl/x509/moonCert.pem
cp moon.key /etc/swanctl/private/moonKey.pem
```

> **注意**：终端实体证书必须包含 `subjectAltName` 扩展（与 swanctl.conf 中配置的 `id` 匹配），否则 strongSwan 无法在信任链验证时找到匹配的证书。

## Docker 端到端测试

本仓库提供了基于 Docker 的全国密 IKEv2 握手端到端测试。

### 运行测试

```sh
./scripts/sm2-ikev2-test.sh
```

该脚本会：
1. 构建包含国密支持的 strongSwan Docker 镜像
2. 生成 SM2 CA 和终端实体证书
3. 启动两个容器（moon 发起方 / sun 响应方）
4. 执行 IKEv2 握手并验证 SA 建立状态
5. 检查 SM4-CBC 和 SM3 算法协商结果

### 测试架构

```
┌──────────────┐         IKEv2/SM2         ┌──────────────┐
│     moon     │ ◄═══════════════════════► │     sun      │
│  (发起方)    │    SM4-CBC + HMAC-SM3     │  (响应方)    │
│  10.10.0.10  │      ESP 传输模式         │  10.10.0.20  │
└──────────────┘                           └──────────────┘
         sm2net (10.10.0.0/24)
```

### 相关文件

| 文件 | 说明 |
|------|------|
| `Dockerfile.sm2-ikev2` | 全国密 IKEv2 Docker 镜像 |
| `docker-compose.sm2-ikev2.yml` | 双容器编排（moon + sun） |
| `scripts/sm2-ikev2-setup.sh` | SM2 证书生成脚本 |
| `scripts/sm2-ikev2-entrypoint.sh` | 容器入口脚本（配置 + 启动 charon） |
| `scripts/sm2-ikev2-test.sh` | 端到端测试编排脚本 |

## 技术实现

### 修改的源码文件

<details>
<summary>点击展开完整列表</summary>

**密码算法注册**
- `src/libstrongswan/crypto/hashers/hasher.c` — SM3 哈希注册
- `src/libstrongswan/crypto/crypters/crypter.c` — SM4-CBC 加密器注册
- `src/libstrongswan/crypto/signers/signer.c` — HMAC-SM3 签名器注册
- `src/libstrongswan/crypto/prfs/prf.c` — PRF-HMAC-SM3 注册
- `src/libstrongswan/crypto/proposal/proposal.c` — 协商关键字解析
- `src/libstrongswan/crypto/proposal/proposal_keywords_static.txt` — 关键字定义

**OpenSSL 插件**
- `src/libstrongswan/plugins/openssl/openssl_plugin.c` — SM2/SM3/SM4 特性注册
- `src/libstrongswan/plugins/openssl/openssl_crypter.c` — SM4-CBC 加密实现
- `src/libstrongswan/plugins/openssl/openssl_ec_private_key.c` — SM2 签名
- `src/libstrongswan/plugins/openssl/openssl_ec_public_key.c` — SM2 验签 + SM2 公钥加载
- `src/libstrongswan/plugins/openssl/openssl_x509.c` — SM2 证书解析与验证

**HMAC 插件**
- `src/libstrongswan/plugins/hmac/hmac.c` — HMAC-SM3 构造
- `src/libstrongswan/plugins/hmac/hmac_plugin.c` — SM3 签名器/PRF 特性注册

**公钥基础设施**
- `src/libstrongswan/credentials/keys/public_key.c` — SM2 签名方案 OID 映射
- `src/libstrongswan/plugins/pkcs1/pkcs1_builder.c` — SM2 公钥解析
- `src/libstrongswan/plugins/pkcs8/pkcs8_builder.c` — SM2 私钥解析

**ASN.1/OID**
- `src/libstrongswan/asn1/oid.txt` — SM2/SM3 OID 定义

</details>

### 关键设计决策

1. **SM2 签名**：使用 OpenSSL 的 `EVP_DigestSign/Verify` API，依赖 OpenSSL 内部的 Z 值（区分标识符）计算，使用默认 ID `"1234567812345678"`。
2. **SM2 证书验证**：通过 `X509_verify()` 实现（OpenSSL 内部正确处理 SM2 Z 值计算），而非手动提取公钥验签。
3. **私有算法范围**：SM4-CBC、HMAC-SM3 的 IKE Transform ID 使用私有范围值（>=1024），需要在 `strongswan.conf` 中设置 `accept_private_algs = yes`。

## 上游 strongSwan 文档

本分支基于 strongSwan 6.0.4。关于 strongSwan 的通用使用方法（证书管理、swanctl 配置、各种 VPN 场景等），请参阅：

- [strongSwan 官方文档](https://docs.strongswan.org)
- [strongSwan Wiki](https://wiki.strongswan.org)
- [原始 README（英文）](README.md)

## 许可证

与 strongSwan 相同，采用 [GPLv2](COPYING) 许可证。
