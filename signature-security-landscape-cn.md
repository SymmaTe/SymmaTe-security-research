# 签名安全全景：四种签名体系的常见漏洞模式

> Author: Mingyang Fan (@SymmaTe)
> Published: 2026-03

---

签名是区块链安全的核心机制——它证明"这个操作经过了授权"。但在审计中我反复看到一个规律：**问题几乎从不出在签名算法本身，而是出在算法被使用的方式上**。

hash 构造缺少上下文、验证逻辑存在旁路、签名被错误的场景复用、数学合法与业务合法之间的割裂——每种签名体系都有自己的陷阱。

本文按签名类型逐一梳理，每种讲清楚它是什么、怎么用、以及审计中最常见的漏洞模式。

---

## 一、ECDSA + EIP-712

### 签名原理

ECDSA（椭圆曲线数字签名算法）是以太坊的基础签名算法。签名过程：

```
私钥 + hash → 签名（r, s, v）
ecrecover(hash, 签名) → 公钥 / 地址
```

ECDSA 本身对 hash 的内容完全不关心，只管数学。安全性完全依赖 **hash 是否绑定了足够的上下文**。

EIP-712 是 hash 的构造规范，定义了一套结构化数据序列化标准，并强制在 hash 中加入 domain separator：

```
domain separator = hash({
    chainId,           ← 绑定链
    verifyingContract, ← 绑定合约
    name, version      ← 绑定协议版本
})

最终 hash = hash("\x19\x01" + domain_separator + struct_hash)
```

ERC1271 是智能合约钱包的签名验证标准，定义了 `isValidSignature(bytes32 hash, bytes sig)` 接口，让智能合约也能像 EOA 一样验证签名。

### 常见漏洞

**1. ERC1271 签名重放：hash 缺少上下文绑定**

`isValidSignature` 对 EOA 签名的验证只做"恢复地址是否匹配 owner"，不检查 hash 的构造。如果 hash 缺少以下绑定：

| 缺少的绑定 | 后果 |
|--|--|
| chainId | 跨链重放：同一签名在其他链有效 |
| verifyingContract | 跨账户重放：同一 EOA 控制的多个智能钱包可互相重放 |
| nonce / 使用标记 | 历史签名重放：用过的签名可再次使用 |

### 案例：SSO Account OIDC Recovery — ERC1271 签名重放

> 原始报告：[SSO Account OIDC Recovery Solidity Audit · May 2025](https://solodit.cyfrin.io/issues/potential-signature-replay-attack-in-erc1271handler-openzeppelin-none-sso-account-oidc-recovery-solidity-audit-markdown)

```
场景 1：历史签名重放
用户曾签名授权操作 A（hash_A + sig_A）
    ↓
攻击者发现场景 B 也接受相同的 hash_A
    ↓
isValidSignature(hash_A, sig_A) 返回 valid → 场景 B 被执行

场景 2：跨链重放（hash 不含 chainId）
用户在 Chain A 上签名
    ↓
攻击者把相同的 hash + sig 提交到 Chain B
isValidSignature 同样返回 valid

场景 3：跨账户重放（hash 不含 verifyingContract）
同一 EOA 控制 Account_1 和 Account_2
用户在 Account_1 签名的操作
    ↓
攻击者把 hash + sig 提交给 Account_2 → 同样通过
```

修复方案：使用 ERC7739 的防御性重哈希方案，在 app 层 hash 外再套一层 EIP-712，强制绑定 chainId 和 verifyingContract。Solady 的 `ERC1271.sol` 提供了标准实现。

---

**2. typehash 拼写错误：签名永久失效**

```solidity
// 错误：typo 导致 typehash 与钱包计算的不一致
bytes32 constant MESSAGE_TYPEHASH =
    keccak256("SnowmanClaim(addres receiver, uint256 amount)");
//                          ↑ 缺少 's'

// 钱包用正确拼写生成的签名，与合约的 typehash 不匹配 → 所有人无法 claim
```

后果是功能完全 DoS——所有合法签名都验证失败。这类 bug 在测试时容易漏掉，因为测试用的 typehash 和合约一致，只有和标准钱包交互时才会暴露。

### 案例：Snowman Merkle Airdrop — MESSAGE_TYPEHASH 拼写错误

> 原始报告：[Snowman Merkle Airdrop Audit · Mar 2026（个人审计）](https://github.com/SymmaTe/my-audit-reports/blob/main/2026-03-08-MerkleAirdrop-audit.pdf)

```
合约：keccak256("SnowmanClaim(addres receiver, uint256 amount)")
                              ↑ 缺少 's'
钱包：keccak256("SnowmanClaim(address receiver, uint256 amount)")

两个 typehash 不同
    ↓
所有通过标准钱包生成的签名，签名验证全部失败
没有任何用户能 claim Snowman NFT
```

---

**3. 签名 flag 操控：验证路径被劫持**

签名本身有效，但验证逻辑存在旁路。比如用 bitmask 表示"是否启用某个验证模块"，攻击者在签名外附加自己构造的 flag，让验证器把 flag 一起纳入 hash 计算，从而控制验证路径。

根因：签名只绑定了"谁签的"，没有绑定"用什么配置验证"。

### 案例：Sequence — 签名 bitmask flag 操控绕过 checkpointer

> 原始报告：[Sequence · Code4rena](https://solodit.cyfrin.io/issues/h-01-chained-signature-with-checkpoint-usage-disabled-can-bypass-all-checkpointer-validation-code4rena-sequence-sequence-git)

```
前提：攻击者本身是合法签名者，但想绕过 checkpointer 的额外限制。

正常流程：
  签名 = sign(hash) + checkpointerEnabled flag
  验证器读取 flag → 启用 checkpointer → 进行额外验证

攻击：
  攻击者自己构造 flag = disabled，把 flag 附加在签名后提交
    ↓
  验证器把攻击者的 flag 纳入 hash 计算
  攻击者用自己私钥签署这个包含 flag=disabled 的 hash → 签名有效
    ↓
  checkpointer 被禁用 → 绕过所有检查点验证
```

### 审计 checklist

- `isValidSignature` 实现中，hash 是否包含 chainId 和 verifyingContract？
- TYPE_HASH 的类型字符串是否有拼写错误？
- 验证路径中是否存在用户可控的配置参数没有被纳入签名？
- 是否使用了经过审计的标准库（OpenZeppelin、Solady）？

---

## 二、EIP-2612 Permit

### 签名原理

EIP-2612 是 ERC20 的扩展，允许用签名代替 `approve`，实现 gasless 授权：

```
用户签名：permit(owner, spender, value, deadline, v, r, s)
任何人都可以把这个签名提交到链上 → 效果等同于 owner 调用了 approve(spender, value)
```

核心特点：**签名可以由任何人提交**，这是有意设计的，允许 relayer 代替用户支付 gas。

### 常见漏洞

**1. permit 调用未包裹 try/catch：griefing DoS（持续骚扰型拒绝服务）**

permit 签名进入 mempool 后，任何人都可以抢先提交。如果合约把 `permit` 和后续操作写在同一笔交易里且不容忍 `permit` 失败，攻击者只需复制签名参数提前调用，就能让用户的交易因签名已使用而永远 revert。

### 案例：LI.FI — permit 被抢先提交导致用户交易失败

> 原始报告：[LI.FI · Dec 2024](https://solodit.cyfrin.io/issues/griefing-attack-possible-by-frontrunning-the-calldiamondwitheip2612signature-function-call-cantina-none-lifi-pdf)

```
用户签名 permit → 提交 callDiamondWithEIP2612Signature → 进入 mempool
    ↓
攻击者监控 mempool，复制 permit 参数，直接调用 ERC20.permit()
攻击者交易先被打包：allowance 被设置，签名标记为已使用
    ↓
用户交易被打包：
  ERC20.permit() 因签名已使用而 revert
  整个交易失败
```

攻击者无法获利（allowance 被设置给了正确的 spender），但可以持续阻止用户交易执行。

正确写法：

```solidity
// ✅ permit 失败了没关系，检查 allowance 是否足够才是目的
try IERC20Permit(token).permit(owner, spender, amount, deadline, v, r, s) {
} catch {}

if (IERC20(token).allowance(owner, spender) < amount) revert InsufficientAllowance();
```

不管是用户自己提交的 permit 还是攻击者抢先提交的，结果都是 allowance 被正确设置——目的已达成，permit 调用本身失败不代表 allowance 不足。

---

**2. permit 签名钓鱼**

permit 签名不触发链上交易，用户在 MetaMask 等钱包里签名时没有 gas 提示，警惕性低。恶意 DApp 可以诱导用户签一个针对恶意合约的 permit，然后立刻调用 `transferFrom` 盗取资产。

---

**3. deadline 设置过长**

permit 签名包含 deadline 字段。如果 deadline 设置为极远的未来（甚至 `type(uint256).max`），签名一旦泄露可以在很长时间内被滥用。

### 审计 checklist

- 调用 `permit` 的地方是否包裹了 try/catch？
- try/catch 后是否正确检查 allowance 而不是依赖 permit 成功？
- 前端是否向用户清楚展示 permit 签名的授权对象和金额？
- deadline 是否设置合理？

---

## 三、BLS 聚合签名

### 签名原理

BLS（Boneh-Lynn-Shacham）签名的核心特性是**线性可加性**：多个签名可以合并成一个聚合签名，验证时只需验证一次，大幅减少链上验证开销。常用于 PoS 共识中的验证者集体签名。

```
签名聚合：
  sig_A = BLS.sign(privKey_A, msg)
  sig_B = BLS.sign(privKey_B, msg)
  sig_agg = sig_A + sig_B  ← 椭圆曲线点加法

验证：
  BLS.verify(pubKey_A + pubKey_B, msg, sig_agg) → true
```

### 常见漏洞

**1. 空白条目伪造投票权重（point at infinity）**

BLS 使用 BN254 等椭圆曲线，曲线上存在一个特殊的"无穷远点"（point at infinity），它是椭圆曲线群的单位元：

```
任意点 P + 无穷远点 = P
```

如果验证逻辑没有拒绝无穷远点作为公钥输入，攻击者可以注册一个"透明密钥"（pubKey = 无穷远点），它在聚合时不改变结果，但在统计投票权重时被计入，等于用零成本获得了投票权重。

### 案例：Symbiotic Relay — 无穷远点公钥伪造共识权重

> 原始报告：[Symbiotic Relay · Sherlock Jul 2025](https://solodit.cyfrin.io/issues/m-7-a-malicious-operator-will-control-consensus-without-risking-stake-stake-exit-lag-exploit-sherlock-symbiotic-relay-git)

```
攻击者注册验证者：pubKey = 无穷远点（point at infinity）
    ↓
聚合验证：
  pubKey_agg = 合法验证者集合 + 无穷远点
             = 合法验证者集合（数学上不变）
  sig_agg 验证通过 ✓
    ↓
但投票权重统计时：攻击者的透明密钥被计入
    ↓
攻击者以零质押获得投票权重 → 可能影响共识结果
```

修复：在电路和验证逻辑中明确拒绝无穷远点作为有效公钥。

---

**2. 流氓密钥攻击（Rogue Key Attack）**

BLS 聚合公钥的方式是直接做椭圆曲线点加法：`pubKey_agg = pubKey_A + pubKey_B + ...`。

攻击者注册公钥时，声明自己的公钥是 `pubKey_evil - pubKey_victim`。聚合结果：

```
pubKey_agg = pubKey_victim + (pubKey_evil - pubKey_victim) = pubKey_evil
```

聚合后的公钥完全由攻击者控制，攻击者单独就能对任意消息生成有效的聚合签名，无需受害者配合。

修复：使用 Proof of Possession，要求每个验证者在注册时提供自己私钥的签名，证明确实拥有对应私钥。

### 审计 checklist

- 验证逻辑是否拒绝无穷远点（point at infinity）作为公钥或签名？
- 是否实现了 Proof of Possession 防止流氓密钥攻击？
- 聚合签名中是否有对"参与者身份"的完整验证，而不只是验证签名数学上有效？

---

## 四、Schnorr 签名（Bitcoin Taproot）

### 签名原理

Bitcoin Taproot（2021 年激活）将底层签名算法从 ECDSA 切换为 Schnorr。Schnorr 的核心优势是**线性可加性**（与 BLS 类似），支持多签聚合（MuSig）。

Bitcoin 签名的输入是 **sighash**，而不是直接对交易数据签名。不同的交易格式，sighash 的计算规则不同：

| 格式 | sighash 是否包含 prevOut 数据 |
|--|--|
| Legacy（P2PKH 等） | 否 |
| SegWit v0（P2WPKH） | 是（金额） |
| Taproot / SegWit v1（BIP341） | 是（scriptPubKey + 金额） |

Taproot 要求 sighash 承诺每个输入的前序输出（prevOut）的 `scriptPubKey` 和 `amount`，目的是防止硬件钱包在不知道输入金额的情况下被欺骗签名。

### 常见漏洞

**1. Legacy → Taproot 迁移时 sighash 输入数据错误**

Legacy 格式的 sighash 不依赖 prevOut 数据，所以历史代码里常用 `NewCannedPrevOutputFetcher([]byte{}, 0)` 传入空占位值。迁移到 Taproot 后，sighash 计算规则发生了根本变化——必须传入每个输入对应 UTXO 的真实 `scriptPubKey` 和 `amount`。如果直接复用旧代码，编译照常通过，但计算出的 sighash 与比特币网络验证时用的不一致，签名永远无法通过。

### 案例：ZetaChain — Bitcoin Observer 使用空 prevOut 导致所有提款交易被拒绝

> 原始报告：[ZetaChain Cross-Chain · Sherlock May 2025](https://solodit.cyfrin.io/issues/m-38-bitcoin-observers-signed-transactions-will-be-rejected-due-to-invalid-sighashes-sherlock-zetachain-cross-chain-git)

```go
// 旧代码（Legacy）：没问题，Legacy sighash 不依赖 prevOut
sigHashes := txscript.NewTxSigHashes(tx,
    txscript.NewCannedPrevOutputFetcher([]byte{}, 0))

// 新代码（Taproot）：直接复制过来 → 编译通过，语义错误
sigHashes := txscript.NewTxSigHashes(tx,
    txscript.NewCannedPrevOutputFetcher([]byte{}, 0))  // ← 传入空 script + 0 金额
```

```
Observer（ZetaChain 的链下监听节点）用空 prevOut 计算 sighash_wrong → 签名
    ↓
广播到 Bitcoin 网络
    ↓
Bitcoin 节点从链上查真实 UTXO 数据
重新计算 sighash_correct（使用真实 scriptPubKey + 真实 amount）
    ↓
sighash_correct ≠ sighash_wrong → 签名验证失败
所有提款交易被网络拒绝
```

这类 bug 极难在本地测试中发现——测试用 mock 数据，sighash 验证被跳过，只有广播到真实网络才会暴露。

### 审计 checklist

- 涉及 Bitcoin 交易签名的代码，确认是 Legacy 还是 Taproot 格式？
- 搜索 `NewCannedPrevOutputFetcher` 的使用——生产代码中出现几乎是 bug 的信号
- 是否有针对真实 Bitcoin 网络的集成测试？

---

## 统一视角

四种签名体系，四类问题，但本质上都是同一个问题的不同表现：

| 签名类型 | 核心陷阱 | 根因 |
|--|--|--|
| ECDSA + EIP-712 | hash 上下文不完整 / typehash 错误 / 验证旁路 | 签名绑定的上下文不够完整 |
| EIP-2612 Permit | permit 调用未包裹 try/catch | 对"操作成功"和"目的达成"的混淆 |
| BLS 聚合签名 | 无穷远点伪造权重 / 流氓密钥攻击 | 数学合法 ≠ 业务合法 |
| Schnorr / Bitcoin | sighash 输入数据用了旧格式的占位值 | 新格式规则没有跟上代码迁移 |

签名安全的本质问题不是"算法够不够强"，而是：

> **签名绑定的上下文是否完整？验证的边界是否一致？底层假设是否随格式迁移同步更新？**

---

## 审计速查表

**ECDSA + EIP-712：**
- domain separator 是否包含 chainId 和 verifyingContract？
- typehash 的类型字符串是否有拼写错误？
- 是否存在用户可控的验证配置参数未被纳入签名？
- ERC1271 的 isValidSignature 是否实现了 ERC7739？

**EIP-2612 Permit：**
- permit 调用是否在 try/catch 中？
- try/catch 后是否检查 allowance 而非依赖 permit 成功？

**BLS 聚合签名：**
- 是否拒绝无穷远点（point at infinity）作为公钥？
- 是否实现了 Proof of Possession？

**Schnorr / Bitcoin：**
- 是否使用了 `NewCannedPrevOutputFetcher`（测试占位工具）？
- sighash 计算是否传入了真实的 prevOut 数据？
- 是否有针对真实网络的集成测试？

---

签名相关的代码在审计中往往最容易被跳过——`ecrecover` 返回了地址，`verify` 返回了 true，`permit` 只是一行调用——看起来都没问题。但漏洞从来不在这些调用本身，而在调用前后的上下文：hash 里绑定了什么，签名在哪些场景下有效，验证逻辑是否存在旁路，格式升级之后旧的假设是否还成立。

**审计签名代码时，与其盯着加密调用是否存在，不如追问：这个签名精确授权了什么，在当前场景下能不能被复用或滥用。**