# nonReentrant 挡不住的重入：两种你可能忽略的场景

> 作者：Mingyang Fan (@SymmaTe)
> 发布时间：2026-03

---

在审计智能合约的过程中，我发现一个很普遍的误区：很多开发者看到合约加了 `nonReentrant`，就认为重入问题已经解决了。但在实际的漏洞案例里，我见过两类"加了 `nonReentrant` 依然出问题"的场景，它们的根本原因不同，但都指向同一个结论：**锁只能防止重入这个动作，防不了外部调用期间合约处于中间状态这个事实**。

本文默认你已经了解经典重入攻击和 CEI 原则，直接进入这两种场景。

---

## 场景一：CEI 根本无法遵守——Balance Diff 模式

### 为什么 CEI 在这里失效

CEI 的核心是"先改完所有状态，再做外部调用"。但有一类合约的业务逻辑天生无法遵守这个原则——以 **balance diff（余额差值）** 来记账的合约：

```
记录调用前余额（balanceBefore）
↓
执行外部操作（swap、transfer 等）  ← 外部调用必须在这里
↓
记录调用后余额（balanceAfter）
↓
用差值作为实际转入/转出量
```

这个模式是处理 fee-on-transfer 代币的标准做法，外部调用必须夹在两次余额读取之间，无法前移。这意味着在外部调用发生期间，合约的最终状态**永远是未确定的**——这是结构决定的，加 `nonReentrant` 解决不了这个问题。

### 案例：Notional Finance redeemNative()

> 原始报告：Notional Finance · Sherlock audit https://solodit.cyfrin.io/issues/redeemnative-reentrancy-enables-permanent-fund-freeze-systemic-misaccounting-and-liquidation-cascades-mixbytes-none-notional-finance-markdown

攻击者构造了一条包含恶意 token 的 swap 路径（ETH → 恶意Token → WETH），在恶意 token 的回调里注入攻击逻辑。

**没有 `nonReentrant` 时，经典的重入攻击：**

```
攻击者调用 redeemNative()
    ↓
合约记录：balanceBefore = 1000 ETH
    ↓
合约执行 swap：ETH → 恶意Token → WETH
    ↓  ← 恶意Token的回调触发
    |
    └→ 【重入】攻击者再次调用 redeemNative()
           内层：balanceBefore = 1000 ETH（ETH 还没出去！）
           内层：执行 swap，ETH 转出 → balanceAfter = 900 ETH
           内层：diff = 100 ETH，给攻击者 100 份额
           ↓
    回到外层：balanceAfter = 900 ETH（ETH 已被内层取走）
    外层：diff = 100 ETH，再给攻击者 100 份额
    ↓
结果：攻击者用 100 ETH 的代价拿到了 200 份额的价值
```

**为什么能成功？**

关键在于 `balanceBefore` 是一个快照——它在函数最开始就拍下了"合约有 1000 ETH"。外层调用拍完快照之后，控制权通过回调交给了攻击者，攻击者的内层调用趁机把 ETH 取走了。等外层调用拿到 `balanceAfter` 时，ETH 已经少了，但外层的 `balanceBefore` 还是 1000，所以 diff 被算成了 100，实际上那 100 ETH 早就被内层拿走了。两层各自算了一遍 diff，100 ETH 被记了两次账。

---

**加了 `nonReentrant` 之后：**

内层再次调用 `redeemNative()` 被锁拒绝，上面这条路被堵住了。

但攻击者只需换一条路：**在回调里不重入 `redeemNative()`，而是调用合约里其他没有被同一个锁保护的函数**。

举例：假设合约里还有一个 `claimRewards()` 没有被同一个锁保护：

```
合约记录 balanceBefore = 1000 ETH
    ↓
合约执行 swap，恶意Token的回调触发
    ↓
    └→ 攻击者在回调里调用 claimRewards()
       claimRewards() 从合约取走 50 ETH 给攻击者
    ↓
回到 redeemNative()：
  balanceAfter = 850 ETH（100 ETH swap 花掉 + 50 ETH 被 claimRewards 取走）
  diff = 1000 - 850 = 150 ETH
  合约认为攻击者赎回了 150 份额的资产
  但攻击者实际只花了 100 ETH，额外拿走了 50 ETH
```

**为什么 nonReentrant 没用？**

`nonReentrant` 只是给 `redeemNative()` 这一个函数加了锁，但攻击者在回调里调用的是 `claimRewards()`——完全不同的函数，没有被同一把锁保护。锁拦截不了这条路。

根本问题没有改变：balanceBefore 和 balanceAfter 之间存在一个外部调用窗口，攻击者只要能控制这个窗口里发生的事，就能让 diff 的计算结果偏大。

### 真正的修复

不允许用户指定 swap 路径中的 token 地址，或对 token 合约做白名单限制——切断攻击者对外部调用行为的控制权。只要攻击者无法在回调里插入自己的代码，diff 的计算就是安全的。

---

## 场景二：遵守了 CEI 依然出问题——跨合约只读重入

场景一的根本原因是业务逻辑**无法**遵守 CEI。场景二更反直觉：**代码遵守了 CEI，但依然有漏洞**。

CEI 定义：先做 Effect（状态更新），再做 Interaction（外部调用）。

- `_burn` = Effect（修改 totalSupply）
- `_transferAssets` = Interaction（发送 ETH，触发外部回调）

先 burn 后 transfer，Effect 在前 Interaction 在后——**这正是 CEI 要求的顺序**。但它仍然产生了漏洞。

### 具体场景

```solidity
// ⚠️ 遵守了 CEI，但仍然危险
function redeem(uint256 shares, address receiver) external nonReentrant {
    _burn(msg.sender, shares);    // Effect：totalSupply↓，但 totalAssets 未变
    // ← 此刻 sharePrice = totalAssets / totalSupply 偏高
    _transferAssets(receiver);    // Interaction：发送 ETH，触发攻击者的 receive()
}
```

```
_burn 执行：totalSupply = 900，totalAssets = 1000
    ↓
sharePrice = 1000 / 900 = 1.11  ← 偏高（份额少了但资产还在）
    ↓
_transferAssets 发送 ETH，触发攻击者的 receive()
    ↓
攻击者的 receive() {
    // 此时 ETH 还没真正转出去，receive() 是在传输途中触发的
    // ERC4626 状态：totalSupply=900，totalAssets=1000，sharePrice=1.11
    lendingProtocol.borrow(ERC4626_share_as_collateral);
    // 借贷协议读到 sharePrice=1.11
    // 攻击者手里 100 shares，本来只值 100 USD
    // 现在被估值为 111 USD → 多借出 11 USD
}
    ↓
receive() 执行完，ETH 真正转出
totalAssets = 900，sharePrice 恢复正常
但攻击者已经用偏高的价格多借走了资产
```

**为什么 nonReentrant 没用？**

ERC4626 合约的 `nonReentrant` 保护的是 ERC4626 自身不被重入。但攻击者在 `receive()` 里调用的是**借贷协议**，完全是另一个合约——ERC4626 的锁管不到它。

借贷协议自己就算加了 `nonReentrant` 也没用，因为它的锁防的是借贷协议自身被重入，不影响它去读取 ERC4626 的状态数据。两个合约各自有各自的锁，没有任何一把锁能阻止这个跨合约的状态读取。

### 修复

调换顺序，先 transfer 后 burn：

```solidity
// ✅ 安全顺序
function redeem(uint256 shares, address receiver) external nonReentrant {
    _transferAssets(receiver);    // 先发送 ETH，触发 receive()
    // ← receive() 触发时：totalSupply 和 totalAssets 都没有变化
    // ← sharePrice 完全正常，攻击者在回调里什么都做不了
    _burn(msg.sender, shares);    // receive() 执行完后再销毁 shares
    // ← burn 之后没有任何外部调用，无法被利用
}
```

**为什么安全？**

先执行 `_transferAssets`，ETH 开始发送，`receive()` 被触发。此时 `_burn` 还没有执行，所以 totalSupply 和 totalAssets 都没有任何变化，sharePrice 完全正常。攻击者在回调里读到的是正常价格，借贷协议不会给出超额授信。

等 `receive()` 执行完，ETH 才真正到账，然后 `_burn` 执行销毁份额。整个过程里，外部调用触发的那一刻状态是完整的，没有任何中间状态可以被利用。

---

## 两个场景的统一视角

表面上看两个场景很不一样，但背后的逻辑是一致的：

| | 场景一（balance diff） | 场景二（只读重入） |
|--|--|--|
| CEI 的情况 | 无法遵守，业务逻辑决定的 | 遵守了 CEI，但依然有漏洞 |
| 外部调用来源 | 用户构造的恶意 swap 路径 | ETH transfer 触发的 receive() |
| 攻击者在回调里做什么 | 调用其他函数污染 balanceAfter | 调用第三方合约读取偏高价格 |
| nonReentrant 有没有用 | 没用，换条路就能绕过 | 没用，根本不需要重入 |
| 修复方向 | 限制外部调用的可控范围 | 调换顺序，让外部调用触发时状态完全正常 |

两者都利用了"外部调用期间合约处于中间状态"这个窗口。场景二更值得警惕——代码遵守了 CEI，看起来没有问题，但只要外部调用触发时有任何状态不一致，就可能被跨合约读取利用。

---

## 审计 Checklist

**看到 balance diff 模式：**
- `balanceBefore` / `balanceAfter` 之间有外部调用吗？
- 外部调用的 token 地址或 swap 路径可以由用户指定吗？
- 合约里有没有其他没被同一个锁保护的函数可以被回调利用？

**看到 ERC4626 或类似金库：**
- burn 和 transfer 的顺序是什么？先 burn 后 transfer = 危险
- 中间有外部调用（包括 ETH 转账触发的 receive）吗？
- 有没有第三方协议在读取这个合约的 sharePrice 或类似数据？

**看到 nonReentrant 时不要放心，要问：**
- 外部调用期间，合约的哪些状态是不一致的？
- 攻击者在回调里不重入任何函数，直接作恶，锁还有用吗？
- 有没有跨合约读取中间状态的可能？

---

重入攻击在 2016 年因为 The DAO 事件广为人知，但到今天仍然是审计中最容易被低估的一类漏洞。`nonReentrant` 是必要条件，但远不是充分条件。真正需要关注的不是"有没有加锁"，而是**外部调用发生的那一刻，合约的状态是否完整一致**。
