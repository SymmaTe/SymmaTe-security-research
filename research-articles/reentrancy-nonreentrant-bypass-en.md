# Two Reentrancy Scenarios That nonReentrant Can't Stop

> Author: Mingyang Fan (@SymmaTe)
> Published: 2026-03

---

There's a common misconception I keep seeing in smart contract development: once `nonReentrant` is added, reentrancy is considered solved. In practice, I've encountered two types of scenarios where `nonReentrant` still fails. Their root causes are different, but both point to the same conclusion: **a lock can only prevent the act of re-entering — it cannot prevent a contract from being in an intermediate state during an external call**.

This article assumes you're already familiar with classic reentrancy attacks and the CEI principle.

---

## Scenario 1: CEI Cannot Be Followed — The Balance Diff Pattern

### Why CEI Breaks Down Here

The core of CEI is "update all state before making external calls." But there's a class of contracts whose business logic structurally cannot follow this principle — contracts that use **balance diff accounting**:

```
Record balance before (balanceBefore)
↓
Execute external operation (swap, transfer, etc.)  ← external call must go here
↓
Record balance after (balanceAfter)
↓
Use the difference as the actual amount transferred
```

This pattern is the standard way to handle fee-on-transfer tokens. The external call must sit between the two balance reads and cannot be moved earlier. This means during the external call, **the contract's final state is always undetermined** — that's a structural constraint, and adding `nonReentrant` doesn't solve it.

### Case Study: Notional Finance redeemNative()

> Original report: Notional Finance · Sherlock audit https://solodit.cyfrin.io/issues/redeemnative-reentrancy-enables-permanent-fund-freeze-systemic-misaccounting-and-liquidation-cascades-mixbytes-none-notional-finance-markdown

The attacker crafted a swap path containing a malicious token (ETH → MaliciousToken → WETH), injecting attack logic into the malicious token's callback.

**Classic reentrancy attack without `nonReentrant`:**

```
Attacker calls redeemNative()
    ↓
Contract records: balanceBefore = 1000 ETH
    ↓
Contract executes swap: ETH → MaliciousToken → WETH
    ↓  ← MaliciousToken callback fires
    |
    └→ [REENTRY] Attacker calls redeemNative() again
           Inner: balanceBefore = 1000 ETH (ETH hasn't left yet!)
           Inner: swap executes, ETH sent out → balanceAfter = 900 ETH
           Inner: diff = 100 ETH, attacker receives 100 shares
           ↓
    Back to outer: balanceAfter = 900 ETH (ETH already taken by inner call)
    Outer: diff = 100 ETH, attacker receives another 100 shares
    ↓
Result: attacker gets 200 shares worth of value for the cost of 100 ETH
```

**Why does this work?**

`balanceBefore` is a snapshot taken at the very start of the function — it records "the contract holds 1000 ETH." After the outer call takes its snapshot, control passes to the attacker through the callback. The inner call drains the ETH while the outer call is still in progress. By the time the outer call reads `balanceAfter`, the ETH is already gone — but its `balanceBefore` is still 1000, so the diff is calculated as 100. Those 100 ETH were already claimed by the inner call. Both layers each calculate a diff of 100, so 100 ETH gets accounted for twice.

---

**After adding `nonReentrant`:**

The inner call to `redeemNative()` gets rejected by the lock, so this attack path is blocked.

But the attacker just needs a different route: **instead of re-entering `redeemNative()`, call another function in the contract that isn't protected by the same lock**.

Example — suppose the contract has a `claimRewards()` function not covered by the same lock:

```
Contract records balanceBefore = 1000 ETH
    ↓
Contract executes swap, MaliciousToken callback fires
    ↓
    └→ Attacker calls claimRewards() from the callback
       claimRewards() sends 50 ETH to the attacker
    ↓
Back in redeemNative():
  balanceAfter = 850 ETH (100 ETH spent on swap + 50 ETH drained by claimRewards)
  diff = 1000 - 850 = 150 ETH
  Contract thinks attacker redeemed 150 ETH worth of shares
  But attacker only spent 100 ETH — the extra 50 ETH was free
```

**Why doesn't nonReentrant help?**

`nonReentrant` only locks `redeemNative()` itself. The attacker's callback calls `claimRewards()` — a completely different function with no shared lock. The lock can't intercept this path.

The root problem is unchanged: there's an external call window between `balanceBefore` and `balanceAfter`. As long as the attacker can control what happens inside that window, they can inflate the diff calculation.

### The Real Fix

Don't allow users to specify token addresses in the swap path, or whitelist token contracts — cut off the attacker's ability to control what the external call does. Once an attacker can't inject their own code into the callback, the diff calculation is safe.

---

## Scenario 2: CEI Is Followed, Yet Still Vulnerable — Cross-Contract Read-Only Reentrancy

Scenario 1's root cause is that CEI **cannot** be followed. Scenario 2 is more counterintuitive: **the code follows CEI, but there's still a vulnerability**.

CEI definition: Effects (state changes) before Interactions (external calls).

- `_burn` = Effect (modifies totalSupply)
- `_transferAssets` = Interaction (sends ETH, triggers external callback)

Burn before transfer — Effect before Interaction — **this is exactly what CEI requires**. Yet it still produces a vulnerability.

### The Scenario

```solidity
// ⚠️ Follows CEI — but still dangerous
function redeem(uint256 shares, address receiver) external nonReentrant {
    _burn(msg.sender, shares);    // Effect: totalSupply↓, but totalAssets unchanged
    // ← sharePrice = totalAssets / totalSupply is now inflated
    _transferAssets(receiver);    // Interaction: sends ETH, triggers attacker's receive()
}
```

```
_burn executes: totalSupply = 900, totalAssets = 1000
    ↓
sharePrice = 1000 / 900 = 1.11  ← inflated (fewer shares, same assets)
    ↓
_transferAssets sends ETH, triggering attacker's receive()
    ↓
attacker's receive() {
    // ETH hasn't actually arrived yet — receive() fires mid-transfer
    // ERC4626 state: totalSupply=900, totalAssets=1000, sharePrice=1.11
    lendingProtocol.borrow(ERC4626_share_as_collateral);
    // Lending protocol reads sharePrice=1.11
    // Attacker holds 100 shares, normally worth 100 USD
    // Now valued at 111 USD → borrows 11 USD extra
}
    ↓
receive() completes, ETH actually transfers out
totalAssets = 900, sharePrice returns to normal
But the attacker already borrowed against the inflated price
```

**Why doesn't nonReentrant help?**

ERC4626's `nonReentrant` protects ERC4626 itself from being re-entered. But in `receive()`, the attacker calls the **lending protocol** — a completely separate contract. ERC4626's lock has no jurisdiction over it.

Even if the lending protocol adds its own `nonReentrant`, it doesn't matter — that lock protects the lending protocol from being re-entered, not from reading ERC4626's state. Each contract has its own lock, and no single lock can prevent this cross-contract state read.

### The Fix

Swap the order — transfer before burn:

```solidity
// ✅ Safe ordering
function redeem(uint256 shares, address receiver) external nonReentrant {
    _transferAssets(receiver);    // Send ETH first, triggers receive()
    // ← When receive() fires: totalSupply and totalAssets are both unchanged
    // ← sharePrice is completely normal — nothing the attacker can exploit
    _burn(msg.sender, shares);    // Burn shares after receive() completes
    // ← No external calls after burn — no window to exploit
}
```

**Why is this safe?**

`_transferAssets` executes first, ETH begins transferring, `receive()` fires. At this point `_burn` hasn't run yet, so both totalSupply and totalAssets are unchanged — sharePrice is completely normal. Whatever the attacker does in the callback, they're reading accurate prices and can't get inflated collateral valuations.

After `receive()` completes, `_burn` runs and destroys the shares. At the moment the external call fires, the contract state is fully consistent. There's no intermediate state to exploit.

---

## The Unified View

The two scenarios look different on the surface, but share the same underlying logic:

| | Scenario 1 (Balance Diff) | Scenario 2 (Read-only Reentrancy) |
|--|--|--|
| CEI situation | Cannot be followed — structural constraint | Followed CEI, yet still vulnerable |
| Source of external call | Attacker-crafted malicious swap path | ETH transfer triggers receive() |
| What attacker does in callback | Calls another function to corrupt balanceAfter | Calls third-party protocol to read inflated price |
| Does nonReentrant help? | No — attacker just takes a different path | No — no re-entry needed at all |
| Fix direction | Restrict what the external call can do | Reorder so state is consistent when external call fires |

Both exploit the window where "a contract is in an intermediate state during an external call." Scenario 2 is more insidious — the code follows CEI and looks correct, but any state inconsistency at the moment of an external call can be read and exploited across contract boundaries.

---

## Audit Checklist

**When you see the balance diff pattern:**
- Is there an external call between `balanceBefore` and `balanceAfter`?
- Can the user control the token address or swap path?
- Are there other functions not covered by the same lock that could be called from a callback?

**When you see ERC4626 or similar vaults:**
- What order are burn and transfer in? burn before transfer = dangerous
- Is there any external call in between (including ETH transfers that trigger receive)?
- Is any third-party protocol reading this contract's sharePrice or equivalent?

**When you see nonReentrant, don't relax — ask:**
- What state is inconsistent during the external call?
- If the attacker doesn't re-enter any function and just acts maliciously in the callback, does the lock still help?
- Is there any possibility of cross-contract reads of intermediate state?

---

Reentrancy has been known since The DAO hack in 2016, but it remains one of the most underestimated vulnerability classes in auditing. `nonReentrant` is necessary but far from sufficient. The real question isn't "is there a lock?" — it's **"is the contract's state fully consistent at the moment an external call fires?"**
