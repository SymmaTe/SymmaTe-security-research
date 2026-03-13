# SymmaTe Security Research

Smart contract security research by [SymmaTe](https://github.com/SymmaTe).

## research-articles

In-depth vulnerability analysis and security concepts, published bilingually (EN/CN).

| Title | EN | CN |
|-------|----|----|
| Reentrancy & nonReentrant Bypass | [EN](research-articles/reentrancy-nonreentrant-bypass-en.md) | [CN](research-articles/reentrancy-nonreentrant-bypass-cn.md) |
| Signature Security Landscape | [EN](research-articles/signature-security-landscape-en.md) | [CN](research-articles/signature-security-landscape-cn.md) |

## defi-exploits-lab

Minimal proof-of-concept exploits for common DeFi vulnerability patterns.

| Exploit | Contracts |
|---------|-----------|
| Reentrancy | [src](defi-exploits-lab/src/reentrancy/) · [test](defi-exploits-lab/test/ReentrancyTest.t.sol) |
| Flash Loan Price Manipulation | [src](defi-exploits-lab/src/flash-loan/) · [test](defi-exploits-lab/test/FlashLoanTest.t.sol) |
| Oracle Manipulation | [src](defi-exploits-lab/src/oracle-manipulation/) · [test](defi-exploits-lab/test/OracleManipulationTest.t.sol) |
| Vault Share Inflation | [src](defi-exploits-lab/src/vault-share-inflation/) · [test](defi-exploits-lab/test/VaultShareInflationTest.t.sol) |
| Sandwich MEV | [src](defi-exploits-lab/src/sandwich-mev/) · [test](defi-exploits-lab/test/SandwichMEVTest.t.sol) |