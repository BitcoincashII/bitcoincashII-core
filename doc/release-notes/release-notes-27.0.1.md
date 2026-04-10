# Bitcoin Cash II (BCH2) Core v27.0.1 Release Notes

## Summary

This is a bug fix release addressing two issues. All node operators and miners should upgrade.

---

## Bug Fixes

### 1. Fix CashToken transaction deserialization (CRITICAL)

CashToken-bearing transactions could not be decoded, broadcast, or mined. The node rejected
all token transactions with "TX decode failed" due to a range check in the token amount
deserializer.

**Root cause:** `OutputToken::Unserialize()` used `ReadCompactSize()` with the default
range check enabled. Bitcoin Core's `ReadCompactSize` limits values to 32MB (`MAX_SIZE`),
which is appropriate for buffer sizes but not for token amounts. Any token with an amount
greater than 33,554,432 triggered `ReadCompactSize(): size too large`, causing the
transaction to be unparseable.

**Impact:** CashTokens (CHIP-2022-02) could not be created, sent, or received on the BCH2
network. The consensus validation code and UTXO storage were correct, but the transaction
serialization path prevented any token transaction from being processed.

**Fix:** Disabled the range check for token amounts (`ReadCompactSize(s, false)`). Token
amounts are validated separately against `token::MAX_AMOUNT` (2,099,999,997,690,000).
Additionally, improved `CTxOut` serialization to use CScript-based blob handling, matching
the proven pattern used by `TxOutCompression` in the UTXO compressor.

**Files changed:**
- `src/primitives/token.h` — `ReadCompactSize(s)` → `ReadCompactSize(s, false)`
- `src/primitives/transaction.h` — Improved CTxOut Serialize/Unserialize

**This fix is required before any CashToken transactions can be used on the BCH2 network.
Nodes that do not upgrade will reject blocks containing token transactions.**

---

### 2. Fix build failure with miniupnpc 2.2.8+ (LOW)

Compilation failed on systems with miniupnpc version 2.2.8 or newer (e.g., Fedora 39+,
Arch Linux) due to a changed function signature in the miniupnpc library.

**Root cause:** miniupnpc 2.2.8 added two extra parameters (`wanaddr`, `wanaddrlen`) to
`UPNP_GetValidIGD()`. The BCH2 code called the function with the old 5-parameter signature,
causing a compile error: "too few arguments to function."

**Impact:** Users on distributions shipping miniupnpc >= 2.2.8 could not compile from source
unless they used the depends system or disabled UPnP with `--without-miniupnpc`.

**Fix:** Added compile-time version detection using `MINIUPNPC_API_VERSION`. Systems with
API version 18+ (miniupnpc 2.2.8+) use the new 7-parameter signature with `nullptr, 0` for
the WAN address buffer. Older versions continue using the 5-parameter signature.

Backported from Bitcoin Core PR #30283.

**Files changed:**
- `src/mapport.cpp` — Version-conditional `UPNP_GetValidIGD()` call

---

## Upgrade Instructions

This release is a drop-in replacement for v27.0.0. No configuration changes or reindex
required.

1. Download the new binaries for your platform
2. Stop your node: `bitcoincashII-cli stop`
3. Replace the binaries (`bitcoincashIId`, `bitcoincashII-cli`, `bitcoincashII-qt`)
4. Start your node: `bitcoincashIId`

---

## Compatibility

- Bitcoin Cash II Core v27.0.1 is compatible with all existing chain data
- No reindex required
- No configuration changes needed
- Wire format for existing (non-token) transactions is unchanged
- Nodes running v27.0.0 will continue to sync the existing chain but will reject blocks
  containing CashToken transactions after this upgrade is deployed
