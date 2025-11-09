# 🔐 Two-Signature Linear Nonce Attack → Private Key & Address Verification

This script demonstrates an **end-to-end ECDSA recovery workflow** when two signatures exhibit a **linear nonce relationship**.  
It recovers the private key `d` from two signatures `(r₁,s₁,z₁)` and `(r₂,s₂,z₂)`, then derives and verifies both **Bech32 (bc1…)** and **Nested SegWit (P2SH, “3…”)** addresses from the recovered key.

---

## 🧮 Math Recap

ECDSA signing (mod n):
s ≡ k⁻¹ (z + r·d)
⇒ s·k ≡ z + r·d

Subtract two signatures sharing a linear relation:


(s₁ − s₂)·k ≡ (z₁ − z₂) (mod n)
⇒ k ≡ (z₁ − z₂) · (s₁ − s₂)⁻¹ (mod n)

Recover the private key with one signature:


d ≡ (s₁·k − z₁) · r₁⁻¹ (mod n)


---

## 🧩 What the script does

1. **Inputs:** two signatures `(r₁, s₁, z₁)` and `(r₂, s₂, z₂)`.  
2. **Compute Δ values:**  


delta_s = (s₁ − s₂) mod n
delta_z = (z₁ − z₂) mod n

3. **Recover nonce `k`:**  


k = delta_z * inverse_mod(delta_s, n) (mod n)

4. **Recover private key `d`:**  


d = (s₁*k − z₁) * r₁⁻¹ (mod n)

5. **Derive addresses from `d`:**  
- **Bech32 P2WPKH (bc1…):** `HASH160(pubkey)` → Bech32 (witness v0).  
- **Nested SegWit (P2SH-P2WPKH, “3…”):** wrap witness program in P2SH redeemScript.
6. **Verify:** compare derived addresses with the given expected `P2SH` and `Bech32`.

---

## 🔢 Visual Flow



(r₁,s₁,z₁) + (r₂,s₂,z₂)
↓
Δs, Δz (mod n)
↓
k = Δz * (Δs)⁻¹ (mod n)
↓
d = (s₁*k − z₁) * r₁⁻¹ (mod n)
↓
pubkey ← ECDSA(d)
↓
HASH160(pubkey)
↓ ↓
Bech32 (bc1…) P2SH (3…)
↓
Compare with expected


---

## 🧾 Example Console Output



✅ Wykryto liniową zależność k! k = 0x...
🚀 🔥 Obliczone wartości:
🔹 r = 0x...
🔹 s = 0x...
🔹 z = 0x...
🔹 k = 0x...
🔹 d = 0x...

🚀 ✅ Obliczone adresy:
🔹 Obliczony adres Bech32: bc1q...
🔹 Obliczony Nested P2SH: 3M21...
📌 Oczekiwany P2SH: 3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6
📌 Oczekiwany Bech32: bc1qqufw4em00p4pr8s2xuna883ly4jj9tqer808c5

✅ 🔥 Klucz prywatny pasuje do obu adresów! To ten sam właściciel!


> If the addresses don’t match, it prints:
> ```
> ❌ Adresy nie pasują! Możliwe, że P2SH było multisig lub inny typ skryptu.
> ```

---

## ⚠️ Notes & Caveats

- Requires `(s₁ − s₂)` to be invertible modulo `n`. If `delta_s == 0`, the method fails.  
- Works when the two signatures leak a **linear nonce relation**; arbitrary pairs won’t satisfy the equations.  
- P2SH outputs may represent **multisig** or other scripts; a non-match doesn’t necessarily invalidate `d` for other address types.

---

## ⚖️ Ethical Reminder

Use only on data you **own** or are explicitly authorized to analyze.  
Recovering private keys without permission is illegal and unethical.  
This code is for **research, auditing, and education**.

© 2025 — Author: [ethicbrudhack]

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
