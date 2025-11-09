import hashlib
import ecdsa
import base58
import bech32
from ecdsa.numbertheory import inverse_mod
from ecdsa.ecdsa import generator_secp256k1

# ✅ Dane z pierwszej transakcji
r1 = int("ab9467e44699c0ab5ee2da6389e1646725a03bd66433eb99e531e45d76476ee0", 16)
s1 = int("59098b9fe30776049508f91eea10e4a9972eec2c1afe79674379578447b7aa46", 16)
z1 = int("876e9343f6846e54128270a756aa79f76df0c46a5f59821efb936c9396ac7605", 16)

# ✅ Dane z drugiej transakcji
r2 = int("a92de155df39a35e154940d8f8f78c23fe772c35855fc16ca7cddea31ab9e75a", 16)
s2 = int("5571c0b9af7fe3d6d04173e52b119eca11cc94eb882fa1228add9e206eeb5543", 16)
z2 = int("b91d628805f11c602df82fd34e792e604963efd6e08c7efac188d176ae561319", 16)

# ✅ Stała wartość krzywej secp256k1 (order n)
n = generator_secp256k1.order()

# ✅ **Obliczenie `k`**
delta_s = (s1 - s2) % n
delta_z = (z1 - z2) % n

if delta_s != 0:
    k = (delta_z * inverse_mod(delta_s, n)) % n
    print(f"✅ Wykryto liniową zależność k! k = {hex(k)}")
else:
    print("❌ Brak liniowej zależności w k")
    exit()

# ✅ **Obliczenie klucza prywatnego `d`**
d = ((s1 * k - z1) * inverse_mod(r1, n)) % n

print("\n🚀 🔥 **Obliczone wartości:**")
print(f"🔹 r  = {hex(r1)}")
print(f"🔹 s  = {hex(s1)}")
print(f"🔹 z  = {hex(z1)}")
print(f"🔹 k  = {hex(k)}")
print(f"🔹 d  = {hex(d)}")

def generate_addresses_from_private_key(d):
    """ Konwersja klucza prywatnego na różne formaty adresów """
    G = ecdsa.SigningKey.from_secret_exponent(d, curve=ecdsa.SECP256k1).verifying_key
    pubkey = b'\x04' + G.to_string()

    # ✅ P2WPKH (Bech32 bc1...)
    pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    bech32_address = bech32.encode("bc", 0, pubkey_hash)

    # ✅ Nested SegWit (P2SH-P2WPKH 3...)
    nested_script = b'\x00\x14' + pubkey_hash  # OP_0 + PUSH(20) + pubkey hash
    nested_hash = hashlib.new('ripemd160', hashlib.sha256(nested_script).digest()).digest()
    nested_p2sh = base58.b58encode_check(b'\x05' + nested_hash).decode()

    return bech32_address, nested_p2sh

# ✅ Generujemy adresy z `d`
bech32_addr, nested_p2sh_addr = generate_addresses_from_private_key(d)

# ✅ Oczekiwane adresy
expected_p2sh = "3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6"
expected_bech32 = "bc1qqufw4em00p4pr8s2xuna883ly4jj9tqer808c5"

print("\n🚀 ✅ **Obliczone adresy:**")
print(f"🔹 Obliczony adres Bech32: {bech32_addr}")
print(f"🔹 Obliczony Nested P2SH: {nested_p2sh_addr}")
print(f"📌 Oczekiwany P2SH: {expected_p2sh}")
print(f"📌 Oczekiwany Bech32: {expected_bech32}")

# ✅ Sprawdzamy, czy adresy pasują
if expected_p2sh == nested_p2sh_addr and expected_bech32 == bech32_addr:
    print("\n✅ 🔥 Klucz prywatny pasuje do obu adresów! To ten sam właściciel!")
else:
    print("\n❌ Adresy nie pasują! Możliwe, że P2SH było multisig lub inny typ skryptu.")
