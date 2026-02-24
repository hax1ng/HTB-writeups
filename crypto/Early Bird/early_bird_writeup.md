# Early Bird

**Category:** Crypto | **Difficulty:** Medium | **Flag:** `HTB{...}`

## Overview
A Flask app implements RSA-OAEP encryption with a custom hash function (PBKDF2 with 2M iterations). A timing side-channel in the OAEP verification logic enables Manger's attack to recover the encrypted admin token.

## Solution

### Source Code Analysis
The app has three endpoints:
- `/` — sets a cookie containing `n` (RSA modulus) and `tok` (OAEP-encrypted PRO_TOKEN)
- `/verify-token` — decrypts and verifies an OAEP ciphertext
- `/download` — serves admin config (with flag) if you provide `PRO_TOKEN.hex()`

The `decrypt_and_verify` function has a critical timing vulnerability in its error check:

```python
if Y != 0 or not self.H_verify(self.L, DB[:self.hLen]) or self.os2ip(PS) != 0:
    return { "ok": False, "error": "decryption error" }
```

Python's `or` short-circuits: if `Y != 0` is True, `H_verify` (which runs PBKDF2 with 2M iterations, taking ~2 seconds) is never called. This creates a timing oracle:
- **Fast (~0.6s)**: Y != 0 (first byte of decrypted message is nonzero)
- **Slow (~2s)**: Y == 0 (first byte is zero, PBKDF2 executes)

### Manger's Attack
This timing oracle maps directly to Manger's chosen ciphertext attack on RSA-OAEP. The oracle tells us whether `m = c^d mod n` is less than `B = 2^(8*(k-1))`, which is equivalent to the first byte being 0x00.

The attack proceeds in three steps:
1. **Step 1**: Find `f1 = 2^i` where `f1 * m >= B`
2. **Step 2**: Find `f2` where `n <= f2 * m < n + B`
3. **Step 3**: Binary search to narrow m to an exact value (~1024 iterations)

The key to making the remote oracle reliable is **strict timing bounds with retry**:
```python
def padding_oracle(c_int):
    while True:
        total = measure_response_time(c_int)
        if SLOW_LOWER < total < SLOW_UPPER:
            return True   # Y == 0
        elif total < FAST_UPPER:
            return False  # Y != 0
        # Ambiguous: retry
```

After recovering `m`, we locally decode the OAEP padding (we know `n`, hence `L` and the PBKDF2 salt) to extract the 32-byte PRO_TOKEN. We verify correctness by checking the OAEP label hash locally before submitting.

Finally, POST the token hex to `/download` to get the admin config containing the base64-encoded flag.

Reference: `solve.py` for the full exploit code.

## Key Takeaways
- Python's short-circuit `or` evaluation can create timing oracles in crypto implementations
- RFC 8017 warns: "Care must be taken to ensure that an opponent cannot distinguish the different error conditions in Step 3.g" — here, the timing makes them distinguishable
- Manger's attack requires ~1024 oracle queries for 1024-bit RSA, making it very practical
- Reliable timing oracles over the network need strict bounds and retry logic to handle jitter
