#!/usr/bin/env python3
"""
Manger's attack on RSA-OAEP timing oracle.
Oracle: True if slow (Y==0), False if fast (Y!=0).
Uses strict timing bounds with retry for reliability.
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import base64
import json
import time
import sys
import re
from Crypto.Signature.pss import MGF1
from Crypto.Hash import SHA256 as HF
from Crypto.Protocol.KDF import PBKDF2

HOST = "154.57.164.80"
PORT = 31463
URL = f"http://{HOST}:{PORT}"

oracle_calls = 0

# Will be set by calibration
FAST_UPPER = 1.0     # Definitely fast if < this
SLOW_LOWER = 2.0     # Definitely slow if > this
SLOW_UPPER = 5.0     # Probably network issue if > this

def make_session():
    s = requests.Session()
    retries = Retry(total=3, backoff_factor=0.3)
    s.mount('http://', HTTPAdapter(max_retries=retries))
    return s

session = make_session()

def get_params():
    r = session.get(f"{URL}/")
    cookie = r.cookies.get("token")
    d = json.loads(base64.b64decode(cookie))
    n = int(d["n"], 16)
    tok = int(d["tok"], 16)
    return n, 65537, tok

def i2osp(i, k):
    return i.to_bytes(k, 'big')

def padding_oracle(c_int, n, k):
    """
    Returns True if decrypted message < B (Y == 0, slow response).
    Retries until confident.
    """
    global oracle_calls, session
    enc_b64 = base64.b64encode(i2osp(c_int, k)).decode()

    while True:
        for attempt in range(3):
            try:
                oracle_calls += 1
                start = time.time()
                r = session.post(f"{URL}/verify-token",
                               json={"encrypted_token": enc_b64},
                               timeout=15)
                total = time.time() - start

                # Definitely slow (Y==0): True
                if SLOW_LOWER < total < SLOW_UPPER:
                    return True
                # Definitely fast (Y!=0): False
                elif total < FAST_UPPER:
                    return False
                # Ambiguous or network hiccup: retry
                time.sleep(0.1)
                break  # break attempt loop, continue while
            except:
                time.sleep(1)
                session = make_session()
        else:
            time.sleep(2)
            session = make_session()

def calibrate(n, e, k):
    global FAST_UPPER, SLOW_LOWER, SLOW_UPPER
    B = pow(2, 8 * (k - 1))

    slow_times = []
    fast_times = []
    for i in range(5):
        enc = base64.b64encode(pow(B - 1 - i*100, e, n).to_bytes(k, 'big')).decode()
        start = time.time()
        session.post(f"{URL}/verify-token", json={"encrypted_token": enc}, timeout=15)
        slow_times.append(time.time() - start)

        enc = base64.b64encode(pow(B + 1 + i*100, e, n).to_bytes(k, 'big')).decode()
        start = time.time()
        session.post(f"{URL}/verify-token", json={"encrypted_token": enc}, timeout=15)
        fast_times.append(time.time() - start)

    min_slow = min(slow_times)
    max_fast = max(fast_times)
    avg_slow = sum(slow_times) / len(slow_times)
    avg_fast = sum(fast_times) / len(fast_times)

    # Set very strict bounds:
    # FAST_UPPER: max_fast * 1.5 (generous but well below slow zone)
    # SLOW_LOWER: min_slow * 0.9 (only accept if clearly slow)
    # SLOW_UPPER: max_slow * 1.5 (reject network timeouts)
    FAST_UPPER = max_fast * 1.5
    SLOW_LOWER = min_slow * 0.9
    SLOW_UPPER = max(slow_times) * 1.5

    # Safety: ensure there's a gap
    if FAST_UPPER >= SLOW_LOWER:
        midpoint = (min_slow + max_fast) / 2
        FAST_UPPER = midpoint * 0.9
        SLOW_LOWER = midpoint * 1.1

    print(f"[*] Slow: {[f'{t:.3f}' for t in sorted(slow_times)]}")
    print(f"[*] Fast: {[f'{t:.3f}' for t in sorted(fast_times)]}")
    print(f"[*] FAST_UPPER={FAST_UPPER:.3f}, SLOW_LOWER={SLOW_LOWER:.3f}, SLOW_UPPER={SLOW_UPPER:.3f}")

def ceil_div(a, b):
    return a // b + (a % b > 0)

def floor_div(a, b):
    return a // b

def compute_lhash(n):
    L = str(n)[:72].encode()
    salt = HF.new(str(n).encode()).hexdigest()
    return PBKDF2(L, salt, HF.digest_size, count=2_000_000, hmac_hash_module=HF)

def main():
    global oracle_calls

    print("[*] Connecting...")
    n, e, c = get_params()
    k = n.bit_length() // 8
    B = pow(2, 8 * (k - 1))
    print(f"[*] n={n.bit_length()} bits, k={k}")

    print("[*] Computing lHash...")
    lhash = compute_lhash(n)
    print(f"[*] lHash = {lhash.hex()}")

    print("[*] Calibrating...")
    calibrate(n, e, k)
    oracle_calls = 0

    def oracle(c_val):
        return padding_oracle(c_val, n, k)

    # Step 1
    print("[*] Step 1...")
    f1 = 2
    while oracle((pow(f1, e, n) * c) % n):
        f1 *= 2
    print(f"[+] f1 = {f1}")

    # Step 2
    print("[*] Step 2...")
    f2 = floor_div(n + B, B) * f1 // 2
    count = 0
    while not oracle((pow(f2, e, n) * c) % n):
        f2 += f1 // 2
        count += 1
    print(f"[+] f2 = {f2} ({count} iters)")

    # Step 3
    print("[*] Step 3...")
    mmin = ceil_div(n, f2)
    mmax = floor_div(n + B, f2)
    it = 0
    while mmin < mmax:
        it += 1
        diff = mmax - mmin
        bits = diff.bit_length()
        if it % 100 == 1 or bits <= 10:
            print(f"  Iter {it}: {bits} bits, {oracle_calls} q")
            sys.stdout.flush()

        f = floor_div(2 * B, mmax - mmin)
        i = floor_div(f * mmin, n)
        f3 = ceil_div(i * n, mmin)
        if oracle((pow(f3, e, n) * c) % n):
            mmax = floor_div(i * n + B, f3)
        else:
            mmin = ceil_div(i * n + B, f3)

        if it > 2500:
            break

    m = mmin
    print(f"[+] Converged: {it} iters, {oracle_calls} q")

    # OAEP decode
    EM = i2osp(m, k)
    hLen = HF.digest_size
    print(f"[*] EM[0] = {EM[0]}")

    maskedSeed = EM[1:hLen+1]
    maskedDB = EM[hLen+1:]
    seedMask = MGF1(maskedDB, hLen, HF)
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
    dbMask = MGF1(seed, k - hLen - 1, HF)
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))

    if DB[:hLen] == lhash:
        print("[+] lHash MATCHES!")
    else:
        print(f"[*] DB[:32] = {DB[:32].hex()}")
        print(f"[*] lHash   = {lhash.hex()}")
        print("[-] lHash mismatch, searching +/-100...")
        found = False
        for delta in range(-100, 101):
            candidate = m + delta
            if candidate <= 0:
                continue
            try:
                EM2 = i2osp(candidate, k)
            except:
                continue
            if EM2[0] != 0:
                continue
            ms2 = EM2[1:hLen+1]
            mdb2 = EM2[hLen+1:]
            sm2 = MGF1(mdb2, hLen, HF)
            s2 = bytes(a ^ b for a, b in zip(ms2, sm2))
            dm2 = MGF1(s2, k - hLen - 1, HF)
            db2 = bytes(a ^ b for a, b in zip(mdb2, dm2))
            if db2[:hLen] == lhash:
                print(f"[+] Found at m+{delta}")
                DB = db2
                found = True
                break
        if not found:
            print("[-] Failed to find correct m")
            sys.exit(1)

    # Extract M from DB
    rest = DB[hLen:]
    idx = 0
    while idx < len(rest) and rest[idx] == 0:
        idx += 1
    if rest[idx] == 1:
        M = rest[idx+1:]
        token = M.hex()
        print(f"[+] PRO_TOKEN = {token} (len={len(M)})")
    else:
        print("[-] Invalid OAEP padding")
        sys.exit(1)

    # Download admin config
    print(f"[*] Downloading admin config...")
    r = session.post(f"{URL}/download", json={"token": token})
    admin = "firmware_lock>true" in r.text
    print(f"[*] Got {'ADMIN' if admin else 'user'} config")

    # Extract flag
    config_match = re.search(r'<token>(.+?)</token>', r.text)
    if config_match:
        try:
            decoded = base64.b64decode(config_match.group(1)).decode()
            flag = re.search(r'HTB\{[^}]+\}', decoded)
            if flag:
                print(f"\n[+] FLAG: {flag.group()}")
                with open("/home/kali/HTB/challenges/crypto/crypto_early_bird/flag.txt", "w") as f:
                    f.write(flag.group() + "\n")
                return
        except:
            pass
    print(r.text[:500])

if __name__ == "__main__":
    main()
