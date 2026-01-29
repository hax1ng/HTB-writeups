# ShadowLabyrinth Writeup

**Challenge:** ShadowLabyrinth
**Category:** Reversing (Hard)


---

## TL;DR

This challenge is a two-part flag validator wrapped in layers of crypto and a custom virtual machine. The first 48 characters are validated through matrix math, then used to decrypt bytecode for a VM that validates the remaining 35 characters. Both parts boil down to solving systems of linear equations.

---

## Initial Recon

We're given a binary called `shadow_labyrinth` and an encrypted file `file.bin`. Running the binary asks for input and then tells us our flag is wrong:

```
$ ./shadow_labyrinth
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Flag is incorrect.
```

Throwing it into Binary Ninja, we can see it expects an 83-character input (plus the `HTB{}` wrapper for 88 total). The validation happens in two phases.

---

## Phase 1: The Matrix Has You (First 48 chars)

The first thing the binary does is take our input, shuffle it around using a permutation table, and then check it against some crazy matrix multiplication.

### The Shuffle

There's a permutation table at `0x4022c0` that rearranges our 48 input characters:

```
[16, 25, 32, 5, 0, 45, 38, 2, 14, 40, 24, 17, 7, 33, 23, 29, ...]
```

So `key[0] = input[16]`, `key[1] = input[25]`, etc. This shuffled key is used for two things:
- First 32 bytes become the AES decryption key
- Last 16 bytes are used for XOR obfuscation

### The Math Check

The binary groups the permuted characters into sets of 4 and multiplies them by coefficient matrices. Each group has to produce a specific result. This gives us 12 systems of equations to solve.

The trick here is that regular algebra won't cut it - the numbers are huge (64-bit) and we need integer solutions that happen to be printable ASCII characters (32-126). This is where lattice-based cryptography comes in.

Using the **Closest Vector Problem (CVP)** with LLL reduction (fancy math that finds the nearest point in a lattice), we can recover the original characters. The official solution uses SageMath for this, but the key insight is that this is a constrained optimization problem that lattices handle beautifully.

After solving all 12 systems and unshuffling, we get:

```
by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy
```

Nice! That's the first half of our flag.

---

## Phase 2: VM Adventure (Last 35 chars)

Now things get spicy. The binary uses our 48-character key to decrypt `file.bin`:

1. XOR the file with the last 16 bytes of the permuted key
2. AES-256-CBC decrypt using the first 32 bytes as the key
3. Decompress with zlib

What pops out? A whopping 508KB of custom VM bytecode.

### The Virtual Machine

The binary implements a 16-instruction VM:

| Opcode | Instruction | What it does |
|--------|-------------|--------------|
| 0 | SET0 | Set register to 0 |
| 1 | SET1 | Set register to 1 |
| 2 | ADD | Add immediate to register |
| 3 | CMP | Compare and set flag |
| 4 | SHL | Shift left |
| 5 | ADD_REG | Add two registers |
| 6 | ??? | Mystery op (skip 3 words) |
| 7 | XOR | XOR two registers |
| 8 | STORE | Store to memory |
| 9 | LOAD | Load from memory |
| 10 | JZ | Jump if zero |
| 11 | JNZ | Jump if not zero |
| 12 | JMP | Unconditional jump |
| 13 | READ | Read input character |
| 14 | PRINT | Print value |
| 15 | EXIT | Exit (success = exit(0)) |

### What the VM Does

After tracing through the bytecode, here's the flow:

1. **Read 35 input characters** and store them in memory
2. **Do a TON of math** - shifts, adds, multiplications implemented via loops
3. **Store 35 computed values** based on weighted sums of input
4. **Compare against expected values** stored in the bytecode
5. **XOR pairs of values** - if everything matches, all registers become 0
6. **Check all registers are 0** - if so, print success and exit

The key realization: this is another matrix multiplication! Each output is a linear combination of all 35 inputs:

```
output[i] = sum(coef[i][j] * input[j]) for j in 0..34
```

### Extracting the Matrix

By running the VM with different inputs and observing the outputs, we can extract the 35x35 coefficient matrix. The official solution dumps these directly from the bytecode:

```python
coefs = [
    (281, 123, 291, 110, 116, 87, 13, 150, ...),  # Row 0
    (294, 112, 298, 15, 99, 60, 148, 280, ...),   # Row 1
    # ... 35 rows total
]
```

The expected output values are also in the bytecode:

```python
v = [526162, 517711, 490345, 529536, 636090, ...]  # 35 values
```

### Solving the System

Now we have `M * x = v` where:
- `M` is our 35x35 coefficient matrix
- `x` is what we want (the 35 flag characters)
- `v` is the expected output
- Everything is mod 2^32 (32-bit arithmetic)

Standard Gaussian elimination with modular arithmetic gives us:

```python
x = [95, 116, 117, 116, 117, 114, 117, 116, 117, 116, 117, 95,
     110, 51, 118, 51, 114, 95, 103, 48, 110, 110, 97, 95,
     103, 49, 118, 51, 95, 121, 48, 117, 95, 117, 112]
```

Converting to ASCII: `_tuturututu_n3v3r_g0nna_g1v3_y0u_up`

Wait... is that a Rickroll reference? In a CTF challenge? Never gonna give you up indeed!

---

## Putting It All Together

Combining both parts:

```
HTB{you_got_this}
```

Let's verify:

```
$ echo "HTB{by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy_tuturututu_n3v3r_g0nna_g1v3_y0u_up}" | ./shadow_labyrinth
[Central Command Node]: Motion triggered! Labyrinth entrance...
[Central Command Node]: Motion triggered! Magnetosphere...
[Central Command Node]: Authentication complete!
```

---

## Key Takeaways

1. **Layered validation** - Don't assume one check means you're done
2. **Crypto unlocks more reversing** - The first part's solution was the key (literally) to the second part
3. **Custom VMs are just state machines** - Trace them methodically and patterns emerge
4. **Linear algebra is your friend** - Both parts were essentially matrix equations in disguise
5. **CTF authors love memes** - Always expect a Rickroll

---

## Tools Used

- Binary Ninja (static analysis)
- Python + Z3 (constraint solving attempts)
- SageMath (lattice reduction for CVP)
- NumPy/SymPy (matrix operations)
- Lots of coffee

---

## Final Thoughts

This was a beefy challenge that combined cryptography, reverse engineering, and linear algebra. The key insight for both phases was recognizing that the validation was fundamentally linear - once you see that, it becomes a matter of extracting the right coefficients and solving the system.

And yes, we all got Rickrolled by a CTF challenge. Never gonna give this flag up!
