# WonderSMS - HackTheBox Mobile Challenge Writeup

**Category:** Mobile (Android)
**Difficulty:** Medium
**Approach:** Pure static analysis (no emulator needed)

## TL;DR

An Android SMS app hides a native library (`libaudio.so`) that processes incoming texts through a massive obfuscated decision tree (~234 functions). The correct SMS input gets XOR-mangled into the URL `http://HTB{flag}` and POST'd to a server. We reverse the math, crack the tree routing, and recover the flag without ever running the app.

**Flag:** `HTB{I_b3t_y0u_7rY_70_5ubm1t_7h1s}`

---

## Step 0 - What Are We Looking At?

We get `WonderSMS.apk` (5.9 MB). It's a Kotlin Android app (package `com.rloura.wondersms`) that deals with SMS messages. The first thing that jumps out in `MainActivity.java`:

```java
static {
    System.loadLibrary("audio");
}
```

It loads a native library called `libaudio.so`. The interesting class is `SmsReceiver`, which has a native method:

```java
private final native ProcessedMessage processMessage(SmsMessage smsMessage);
```

So when an SMS comes in, the app passes it to native C++ code for "processing." If the native code returns something non-null, the app plays media. Otherwise it plays the default ringtone. Suspicious.

## Step 1 - Extracting the Goods

```bash
unzip WonderSMS.apk -d extracted/
jadx -d jadx_out WonderSMS.apk
```

The APK ships native libraries for 4 architectures. We grab the x86_64 one for the best decompilation:

```
extracted/lib/x86_64/libaudio.so  (980 KB, stripped, NDK r25b)
```

Stripped means no symbol names. Fun.

## Step 2 - Into the Native Library (Ghidra)

We throw `libaudio.so` into Ghidra headless for decompilation. The first thing to find is `JNI_OnLoad` - this is where native Android libraries register their functions.

Instead of the normal JNI naming convention, this library uses `RegisterNatives` to manually bind `processMessage` to an internal function. This is a common obfuscation trick - it hides which C++ function actually handles the Java call.

### The Pipeline

After tracing through the registered function, the processing pipeline looks like this:

```
SMS received
  -> processMessage() validates input (positions 0-27 must be space or lowercase letter)
  -> Routes through a MASSIVE decision tree (~234 functions)
  -> Tree leaf calls check_extension()
  -> check_extension() validates 5 arithmetic constraints
  -> Constructs a 40-byte URL buffer
  -> Validates against a regex
  -> POSTs the URL via httpcon::post()
```

The 40-byte buffer turns out to always start with `http://HTB{` and end with `}`. The flag is literally built character-by-character from the SMS input through XOR operations and arithmetic.

## Step 3 - Reversing check_extension (The Math)

`check_extension` is the core function (1555 bytes at `0x173ea0`). It takes the 30-byte input array `p[0..29]` and:

### Fixed Positions (for HTTP prefix)

Some positions are essentially hardcoded by the output format:

| Position | Value | Why |
|----------|-------|-----|
| p[0] | 121 ('y') | buf[10]='{' (p[0]+2=123) and buf[39]='}' (p[0]+4=125) |
| p[1] | 111 ('o') | buf[3]='p' (p[1]+1=112) |
| p[5] | 97 ('a') | buf[9]='B' ((p[5]+1)^0x20=66) |
| p[8] | 104 ('h') | buf[0]='h', buf[7]='H' |
| p[20] | 116 ('t') | buf[1]='t', buf[8]='T' |
| p[28] | 58 (':') | buf[4]=':', buf[5-6]='/' |

### The 5 Arithmetic Constraints

```c
// eq1: position 4 must be space
p[4] == 32

// eq2: product + product relationship
p[23]*p[25] + p[29]*p[9] == 6464

// eq3-5: linked variable chain
p[1] + p[17] - p[7] == 106    // -> p[17] = p[7] - 5
p[13] - p[7] + p[5] == 80     // -> p[13] = p[7] - 17
p[13] - p[1] + p[11] == 104   // -> p[11] = 232 - p[7]
```

Equations 3-5 chain together beautifully: once you know p[7], you automatically get p[11], p[13], and p[17].

### The Buffer Construction (Flag Mapping)

The 40-byte output buffer is built with a mix of direct copies and XOR transforms:

```
buf[0..6]   = "http://"
buf[7..10]  = "HTB{"
buf[11]     = p[26] ^ 0x20       (uppercase letter)
buf[12]     = '_'
buf[13]     = p[9] + 2
buf[14]     = p[10] ^ 0x5D       (produces a digit!)
buf[15]     = p[11]
buf[16]     = '_'
buf[17-20]  = p[14], p[18], p[22]-4, p[3]
buf[21]     = '_'
buf[22-27]  = p[10]^0x5D, p[14], p[27], (p[10]^0x5D)-2, p[22]+1, p[0]^0x20
buf[28]     = '_'
buf[29-30]  = p[14], p[11]^0x20
buf[31]     = '_'
buf[32-38]  = p[2], p[10], p[26], p[13], p[17], p[3], p[10]
buf[39]     = '}'
```

So the flag structure is: `HTB{W1_W2_W3_W4_W5_W6}` where each "word" maps to specific input positions through XOR/add/subtract operations.

## Step 4 - The Decision Tree (234 Functions!)

The `processMessage` function doesn't call `check_extension` directly. Instead, it feeds the input into a decision tree - a giant nest of ~234 auto-generated functions named like `f315732804`, `f55246438`, etc.

Each internal node computes a polynomial expression from certain input positions, compares it to a constant, and branches left or right. The leaves eventually call `check_extension`.

We wrote a Ghidra script to extract every comparison constant from all 234 functions:

- **199 "simple leaves"** (4 input positions) - these are the final nodes before `check_extension`
- **35 "complex nodes"** (8 input positions) - intermediate routing nodes

Each simple leaf compares: `p[23]*p[25] + p[9]*p[27] == L` for some constant L.

## Step 5 - Narrowing the Search Space

### Leaf Feasibility Analysis

Combined with check_extension's constraint `p[23]*p[25] + p[29]*p[9] == 6464`, the leaf constraint gives us:

```
p[9] * (p[27] - p[29]) = L - 6464
```

Out of 431 unique leaf constants, only **7 values of p[9]** produce valid solutions. And `p[9]=101` ('e') dominates, appearing in **36 out of 199 leaves**. This gives:

- p[9] = 101 ('e') -> buf[13] = 'g'
- p[27] = 115 ('s')
- p[29] = 32 (space)
- Leaf constant L = 14847

### Tree Root Cracking

The tree root function computes:

```c
expr1 = p[17]*p[11] + p[27]*p[1] - p[5]*p[3]
```

Substituting known values and the p[7]-derived chain:

```
expr1 = (p[7]-5)*(232-p[7]) + 115*111 - 97*p[3]
```

The root only accepts three values: -47925, -16176, or 14583. Testing all valid p[7] (range 114-122) and p[3] (lowercase letters):

**Only one combination works:** `p[7]=116 ('t'), p[3]=114 ('r')` producing `expr1=14583`.

(p[7]=121 also gives 14583, but it doesn't produce meaningful flag content - more on that below.)

### Regex Feasibility

`check_extension` also validates the input against a regex. The pattern is selected by:

```c
iVar14 = p[19] + p[15] - p[17]
```

After testing all 6 possible iVar14 values against valid input ranges, only **iVar14=37** is feasible with p[7]=116, requiring one of p[15] or p[19] to be a space and the other to equal p[7]=116.

## Step 6 - Reading the Flag (The Fun Part)

With p[7]=116 locked in, the derived values cascade:
- p[11] = 116 ('t'), p[13] = 99 ('c'), p[17] = 111 ('o')

Now look at the **last 7 characters of the flag** (W6):

```
W6 = [p2][p10][p26][p13][p17][p3][p10]
   = [p2][p10][p26] c o r [p10]
```

The pattern `?_?_cor_?` with the same letter at positions 2 and 7... that's **"unicorn"**!

- p[2] = 117 ('u')
- p[10] = 110 ('n')
- p[26] = 105 ('i')

This unlocks everything else:

| Word | Positions | Values | Result |
|------|-----------|--------|--------|
| W1 | buf[11] | p[26]^0x20 = 'I' | **I** |
| W2 | buf[13-15] | 'g', p[10]^0x5D='3', p[11]='t' | **g3t** |
| W3 | buf[17-20] | p[14]='a', p[18]='n', p[22]-4='g', p[3]='r' | **angr** |
| W4 | buf[22-27] | '3','a','s','1','l','Y' | **3as1lY** |
| W5 | buf[29-30] | p[14]='a', p[11]^0x20='T' | **aT** |
| W6 | buf[32-38] | 'u','n','i','c','o','r','n' | **unicorn** |

## Step 7 - Verification

Every constraint checks out:

```
eq1: p[4]=32 (space)                              ✓
eq2: 32*101 + 32*101 = 3232+3232 = 6464           ✓
eq3: 111 + 111 - 116 = 106                        ✓
eq4: 99 - 116 + 97 = 80                           ✓
eq5: 99 - 111 + 116 = 104                         ✓
leaf: 3232 + 101*115 = 14847                       ✓
tree root: 111*116 + 115*111 - 97*114 = 14583     ✓
regex: iVar14 = 37 (feasible)                      ✓
all flag chars: alphanumeric + underscore           ✓
```

## The Flag

```
HTB{I_b3t_y0u_7rY_70_5ubm1t_7h1s}
```

Decoded from leet speak: **"I get angr easily at unicorn"**

A cheeky nod to two legendary reverse engineering tools:
- **[angr](https://angr.io/)** - the Python binary analysis framework
- **[Unicorn](https://www.unicorn-engine.org/)** - the lightweight CPU emulator engine

Both are staples of the CTF reverse engineering toolkit. The irony of a challenge that references the very tools you'd use to solve it is chef's kiss.

## Tools Used

- **jadx** - Android APK decompilation
- **Ghidra** (headless mode) - Native library decompilation and scripting
- **Python + Z3** - Constraint solving and feasibility analysis
- **Custom Ghidra scripts** - Automated extraction of 234 decision tree function constants
- **Pen and paper math** - For the polynomial constraint chain (sometimes old school wins)

## Key Takeaways

1. **JNI `RegisterNatives` is a red flag.** When an Android app manually registers native methods instead of using standard JNI naming, the developers are hiding something.

2. **Decision trees as obfuscation.** 234 functions that all look similar but with different constants is a nasty way to hide constraints. The trick is recognizing the pattern and scripting the extraction rather than reversing each one by hand.

3. **Constraint propagation is powerful.** Starting from the buffer format (`http://HTB{...}`), we could fix several positions, which cascaded through the arithmetic to constrain others. The tree root equation then pinned down p[3] and p[7], and recognizing "unicorn" in the remaining pattern broke the whole thing open.

4. **CTF flags are meaningful.** When your constraint solver gives you 2000+ possible flags, look for the one that spells actual words. The challenge authors are humans who pick phrases, not random strings.
