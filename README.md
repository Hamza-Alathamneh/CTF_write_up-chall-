# Runtime - NullXBytes CTF Challenge

## Challenge Overview

**Source:** NullXBytes  
**Challenge Name:** Runtime  
**Category:** Reverse Engineering / Cryptography

This challenge involves reverse engineering an encrypted flag that has been obfuscated through multiple layers of cryptographic operations extracted from a compiled binary.

---

## Challenge Description

The challenge provides:
- **chall.exe** - A Windows executable containing hardcoded encrypted data
- **chall.py** - A Python solution script that decrypts and reveals the flag

The task is to analyze the binary and extract the encryption key along with the encrypted bytes to recover the original flag.


### Step 1: Extract Encrypted Data from Binary

```python
# Extracted bytes from xmmword_7FF6EBA54900 (16 bytes in little endian)
part1 = bytes.fromhex("0D8FFF415E89A804F9FACC6850A34E95")

# Extracted from xmmword_7FF6EBA54910 (16 bytes also little endian)
part2 = bytes.fromhex("78E18A6BA55AAEF317E55D0B65D8D34C")

# Hardcoded values in v7/v8 from the pseudo-code
part3 = struct.pack('<Q', 0x2A5993F984037330)
part4 = struct.pack('<I', 0x0B8A83F0)
```

### Step 2: First Layer Decryption - XOR with Constant

The encrypted buffer is decrypted using XOR with a hardcoded constant `0xC3D2E1F0`:

```python
encrypted_buffer = part1 + part2 + part3 + part4
intermediate_bytes = bytearray()

for i in range(0, len(encrypted_buffer), 4):
    chunk = encrypted_buffer[i:i+4]
    if len(chunk) < 4:
        break
    val = struct.unpack('<I', chunk)[0]
    decrypted_block = val ^ 0xC3D2E1F0
    intermediate_bytes += struct.pack('<I', decrypted_block)
```

**Key Insight:** This XOR operation removes the first layer of encryption, revealing intermediate encrypted bytes.

### Step 3: Second Layer Decryption - Complex Byte-Level Operations

Each byte in the intermediate buffer undergoes a multi-step decryption process:

```python
def ror(val, r_bits, max_bits=8):
    """Rotate right function"""
    return ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | \
           (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))

flag = ""

for i, byte_val in enumerate(intermediate_bytes):
    # Step 1: XOR with position-dependent value
    v19 = byte_val ^ ((92 - 9 * i) & 0xFF)
    
    # Step 2: Rotate right by position-dependent amount
    rot_amt = (5 * i + 1) & 7
    v18 = ror(v19, rot_amt)
    
    # Step 3: Subtract position-dependent modulo value
    mod_val = (3 * i + 7) % 29
    v17 = (v18 - mod_val) & 0xFF
    
    # Step 4: XOR with another position-dependent key
    key_val = (11 * i - 89) & 0xFF
    original_char = v17 ^ key_val
    
    flag += chr(original_char)

print(flag)
```

### Decryption Logic Explanation

For each byte at position `i`:

1. **XOR Operation**: `v19 = byte_val ^ ((92 - 9*i) & 0xFF)`
   - Position-dependent XOR key that changes with each byte

2. **Bit Rotation**: `v18 = ror(v19, (5*i + 1) & 7)`
   - Right rotate the result by `(5*i + 1) mod 8` bits
   - Creates diffusion across bit positions

3. **Modular Subtraction**: `v17 = (v18 - ((3*i + 7) % 29)) & 0xFF`
   - Subtracts a position-dependent value (mod 29)
   - Wrapped to keep within byte range

4. **Final XOR**: `original_char = v17 ^ ((11*i - 89) & 0xFF)`
   - Final position-dependent XOR to recover original character

---

## Key Concepts

### Obfuscation Techniques Used

1. **Multiple Encryption Layers** - Initial XOR followed by per-byte transformations
2. **Position-Dependent Keys** - Each byte uses different keys based on its index
3. **Bit Manipulation** - Rotations and shifts make pattern analysis difficult
4. **Modular Arithmetic** - Non-linear operations increase complexity

### Why This Works

- The decryption algorithm is deterministic and reversible
- XOR operations are self-inverse (A XOR B XOR B = A)
- Rotate operations are invertible (rotate right can be undone by rotate left)
- Subtraction modulo 256 is invertible through addition

---

## Running the Solution

```bash
python3 chall.py
```

The script will output the decrypted flag.
