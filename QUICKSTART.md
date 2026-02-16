# Quick Start Guide: labHE with Paillier

## 5-Minute Setup and First Example

### Step 1: Install Dependencies (1 minute)

```bash
pip install phe
```

### Step 2: Save the Implementation (1 minute)

Save `labhe_paillier_implementation.py` to your working directory.

### Step 3: Run the Examples (2 minutes)

```bash
python labhe_paillier_implementation.py
```

You'll see three examples run automatically:
1. Computing mean on encrypted data
2. Computing covariance (degree-2 polynomial)
3. Multi-user genetic testing

### Step 4: Your First Custom Example (1 minute)

Create a file `my_first_labhe.py`:

```python
from labhe_paillier_implementation import LabHE_Paillier, LabeledProgram

# Initialize
labhe = LabHE_Paillier()
epk, sk = labhe.keygen()

# Encrypt your data
my_data = [100, 200, 300]
ciphertexts = [
    labhe.encrypt(sk, f"item_{i}", val) 
    for i, val in enumerate(my_data)
]

# Cloud computes sum
result_ct = ciphertexts[0]
for ct in ciphertexts[1:]:
    result_ct = labhe.add(result_ct, ct)

# Decrypt
program = LabeledProgram(
    function=sum,
    labels=[f"item_{i}" for i in range(len(my_data))],
    function_name="sum"
)

result = labhe.decrypt(sk, program, result_ct)
print(f"Sum: {result}")  # Output: 600
```

Run it:
```bash
python my_first_labhe.py
```

## Common Operations

### Computing Average

```python
# After getting encrypted sum (result_ct)
n = len(my_data)
encrypted_sum = labhe.decrypt(sk, program, result_ct)
average = encrypted_sum / n
```

### Computing Variance

```python
# Encrypt squared values
squared_cts = []
for i, val in enumerate(my_data):
    ct = labhe.encrypt(sk, f"item_{i}", val)
    squared_ct = labhe.mult(ct, ct)  # Square it
    squared_cts.append(squared_ct)

# Sum of squares
sum_sq = squared_cts[0]
for ct in squared_cts[1:]:
    sum_sq = labhe.add(sum_sq, ct)

# Decrypt and compute variance
# variance = E[X²] - E[X]²
```

### Working with Real Numbers

```python
# Use fixed-point encoding
SCALE = 10000  # 4 decimal places

real_value = 3.1416
encoded = int(real_value * SCALE)  # 31416

# Encrypt
ct = labhe.encrypt(sk, "pi", encoded)

# After computation and decryption
result_encoded = labhe.decrypt(sk, program, ct)
result_real = result_encoded / SCALE
```

## Understanding the Output

When you run the examples, you'll see:

```
[KeyGen] Generating 2048-bit Paillier keys...
[KeyGen] Complete in 0.234s
```
- This generates cryptographic keys (one-time setup)

```
[Offline-Dec] Computed offset: 1234567890...
[Offline-Dec] Time: 2.34ms
```
- This is preprocessing that happens while Cloud computes
- Very fast (milliseconds)

```
[Online-Dec] Result: 150
[Online-Dec] Time: 0.12ms
```
- This is the final fast decryption step
- Constant time regardless of computation complexity

## Key Concepts

### Labels
- Every piece of data has a unique label (string)
- Examples: "patient_123", "sensor_5_reading_10", "value_42"
- Labels are NOT secret

### Labeled Programs
- Specifies what function to compute
- Lists which labels are inputs
- Example: P = (addition, ["a", "b"])

### Offline/Online Split
- **Offline**: Preprocessing before receiving result (runs during Cloud computation)
- **Online**: Fast extraction after receiving result (~50ms)

### Two Ciphertext Levels
- **Level-1**: Fresh encryptions and additions
- **Level-2**: Results of multiplications
- Can add same levels, multiply level-1 only

## Troubleshooting

**Q: "Decryption gives wrong results"**  
A: Check that program labels exactly match encryption labels

**Q: "Can I multiply level-2 ciphertexts?"**  
A: No, only degree-2 polynomials supported. Multiply level-1 only.

**Q: "How to compute X²?"**  
A: Use `labhe.mult(ct, ct)` where ct is level-1

**Q: "Encryption is slow"**  
A: First key generation is slow (~200ms). Encryption itself is ~50ms.  
   Use `offline_enc` to precompute before knowing the message.

## Next Steps

1. **Read the paper** - Understand the theory
2. **Modify examples** - Try different computations
3. **Build an application** - See "Applications" in README
4. **Optimize** - Use offline/online split for better performance

## Getting Help

- Check the extensive code comments
- Review the three built-in examples
- Read the full README.md
- Refer to the original paper

---

**You're now ready to use labHE! Start with simple examples and build up.** 🚀
