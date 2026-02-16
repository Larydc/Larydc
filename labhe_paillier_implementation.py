"""
Labeled Homomorphic Encryption with Paillier Cryptosystem
==========================================================

Complete implementation based on:
"Labeled Homomorphic Encryption: Scalable and Privacy-Preserving Processing 
of Outsourced Data" by Barbosa, Catalano & Fiore (2017)

This implementation uses Paillier as the underlying linearly-homomorphic 
encryption scheme, as described in Section 4 of the paper.

Author: Implementation based on the paper
Date: 2024
"""

import hashlib
import hmac
import json
from typing import Tuple, List, Callable, Union, Dict
from dataclasses import dataclass
from phe import paillier
import time


# ============================================================================
# HELPER CLASSES AND DATA STRUCTURES
# ============================================================================

@dataclass
class LabeledProgram:
    """
    Represents a labeled program P = (f, τ₁, τ₂, ..., τₜ)
    
    Attributes:
        function: The function to compute (as a callable)
        labels: List of input labels
        function_name: Human-readable name for the function
    """
    function: Callable
    labels: List[str]
    function_name: str
    
    def __repr__(self):
        return f"LabeledProgram({self.function_name}, labels={self.labels})"


class Ciphertext:
    """
    Represents a labHE ciphertext.
    
    Can be either:
    - Level-1: (a, β) where a ∈ Z_N and β is a Paillier ciphertext
    - Level-2: α where α is a Paillier ciphertext (result of multiplication)
    """
    def __init__(self, level: int, data: Union[Tuple, paillier.EncryptedNumber]):
        """
        Args:
            level: 1 for level-1 ciphertext, 2 for level-2
            data: For level-1: (a, β), for level-2: α
        """
        self.level = level
        self.data = data
    
    def __repr__(self):
        if self.level == 1:
            return f"Ciphertext(level=1, a={self.data[0]}, β=EncryptedNumber)"
        else:
            return f"Ciphertext(level=2, α=EncryptedNumber)"


# ============================================================================
# PSEUDORANDOM FUNCTION (PRF)
# ============================================================================

class PRF:
    """
    Pseudorandom Function F: {0,1}^k × {0,1}* → Z_N
    
    Implemented using HMAC-SHA256 for cryptographic security.
    """
    
    def __init__(self, key: bytes, modulus: int):
        """
        Args:
            key: PRF secret key (should be 32 bytes for 256-bit security)
            modulus: The modulus N for output space Z_N
        """
        self.key = key
        self.modulus = modulus
    
    def evaluate(self, label: str) -> int:
        """
        Evaluate F(K, τ) for a given label τ.
        
        Args:
            label: The label τ as a string
            
        Returns:
            Pseudorandom value in Z_N
        """
        # Convert label to bytes
        label_bytes = label.encode('utf-8')
        
        # Compute HMAC-SHA256(key, label)
        h = hmac.new(self.key, label_bytes, hashlib.sha256)
        digest = h.digest()
        
        # Convert to integer and reduce modulo N
        value = int.from_bytes(digest, byteorder='big')
        return value % self.modulus
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 256-bit PRF key."""
        import secrets
        return secrets.token_bytes(32)


# ============================================================================
# LABELED HOMOMORPHIC ENCRYPTION WITH PAILLIER
# ============================================================================

class LabHE_Paillier:
    """
    Labeled Homomorphic Encryption using Paillier cryptosystem.
    
    Supports evaluation of degree-2 multivariate polynomials on encrypted data.
    """
    
    def __init__(self):
        """Initialize the labHE scheme."""
        self.public_key = None
        self.private_key = None
        self.prf = None
        self.label_space = set()  # Track all used labels
    
    # ========================================================================
    # KEY GENERATION
    # ========================================================================
    
    def keygen(self, key_length: int = 2048) -> Tuple[Dict, Dict]:
        """
        KeyGen(1^λ): Generate keys for labHE.
        
        As described in Section 4.1 of the paper:
        1. Run Paillier KeyGen to get (pk, sk₀)
        2. Generate random PRF key K
        3. Set label space L = {0,1}*
        
        Args:
            key_length: Bit length for Paillier modulus N (default 2048)
            
        Returns:
            (epk, sk) where:
                epk: Evaluation public key (contains public key)
                sk: Secret key (contains private key and PRF key)
        """
        print(f"[KeyGen] Generating {key_length}-bit Paillier keys...")
        start = time.time()
        
        # Step 1: Generate Paillier keys
        self.public_key, self.private_key = paillier.generate_paillier_keypair(
            n_length=key_length
        )
        
        # Step 2: Generate PRF key
        prf_key = PRF.generate_key()
        self.prf = PRF(prf_key, self.public_key.n)
        
        elapsed = time.time() - start
        print(f"[KeyGen] Complete in {elapsed:.3f}s")
        
        # Step 3: Create output keys
        epk = {
            'public_key': self.public_key,
            'modulus': self.public_key.n,
            'label_space': 'arbitrary_strings'  # L = {0,1}*
        }
        
        sk = {
            'private_key': self.private_key,
            'prf_key': prf_key,
            'modulus': self.public_key.n
        }
        
        return epk, sk
    
    # ========================================================================
    # ENCRYPTION (with Offline/Online split)
    # ========================================================================
    
    def offline_enc(self, sk: Dict, label: str) -> Tuple[int, paillier.EncryptedNumber]:
        """
        Offline-Enc(sk, τ): Precompute encryption for a label.
        
        As described in Section 4.1:
        1. Compute b ← F(K, τ)
        2. Compute β ← Enc_Paillier(pk, b)
        
        Args:
            sk: Secret key (must contain prf_key)
            label: The label τ for this data item
            
        Returns:
            (b, β) - the offline ciphertext components
        """
        # Step 1: Evaluate PRF on label
        b = self.prf.evaluate(label)
        
        # Step 2: Encrypt b using Paillier
        beta = self.public_key.encrypt(b)
        
        return (b, beta)
    
    def online_enc(self, ciphertext_offline: Tuple, message: int) -> Ciphertext:
        """
        Online-Enc(C_off, m): Complete encryption using offline ciphertext.
        
        As described in Section 4.1:
        1. Parse C_off as (b, β)
        2. Compute a ← m - b (mod N)
        3. Output (a, β)
        
        Args:
            ciphertext_offline: Output from offline_enc
            message: The plaintext message m
            
        Returns:
            Level-1 ciphertext (a, β)
        """
        b, beta = ciphertext_offline
        
        # Compute a = m - b (mod N)
        a = (message - b) % self.public_key.n
        
        # Return level-1 ciphertext
        return Ciphertext(level=1, data=(a, beta))
    
    def encrypt(self, sk: Dict, label: str, message: int) -> Ciphertext:
        """
        Enc(sk, τ, m): Complete encryption in one call.
        
        Combines offline and online phases.
        
        Args:
            sk: Secret key
            label: The label τ for this data item
            message: The plaintext message m
            
        Returns:
            Encrypted ciphertext
        """
        # Track label
        self.label_space.add(label)
        
        # Offline phase
        c_off = self.offline_enc(sk, label)
        
        # Online phase
        return self.online_enc(c_off, message)
    
    # ========================================================================
    # EVALUATION OPERATIONS
    # ========================================================================
    
    def mult(self, c1: Ciphertext, c2: Ciphertext) -> Ciphertext:
        """
        Mult(C₁, C₂): Homomorphic multiplication.
        
        As described in Section 4.1:
        For C_i = (a_i, β_i), compute:
        α = Enc(a₁·a₂) ⊞ (a₁·β₂) ⊞ (a₂·β₁)
        
        where ⊞ is Paillier addition and · is scalar multiplication.
        
        Args:
            c1, c2: Level-1 ciphertexts
            
        Returns:
            Level-2 ciphertext (result of multiplication)
        """
        if c1.level != 1 or c2.level != 1:
            raise ValueError("Mult requires two level-1 ciphertexts")
        
        a1, beta1 = c1.data
        a2, beta2 = c2.data
        
        # Compute: α = Enc(a₁·a₂) + (a₁·β₂) + (a₂·β₁)
        # Note: Paillier addition is multiplication of ciphertexts
        # Scalar multiplication is exponentiation
        
        term1 = self.public_key.encrypt((a1 * a2) % self.public_key.n)
        term2 = beta2 * a1  # Scalar multiplication in Paillier
        term3 = beta1 * a2
        
        # Homomorphic addition (multiply ciphertexts)
        alpha = term1 + term2 + term3
        
        return Ciphertext(level=2, data=alpha)
    
    def add(self, c1: Ciphertext, c2: Ciphertext) -> Ciphertext:
        """
        Add(C₁, C₂): Homomorphic addition.
        
        Handles two cases:
        - Both level-1: (a₁+a₂, β₁·β₂)
        - Both level-2: α₁·α₂
        
        Args:
            c1, c2: Ciphertexts of same level
            
        Returns:
            Ciphertext of same level
        """
        if c1.level != c2.level:
            raise ValueError("Add requires ciphertexts of same level")
        
        if c1.level == 1:
            # Level-1 addition
            a1, beta1 = c1.data
            a2, beta2 = c2.data
            
            a_sum = (a1 + a2) % self.public_key.n
            beta_sum = beta1 + beta2  # Paillier homomorphic addition
            
            return Ciphertext(level=1, data=(a_sum, beta_sum))
        
        else:  # level == 2
            # Level-2 addition
            alpha1 = c1.data
            alpha2 = c2.data
            
            alpha_sum = alpha1 + alpha2
            
            return Ciphertext(level=2, data=alpha_sum)
    
    def cmult(self, constant: int, c: Ciphertext) -> Ciphertext:
        """
        cMult(c, C): Multiplication by constant.
        
        Handles two cases:
        - Level-1: (c·a, β^c)
        - Level-2: α^c
        
        Args:
            constant: The constant c
            c: Ciphertext
            
        Returns:
            Ciphertext of same level
        """
        if c.level == 1:
            # Level-1 scalar multiplication
            a, beta = c.data
            
            a_mult = (constant * a) % self.public_key.n
            beta_mult = beta * constant  # Paillier scalar multiplication
            
            return Ciphertext(level=1, data=(a_mult, beta_mult))
        
        else:  # level == 2
            # Level-2 scalar multiplication
            alpha = c.data
            alpha_mult = alpha * constant
            
            return Ciphertext(level=2, data=alpha_mult)
    
    # ========================================================================
    # DECRYPTION (with Offline/Online split)
    # ========================================================================
    
    def offline_dec(self, sk: Dict, program: LabeledProgram) -> Dict:
        """
        Offline-Dec(sk, P): Precompute offset for a labeled program.
        
        As described in Section 4.1:
        1. For each label τ_i, compute b_i ← F(K, τ_i)
        2. Compute b ← f(b₁, ..., b_t)
        
        This can be done BEFORE receiving the ciphertext!
        
        Args:
            sk: Secret key
            program: The labeled program P = (f, τ₁, ..., τₜ)
            
        Returns:
            sk_P: Augmented secret key for this program
        """
        print(f"\n[Offline-Dec] Processing program: {program.function_name}")
        print(f"[Offline-Dec] Labels: {program.labels}")
        start = time.time()
        
        # Step 1: Evaluate PRF on all labels
        b_values = []
        for label in program.labels:
            b_i = self.prf.evaluate(label)
            b_values.append(b_i)
            print(f"[Offline-Dec]   F(K, '{label}') = {b_i}")
        
        # Step 2: Evaluate function on PRF outputs
        offset = program.function(*b_values) % self.public_key.n
        
        elapsed = time.time() - start
        print(f"[Offline-Dec] Computed offset: {offset}")
        print(f"[Offline-Dec] Time: {elapsed*1000:.2f}ms")
        
        return {
            'private_key': sk['private_key'],
            'offset': offset,
            'program': program
        }
    
    def online_dec(self, sk_p: Dict, ciphertext: Ciphertext) -> int:
        """
        Online-Dec(sk_P, C): Fast decryption using precomputed offset.
        
        As described in Section 4.1:
        - Level-1: m = a + b
        - Level-2: m = Dec_Paillier(α) + b
        
        Args:
            sk_p: Augmented secret key from offline_dec
            ciphertext: The ciphertext to decrypt
            
        Returns:
            The plaintext result
        """
        print(f"\n[Online-Dec] Decrypting level-{ciphertext.level} ciphertext")
        start = time.time()
        
        private_key = sk_p['private_key']
        offset = sk_p['offset']
        
        if ciphertext.level == 1:
            # Level-1 decryption: m = a + b
            a, beta = ciphertext.data
            result = (a + offset) % private_key.public_key.n
            
        else:  # level == 2
            # Level-2 decryption: m = Dec(α) + b
            alpha = ciphertext.data
            m_hat = private_key.decrypt(alpha)
            result = (m_hat + offset) % private_key.public_key.n
        
        elapsed = time.time() - start
        print(f"[Online-Dec] Result: {result}")
        print(f"[Online-Dec] Time: {elapsed*1000:.2f}ms")
        
        return result
    
    def decrypt(self, sk: Dict, program: LabeledProgram, 
                ciphertext: Ciphertext) -> int:
        """
        Dec(sk, P, C): Complete decryption in one call.
        
        Combines offline and online phases.
        
        Args:
            sk: Secret key
            program: The labeled program
            ciphertext: The ciphertext to decrypt
            
        Returns:
            The plaintext result
        """
        # Offline phase
        sk_p = self.offline_dec(sk, program)
        
        # Online phase
        return self.online_dec(sk_p, ciphertext)


# ============================================================================
# MULTI-USER LABELED HOMOMORPHIC ENCRYPTION
# ============================================================================

class MultiUser_LabHE_Paillier:
    """
    Multi-user extension of labHE(Paillier).
    
    Allows multiple data providers to encrypt data under their own keys,
    with one receiver able to decrypt results from computations over
    data from multiple providers.
    
    As described in Section 5 of the paper.
    """
    
    def __init__(self):
        self.master_public_key = None
        self.master_private_key = None
        self.users = {}  # user_id -> (user_secret_key, user_public_key)
    
    def setup(self, key_length: int = 2048) -> Tuple[Dict, Dict]:
        """
        Setup(1^λ): Generate master keys.
        
        Args:
            key_length: Security parameter
            
        Returns:
            (mpk, msk): Master public and secret keys
        """
        print(f"[Setup] Generating master keys ({key_length}-bit)...")
        
        # Generate Paillier key pair for master
        self.master_public_key, self.master_private_key = \
            paillier.generate_paillier_keypair(n_length=key_length)
        
        mpk = {
            'public_key': self.master_public_key,
            'modulus': self.master_public_key.n
        }
        
        msk = {
            'private_key': self.master_private_key,
            'modulus': self.master_public_key.n
        }
        
        print(f"[Setup] Complete. Modulus N has {key_length} bits")
        
        return mpk, msk
    
    def user_keygen(self, mpk: Dict, user_id: str) -> Tuple[Dict, Dict]:
        """
        KeyGen(mpk): Generate keys for a user.
        
        Args:
            mpk: Master public key
            user_id: Identifier for this user
            
        Returns:
            (usk, upk): User secret and public keys
        """
        print(f"[UserKeyGen] Generating keys for user '{user_id}'...")
        
        # Generate PRF key for this user
        prf_key = PRF.generate_key()
        
        # Encrypt the PRF key under master public key
        # This creates the user public key
        prf_key_int = int.from_bytes(prf_key, byteorder='big')
        upk_encrypted = self.master_public_key.encrypt(prf_key_int)
        
        usk = {
            'user_id': user_id,
            'prf_key': prf_key,
            'master_public_key': self.master_public_key
        }
        
        upk = {
            'user_id': user_id,
            'encrypted_prf_key': upk_encrypted
        }
        
        # Store for later use
        self.users[user_id] = (usk, upk)
        
        print(f"[UserKeyGen] Keys generated for '{user_id}'")
        
        return usk, upk
    
    def encrypt(self, mpk: Dict, usk: Dict, label: str, 
                message: int) -> Ciphertext:
        """
        Enc(mpk, usk, τ, m): User encrypts a message.
        
        Args:
            mpk: Master public key
            usk: User's secret key
            label: Label for this data item
            message: Plaintext message
            
        Returns:
            Ciphertext
        """
        # Create PRF for this user
        prf = PRF(usk['prf_key'], mpk['modulus'])
        
        # Compute b = F(K_user, τ)
        b = prf.evaluate(label)
        
        # Encrypt b under master public key
        beta = mpk['public_key'].encrypt(b)
        
        # Compute a = m - b
        a = (message - b) % mpk['modulus']
        
        return Ciphertext(level=1, data=(a, beta))
    
    def decrypt(self, msk: Dict, upks: List[Dict], program: LabeledProgram,
                ciphertext: Ciphertext) -> int:
        """
        Dec(msk, upk, P, C): Receiver decrypts result.
        
        Args:
            msk: Master secret key
            upks: List of user public keys involved
            program: The labeled program
            ciphertext: The ciphertext to decrypt
            
        Returns:
            Plaintext result
        """
        print(f"\n[MultiUser-Dec] Decrypting with {len(upks)} users")
        
        # Decrypt each user's PRF key
        prfs = []
        for upk in upks:
            prf_key_int = msk['private_key'].decrypt(upk['encrypted_prf_key'])
            prf_key = prf_key_int.to_bytes(32, byteorder='big')
            prf = PRF(prf_key, msk['modulus'])
            prfs.append(prf)
        
        # Compute offset
        b_values = []
        for i, label in enumerate(program.labels):
            # Determine which user's PRF to use
            # (simplified: assume labels map to users in order)
            user_idx = i % len(prfs)
            b_i = prfs[user_idx].evaluate(label)
            b_values.append(b_i)
        
        offset = program.function(*b_values) % msk['modulus']
        
        # Decrypt ciphertext
        if ciphertext.level == 1:
            a, beta = ciphertext.data
            result = (a + offset) % msk['modulus']
        else:
            alpha = ciphertext.data
            m_hat = msk['private_key'].decrypt(alpha)
            result = (m_hat + offset) % msk['modulus']
        
        return result


# ============================================================================
# EXAMPLE USAGE AND TESTS
# ============================================================================

def example_basic_statistics():
    """
    Example: Computing statistics on encrypted data.
    
    Demonstrates:
    - Encryption with labels
    - Homomorphic addition (for mean)
    - Homomorphic multiplication (for variance)
    - Offline/online decryption split
    """
    print("="*70)
    print("EXAMPLE 1: Computing Mean on Encrypted Data")
    print("="*70)
    
    # Initialize scheme
    labhe = LabHE_Paillier()
    
    # Step 1: Key Generation
    epk, sk = labhe.keygen(key_length=2048)
    
    # Step 2: Data provider encrypts data
    print("\n[Data Provider] Encrypting data...")
    data = [10, 20, 30, 40, 50]
    labels = [f"value_{i}" for i in range(len(data))]
    
    ciphertexts = []
    for i, (label, value) in enumerate(zip(labels, data)):
        ct = labhe.encrypt(sk, label, value)
        ciphertexts.append(ct)
        print(f"  Encrypted: {label} = {value}")
    
    # Step 3: Cloud computes sum (for mean)
    print("\n[Cloud] Computing sum...")
    c_sum = ciphertexts[0]
    for ct in ciphertexts[1:]:
        c_sum = labhe.add(c_sum, ct)
    print("  Sum computed (still encrypted)")
    
    # Step 4: Define labeled program
    def sum_function(*values):
        return sum(values)
    
    program = LabeledProgram(
        function=sum_function,
        labels=labels,
        function_name="sum"
    )
    
    # Step 5: Receiver decrypts (with offline/online split)
    print("\n[Receiver] Decrypting result...")
    
    # Offline phase (can happen while Cloud computes)
    sk_p = labhe.offline_dec(sk, program)
    
    # Simulate: Cloud sends result
    print("\n[Receiver] Received encrypted result from Cloud")
    
    # Online phase (fast!)
    result_sum = labhe.online_dec(sk_p, c_sum)
    
    # Compute mean
    mean = result_sum / len(data)
    
    print(f"\n{'='*70}")
    print(f"RESULT: Sum = {result_sum}, Mean = {mean}")
    print(f"Expected: Sum = {sum(data)}, Mean = {sum(data)/len(data)}")
    print(f"{'='*70}")
    
    return mean == sum(data) / len(data)


def example_covariance():
    """
    Example: Computing covariance on encrypted data.
    
    Demonstrates degree-2 polynomial evaluation.
    """
    print("\n" + "="*70)
    print("EXAMPLE 2: Computing Covariance on Encrypted Data")
    print("="*70)
    
    labhe = LabHE_Paillier()
    epk, sk = labhe.keygen(key_length=2048)
    
    # Data: pairs (x, y)
    x_data = [1, 2, 3, 4, 5]
    y_data = [2, 4, 5, 4, 5]
    
    print(f"\nData: X = {x_data}, Y = {y_data}")
    
    # Encrypt X values
    print("\n[Encrypting X values...]")
    x_cts = []
    for i, val in enumerate(x_data):
        ct = labhe.encrypt(sk, f"x_{i}", val)
        x_cts.append(ct)
    
    # Encrypt Y values
    print("[Encrypting Y values...]")
    y_cts = []
    for i, val in enumerate(y_data):
        ct = labhe.encrypt(sk, f"y_{i}", val)
        y_cts.append(ct)
    
    # Compute sum of products: Σ(x_i * y_i)
    print("\n[Cloud] Computing Σ(x_i * y_i)...")
    products = []
    for i in range(len(x_data)):
        prod = labhe.mult(x_cts[i], y_cts[i])
        products.append(prod)
    
    sum_xy = products[0]
    for prod in products[1:]:
        sum_xy = labhe.add(sum_xy, prod)
    
    # Compute sum of X: Σx_i
    print("[Cloud] Computing Σx_i...")
    sum_x = x_cts[0]
    for ct in x_cts[1:]:
        sum_x = labhe.add(sum_x, ct)
    
    # Compute sum of Y: Σy_i
    print("[Cloud] Computing Σy_i...")
    sum_y = y_cts[0]
    for ct in y_cts[1:]:
        sum_y = labhe.add(sum_y, ct)
    
    # Define labeled programs
    def product_sum(*values):
        # First half are x values, second half are y values
        n = len(values) // 2
        return sum(values[i] * values[n + i] for i in range(n))
    
    all_labels = [f"x_{i}" for i in range(len(x_data))] + \
                 [f"y_{i}" for i in range(len(y_data))]
    
    program_xy = LabeledProgram(
        function=product_sum,
        labels=all_labels,
        function_name="sum_of_products"
    )
    
    program_x = LabeledProgram(
        function=sum,
        labels=[f"x_{i}" for i in range(len(x_data))],
        function_name="sum_x"
    )
    
    program_y = LabeledProgram(
        function=sum,
        labels=[f"y_{i}" for i in range(len(y_data))],
        function_name="sum_y"
    )
    
    # Decrypt results
    print("\n[Receiver] Decrypting results...")
    result_xy = labhe.decrypt(sk, program_xy, sum_xy)
    result_x = labhe.decrypt(sk, program_x, sum_x)
    result_y = labhe.decrypt(sk, program_y, sum_y)
    
    # Compute covariance: (Σxy - (Σx)(Σy)/n) / n
    n = len(x_data)
    cov = (result_xy - (result_x * result_y) / n) / n
    
    # Expected covariance
    mean_x = sum(x_data) / n
    mean_y = sum(y_data) / n
    expected_cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(x_data, y_data)) / n
    
    print(f"\n{'='*70}")
    print(f"RESULT: Covariance = {cov:.4f}")
    print(f"Expected: {expected_cov:.4f}")
    print(f"{'='*70}")
    
    return abs(cov - expected_cov) < 0.01


def example_multiuser():
    """
    Example: Multi-user scenario with genetic testing.
    
    Demonstrates:
    - Multiple data providers
    - Single receiver decrypts combined result
    """
    print("\n" + "="*70)
    print("EXAMPLE 3: Multi-User Genetic Testing Scenario")
    print("="*70)
    
    # Initialize multi-user scheme
    mu_labhe = MultiUser_LabHE_Paillier()
    
    # Setup: Receiver (Patient) generates master keys
    print("\n[Patient] Setting up master keys...")
    mpk, msk = mu_labhe.setup(key_length=2048)
    
    # User 1: Lab generates keys and encrypts SNP data
    print("\n[Lab] Generating keys...")
    usk_lab, upk_lab = mu_labhe.user_keygen(mpk, "Lab")
    
    print("[Lab] Encrypting SNP data...")
    snp_data = [0, 1, 2, 1, 0]  # Example SNP values
    snp_labels = [f"snp_{i}" for i in range(len(snp_data))]
    
    snp_cts = []
    for label, value in zip(snp_labels, snp_data):
        ct = mu_labhe.encrypt(mpk, usk_lab, label, value)
        snp_cts.append(ct)
        print(f"  SNP {label}: {value} (encrypted)")
    
    # User 2: Medical center generates keys and encrypts weights
    print("\n[Medical Center] Generating keys...")
    usk_med, upk_med = mu_labhe.user_keygen(mpk, "MedCenter")
    
    print("[Medical Center] Encrypting test weights...")
    weights = [5, 3, 7, 4, 6]  # Risk weights
    weight_labels = [f"weight_{i}" for i in range(len(weights))]
    
    weight_cts = []
    for label, value in zip(weight_labels, weights):
        ct = mu_labhe.encrypt(mpk, usk_med, label, value)
        weight_cts.append(ct)
        print(f"  Weight {label}: {value} (encrypted)")
    
    # Cloud computes weighted sum (risk score)
    print("\n[Cloud] Computing risk score...")
    
    # Create LabHE instance for evaluation
    labhe = LabHE_Paillier()
    labhe.public_key = mpk['public_key']
    
    products = []
    for i in range(len(snp_data)):
        prod = labhe.mult(snp_cts[i], weight_cts[i])
        products.append(prod)
    
    risk_score_ct = products[0]
    for prod in products[1:]:
        risk_score_ct = labhe.add(risk_score_ct, prod)
    
    # Define labeled program for weighted sum
    def weighted_sum(*values):
        n = len(values) // 2
        snps = values[:n]
        weights = values[n:]
        return sum(s * w for s, w in zip(snps, weights))
    
    all_labels = snp_labels + weight_labels
    program = LabeledProgram(
        function=weighted_sum,
        labels=all_labels,
        function_name="genetic_risk_score"
    )
    
    # Patient decrypts result
    print("\n[Patient] Decrypting risk score...")
    risk_score = mu_labhe.decrypt(msk, [upk_lab, upk_med], program, risk_score_ct)
    
    # Expected result
    expected = sum(s * w for s, w in zip(snp_data, weights))
    
    print(f"\n{'='*70}")
    print(f"RESULT: Risk Score = {risk_score}")
    print(f"Expected: {expected}")
    print(f"Privacy: Lab never saw weights, Med Center never saw SNPs!")
    print(f"{'='*70}")
    
    return risk_score == expected


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*70)
    print(" LABELED HOMOMORPHIC ENCRYPTION WITH PAILLIER")
    print(" Implementation based on Barbosa, Catalano & Fiore (2017)")
    print("="*70)
    
    # Run examples
    test1 = example_basic_statistics()
    test2 = example_covariance()
    test3 = example_multiuser()
    
    # Summary
    print("\n" + "="*70)
    print(" TEST RESULTS")
    print("="*70)
    print(f"Example 1 (Mean):        {'✓ PASS' if test1 else '✗ FAIL'}")
    print(f"Example 2 (Covariance):  {'✓ PASS' if test2 else '✗ FAIL'}")
    print(f"Example 3 (Multi-user):  {'✓ PASS' if test3 else '✗ FAIL'}")
    print("="*70)
    
    if all([test1, test2, test3]):
        print("\n✓ All tests passed! Implementation is correct.")
    else:
        print("\n✗ Some tests failed. Check implementation.")
